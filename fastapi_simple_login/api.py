from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from datetime import timedelta
from typing import Any

from fastapi import APIRouter
from fastapi import Depends
from fastapi import FastAPI
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_utils.cbv import cbv
from fastapi_utils.inferring_router import InferringRouter
from jose import jwt
from jose.exceptions import ExpiredSignatureError
from jose.exceptions import JWTClaimsError
from jose.exceptions import JWTError
from passlib.hash import bcrypt
from pydantic import BaseModel
from sqlalchemy.exc import NoResultFound

from .exception import AuthorizationHeaderNotFound
from .exception import DatabaseSessionMakerNotSet
from .exception import InsufficientScope
from .exception import InvalidRequest
from .exception import InvalidToken
from .exception import RedisSessionNotSet
from .exception import RequiredColumnsNotDefined

_api_router = InferringRouter()


class JwtTokenClaims(BaseModel):
    sub: str
    exp: datetime
    jti: str
    grant: str


@cbv(_api_router)
class SimpleLoginAPI():
    __SECRET_KEY = secrets.token_hex(64)
    __JWT_SIGNING_ALGORITHM = 'HS256'
    __ACCESS_TOKEN_EXPIRE_MINUTES = 60
    __REFRESH_TOKEN_EXPIRE_MINUTES = 7200

    __redis_session = None
    __database_session_maker = None
    __user_model = None

    @classmethod
    def set_config(cls, redis_session=None, database_session_maker=None, user_model=None):
        if redis_session is not None:
            cls.__redis_session = redis_session
        if database_session_maker is not None:
            cls.__database_session_maker = database_session_maker
        if user_model is not None:
            cls.__user_model = user_model

    @classmethod
    def validate_access_token(cls, encoded_jwt: str | Any = Depends(OAuth2PasswordBearer(tokenUrl='login'))) -> str:
        return cls.__validate_token('access', encoded_jwt)

    @staticmethod
    def set_exception_handlers(app: FastAPI) -> None:
        exceptions = [
            DatabaseSessionMakerNotSet,
            RedisSessionNotSet,
            InsufficientScope,
            AuthorizationHeaderNotFound,
            InvalidRequest,
            RequiredColumnsNotDefined,
            InvalidToken,
        ]

        for exception in exceptions:
            app.add_exception_handler(exception, exception.exception_handler)  # type: ignore

    @staticmethod
    def get_api_router() -> APIRouter:
        return _api_router

    @classmethod
    def __generate_token(cls, ulid, grant, expire_minutes):
        claims = JwtTokenClaims(
            sub=ulid,
            exp=datetime.utcnow() + timedelta(minutes=expire_minutes),
            jti=f'{ulid}:{uuid.uuid4()}',
            grant=grant,
        )

        encoded_jwt = jwt.encode(claims.dict(), cls.__SECRET_KEY, algorithm=cls.__JWT_SIGNING_ALGORITHM)

        return encoded_jwt, claims.jti

    @classmethod
    def __generate_access_token(cls, ulid: str):
        return cls.__generate_token(ulid, 'access', cls.__ACCESS_TOKEN_EXPIRE_MINUTES)

    @classmethod
    def __generate_refresh_token(cls, ulid: str):
        return cls.__generate_token(ulid, 'refresh', cls.__REFRESH_TOKEN_EXPIRE_MINUTES)

    @classmethod
    def __valiate_password_and_username(cls, username: str, password: str) -> str:
        if cls.__database_session_maker is None:
            raise DatabaseSessionMakerNotSet

        with cls.__database_session_maker() as db_session:
            try:
                user_record = db_session.query(cls.__user_model).filter(cls.__user_model.name == username).one()
            except NoResultFound:
                raise InvalidRequest

        if bcrypt.verify(password, user_record.bcrypt_hash):
            return user_record.ulid

        raise InvalidRequest

    @classmethod
    def __validate_token(cls, grant, encoded_jwt) -> str:
        try:
            claims = JwtTokenClaims(
                **jwt.decode(
                    encoded_jwt, cls.__SECRET_KEY,
                    algorithms=cls.__JWT_SIGNING_ALGORITHM,
                ),
            )
        except (JWTError, JWTClaimsError, ExpiredSignatureError):
            raise InvalidToken

        if claims.grant != grant:
            raise InsufficientScope

        if cls.__redis_session is None:
            raise RedisSessionNotSet

        ulid = claims.sub
        if cls.__redis_session.get(f'{ulid}:{grant}_token').decode('utf-8') != claims.jti:
            raise InvalidToken

        return ulid

    @classmethod
    def __validate_access_token(cls, encoded_jwt) -> str:
        return cls.__validate_token('access', encoded_jwt)

    @classmethod
    def __validate_refresh_token(cls, encoded_jwt) -> str:
        return cls.__validate_token('refresh', encoded_jwt)

    @_api_router.post('/login')
    async def __login(self, form_data: OAuth2PasswordRequestForm = Depends()) -> dict:
        username = form_data.username
        password = form_data.password

        ulid = self.__valiate_password_and_username(username, password)
        access_token, access_token_jti = self.__generate_access_token(ulid)
        refresh_token, refresh_token_jti = self.__generate_refresh_token(ulid)

        self.__redis_session.set(f'{ulid}:access_token', access_token_jti)  # type: ignore
        self.__redis_session.set(f'{ulid}:refresh_token', refresh_token_jti)  # type: ignore

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
        }

    @_api_router.post('/refresh')
    async def __refresh(self, encoded_jwt: str | Any = Depends(OAuth2PasswordBearer(tokenUrl='login'))) -> dict:
        ulid = self.__validate_refresh_token(encoded_jwt)
        access_token, access_token_jti = self.__generate_access_token(ulid)
        refresh_token, refresh_token_jti = self.__generate_refresh_token(ulid)

        self.__redis_session.set(f'{ulid}:access_token', access_token_jti)  # type: ignore
        self.__redis_session.set(f'{ulid}:refresh_token', refresh_token_jti)  # type: ignore

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
        }

    @_api_router.post('/logout')
    async def __logout(self, encoded_jwt: str = Depends(OAuth2PasswordBearer(tokenUrl='login'))) -> dict:
        ulid = self.__validate_access_token(encoded_jwt)

        self.__redis_session.delete(f'{ulid}:access_token', f'{ulid}:refresh_token')  # type: ignore

        return {}

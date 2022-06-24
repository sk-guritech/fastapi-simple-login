from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from datetime import timedelta

from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_utils.cbv import cbv
from fastapi_utils.inferring_router import InferringRouter
from jose import jwt
from passlib.hash import bcrypt
from pydantic import BaseModel
from pydantic import ValidationError
from redis import Redis
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import sessionmaker

from .exception import DatabaseSessionMakerNotSet
from .exception import InvalidToken
from .exception import RedisSessionNotSet
from .model import UserModel


_api_router = InferringRouter()


class JwtTokenClaims(BaseModel):
    sub: str
    exp: int
    jti: str
    grant: str


@cbv(_api_router)
class SimpleLoginAPIs():
    __SECRET_KEY = secrets.token_hex(64)
    __JWT_SIGNING_ALGORITHM = 'HS256'
    __ACCESS_TOKEN_EXPIRE_MINUTES = 60
    __REFRESH_TOKEN_EXPIRE_MINUTES = 7200

    __redis_session: Redis
    __database_session_maker: sessionmaker
    __user_model: type[UserModel]

    @classmethod
    def __generate_token(cls, ulid, grant, expire_minutes):
        claims = JwtTokenClaims(
            sub=ulid,
            exp=int((datetime.utcnow() + timedelta(minutes=expire_minutes)).timestamp()),
            jti=f'{ulid}:{uuid.uuid4}',
            grant=grant,
        )

        encoded_jwt = jwt.encode(claims, cls.__SECRET_KEY, algorithm=cls.__JWT_SIGNING_ALGORITHM)

        return encoded_jwt, claims.jti

    @classmethod
    def __generate_access_token(cls, ulid: str):
        return cls.__generate_token(ulid, 'access', cls.__ACCESS_TOKEN_EXPIRE_MINUTES)

    @classmethod
    def __generate_refresh_token(cls, ulid: str):
        return cls.__generate_token(ulid, 'refresh', cls.__REFRESH_TOKEN_EXPIRE_MINUTES)

    @classmethod
    def __validate_token(cls, grant, encoded_jwt: str = Depends(OAuth2PasswordBearer(tokenUrl='/login'))) -> str:
        try:
            claims = JwtTokenClaims(
                **jwt.decode(
                    encoded_jwt, cls.__SECRET_KEY,
                    algorithms=cls.__JWT_SIGNING_ALGORITHM,
                ),
            )
        except ValidationError:
            raise InvalidToken

        if claims.grant != grant:
            raise InvalidToken

        if cls.__redis_session is None:
            raise RedisSessionNotSet

        ulid = claims.sub

        if cls.__redis_session.get(f'{ulid}:{grant}_token') == claims.jti:
            raise InvalidToken

        return ulid

    @classmethod
    def validate_access_token(cls) -> str:
        return cls.__validate_token('access')

    @classmethod
    def validate_refresh_token(cls) -> str:
        return cls.__validate_token('refresh')

    @classmethod
    def __valiate_password_and_username(cls, form_data: OAuth2PasswordRequestForm = Depends()) -> str:
        username = form_data.username
        password = form_data.password

        if cls.__database_session_maker is None:
            raise DatabaseSessionMakerNotSet

        with cls.__database_session_maker() as db_session:
            try:
                user_record = db_session.query(cls.__user_model).filter(cls.__user_model.name == username).one()
            except NoResultFound:
                raise Exception

        if bcrypt.verify(password, user_record.bcrypt_hash):
            return user_record.ulid

        raise Exception

    # @staticmethod
    # def __callback_for_http_unauthorized_with_password() -> HTTPException:
    #     return HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED,
    #         headers={'WWW-Authentication': 'Bearer'},
    #     )

    @staticmethod
    def __callback_for_http_unauthorized_with_bearer() -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={'WWW-Authentication': 'Bearer'},
        )

    @_api_router.post('/login')
    async def __login(self) -> dict:
        return {}

    @_api_router.post('/refresh')
    async def __refresh(self) -> dict:
        try:
            ulid = self.validate_refresh_token()
        except InvalidToken:
            raise self.__callback_for_http_unauthorized_with_bearer()

        access_token = self.__generate_access_token(ulid)
        refresh_token = self.__generate_refresh_token(ulid)

        return {'access_token': access_token, 'refresh_token': refresh_token}

    @_api_router.post('/logout')
    async def __logout(self) -> dict:
        try:
            ulid = self.validate_access_token()
        except InvalidToken:
            raise self.__callback_for_http_unauthorized_with_bearer()

        self.__redis_session.delete(f'{ulid}:access_token')
        self.__redis_session.delete(f'{ulid}:refresh_token')

        return {}

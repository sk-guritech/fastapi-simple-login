from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from datetime import timedelta
from typing import Any

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


class _JwtTokenClaims(BaseModel):
    sub: str
    exp: datetime
    jti: str
    grant: str


@cbv(_api_router)
class SimpleLoginAPI():
    '''Provides APIs and Method for authorization and authentication.
    '''

    __SECRET_KEY = secrets.token_hex(64)
    __JWT_SIGNING_ALGORITHM = 'HS256'
    __ACCESS_TOKEN_EXPIRE_MINUTES = 60
    __REFRESH_TOKEN_EXPIRE_MINUTES = 7200

    __redis_session = None
    __database_session_maker = None
    __user_model = None

    @classmethod
    def deploy(cls, app: FastAPI, redis_session: Any, database_session_maker: Any, user_model: Any, router_settings: dict = {}):
        '''Deploys the APIs to the app.

        Args:
            app (FastAPI): FastAPI instance.
            redis_session (Any): Redis session for managing token sessions.
            database_session_maker (Any): Session maker for DB that is
                necessary for fetching user record.
            user_model (Any):SQLAlchemy model with the columns required to
                use the features for authorization and authentication.
            router_settings (dict, optional): FastAPI.include_router's arguments. Defaults to {}.
        '''
        cls.__set_exception_handlers(app)
        cls.__redis_session = redis_session
        cls.__database_session_maker = database_session_maker
        cls.__user_model = user_model
        app.include_router(_api_router, **router_settings)

    @classmethod
    def set_configs(
        cls,
        redis_session: Any | None = None,
        database_session_maker: Any | None = None,
        user_model: Any | None = None,
        secret_key: str | None = None,
        jwt_signing_algorithm: str | None = None,
        access_token_expire_minutes: int | None = None,
        refresh_token_expire_minutes: int | None = None,
    ):
        '''Set API configs.
            If you give an argument other than None, the setting will be reflected.

        Args:
            redis_session (Any | None, optional):Redis session for managing token
                sessions. Defaults to None, but necessary.
            database_session_maker (Any | None, optional): Session maker for DB
                that is necessary for fetching user record. Defaults to None,
                but necessary.
            user_model (Any | None, optional): SQLAlchemy model with the columns
                required to use the features for authorization and authentication.
                Defaults to None, but necessary.
            secret_key (str | None, optional): Secret key for signing. Defaults to
                set automatically.
            jwt_signing_algorithm (str | None, optional): Algorithm used to sign.
                Defaults to HS256.
            access_token_expire_minutes (int | None, optional): The period in minutes
                during which the access token can be used. Defaults to 60.
            refresh_token_expire_minutes (int | None, optional): The period in minutes
                during which the refresh token can be used. Defaults to 7200.
        '''
        if redis_session is not None:
            cls.__redis_session = redis_session
        if database_session_maker is not None:
            cls.__database_session_maker = database_session_maker
        if user_model is not None:
            cls.__user_model = user_model
        if secret_key is not None:
            cls.__SECRET_KEY = secret_key
        if jwt_signing_algorithm is not None:
            cls.__JWT_SIGNING_ALGORITHM = jwt_signing_algorithm
        if access_token_expire_minutes is not None:
            cls.__ACCESS_TOKEN_EXPIRE_MINUTES = access_token_expire_minutes
        if refresh_token_expire_minutes is not None:
            cls.__REFRESH_TOKEN_EXPIRE_MINUTES = refresh_token_expire_minutes

    @classmethod
    def validate_access_token(cls, encoded_jwt: str | Any = Depends(OAuth2PasswordBearer(tokenUrl='login'))) -> str:
        '''Validates access_token and returns the user's ulid.
            If the verification fails, the HTTP response according to the
            verification content is returned.

        Args:
            encoded_jwt (str | Any, optional): Received JWT. Defaults to Depends(OAuth2PasswordBearer(tokenUrl='login')).

        Returns:
            str: Ulid of the user.
        '''
        return cls.__validate_token('access', encoded_jwt)

    @staticmethod
    def __set_exception_handlers(app: FastAPI) -> None:
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

    @classmethod
    def __generate_token(cls, ulid: str, grant: str, expire_minutes: int) -> tuple[Any, str]:
        claims = _JwtTokenClaims(
            sub=ulid,
            exp=datetime.utcnow() + timedelta(minutes=expire_minutes),
            jti=f'{ulid}:{uuid.uuid4()}',
            grant=grant,
        )

        encoded_jwt = jwt.encode(claims.dict(), cls.__SECRET_KEY, algorithm=cls.__JWT_SIGNING_ALGORITHM)

        return encoded_jwt, claims.jti

    @classmethod
    def __generate_access_token(cls, ulid: str) -> tuple[Any, str]:
        return cls.__generate_token(ulid, 'access', cls.__ACCESS_TOKEN_EXPIRE_MINUTES)

    @classmethod
    def __generate_refresh_token(cls, ulid: str) -> tuple[Any, str]:
        return cls.__generate_token(ulid, 'refresh', cls.__REFRESH_TOKEN_EXPIRE_MINUTES)

    @classmethod
    def __valiate_password_and_username(cls, username: str, password: str) -> str:
        if cls.__database_session_maker is None:
            raise DatabaseSessionMakerNotSet

        with cls.__database_session_maker() as db_session:
            try:
                user_record = db_session.query(cls.__user_model).filter(cls.__user_model.name == username).one()  # type: ignore
            except NoResultFound:
                raise InvalidRequest

        if bcrypt.verify(password, user_record.bcrypt_hash):
            return user_record.ulid

        raise InvalidRequest

    @classmethod
    def __validate_token(cls, grant: str, encoded_jwt: str) -> str:
        try:
            claims = _JwtTokenClaims(
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
        jti_in_redis = cls.__redis_session.get(f'{ulid}:{grant}_token')
        if jti_in_redis is None:
            raise InvalidToken

        if jti_in_redis.decode('utf-8') != claims.jti:
            raise InvalidToken

        return ulid

    @classmethod
    def __validate_access_token(cls, encoded_jwt: str) -> str:
        return cls.__validate_token('access', encoded_jwt)

    @classmethod
    def __validate_refresh_token(cls, encoded_jwt: str) -> str:
        return cls.__validate_token('refresh', encoded_jwt)

    @_api_router.post('/login')
    async def __login(self, form_data: OAuth2PasswordRequestForm = Depends()) -> dict:
        '''Generates access token and refresh token.
            If InvalidRequest exception is occured, returns HTTP_400_BAD_REQUEST.
            If form_data is None, returns HTTP_422_UNPROCESSABLE_ENTITY.
            If other exception is occured , retunrs HTTP_500_INTERNAL_SERVER_ERROR.

        Args:
            encoded_jwt (str | Any, optional): JWT. Defaults to Depends(OAuth2PasswordBearer(tokenUrl='login')).

        Returns:
            dict: API response.
        '''
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
        '''Refreshes access token and refresh token.
            If InvalidToken exception is occured , retunrs HTTP_401_UNAUTHORIZED.
            If InsufficientScope exception is occured, retunrs HTTP_HTTP_403_FORBIDDEN.
            If other exception is occured , retunrs HTTP_500_INTERNAL_SERVER_ERROR.

        Args:
            encoded_jwt (str | Any, optional): JWT. Defaults to Depends(OAuth2PasswordBearer(tokenUrl='login')).

        Returns:
            dict: API response.
        '''

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
    async def __logout(self, encoded_jwt: str | Any = Depends(OAuth2PasswordBearer(tokenUrl='login'))) -> dict:
        '''Deletes session from the redis.
            If InvalidToken exception is occured , retunrs HTTP_401_UNAUTHORIZED.
            If InsufficientScope exception is occured, retunrs HTTP_HTTP_403_FORBIDDEN.
            If other exception is occured , retunrs HTTP_500_INTERNAL_SERVER_ERROR.

        Args:
            encoded_jwt (str | Any, optional): JWT. Defaults to Depends(OAuth2PasswordBearer(tokenUrl='login')).

        Returns:
            dict: API response.
        '''
        ulid = self.__validate_access_token(encoded_jwt)

        self.__redis_session.delete(f'{ulid}:access_token', f'{ulid}:refresh_token')  # type: ignore

        return {}

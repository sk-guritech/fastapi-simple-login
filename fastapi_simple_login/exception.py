from __future__ import annotations

from fastapi import HTTPException
from fastapi import Request
from fastapi import status
from fastapi.responses import JSONResponse


class DatabaseSessionMakerNotSet(Exception):
    """Occured when session_maker is not set."""
    @staticmethod
    def exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {},
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class RedisSessionNotSet(Exception):
    """Occured when redis_session is not set."""
    @staticmethod
    def exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {},
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class RequiredColumnsNotDefined(Exception):
    """Occured when required columns are not defined."""
    @staticmethod
    def exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {},
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class InvalidRequest(Exception):
    """Occured when the request parameter is invalid."""
    @staticmethod
    def exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {},
            status.HTTP_400_BAD_REQUEST,
            {'WWW-Authenticate': 'Bearer error="invalid_request"'},
        )


class AuthorizationHeaderNotFound(Exception):
    """Occured when the authorization header is not found."""
    @staticmethod
    def exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {},
            status.HTTP_401_UNAUTHORIZED,
            {'WWW-Authenticate': 'Bearer realm=""'},
        )


class InvalidToken(Exception):
    """Occured when the token is invalid."""
    @staticmethod
    def exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {},
            status.HTTP_401_UNAUTHORIZED,
            {'WWW-Authenticate': 'Bearer error="invalid_token"'},
        )


class InsufficientScope(Exception):
    """Occured when the token's scope is insufficient."""
    @staticmethod
    def exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {},
            status.HTTP_403_FORBIDDEN,
            {'WWW-Authenticate': 'Bearer error="insufficient_scope"'},
        )

from __future__ import annotations


class DatabaseSessionMakerNotSet(Exception):
    """Occured when session_maker is not set."""


class RedisSessionNotSet(Exception):
    """Occured when redis_session is not set."""


class RequiredColumnsNotDefined(Exception):
    """Occured when required columns are not defined."""


class InvalidToken(Exception):
    """Occured when token is invalid."""

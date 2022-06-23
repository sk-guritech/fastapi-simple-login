from __future__ import annotations

from sqlalchemy import Column
from sqlalchemy import String


class UserModel:
    '''Model for using the login functions

    Args:
        ulid (Column): The unique identifier of the user.
        bcrypt_hash (Column): The password hash of the user hashed by bcrypt.
        name (Column): The name of the user
    '''
    ulid = Column(String(26), unique=True, nullable=False)
    bcrypt_hash = Column(String(60), nullable=False)
    name = Column(String(255), nullable=False)

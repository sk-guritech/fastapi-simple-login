from __future__ import annotations

from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class UserModel(Base):  # type: ignore
    '''Model for using the login functions.

    Args:
        ulid (Column): The unique identifier of the user.
        bcrypt_hash (Column): The password hash of the user hashed by bcrypt.
        name (Column): The name of the user
    '''
    __tablename__ = 'users'
    ulid = Column(String(26), primary_key=True)
    bcrypt_hash = Column(String(60), nullable=False)
    name = Column(String(255), nullable=False)

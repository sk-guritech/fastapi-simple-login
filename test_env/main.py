# flake8: noqa: E402
from __future__ import annotations

import sys
sys.path.append('.')  # noqa: E402

import uvicorn
from fastapi import Depends
from fastapi import FastAPI
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from fastapi_simple_login import SimpleLoginAPI  # type: ignore
from fastapi_simple_login import UserModel


app = FastAPI()

redis = Redis('redis', 6379, 0)
engine = create_engine('mysql://user:password@db/database')
SessionMaker = sessionmaker(engine)

SimpleLoginAPI.deploy(app, redis, SessionMaker, UserModel)


@app.get('/')
async def read_root(ulid=Depends(SimpleLoginAPI.validate_access_token)):
    return {'ulid': ulid}


if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=8000, reload=True, debug=True)

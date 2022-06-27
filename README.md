# fastapi-simple-login
FastAPI-Simple-Login is a very simple library for adding login feature that based bearer token to your fastapi application.

## How to use
First, prepare Redis server and RDB server.

Then, add the login function to your application with the code below.
```
<main.py>
from fastapi_simple_login import SimpleLoginAPI, UserModel

from fastapi import FastAPI, Depends
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import uvicorn


app = FastAPI()

redis_session = Redis('redis')
rdb_engine = create_engine('mysql://user:password@db/database')
rdb_session_maker = sessionmaker(rdb_engine)

SimpleLoginAPI.deploy(app, redis_session, rdb_session_maker, UserModel)

if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=8000)
```
That's it.

## Installing and Supported Versions
$ FastAPI-Simple-Login is available on PyPI:
```
$ pip install fastapi-simple-login
```
This lib officially supprts Python 3.10+.

## APIs
This library enables your application to use the following APIs.

- /login

    Send a username and a password, an access-token and a  refresh-token will be issued.
    ```
    $ curl -X POST 127.0.0.1:8000/login -d "username=johndoe&password=secret"
    {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NjM1Mzg1OSwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6MDYzZDE0Y2EtNDljYS00YjUzLWJiNDgtYWMzOTM3YjkwMWMxIiwiZ3JhbnQiOiJhY2Nlc3MifQ.iNRWK64lXPfChGag_uS7UZI2UIalJwaUCV4G48RU_qc","refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1Njc4MjI1OSwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6YzMxNWVkNjItY2RkYS00ZjYzLThmNjAtMjllMWE5YTY1YThlIiwiZ3JhbnQiOiJyZWZyZXNoIn0.6tmzgsS6Mj47zBQXhIJPE878Yd0sLDbsLdeNxTy4K8Q"}
    ```

- /refresh

    Send the refresh-token and tokens will be reissued.
    ```
    $ curl -X POST 127.0.0.1:8000/refresh -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1Njc4MjI1OSwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6YzMxNWVkNjItY2RkYS00ZjYzLThmNjAtMjllMWE5YTY1YThlIiwiZ3JhbnQiOiJyZWZyZXNoIn0.6tmzgsS6Mj47zBQXhIJPE878Yd0sLDbsLdeNxTy4K8Q"
    {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NjM1Mzg5OCwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6YmNkMTQ2ZWEtNDE5YS00MGVhLWE3YjktNjI1MDdhZWU2YmFlIiwiZ3JhbnQiOiJhY2Nlc3MifQ.mMMkJfRrXKsSD71wYFcDxjNn-uL-iFapFvsAqijfotE","refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1Njc4MjI5OCwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6ZTVkNjE1NjEtNmQwNi00Mjc1LWE5MDQtMGFlODM0ZGRlMDYzIiwiZ3JhbnQiOiJyZWZyZXNoIn0.tYpo2z6bmPqoGfFR4SAkGbGSQeAQxaJSdA99nHpSFLc"}
    ```

- /logout

    Send the access-token and tokens will be deactivated.
    ```
    $ curl -X POST 127.0.0.1:8000/logout -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NjM1Mzg5OCwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6YmNkMTQ2ZWEtNDE5YS00MGVhLWE3YjktNjI1MDdhZWU2YmFlIiwiZ3JhbnQiOiJhY2Nlc3MifQ.mMMkJfRrXKsSD71wYFcDxjNn-uL-iFapFvsAqijfotE"
    {}
    ```

## Add an approval function to the API.
The following code shows how to add an approval function to the API.

```
@app.get('/')
async def index(ulid=Depends(SimpleLoginAPI.validate_access_token)):
    return {'ulid': ulid}
```

## Author
- sk-guritech
    - https://github.com/sk-guritech/
    - https://twitter.com/GuriTech

## License
Copyright (c) 2022~ @sk-guritech

Released under the MIT License

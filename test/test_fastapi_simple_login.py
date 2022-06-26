from __future__ import annotations

import requests


def test_login():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    assert res.status_code == 200
    assert list(res.json().keys()) == ['access_token', 'refresh_token']


def test_login_with_no_parameters():
    res = requests.post('http://127.0.0.1:8000/login', data={})
    assert res.status_code == 422


def test_login_with_invalid_password():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secrets'})
    assert res.status_code == 400
    assert res.headers['WWW-Authenticate'] == 'Bearer error="invalid_request"'


def test_login_with_invalid_username():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoes', 'password': 'secret'})
    assert res.status_code == 400
    assert res.headers['WWW-Authenticate'] == 'Bearer error="invalid_request"'


def test_refresh():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    refresh_token = res.json()['refresh_token']

    res = requests.post('http://127.0.0.1:8000/refresh', headers={'Authorization': 'Bearer ' + refresh_token})
    assert res.status_code == 200
    assert list(res.json().keys()) == ['access_token', 'refresh_token']


def test_refresh_with_invalid_token():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    refresh_token = res.json()['refresh_token']
    refresh_token = list(refresh_token)
    refresh_token[0] = refresh_token[1]

    res = requests.post('http://127.0.0.1:8000/refresh', headers={'Authorization': 'Bearer ' + ''.join(refresh_token)})
    assert res.status_code == 401
    assert res.headers['WWW-Authenticate'] == 'Bearer error="invalid_token"'


def test_refresh_with_insuffieicnt_scope():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    access_token = res.json()['access_token']

    res = requests.post('http://127.0.0.1:8000/refresh', headers={'Authorization': 'Bearer ' + access_token})
    assert res.status_code == 403
    assert res.headers['WWW-Authenticate'] == 'Bearer error="insufficient_scope"'


def test_logout():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    access_token = res.json()['access_token']

    res = requests.post('http://127.0.0.1:8000/logout', headers={'Authorization': 'Bearer ' + access_token})
    assert res.status_code == 200


def test_logout_with_invalid_token():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    access_token = res.json()['access_token']
    access_token = list(access_token)
    access_token[0] = access_token[1]

    res = requests.post('http://127.0.0.1:8000/logout', headers={'Authorization': 'Bearer ' + ''.join(access_token)})
    assert res.status_code == 401
    assert res.headers['WWW-Authenticate'] == 'Bearer error="invalid_token"'


def test_logout_with_insuffieicnt_scope():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    refresh_token = res.json()['refresh_token']

    res = requests.post('http://127.0.0.1:8000/logout', headers={'Authorization': 'Bearer ' + refresh_token})
    assert res.status_code == 403
    assert res.headers['WWW-Authenticate'] == 'Bearer error="insufficient_scope"'


def test_validate_access_token():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    access_token = res.json()['access_token']

    res = requests.get('http://127.0.0.1:8000/', headers={'Authorization': 'Bearer ' + access_token})
    assert res.status_code == 200
    assert res.json() == {'ulid': '01G5EXPGEREF4Q9Q8NKQPJ3BBT'}


def test_validate_access_token_with_invalid_token():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    access_token = res.json()['access_token']
    access_token = list(access_token)
    access_token[0] = access_token[1]

    res = requests.get('http://127.0.0.1:8000/', headers={'Authorization': 'Bearer ' + ''.join(access_token)})
    assert res.status_code == 401
    assert res.headers['WWW-Authenticate'] == 'Bearer error="invalid_token"'


def test_validate_access_token_with_insufficient_scope():
    res = requests.post('http://127.0.0.1:8000/login', data={'username': 'johndoe', 'password': 'secret'})
    refresh_token = res.json()['refresh_token']

    res = requests.get('http://127.0.0.1:8000/', headers={'Authorization': 'Bearer ' + refresh_token})
    assert res.status_code == 403
    assert res.headers['WWW-Authenticate'] == 'Bearer error="insufficient_scope"'

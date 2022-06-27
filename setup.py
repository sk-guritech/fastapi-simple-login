from __future__ import annotations

from setuptools import setup

setup(
    name='fastapi-simple-login',
    packages=['fastapi_simple_login'],
    version='0.1.0',
    license='MIT',
    install_requires=[
        'sqlalchemy>=1.4.37',
        'fastapi>=0.78.0',
        'fastapi-utils>=0.2.1',
        'passlib[bcrypto]>=1.7.4',
        'python-jose>=3.3.0',
        'python-multipart>=0.0.5',
    ],
    author='sk-guritech',
    url='https://github.com/sk-guritech/fastapi-simple-login',
    keywords='fastapi login bearer simple session',
    classifiers=[
        'Framework :: FastAPI',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.10',
    ],
)

FROM python:3.10.4
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt update -y
RUN mkdir -p /var/app
RUN mkdir -p /var/tools

COPY ./requirements/requirements.txt /var/tools
RUN pip install -r /var/tools/requirements.txt

WORKDIR /var/app

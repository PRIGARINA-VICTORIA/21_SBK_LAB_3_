FROM python:3.10

WORKDIR /app

ENV tmp_value="hello"

COPY . .

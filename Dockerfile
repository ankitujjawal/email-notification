FROM python:3.7.0-alpine3.8
WORKDIR /usr/src
RUN apk add gcc linux-headers musl-dev
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ./app.py .
ADD keywords /usr/src/keywords
CMD ["python", "./app.py", "<vault_token_here>"]

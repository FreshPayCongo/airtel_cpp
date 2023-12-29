

FROM python:3.7.6-stretch

WORKDIR /app

ADD . /app

ENV DEBIAN_FRONTEND noninteractive

COPY airtel-cd-chain.pem /etc/ssl/certs/

RUN apt-get update && apt-get install -q  -y build-essential libpq-dev php --no-install-recommends

RUN pip install -r requirements.txt

CMD ["uwsgi", "app.ini"]

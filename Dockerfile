FROM python:3.9-alpine3.13
LABEL maintainer="AJIT-MAURYA"

ENV PYTHONUNBUFFERED 1

COPY ./requirements.txt /requirements.txt
COPY ./SecureFileShare /app
COPY ./scripts /scripts

WORKDIR /app
EXPOSE 8000

RUN ls -la && \
    python3 -m venv /py && \
    /py/bin/pip install --upgrade pip && \
    apk add --update --no-cache postgresql-client && \
    apk add --update --no-cache --virtual .tmp-deps \
        build-base postgresql-dev musl-dev linux-headers && \
    /py/bin/pip install -r /requirements.txt && \
    /py/bin/pip list && \
    apk del .tmp-deps && \
    adduser --disabled-password --no-create-home app && \
    mkdir -p /vol/web/static && \
    mkdir -p /vol/web/media && \
    chown -R app:app /vol && \
    chmod -R g+w /vol && \
    chmod -R g+w /vol/web/static && \
    chmod -R g+w /vol/web/media && \
    chmod -R +x /scripts


ENV PATH="/scripts:/py/bin:$PATH"

USER app

CMD [ "run.sh" ]
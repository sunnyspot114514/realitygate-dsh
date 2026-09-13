FROM python:3.12-slim
WORKDIR /srv
RUN groupadd --gid 10001 mock     && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin mock     && printf "mock response service
" > /srv/index.html     && chown -R 10001:10001 /srv
USER 10001:10001
EXPOSE 8080

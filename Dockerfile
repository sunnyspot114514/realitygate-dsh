FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     PYTHONPATH=/app

RUN groupadd --gid 10001 sandbox     && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin sandbox

WORKDIR /app
COPY --chown=sandbox:sandbox pyproject.toml ./
COPY --chown=sandbox:sandbox policy.json ./
COPY --chown=sandbox:sandbox realitygate ./realitygate
COPY --chown=sandbox:sandbox dsh_adapter ./dsh_adapter

USER 10001:10001

ENTRYPOINT ["python", "-m", "realitygate.cli"]
CMD ["--help"]

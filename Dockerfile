FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

ARG PYPI_INDEX_URL=https://pypi.org/simple

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN sed "s|^--index-url .*|--index-url ${PYPI_INDEX_URL}|" requirements.txt \
    > /tmp/requirements.txt \
    && pip install --require-hashes --requirement /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY cloud_dast ./cloud_dast
COPY README.md plan.md ./

RUN useradd --create-home --uid 10001 dast \
    && mkdir --parents /var/lib/cloud-dast \
    && chown --recursive dast:dast /app /var/lib/cloud-dast

USER dast
ENV CLOUD_DAST_EVENT_LOG=/var/lib/cloud-dast/events.jsonl

ENTRYPOINT ["python", "-m", "cloud_dast.composition.live_cli"]

# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim

ARG CODEX_NPM_PACKAGE=@openai/codex
ARG CODEX_NPM_VERSION=latest
ARG CODEX_CLI_PATH=/usr/local/bin/codex

ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        findutils \
        gawk \
        git \
        grep \
        gzip \
        jq \
        openssh-client \
        python3 \
        python3-pip \
        python3-venv \
        sed \
        tar \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g "${CODEX_NPM_PACKAGE}@${CODEX_NPM_VERSION}" \
    && test -x "${CODEX_CLI_PATH}" \
    && ("${CODEX_CLI_PATH}" --version >/dev/null 2>&1 || "${CODEX_CLI_PATH}" --help >/dev/null 2>&1)

WORKDIR /execution/run/work

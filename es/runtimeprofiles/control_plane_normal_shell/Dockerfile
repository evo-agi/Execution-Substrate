# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim

ARG CODEX_NPM_PACKAGE=@openai/codex
ARG CODEX_NPM_VERSION=latest
ARG CODEX_CLI_PATH=/usr/local/bin/codex
ARG CODEX_REALIZATION=npm

ENV PYTHONUNBUFFERED=1

COPY es/runtimeprofiles/control_plane_normal_shell/proof-codex-shim.py /tmp/execution-substrate-proof-codex-shim.py

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

RUN if [ "${CODEX_REALIZATION}" = "proof" ]; then \
        install -D -m 0755 /tmp/execution-substrate-proof-codex-shim.py "${CODEX_CLI_PATH}"; \
    elif [ "${CODEX_REALIZATION}" = "npm" ]; then \
        npm install -g "${CODEX_NPM_PACKAGE}@${CODEX_NPM_VERSION}"; \
    else \
        echo "unsupported CODEX_REALIZATION=${CODEX_REALIZATION}" >&2; \
        exit 1; \
    fi \
    && rm -f /tmp/execution-substrate-proof-codex-shim.py \
    && test -x "${CODEX_CLI_PATH}" \
    && ("${CODEX_CLI_PATH}" --version >/dev/null 2>&1 || "${CODEX_CLI_PATH}" --help >/dev/null 2>&1)

WORKDIR /execution/run/work

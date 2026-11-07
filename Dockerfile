# syntax=docker/dockerfile:1
# Base image pinned by digest (python:3.12-slim-bookworm). Update deliberately, not implicitly.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

# ---------------------------------------------------------------------------
# Builder: resolve dependencies from the pinned lock file into a virtualenv
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /build
COPY requirements.lock ./
RUN pip install -r requirements.lock
COPY pyproject.toml README.md LICENSE ./
COPY backend/ ./backend/
RUN pip install --no-deps .

# ---------------------------------------------------------------------------
# Runtime: non-root user, no build tooling
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE}
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/opt/venv/bin:$PATH" \
    MODEL_PATH=/app/models
RUN groupadd --system --gid 10001 siem \
    && useradd --system --uid 10001 --gid siem --home-dir /app --shell /usr/sbin/nologin siem \
    && mkdir -p /app/models /app/data \
    && chown -R siem:siem /app
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=siem:siem scripts/ ./scripts/
USER siem
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/live', timeout=3).status == 200 else 1)"]
# Trains a synthetic DEMO model on first start if /app/models has none, then serves the API.
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

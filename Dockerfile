FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Runtime state (SQLite db, uploads) lives on a mounted volume, outside the
    # image and outside anything a static handler can reach.
    FEEFIX_DB=/app/runtime/feefix.db \
    FEEFIX_UPLOAD_DIR=/app/runtime/uploads \
    FEEFIX_AI_BACKEND=ngram

# Argon2id needs a C toolchain only at build time of the wheel; the published
# argon2-cffi wheels are manylinux, so no compiler is required here. If you pin
# a source build, add `build-essential` to this stage and use a multi-stage
# image so the toolchain never ships to production.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# -- production defaults ------------------------------------------------------ #
# Fail closed on weak configuration instead of warning and serving anyway.
# (FEEFIX_SECRETS_STRICT is the dual-name form of FEEFIX_STRICT_SECRETS; both
# are honoured by services/secrets.py.)
ENV FEEFIX_ENV=production \
    FEEFIX_PASSWORD_ALGO=argon2id \
    FEEFIX_SECRETS_STRICT=1 \
    FEEFIX_STRICT_SECRETS=1 \
    FEEFIX_RATELIMIT_FAIL_MODE=auth

# State lives on a volume, not in the image: the SQLite database and uploaded
# documents must survive a container restart, and `runtime/` is git-ignored.
ENV FEEFIX_DB=/data/feefix.db \
    FEEFIX_UPLOAD_DIR=/data/uploads \
    FEEFIX_RATELIMIT_DB=/data/ratelimit.db
RUN mkdir -p /data

# Run as a non-root user that owns the state volume — a compromised process
# should not be able to rewrite the image or the database files as root.
RUN useradd --create-home --uid 10001 feefix \
    && chown -R feefix:feefix /app /data
USER feefix

EXPOSE 7860

# Multiple workers are safe: the rate limiter's default store is the SQLite file,
# so counters are shared across processes (see backend/services/ratelimit.py).
# A multi-instance deployment needs FEEFIX_REDIS_URL — with it unset, the app
# logs a topology warning (and refuses to start under FEEFIX_STRICT_SECRETS).
ENV WEB_CONCURRENCY=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7860/api/health', timeout=4).status == 200 else 1)"

# `--proxy-headers` lets uvicorn rewrite `request.client.host` from
# X-Forwarded-For, but only when the peer is a trusted proxy address
# (`--forwarded-allow-ips`, default 127.0.0.1) — so a directly-exposed
# container cannot be spoofed by a header. Behind a non-loopback ingress also
# set FEEFIX_TRUST_PROXY=1 / FEEFIX_TRUSTED_PROXY_COUNT=1 so the limiter does
# not bucket everyone under the proxy address (services/ratelimit.py).
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port 7860 --proxy-headers --workers ${WEB_CONCURRENCY}"]

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Argon2id needs a C toolchain only at build time of the wheel; the published
# argon2-cffi wheels are manylinux, so no compiler is required here. If you pin
# a source build, add `build-essential` to this stage and use a multi-stage
# image so the toolchain never ships to production.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# -- production defaults ------------------------------------------------------ #
# Fail closed on weak configuration instead of warning and serving anyway.
ENV FEEFIX_ENV=production \
    FEEFIX_PASSWORD_ALGO=argon2id \
    FEEFIX_SECRETS_STRICT=1 \
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

# `--proxy-headers` lets uvicorn rewrite `request.client.host` from
# X-Forwarded-For, but only when the peer is a trusted proxy address
# (`--forwarded-allow-ips`, default 127.0.0.1) — so a directly-exposed
# container cannot be spoofed by a header.
#
# Behind a proxy/ingress that is *not* on loopback, also set
#   FEEFIX_TRUST_PROXY=1   (and uvicorn's --forwarded-allow-ips=<proxy cidr>)
# or every request looks like it came from the proxy and all users share one
# rate-limit bucket. The forwarded header is read rightmost, i.e. the hop our
# own proxy observed, so the client cannot forge an identity through it.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "7860", "--proxy-headers"]

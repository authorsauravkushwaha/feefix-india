FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Runtime state (SQLite db, uploads) lives on a mounted volume, outside the
    # image and outside anything a static handler can reach.
    FEEFIX_DB=/app/runtime/feefix.db \
    FEEFIX_UPLOAD_DIR=/app/runtime/uploads \
    FEEFIX_AI_BACKEND=ngram

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Own runtime state as a non-root user: a compromised process should not be able
# to rewrite the application code.
RUN useradd --create-home --uid 10001 feefix \
    && mkdir -p /app/runtime/uploads \
    && chown -R feefix:feefix /app/runtime
USER feefix

EXPOSE 7860

# Multiple workers are safe: the rate limiter's default store is the SQLite file,
# so counters are shared across processes (see backend/services/ratelimit.py).
# A multi-instance deployment needs FEEFIX_REDIS_URL — with it unset, the app
# logs a topology warning (and refuses to start under FEEFIX_STRICT_SECRETS).
ENV WEB_CONCURRENCY=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7860/api/health', timeout=4).status == 200 else 1)"

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port 7860 --workers ${WEB_CONCURRENCY}"]

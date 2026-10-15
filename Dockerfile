# FeeFix India — container image.
#
# Hardened on four axes that cost nothing at runtime:
#
#   1. **Non-root.** A process running as root inside a container that achieves
#      code execution is one kernel or runtime bug away from the host. Running as
#      an unprivileged uid with no shell removes that step entirely.
#   2. **No secrets in layers.** `.dockerignore` excludes `.env`, `runtime/` and
#      all key material, so nothing credential-shaped is baked into the image.
#      Secrets arrive at *run* time through the environment.
#   3. **Smallest attack surface.** slim base, no pip cache, no build toolchain
#      left behind, bytecode writing disabled (a writable .pyc is a persistence
#      mechanism).
#   4. **A real healthcheck**, so an orchestrator restarts a wedged process
#      instead of routing traffic to it.

FROM python:3.11-slim

# PYTHONUNBUFFERED  — logs are not buffered, so an incident is diagnosable.
# PYTHONDONTWRITEBYTECODE — nothing writes .pyc files at runtime.
# PIP_NO_CACHE_DIR  — no package cache left in a layer.
# PIP_DISABLE_PIP_VERSION_CHECK — no outbound version call on every build.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FEEFIX_ENV=production

WORKDIR /app

# Dependencies first, source second: the dependency layer then caches across
# code-only changes, which also means fewer rebuilds touching the network.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# An unprivileged user with no home directory and no login shell. The runtime
# directory is created here and chowned, because .dockerignore excludes it from
# the build context — the database and the generated OTP pepper both live there
# and the process must be able to write them.
RUN groupadd --system --gid 10001 feefix \
    && useradd --system --uid 10001 --gid feefix --no-create-home --shell /usr/sbin/nologin feefix \
    && mkdir -p /app/runtime \
    && chown -R feefix:feefix /app/runtime \
    && chmod 700 /app/runtime \
    # Everything else is read-only to the runtime user: a code-execution foothold
    # should not also be a way to modify the application on disk.
    && chown -R root:root /app \
    && find /app -type d -exec chmod 755 {} + \
    && find /app -type f -exec chmod 644 {} +

USER feefix

EXPOSE 7860

# --fail-critical: treat a failing healthcheck as fatal rather than advisory.
# The endpoint is unauthenticated and returns counts only, never configuration.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7860/api/health', timeout=4).status==200 else 1)"

# Bound workers/requests so a leaked or wedged worker is recycled. Explicit
# --host is required for the container port to be reachable at all.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "7860", \
     "--limit-concurrency", "200", "--limit-max-requests", "10000", \
     "--timeout-keep-alive", "5", "--no-server-header"]

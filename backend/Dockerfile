# VulScanner API container.
#
# NOTE ON SCOPE
# -------------
# A Linux container cannot run the Windows collectors: those need PowerShell,
# CIM/WMI and the registry on a Windows host. This image is intended for the
# API, database, dashboard and reporting tiers - the "management plane" - with
# Windows collection performed by the CLI or a Windows-hosted API instance.
# Network discovery works from this container for any authorized scope it can
# route to.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Build dependencies for the wheels that need compiling, removed afterwards.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y build-essential \
    && apt-get autoremove -y

# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VULSCANNER_ENV=production \
    VULSCANNER_HOST=0.0.0.0 \
    VULSCANNER_PORT=8000 \
    PATH="/usr/local/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin vulscanner

COPY --from=base /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=base /usr/local/bin /usr/local/bin

WORKDIR /app

COPY --chown=vulscanner:vulscanner backend/ ./backend/
COPY --chown=vulscanner:vulscanner cli/ ./cli/
COPY --chown=vulscanner:vulscanner reports/templates/ ./reports/templates/

RUN mkdir -p /app/logs /app/cache/cve /app/reports/generated \
    && chown -R vulscanner:vulscanner /app

USER vulscanner
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

WORKDIR /app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]

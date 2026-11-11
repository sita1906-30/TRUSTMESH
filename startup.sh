#!/bin/bash
# ============================================================================
# TRUSTMESH — Azure App Service Linux Startup Script
# Phase 4, Task 5: Production Deployment Host
# ============================================================================

set -e

echo "[TRUSTMESH] Initiating Azure App Service Linux production startup..."

# 1. Resolve host and port from Azure App Service environment
PORT="${PORT:-8000}"
HOST="0.0.0.0"

# 2. Worker & Thread Concurrency configuration
# Basic / Free F1 App Service plans have 1-2 vCPUs; 2-4 workers/threads is ideal.
WORKERS="${GUNICORN_WORKERS:-2}"
THREADS="${GUNICORN_THREADS:-4}"
TIMEOUT="${GUNICORN_TIMEOUT:-120}"

echo "[TRUSTMESH] Hosting on ${HOST}:${PORT} (Workers: ${WORKERS}, Threads: ${THREADS}, Timeout: ${TIMEOUT}s)"
echo "[TRUSTMESH] Environment: ${FLASK_ENV:-production}"
echo "[TRUSTMESH] Database Mode: ${DATABASE_MODE:-sqlite}"

# 3. Launch production WSGI application server with Gunicorn
exec gunicorn \
    --bind="${HOST}:${PORT}" \
    --workers="${WORKERS}" \
    --threads="${THREADS}" \
    --timeout="${TIMEOUT}" \
    --access-logfile "-" \
    --error-logfile "-" \
    --log-level "info" \
    app:app


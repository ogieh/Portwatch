# PortWatch Pro container image.
# Includes nmap so the container can run real scans out of the box.
#
# Scan type: the app defaults to TCP connect scans (-sT), which need no extra
# privileges. For SYN scans (-sS) set PORTWATCH_NMAP_SCAN_TYPE=syn and give the
# container NET_RAW + NET_ADMIN (see docker-compose.yml).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    # Let nmap open raw sockets as a non-root user when the container grants
    # the capability (no effect for connect scans).
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap || true

WORKDIR /app

# Install Python deps first for layer caching.
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# App code.
COPY backend /app/backend
COPY frontend /app/frontend

# Run as an unprivileged user; the data volume is owned by it.
RUN useradd --system --create-home --uid 10001 portwatch \
    && mkdir -p /app/backend/data \
    && chown -R portwatch:portwatch /app
USER portwatch

WORKDIR /app/backend

ENV PORT=5000 \
    PORTWATCH_ENV=production \
    PORTWATCH_SCHEDULER=1 \
    PYTHONUNBUFFERED=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=4).status == 200 else 1)"

# One worker process on purpose: the scan queue, scheduler and rate limiter
# are in-process. Threads give concurrency for the API while scans run in the
# background pool.
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "8", \
     "--timeout", "120", "--access-logfile", "-"]

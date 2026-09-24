# PortWatch Pro: Deployment Guide

This document covers running PortWatch Pro for real: a single small VPS, Docker,
PostgreSQL, TLS, backups, and the nmap capability question. It assumes Ubuntu
22.04 or later with Docker Engine and the compose plugin installed, but nothing
here is Ubuntu-specific.

## 1. Deployment shape

One host runs three containers:

| Container | Role |
|-----------|------|
| `portwatch` | gunicorn (one worker, eight threads) serving the API and SPA; the scan thread pool, the APScheduler poller and the rate limiter live in this process |
| `db` | PostgreSQL 16 (compose profile `postgres`) |
| `backup` | nightly `pg_dump` into `./backups`, 14 days retained |

A reverse proxy (nginx or Caddy) on the host terminates TLS and forwards to
port 5000. The application never listens on a public interface directly.

The single-worker design is deliberate. The scan queue, scheduler and rate
limiter are in-process; a second gunicorn worker would mean two queues and two
schedulers. If one process becomes a bottleneck, the path is a shared queue
(RQ or Celery on Redis) and Flask-Limiter on Redis, not more workers. Scans
themselves already run off the request thread, so the API stays responsive
while nmap works.

## 2. Secrets and environment

Everything is configured through environment variables. Copy `.env.example`
to `.env` in the project root and set at least:

```
PORTWATCH_SECRET=<python -c "import secrets;print(secrets.token_urlsafe(48))">
PORTWATCH_PUBLIC_URL=https://portwatch.example.com
POSTGRES_PASSWORD=<strong password>
PORTWATCH_DB_URI=postgresql+psycopg://portwatch:<same password>@db:5432/portwatch
```

The container runs with `PORTWATCH_ENV=production`. In that mode the app
refuses to start if `PORTWATCH_SECRET` is unset, is the development default, or
is shorter than 16 characters. Rotating the secret invalidates every access
token; users simply sign in again (refresh tokens are database-backed and keep
working).

`.env` is in `.gitignore`. Verify nothing sensitive is committed:

```
git grep -nE "PORTWATCH_SECRET=|SMTP_PASSWORD=|POSTGRES_PASSWORD=" -- ':!*.example' ':!docs/*'
```

Full variable reference:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORTWATCH_ENV` | `development` | `production` enables the strict checks above |
| `PORTWATCH_SECRET` | dev value | JWT signing key |
| `PORTWATCH_JWT_HOURS` | `1` | Access-token lifetime |
| `PORTWATCH_REFRESH_DAYS` | `30` | Refresh-token lifetime |
| `PORTWATCH_RESET_MINUTES` | `30` | Password-reset link lifetime |
| `PORTWATCH_PUBLIC_URL` | `http://localhost:5000` | Base of reset links in email |
| `PORTWATCH_DB_URI` | SQLite in `backend/data` | SQLAlchemy URL |
| `PORTWATCH_AUTO_MIGRATE` | `1` | Run Alembic to head on boot |
| `PORTWATCH_CORS_ORIGINS` | empty | Comma list; production allows only these (empty = CORS off, which is right for the same-origin SPA) |
| `PORTWATCH_RATELIMIT` | `1` | Enable the in-process limiter |
| `PORTWATCH_RATELIMIT_LOGIN` | `10/minute` | Per client IP |
| `PORTWATCH_RATELIMIT_REGISTER` | `5/minute` | Per client IP |
| `PORTWATCH_RATELIMIT_RESET` | `5/minute` | Forgot/reset, per client IP |
| `PORTWATCH_RATELIMIT_SCAN` | `10/minute` | Per user |
| `PORTWATCH_SIMULATE` | `0` | Force the simulation engine |
| `PORTWATCH_NMAP_SCAN_TYPE` | `connect` | `connect` (-sT) or `syn` (-sS) |
| `PORTWATCH_SCAN_WORKERS` | `2` | Concurrent scans |
| `PORTWATCH_MAX_QUICK` / `_STANDARD` / `_DEEP` | `180` / `600` / `1800` | Per-profile ceiling in seconds |
| `PORTWATCH_SCHEDULER` | `1` | Background scheduler |
| `PORTWATCH_SCHEDULER_POLL` | `30` | Seconds between due-schedule checks |
| `PORTWATCH_SMTP_*` | unset | `HOST`, `PORT`, `USER`, `PASSWORD`, `FROM` for alerts and reset mail |

## 3. First deploy

```
git clone <repo> portwatch-pro && cd portwatch-pro
cp .env.example .env && nano .env            # fill in section 2
docker compose --profile postgres up -d --build
docker compose logs -f portwatch             # wait for "Database migrated (empty) -> 0002_hardening"
curl -s http://127.0.0.1:5000/api/health
```

The first account registered becomes the administrator. Register it
immediately after the first boot.

Schema management is Alembic. `PORTWATCH_AUTO_MIGRATE=1` (default) upgrades
the database to head on every boot, including a database created by version
2.0 (it is stamped at the baseline revision first). To run migrations as a
separate deploy step instead:

```
docker compose exec portwatch alembic upgrade head
```

and set `PORTWATCH_AUTO_MIGRATE=0`.

## 4. TLS and the reverse proxy

Never expose port 5000 directly; passwords and bearer tokens must travel over
HTTPS only. A minimal nginx site:

```
server {
    listen 443 ssl http2;
    server_name portwatch.example.com;
    ssl_certificate     /etc/letsencrypt/live/portwatch.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/portwatch.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Forwarded-For $remote_addr;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 120s;
    }
}
server { listen 80; server_name portwatch.example.com; return 301 https://$host$request_uri; }
```

`X-Forwarded-For` matters: the rate limiter and the audit log key on the first
address in that header when present, so the proxy must set it (and must
overwrite, not append to, whatever the client sent). Caddy does this by default
with a two-line Caddyfile:

```
portwatch.example.com {
    reverse_proxy 127.0.0.1:5000
}
```

Change the compose port mapping to `127.0.0.1:5000:5000` so the container is
reachable only through the proxy.

## 5. nmap in the container

The image installs nmap. Two scan types are supported:

| `PORTWATCH_NMAP_SCAN_TYPE` | nmap flag | Needs | Notes |
|---|---|---|---|
| `connect` (default) | `-sT` | nothing | Full TCP handshake; works as the unprivileged `portwatch` user, slightly slower and noisier |
| `syn` | `-sS` | `CAP_NET_RAW` + `CAP_NET_ADMIN` | Half-open scan; the compose file already adds both capabilities and the image sets file capabilities on `/usr/bin/nmap` |

The container runs as a non-root user either way. Service/version detection
(`-sV`) and NSE scripts work in both modes. The active mode is shown by
`/api/health` and in Settings.

Validate the live engine once, against a host you own or are authorised to
test (`scanme.nmap.org` is published by the nmap project for this purpose):

```
docker compose exec portwatch python - <<'EOF'
import scanner
r = scanner.run_scan("scanme.nmap.org", profile="quick", scan_type="connect")
print(r["engine"], r["resolved_host"], [(p["port"], p["state"], p["version"]) for p in r["ports"] if p["state"] == "open"])
EOF
```

You should see `nmap`, the resolved address, and port 22 and 80 open. The
output dict has the same keys as the simulation (this contract is also
enforced by `tests/test_real_engine.py`), so scoring, intel, compliance,
diffing and reports need no changes between modes.

## 6. Backups

With the `postgres` profile the `backup` container writes
`backups/portwatch-<UTC timestamp>.sql.gz` every 24 hours and prunes files
older than `BACKUP_KEEP_DAYS` (14). Copy that directory off the host (rclone,
restic, or a plain `scp` cron job); a backup on the same disk is not a backup.

Restore:

```
docker compose --profile postgres stop portwatch
gunzip -c backups/portwatch-20260911-020000.sql.gz | docker compose exec -T db psql -U portwatch portwatch
docker compose --profile postgres start portwatch
```

SQLite deployments: stop the app and copy `backend/data/portwatch.db` (it is
in the `portwatch-data` volume; `docker compose cp portwatch:/app/backend/data/portwatch.db .`).

## 7. Operations

- Logs: `docker compose logs -f portwatch`. gunicorn access logs go to stdout;
  application warnings (config, failed notifications, timed-out scans) too.
- Health: `GET /api/health` (used by the container healthcheck).
- Audit: Settings shows the audit log; admins see all users. It is append-only
  at the application layer; back it up with the database.
- Upgrades: `git pull && docker compose --profile postgres up -d --build`. The
  app migrates the schema on boot; take a backup first.
- Rotating the secret: change `PORTWATCH_SECRET`, restart. Everyone signs in
  again.
- Locking an account out everywhere: the user's own "Sign out everywhere", or
  an admin can bump `users.token_version` in the database.

## 8. Without Docker

```
sudo apt install nmap python3-venv
cd backend && python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
export PORTWATCH_ENV=production PORTWATCH_SECRET=... PORTWATCH_DB_URI=postgresql+psycopg://...
gunicorn app:app --bind 127.0.0.1:5000 --workers 1 --threads 8 --timeout 120
```

Give nmap raw-socket capability only if you want SYN scans:
`sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)` and set
`PORTWATCH_NMAP_SCAN_TYPE=syn`. Run gunicorn under systemd with
`Restart=always` and the environment in an `EnvironmentFile` readable only by
the service user.

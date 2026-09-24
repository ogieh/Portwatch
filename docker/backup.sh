#!/bin/sh
# Nightly pg_dump of the PortWatch database. Runs inside the `backup` service.
# Keeps BACKUP_KEEP_DAYS days of compressed dumps in /backups.
set -eu
KEEP="${BACKUP_KEEP_DAYS:-14}"
while true; do
  stamp="$(date -u +%Y%m%d-%H%M%S)"
  out="/backups/portwatch-${stamp}.sql.gz"
  if pg_dump -h db -U portwatch portwatch | gzip > "$out"; then
    echo "backup written: $out"
  else
    echo "backup FAILED at $stamp" >&2
    rm -f "$out"
  fi
  find /backups -name 'portwatch-*.sql.gz' -mtime "+${KEEP}" -delete
  sleep 86400
done

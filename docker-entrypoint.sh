#!/bin/sh
set -eu
umask 077

DATA_DIR="${TEAM_AKI_DATA_DIR:-/data}"
export TEAM_AKI_DATA_DIR="$DATA_DIR"
mkdir -p "$DATA_DIR"

# Seed a fresh persistent volume from the bundled database only once.
if [ ! -f "$DATA_DIR/data.json" ] && [ -f /app/data.json ]; then
    cp /app/data.json "$DATA_DIR/data.json"
fi

exec gunicorn app:app --bind "0.0.0.0:${PORT:-5000}" --workers 1 --threads 4 --timeout 120 --access-logfile - --error-logfile - --capture-output

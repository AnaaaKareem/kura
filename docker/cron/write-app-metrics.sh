#!/bin/sh
# Saves Kura's application counts (manage.py write_app_metrics) as a metrics
# file for Alloy's textfile collector. Writes to a temporary file first and then
# renames it, so Alloy never reads half a file. Run from the project folder.
set -e
metrics_directory=${KURA_METRICS_DIR:-/var/lib/kura-metrics}
mkdir -p "$metrics_directory"
docker compose exec -T web python manage.py write_app_metrics > "$metrics_directory/kura_app.prom.tmp"
chmod 0644 "$metrics_directory/kura_app.prom.tmp"
mv -f "$metrics_directory/kura_app.prom.tmp" "$metrics_directory/kura_app.prom"

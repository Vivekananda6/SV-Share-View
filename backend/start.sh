#!/usr/bin/env bash
set -euo pipefail

python manage.py migrate --noinput
python manage.py collectstatic --noinput
exec gunicorn core.wsgi:application --bind "0.0.0.0:${PORT:?PORT must be set by Render}" --workers 1 --timeout 120

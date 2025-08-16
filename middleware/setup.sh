#!/usr/bin/env bash
set -e

pip install --upgrade pip
pip install -r requirements.txt

# Run migrations
python manage.py migrate contenttypes --noinput
python manage.py migrate auth --noinput
python manage.py migrate sessions --noinput
python manage.py migrate admin --noinput
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

# Ensure superuser
python manage.py ensure_superuser

#!/usr/bin/env bash
# Setup and run SecureCipher Middleware with Gunicorn

# Exit on error
set -e

# Install dependencies and Gunicorn
pip install -r requirements.txt gunicorn

# Apply migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# (Optional) Create superuser if not exists
python manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.filter(username='admin').exists() or User.objects.create_superuser('admin', 'admin@admin.com', 'securecipher')"

# Start Gunicorn
gunicorn securecipher.wsgi:application --bind 0.0.0.0:8000 --workers 3

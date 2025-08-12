#!/usr/bin/env bash
# Setup SecureCipher Middleware on Render

# Exit immediately on error
set -e

# Install dependencies (Render already does `pip install -r requirements.txt` if in Build Command)
pip install --upgrade pip
pip install -r requirements.txt

# Apply migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Create superuser if not exists
python manage.py shell -c "
from django.contrib.auth import get_user_model;
User = get_user_model();
User.objects.filter(username='admin').exists() or User.objects.create_superuser(
    'admin', 'admin@admin.com', 'securecipher'
)
"

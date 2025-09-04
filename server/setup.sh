#!/usr/bin/env bash
# Setup SecureCipher Bankingapi on Render

# Exit immediately on error
set -e

# Install dependencies (Render already does `pip install -r requirements.txt` if in Build Command)
pip install --upgrade pip
pip install -r requirements.txt

# Apply migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Create superuser using our custom management command
python manage.py create_superuser
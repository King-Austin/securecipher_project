#!/usr/bin/env bash
# Setup SecureCipher Middleware on Render

set -e

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run migrations in the correct order
echo "⚙️ Applying core migrations..."
python manage.py migrate contenttypes --noinput
python manage.py migrate auth --noinput
python manage.py migrate sessions --noinput
python manage.py migrate admin --noinput

# Then migrate everything else
echo "⚙️ Applying project migrations..."
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

# Create superuser safely
python manage.py shell -c "
import os
from django.contrib.auth import get_user_model;

User = get_user_model()
username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@example.com')
password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'securecipher')

if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username=username, email=email, password=password)
    print(f'✅ Superuser {username} created.')
else:
    print(f'ℹ️ Superuser {username} already exists.')
"

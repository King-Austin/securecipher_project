#!/usr/bin/env bash
# Setup SecureCipher Middleware on Render (non-interactive)

set -e

# 1. Dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 2. Migrations (core apps first)
python manage.py migrate contenttypes --noinput
python manage.py migrate auth --noinput
python manage.py migrate api --noinput
python manage.py migrate admin --noinput
python manage.py migrate --noinput

# 3. Collect static
python manage.py collectstatic --noinput

# 4. Create superuser if not exists (inline shell)
cat <<EOF | python manage.py shell
from django.contrib.auth import get_user_model
User = get_user_model()
User.objects.filter(username='admin').exists() or User.objects.create_superuser('admin', 'admin@example.com', 'securecipher')
EOF
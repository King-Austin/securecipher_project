#!/usr/bin/env bash
# Setup SecureCipher bankingapi with environment detection

# Exit immediately on error
set -e

# Detect deployment platform
if [ -n "$RENDER" ]; then
    echo "� Running on Render - installing dependencies in global environment"
    pip install --upgrade pip
    pip install -r requirements.txt
elif [ -n "$DIGITALOCEAN_APP_SPEC" ] || [ -n "$DIGITALOCEAN_APP_ID" ]; then
    echo "🌊 Running on Digital Ocean App Platform - installing dependencies in global environment"
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "� Local development environment detected"
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python -m venv venv
    fi
    # Activate virtual environment
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
fi

# Common setup steps for all environments
echo "📦 Running common setup steps..."

python manage.py migrate
python manage.py collectstatic --noinput

# Create superuser only if it doesn't exist and we have the required environment variables
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_EMAIL" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ]; then
    echo "👤 Creating superuser..."
    python manage.py create_superuser --noinput || echo "Superuser may already exist"
else
    echo "⚠️  Superuser environment variables not set, skipping superuser creation"
fi

echo "✨ Setup completed successfully!"
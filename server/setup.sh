#!/usr/bin/env bash
# Setup SecureCipher bankingapi with environment detection

# Exit immediately on error
set -e

# Detect Render
if [ -z "$RENDER" ]; then
    echo "📍 Local development environment detected"
    # …existing venv creation & activation…
else
    echo "🚀 Running on Render - installing dependencies in global environment"
    pip install --upgrade pip
    pip install -r requirements.txt
fi

# Common setup steps for both environments
echo "📦 Running common setup steps..."

python manage.py migrate
python manage.py collectstatic --noinput
python manage.py create_superuser

echo "✨ Setup completed successfully!"
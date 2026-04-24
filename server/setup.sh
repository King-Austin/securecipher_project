#!/usr/bin/env bash
# Setup SecureCipher Banking API for build and deployment

# Exit immediately on error
set -e

echo "🏗️  Setting up SecureCipher Banking API..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install/update dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Database setup
echo "🗄️  Setting up database..."
python manage.py makemigrations
python manage.py migrate

# Static files
echo "📄 Collecting static files..."
python manage.py collectstatic --noinput

# Create superuser
echo "👤 Creating superuser (admin/admin123)..."
export DJANGO_SUPERUSER_USERNAME=admin
export DJANGO_SUPERUSER_EMAIL=admin@securecipher.com
export DJANGO_SUPERUSER_PASSWORD=admin123
python manage.py createsuperuser --noinput || echo "Superuser may already exist"

echo "✨ Setup completed successfully!"
echo ""
echo "🚀 To start the server, run:"
echo "source venv/bin/activate && gunicorn bankingapi.wsgi:application --bind 0.0.0.0:8001"
#!/usr/bin/env bash
# Setup SecureCipher middleware for build and deployment

# Exit immediately on error
set -e

echo "🏗️  Setting up SecureCipher Middleware..."

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
python manage.py migrate --noinput
python manage.py migrate auth --noinput
python manage.py migrate contenttypes --noinput
python manage.py migrate sessions --noinput

# Static files
echo "📄 Collecting static files..."
mkdir -p staticfiles
python manage.py collectstatic --noinput

# Create superuser using the custom management command
# Requires DEFAULT_SUPERUSER_USERNAME, DEFAULT_SUPERUSER_PASSWORD, DEFAULT_SUPERUSER_EMAIL env vars
echo "👤 Creating default superuser..."
python manage.py create_superuser || echo "Superuser may already exist or creation failed"

echo "✨ Setup completed successfully!"
echo ""
echo "🚀 To start the server, run:"
echo "source venv/bin/activate && gunicorn middleware.wsgi:application --bind 0.0.0.0:8000"
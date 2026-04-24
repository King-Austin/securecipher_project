#!/usr/bin/env bash
# Build and run SecureCipher Middleware

# Exit on error
set -e

echo "🚀 Building SecureCipher Middleware..."

# Run setup
./setup.sh

# Start gunicorn (use PORT from Railway or default to 8000)
PORT=${PORT:-8000}
echo "🌐 Starting Gunicorn server on port $PORT..."
source venv/bin/activate
gunicorn middleware.wsgi:application --bind 0.0.0.0:$PORT --workers 4 --threads 2
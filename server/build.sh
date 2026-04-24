#!/usr/bin/env bash
# Build and run SecureCipher Banking API

# Exit on error
set -e

echo "🚀 Building SecureCipher Banking API..."

# Run setup
./setup.sh

# Start gunicorn (use PORT from Railway or default to 8001)
PORT=${PORT:-8001}
echo "🌐 Starting Gunicorn server on port $PORT..."
source venv/bin/activate
gunicorn bankingapi.wsgi:application --bind 0.0.0.0:$PORT --workers 4 --threads 2
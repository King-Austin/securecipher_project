#!/usr/bin/env bash
# Setup SecureCipher middleware with environment detection

# Exit immediately on error
set -e

# Check if running on Render
if [ -z "$RENDER" ]; then
    echo "📍 Local development environment detected"
    
    # Define virtual environment name
    VENV_NAME="venv"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$VENV_NAME" ]; then
        echo "🔨 Creating virtual environment..."
        python3 -m venv $VENV_NAME
        
        # Activate virtual environment
        echo "🚀 Activating virtual environment..."
        source $VENV_NAME/bin/activate
        
        # Install/upgrade pip in virtual environment
        echo "⚙️ Installing dependencies..."
        pip install --upgrade pip
        pip install -r requirements.txt
    else
        echo "✅ Virtual environment already exists"
        source $VENV_NAME/bin/activate
    fi
else
    echo "🚀 Running on Render - skipping virtual environment setup"
fi

# Common setup steps for both environments
echo "📦 Running common setup steps..."

# Apply migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Create superuser using custom management command
python manage.py create_superuser

echo "✨ Setup completed successfully!"
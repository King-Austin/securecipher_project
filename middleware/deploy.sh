#!/bin/bash

# SecureCipher Production Deployment Script
# Usage: ./deploy.sh [environment]

set -e  # Exit on any error

ENVIRONMENT=${1:-development}
PROJECT_NAME="securecipher"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "🚀 Starting SecureCipher deployment for environment: $ENVIRONMENT"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Python 3.9+ is installed
    if ! python3 --version | grep -E "Python 3\.[9-9]|Python 3\.1[0-9]" > /dev/null; then
        print_error "Python 3.9+ is required"
        exit 1
    fi
    
    # Check if pip is installed
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is required"
        exit 1
    fi
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        print_status "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    print_status "Prerequisites check completed ✅"
}

# Setup environment variables
setup_environment() {
    print_status "Setting up environment variables..."
    
    if [ "$ENVIRONMENT" = "production" ]; then
        # Production environment
        if [ ! -f ".env.production" ]; then
            print_error "Production environment file (.env.production) not found!"
            print_warning "Creating template .env.production file..."
            cat > .env.production << EOF
# Production Environment Variables
SECRET_KEY=generate-a-secure-random-key-here
DEBUG=False
ALLOWED_HOSTS=your-domain.com,your-api-domain.com
DATABASE_URL=postgresql://user:password@localhost:5432/securecipher_prod
REDIS_URL=redis://localhost:6379/0
CORS_ALLOWED_ORIGINS=https://your-frontend-domain.com
ROUTING_TABLE_REGISTER=https://your-bank-api.com/register/
ROUTING_TABLE_TRANSFER=https://your-bank-api.com/transfer/
ROUTING_TABLE_PUBLIC_KEY=https://your-bank-api.com/public-key/
EOF
            print_error "Please configure .env.production and run again!"
            exit 1
        fi
        export $(cat .env.production | xargs)
    else
        # Development environment
        export SECRET_KEY="django-insecure-dev-key-only"
        export DEBUG="True"
        export ALLOWED_HOSTS="localhost,127.0.0.1"
    fi
    
    print_status "Environment variables configured ✅"
}

# Install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    print_status "Dependencies installed ✅"
}

# Setup database
setup_database() {
    print_status "Setting up database..."
    
    source venv/bin/activate
    
    # Create logs directory
    mkdir -p logs
    chmod 750 logs
    
    # Run migrations
    python manage.py makemigrations
    python manage.py migrate
    
    # Create superuser if it doesn't exist (development only)
    if [ "$ENVIRONMENT" = "development" ]; then
        print_status "Creating development superuser..."
        echo "from django.contrib.auth.models import User; User.objects.filter(username='admin').exists() or User.objects.create_superuser('admin', 'admin@example.com', 'admin123')" | python manage.py shell
    fi
    
    print_status "Database setup completed ✅"
}

# Generate or verify cryptographic keys
setup_crypto_keys() {
    print_status "Setting up cryptographic keys..."
    
    source venv/bin/activate
    python manage.py shell << EOF
from api.models import MiddlewareKey
from scripts.generate_keypair import generate

if not MiddlewareKey.objects.filter(label="active").exists():
    print("Generating new middleware keypair...")
    generate()
    print("Middleware keypair generated successfully")
else:
    print("Active middleware keypair already exists")
EOF
    
    print_status "Cryptographic keys setup completed ✅"
}

# Run security tests
run_security_tests() {
    print_status "Running security tests..."
    
    source venv/bin/activate
    python manage.py test api.test_security --verbosity=2
    
    if [ $? -eq 0 ]; then
        print_status "Security tests passed ✅"
    else
        print_error "Security tests failed ❌"
        exit 1
    fi
}

# Collect static files (production only)
collect_static() {
    if [ "$ENVIRONMENT" = "production" ]; then
        print_status "Collecting static files..."
        
        source venv/bin/activate
        python manage.py collectstatic --noinput
        
        print_status "Static files collected ✅"
    fi
}

# Start services
start_services() {
    print_status "Starting services..."
    
    source venv/bin/activate
    
    if [ "$ENVIRONMENT" = "production" ]; then
        # Production: use gunicorn
        print_status "Starting production server with gunicorn..."
        gunicorn securecipher.wsgi:application \
            --bind 0.0.0.0:8000 \
            --workers 3 \
            --worker-class gevent \
            --worker-connections 1000 \
            --timeout 30 \
            --keep-alive 5 \
            --max-requests 1000 \
            --max-requests-jitter 100 \
            --daemon \
            --pid /var/run/securecipher.pid \
            --access-logfile logs/access.log \
            --error-logfile logs/error.log \
            --log-level info
        
        print_status "Production server started ✅"
        print_status "PID file: /var/run/securecipher.pid"
        print_status "Access logs: logs/access.log"
        print_status "Error logs: logs/error.log"
    else
        # Development: use Django dev server
        print_status "Starting development server..."
        python manage.py runserver 0.0.0.0:8000 &
        DEV_PID=$!
        echo $DEV_PID > /tmp/securecipher_dev.pid
        
        print_status "Development server started ✅"
        print_status "PID: $DEV_PID"
        print_status "Server running at: http://localhost:8000"
    fi
}

# Deployment verification
verify_deployment() {
    print_status "Verifying deployment..."
    
    # Wait for server to start
    sleep 5
    
    # Test health endpoint
    if curl -f http://localhost:8000/api/public-key/ > /dev/null 2>&1; then
        print_status "Health check passed ✅"
    else
        print_error "Health check failed ❌"
        exit 1
    fi
    
    print_status "Deployment verification completed ✅"
}

# Create backup (production only)
create_backup() {
    if [ "$ENVIRONMENT" = "production" ]; then
        print_status "Creating backup..."
        
        BACKUP_DIR="backups/${TIMESTAMP}"
        mkdir -p "$BACKUP_DIR"
        
        # Backup database
        if [ -n "$DATABASE_URL" ]; then
            pg_dump "$DATABASE_URL" > "$BACKUP_DIR/database.sql"
        else
            cp db.sqlite3 "$BACKUP_DIR/database.sqlite3" 2>/dev/null || true
        fi
        
        # Backup logs
        cp -r logs "$BACKUP_DIR/" 2>/dev/null || true
        
        print_status "Backup created: $BACKUP_DIR ✅"
    fi
}

# Main deployment function
main() {
    print_status "🚀 Starting SecureCipher deployment..."
    print_status "Environment: $ENVIRONMENT"
    print_status "Timestamp: $TIMESTAMP"
    
    check_prerequisites
    setup_environment
    install_dependencies
    setup_database
    setup_crypto_keys
    run_security_tests
    collect_static
    create_backup
    start_services
    verify_deployment
    
    print_status "🎉 Deployment completed successfully!"
    
    if [ "$ENVIRONMENT" = "production" ]; then
        echo ""
        print_status "Production deployment notes:"
        echo "- Server is running as daemon"
        echo "- Monitor logs: tail -f logs/error.log"
        echo "- Stop server: kill \$(cat /var/run/securecipher.pid)"
        echo "- Restart: ./deploy.sh production"
    else
        echo ""
        print_status "Development deployment notes:"
        echo "- Server is running at http://localhost:8000"
        echo "- Stop server: kill \$(cat /tmp/securecipher_dev.pid)"
        echo "- Admin panel: http://localhost:8000/admin (admin/admin123)"
    fi
}

# Handle script interruption
trap 'print_error "Deployment interrupted!"; exit 1' INT TERM

# Run main function
main "$@"

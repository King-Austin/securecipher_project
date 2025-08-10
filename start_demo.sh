        #!/bin/bash

# SecureCipher Demo Setup and Test Script
# =======================================

echo "🔐 SecureCipher Demo Setup & Test Script"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if ports are available
check_port() {
    local port=$1
    local service=$2
    
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        print_warning "Port $port is already in use (may be running $service)"
        return 1
    else
        print_success "Port $port is available for $service"
        return 0
    fi
}

# Start services function
start_service() {
    local service_name=$1
    local port=$2
    local directory=$3
    local command=$4
    
    print_status "Starting $service_name on port $port..."
    
    cd $directory
    
    # Start the service in background
    eval $command &
    local pid=$!
    
    # Give it time to start
    sleep 3
    
    # Check if it's running
    if kill -0 $pid 2>/dev/null; then
        print_success "$service_name started successfully (PID: $pid)"
        echo $pid > "/tmp/securecipher_${service_name,,}_pid"
        return 0
    else
        print_error "$service_name failed to start"
        return 1
    fi
}

# Main setup
main() {
    print_status "SecureCipher Demo Environment Setup"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is required but not installed"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
    
    # Check ports
    print_status "Checking port availability..."
    check_port 8000 "Middleware"
    check_port 8001 "Banking API"
    check_port 5173 "Frontend (Vite)"
    
    # Setup directories
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    MIDDLEWARE_DIR="$SCRIPT_DIR/middleware"
    SERVER_DIR="$SCRIPT_DIR/server"
    FRONTEND_DIR="$SCRIPT_DIR/frontend"
    
    print_status "Project directories:"
    echo "  Middleware: $MIDDLEWARE_DIR"
    echo "  Server:     $SERVER_DIR"
    echo "  Frontend:   $FRONTEND_DIR"
    
    # Install dependencies
    print_status "Installing dependencies..."
    
    # Middleware
    print_status "Setting up middleware..."
    cd "$MIDDLEWARE_DIR"
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt
        python3 manage.py migrate
        print_success "Middleware setup complete"
    fi
    
    # Server
    print_status "Setting up server..."
    cd "$SERVER_DIR"
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt
        python3 manage.py migrate
        print_success "Server setup complete"
    fi
    
    # Frontend
    print_status "Setting up frontend..."
    cd "$FRONTEND_DIR"
    if [ -f "package.json" ]; then
        npm install
        print_success "Frontend setup complete"
    fi
    
    # Start services
    print_status "Starting all services..."
    
    # Start middleware
    start_service "Middleware" 8000 "$MIDDLEWARE_DIR" "python3 manage.py runserver 8000"
    
    # Start banking API
    start_service "Server" 8001 "$SERVER_DIR" "python3 manage.py runserver 8001"
    
    # Start frontend
    start_service "Frontend" 5173 "$FRONTEND_DIR" "npm run dev"
    
    # Summary
    echo ""
    print_success "🎉 SecureCipher Demo Environment is ready!"
    echo ""
    print_status "Services running:"
    echo "  🔐 Middleware API:   http://localhost:8000"
    echo "  🏦 Banking API:      http://localhost:8001"
    echo "  🌐 Frontend App:     http://localhost:5173"
    echo ""
    print_status "Demo Flow:"
    echo "  1. Open http://localhost:5173"
    echo "  2. Register a new account (all fields required)"
    echo "  3. Set a 6-digit PIN for security"
    echo "  4. Complete registration"
    echo "  5. You'll be redirected to dashboard with ₦50,000 welcome bonus"
    echo ""
    print_warning "To stop all services, run: ./stop_demo.sh"
    echo ""
    print_status "Press Ctrl+C to stop this script (services will continue running)"
    
    # Keep script running
    wait
}

# Cleanup function
cleanup() {
    echo ""
    print_status "Stopping services..."
    
    # Kill services if PID files exist
    for service in middleware server frontend; do
        pidfile="/tmp/securecipher_${service}_pid"
        if [ -f "$pidfile" ]; then
            pid=$(cat "$pidfile")
            if kill -0 $pid 2>/dev/null; then
                kill $pid
                print_success "$service stopped"
            fi
            rm -f "$pidfile"
        fi
    done
    
    print_success "All services stopped"
    exit 0
}

# Handle Ctrl+C
trap cleanup SIGINT

# Run main function
main

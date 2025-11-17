#!/bin/bash
################################################################################
# Three-Tier Auth Services - Automated Setup Script
# This script installs and configures all services on a fresh Ubuntu 22.04 system
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="$HOME/three-tier-auth"
VENV_DIR="venv"
LOG_FILE="$PROJECT_DIR/setup.log"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_error "Please do not run this script as root"
    exit 1
fi

print_info "Starting Three-Tier Auth Services Setup"
print_info "Log file: $LOG_FILE"

# Create log directory
mkdir -p "$(dirname "$LOG_FILE")"

# Check if project directory exists
if [ ! -d "$PROJECT_DIR" ]; then
    print_error "Project directory not found: $PROJECT_DIR"
    print_info "Please upload your code to $PROJECT_DIR first"
    exit 1
fi

cd "$PROJECT_DIR"

# Update system
print_info "Updating system packages..."
sudo apt update >> "$LOG_FILE" 2>&1
sudo apt upgrade -y >> "$LOG_FILE" 2>&1
print_success "System updated"

# Install Python and dependencies
print_info "Installing Python and required packages..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    nginx \
    git \
    curl \
    >> "$LOG_FILE" 2>&1
print_success "Python and dependencies installed"

# Setup each service
SERVICES=("kgaas" "uidaaas" "dmiuaas" "lacryptaas")

for service in "${SERVICES[@]}"; do
    print_info "Setting up $service..."
    
    if [ ! -d "$PROJECT_DIR/$service" ]; then
        print_warning "$service directory not found, skipping..."
        continue
    fi
    
    cd "$PROJECT_DIR/$service"
    
    # Create virtual environment
    print_info "  Creating virtual environment for $service..."
    python3 -m venv "$VENV_DIR" >> "$LOG_FILE" 2>&1
    
    # Activate and install requirements
    print_info "  Installing $service dependencies..."
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip >> "$LOG_FILE" 2>&1
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt >> "$LOG_FILE" 2>&1
        print_success "  $service dependencies installed"
    else
        print_warning "  No requirements.txt found for $service"
    fi
    
    deactivate
    cd "$PROJECT_DIR"
done

# Generate environment file if not exists
if [ ! -f "$PROJECT_DIR/.env" ]; then
    print_info "Creating environment configuration file..."
    
    # Generate secure random keys
    KGAAS_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    DEMO_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    LACRYPT_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    UIDAAS_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    PATTERN_KEY=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
    
    cat > "$PROJECT_DIR/.env" << EOF
# KGaaS Configuration
KGAAS_API_KEY=$KGAAS_KEY
DEMO_API_KEY=$DEMO_KEY
LACRYPTAAS_API_KEY=$LACRYPT_KEY
UIDAAAS_API_KEY=$UIDAAS_KEY

# Lacryptaas Configuration
KGAAS_URL=http://localhost:8001
KG_AAS_APIKEY=$KGAAS_KEY
SERVICE_NAME=lacryptaas
ALLOW_AUTO_KEY_CREATION=true

# UIDAaaS Configuration
KG_AAS_URL=http://localhost:8001
KG_AAS_APIKEY=$KGAAS_KEY
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
FROM_EMAIL=no-reply@three-tier-auth.local
OTP_TTL_SECONDS=900
AUTH_NONCE_WINDOW_SECONDS=120

# DMIUAaas Configuration
PATTERN_ENCRYPTION_KEY=$PATTERN_KEY
CHALLENGE_TTL_SECONDS=300
CHALLENGE_MAX_ATTEMPTS=5
GRID_ROWS=4
GRID_COLS=4
EOF
    
    print_success "Environment file created at $PROJECT_DIR/.env"
    print_warning "Review and update the .env file if needed (especially SMTP settings)"
else
    print_info "Environment file already exists, skipping..."
fi

# Create systemd service files
print_info "Creating systemd service files..."

create_systemd_service() {
    local service_name=$1
    local port=$2
    local depends_on=$3
    
    local service_file="/etc/systemd/system/${service_name}.service"
    
    sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=${service_name^^} - Three-Tier Auth Service
After=network.target $depends_on

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR/$service_name
Environment="PATH=$PROJECT_DIR/$service_name/$VENV_DIR/bin"
Environment="PYTHONPATH=$PROJECT_DIR/$service_name"
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$PROJECT_DIR/$service_name/$VENV_DIR/bin/python app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "  Created service: $service_name"
}

create_systemd_service "kgaas" "8001" ""
create_systemd_service "uidaaas" "5000" "kgaas.service"
create_systemd_service "dmiuaas" "6000" ""
create_systemd_service "lacryptaas" "8002" "kgaas.service"

# Reload systemd
print_info "Reloading systemd daemon..."
sudo systemctl daemon-reload >> "$LOG_FILE" 2>&1
print_success "Systemd daemon reloaded"

# Enable services
print_info "Enabling services to start on boot..."
for service in "${SERVICES[@]}"; do
    sudo systemctl enable "$service" >> "$LOG_FILE" 2>&1
done
print_success "Services enabled"

# Start services
print_info "Starting services..."
sudo systemctl start kgaas
sleep 3  # Wait for KGaaS to fully start
sudo systemctl start uidaaas
sudo systemctl start dmiuaas
sudo systemctl start lacryptaas
sleep 2
print_success "Services started"

# Check service status
print_info "Checking service status..."
all_running=true
for service in "${SERVICES[@]}"; do
    if sudo systemctl is-active --quiet "$service"; then
        print_success "  $service is running"
    else
        print_error "  $service failed to start"
        all_running=false
    fi
done

# Configure Nginx
print_info "Configuring Nginx reverse proxy..."

NGINX_CONF="/etc/nginx/sites-available/three-tier-auth"
sudo tee "$NGINX_CONF" > /dev/null << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # KGaaS
    location /kgaas/ {
        proxy_pass http://localhost:8001/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # UIDAaaS
    location /uidaaas/ {
        proxy_pass http://localhost:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # DMIUAaas
    location /dmiuaas/ {
        proxy_pass http://localhost:6000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Lacryptaas
    location /lacryptaas/ {
        proxy_pass http://localhost:8002/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Health check endpoint
    location /health {
        return 200 "Three-Tier Auth Services OK\n";
        add_header Content-Type text/plain;
    }
}
EOF

# Enable nginx site
sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/three-tier-auth
sudo rm -f /etc/nginx/sites-enabled/default

# Test nginx config
if sudo nginx -t >> "$LOG_FILE" 2>&1; then
    sudo systemctl restart nginx >> "$LOG_FILE" 2>&1
    print_success "Nginx configured and restarted"
else
    print_warning "Nginx configuration test failed, check logs"
fi

# Run service tests
print_info "Running service health checks..."

test_service() {
    local name=$1
    local port=$2
    local endpoint=${3:-/ping}
    
    if curl -s -f "http://localhost:$port$endpoint" > /dev/null 2>&1; then
        print_success "  $name health check passed"
        return 0
    else
        print_error "  $name health check failed"
        return 1
    fi
}

sleep 3  # Give services time to start
test_service "KGaaS" "8001"
test_service "UIDAaaS" "5000"
test_service "DMIUAaas" "6000"
test_service "Lacryptaas" "8002"

# Get instance IP
INSTANCE_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "localhost")

# Print summary
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "                    SETUP COMPLETE!"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
print_success "All services have been installed and configured"
echo ""
echo "Service URLs (Direct Access):"
echo "  KGaaS:      http://$INSTANCE_IP:8001/ping"
echo "  UIDAaaS:    http://$INSTANCE_IP:5000/ping"
echo "  DMIUAaas:   http://$INSTANCE_IP:6000/ping"
echo "  Lacryptaas: http://$INSTANCE_IP:8002/ping"
echo ""
echo "Service URLs (via Nginx):"
echo "  KGaaS:      http://$INSTANCE_IP/kgaas/ping"
echo "  UIDAaaS:    http://$INSTANCE_IP/uidaaas/ping"
echo "  DMIUAaas:   http://$INSTANCE_IP/dmiuaas/ping"
echo "  Lacryptaas: http://$INSTANCE_IP/lacryptaas/ping"
echo ""
echo "Useful Commands:"
echo "  View logs:        sudo journalctl -u SERVICE_NAME -f"
echo "  Restart service:  sudo systemctl restart SERVICE_NAME"
echo "  Stop all:         sudo systemctl stop kgaas uidaaas dmiuaas lacryptaas"
echo "  Start all:        sudo systemctl start kgaas uidaaas dmiuaas lacryptaas"
echo ""
echo "Configuration:"
echo "  Environment file: $PROJECT_DIR/.env"
echo "  Log file:         $LOG_FILE"
echo ""
echo "Next Steps:"
echo "  1. Review and update $PROJECT_DIR/.env (especially SMTP settings)"
echo "  2. Test services using the URLs above"
echo "  3. Review logs: sudo journalctl -u kgaas -n 50"
echo "  4. Set up SSL/TLS with certbot (for production)"
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo ""

if [ "$all_running" = true ]; then
    exit 0
else
    print_warning "Some services failed to start. Check logs for details."
    exit 1
fi
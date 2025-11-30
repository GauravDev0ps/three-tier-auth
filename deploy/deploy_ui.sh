#!/bin/bash
################################################################################
# Deploy UI Components - Automated Script
# This script deploys the complete web interface for Three-Tier Auth Services
################################################################################

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     Three-Tier Auth Services - UI Deployment                 ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Configuration
PROJECT_DIR="/home/ubuntu/three-tier-auth"
UI_BACKEND_DIR="$PROJECT_DIR/ui-backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"

echo -e "${BLUE}[1/8]${NC} Checking prerequisites..."

# Check if running on Ubuntu
if [ ! -f /etc/lsb-release ]; then
    echo -e "${RED}This script requires Ubuntu${NC}"
    exit 1
fi

# Check if main services exist
if [ ! -d "$PROJECT_DIR/kgaas" ]; then
    echo -e "${RED}Main services not found. Deploy main services first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites OK${NC}"

echo ""
echo -e "${BLUE}[2/8]${NC} Creating directory structure..."

mkdir -p "$UI_BACKEND_DIR"
mkdir -p "$FRONTEND_DIR"

echo -e "${GREEN}✓ Directories created${NC}"

echo ""
echo -e "${BLUE}[3/8]${NC} Installing UI Backend..."

# Create requirements.txt
cat > "$UI_BACKEND_DIR/requirements.txt" << 'EOF'
flask==3.0.0
flask-sqlalchemy==3.0.5
flask-cors==4.0.0
requests==2.31.0
EOF

# Create virtual environment and install dependencies
cd "$UI_BACKEND_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate

echo -e "${GREEN}✓ UI Backend dependencies installed${NC}"

echo ""
echo -e "${BLUE}[4/8]${NC} Downloading UI components..."

# In production, you would download from your repository
# For now, we'll assume the files are already in place
if [ ! -f "$UI_BACKEND_DIR/app.py" ]; then
    echo -e "${YELLOW}UI Backend app.py not found. Please copy it to $UI_BACKEND_DIR${NC}"
    echo "You can:"
    echo "  1. scp app.py ubuntu@YOUR_IP:$UI_BACKEND_DIR/"
    echo "  2. nano $UI_BACKEND_DIR/app.py and paste the content"
    echo ""
    read -p "Press Enter after you've added the file, or Ctrl+C to cancel..."
fi

if [ ! -f "$FRONTEND_DIR/index.html" ]; then
    echo -e "${YELLOW}Frontend index.html not found. Please copy it to $FRONTEND_DIR${NC}"
    echo "You can:"
    echo "  1. scp index.html ubuntu@YOUR_IP:$FRONTEND_DIR/"
    echo "  2. nano $FRONTEND_DIR/index.html and paste the content"
    echo ""
    read -p "Press Enter after you've added the file, or Ctrl+C to cancel..."
fi

# Verify files exist
if [ ! -f "$UI_BACKEND_DIR/app.py" ] || [ ! -f "$FRONTEND_DIR/index.html" ]; then
    echo -e "${RED}Required files not found. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ UI components ready${NC}"

echo ""
echo -e "${BLUE}[5/8]${NC} Creating systemd service..."

sudo tee /etc/systemd/system/ui-backend.service > /dev/null << EOF
[Unit]
Description=UI Backend - Three-Tier Auth Integration Service
After=network.target kgaas.service uidaaas.service dmiuaas.service lacryptaas.service
Wants=kgaas.service uidaaas.service dmiuaas.service lacryptaas.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=$UI_BACKEND_DIR
Environment="PATH=$UI_BACKEND_DIR/venv/bin"
Environment="UIDAAAS_URL=http://localhost:5000"
Environment="DMIUAAS_URL=http://localhost:6000"
Environment="KGAAS_URL=http://localhost:8001"
Environment="LACRYPTAAS_URL=http://localhost:8002"
ExecStart=$UI_BACKEND_DIR/venv/bin/python app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ui-backend

echo -e "${GREEN}✓ Systemd service created${NC}"

echo ""
echo -e "${BLUE}[6/8]${NC} Configuring Nginx..."

# Backup existing config
if [ -f /etc/nginx/sites-available/three-tier-auth ]; then
    sudo cp /etc/nginx/sites-available/three-tier-auth /etc/nginx/sites-available/three-tier-auth.backup.$(date +%s)
fi

# Create new Nginx configuration
sudo tee /etc/nginx/sites-available/three-tier-auth > /dev/null << 'NGINX_EOF'
server {
    listen 80 default_server;
    server_name _;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "no-referrer-when-downgrade";
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json;
    
    # Root location - Serve the frontend
    location / {
        root /home/ubuntu/three-tier-auth/frontend;
        index index.html;
        try_files $uri $uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
    
    # UI Backend API
    location /api/ {
        proxy_pass http://localhost:3000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Disable caching for API
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }
    
    # UI Backend Health
    location /health {
        proxy_pass http://localhost:3000/health;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        access_log off;
    }
    
    # Direct service access (for debugging/admin)
    location /services/uidaaas/ {
        proxy_pass http://localhost:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /services/dmiuaas/ {
        proxy_pass http://localhost:6000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /services/kgaas/ {
        proxy_pass http://localhost:8001/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /services/lacryptaas/ {
        proxy_pass http://localhost:8002/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    # Block access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
NGINX_EOF

# Enable site and test configuration
sudo ln -sf /etc/nginx/sites-available/three-tier-auth /etc/nginx/sites-enabled/three-tier-auth
sudo rm -f /etc/nginx/sites-enabled/default

if sudo nginx -t; then
    echo -e "${GREEN}✓ Nginx configuration valid${NC}"
else
    echo -e "${RED}Nginx configuration test failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}[7/8]${NC} Starting services..."

# Start UI Backend
sudo systemctl start ui-backend
sleep 2

# Restart Nginx
sudo systemctl restart nginx

# Check service status
if sudo systemctl is-active --quiet ui-backend; then
    echo -e "${GREEN}✓ UI Backend started${NC}"
else
    echo -e "${RED}✗ UI Backend failed to start${NC}"
    sudo journalctl -u ui-backend -n 20
    exit 1
fi

if sudo systemctl is-active --quiet nginx; then
    echo -e "${GREEN}✓ Nginx restarted${NC}"
else
    echo -e "${RED}✗ Nginx failed to start${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}[8/8]${NC} Testing deployment..."

# Wait for services to fully start
sleep 3

# Test health endpoint
HEALTH_CHECK=$(curl -s http://localhost/health || echo "failed")
if echo "$HEALTH_CHECK" | grep -q "healthy"; then
    echo -e "${GREEN}✓ Health check passed${NC}"
else
    echo -e "${YELLOW}⚠ Health check returned: $HEALTH_CHECK${NC}"
fi

# Test frontend
if curl -s http://localhost/ | grep -q "SecureAuth"; then
    echo -e "${GREEN}✓ Frontend accessible${NC}"
else
    echo -e "${YELLOW}⚠ Frontend may not be loading correctly${NC}"
fi

# Get public IP
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "localhost")

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}UI Deployment Complete!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Access your application:${NC}"
echo "  ��� Web Interface: http://$PUBLIC_IP"
echo "  ��� Health Check:  http://$PUBLIC_IP/health"
echo ""
echo -e "${YELLOW}Direct Service Access (for debugging):${NC}"
echo "  UIDAaaS:    http://$PUBLIC_IP/services/uidaaas/ping"
echo "  DMIUAaas:   http://$PUBLIC_IP/services/dmiuaas/ping"
echo "  KGaaS:      http://$PUBLIC_IP/services/kgaas/ping"
echo "  Lacryptaas: http://$PUBLIC_IP/services/lacryptaas/ping"
echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  Check UI Backend:  sudo systemctl status ui-backend"
echo "  View logs:         sudo journalctl -u ui-backend -f"
echo "  Restart UI:        sudo systemctl restart ui-backend"
echo "  Nginx logs:        sudo tail -f /var/log/nginx/access.log"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Open http://$PUBLIC_IP in your browser"
echo "  2. Create an account (Registration)"
echo "  3. Set up your image pattern"
echo "  4. Login and verify pattern"
echo "  5. Experience the complete authentication flow!"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Create a quick reference file
cat > "$PROJECT_DIR/UI_ACCESS_INFO.txt" << EOF
Three-Tier Authentication System - UI Access Information
=========================================================

Deployed on: $(date)
Public IP: $PUBLIC_IP

WEB INTERFACE
-------------
Main URL: http://$PUBLIC_IP

HEALTH CHECK
------------
Status: http://$PUBLIC_IP/health

API ENDPOINTS
-------------
Registration: POST http://$PUBLIC_IP/api/register
Login:        POST http://$PUBLIC_IP/api/login
Pattern:      POST http://$PUBLIC_IP/api/pattern/verify

ADMIN ENDPOINTS
---------------
Users:     GET http://$PUBLIC_IP/api/admin/users
Sessions:  GET http://$PUBLIC_IP/api/admin/sessions
Analytics: GET http://$PUBLIC_IP/api/analytics/stats

SERVICE LOGS
------------
UI Backend: sudo journalctl -u ui-backend -f
Nginx:      sudo tail -f /var/log/nginx/access.log

DATABASE
--------
Location: $UI_BACKEND_DIR/ui_sessions.db
Tables: user_profile, user_session, authentication_log

TROUBLESHOOTING
---------------
1. Restart UI Backend: sudo systemctl restart ui-backend
2. Check status: sudo systemctl status ui-backend
3. View errors: sudo journalctl -u ui-backend -n 50
4. Test health: curl http://localhost/health

For detailed guide, see: UI_DEPLOYMENT_GUIDE.md
EOF

echo -e "${GREEN}Access information saved to: $PROJECT_DIR/UI_ACCESS_INFO.txt${NC}"
echo ""

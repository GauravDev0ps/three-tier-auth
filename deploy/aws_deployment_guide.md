# Three-Tier Security Authentication Services - AWS Deployment Guide

## 📦 Package Overview

This guide will help you deploy:
- **UIDAaaS** (User ID Authentication as a Service) - Port 5000
- **DMIUAaas** (Dynamic Multi-Image Authentication as a Service) - Port 6000  
- **KGaaS** (Key Generation as a Service) - Port 8001
- **Lacryptaas** (Symmetric Encryption as a Service) - Port 8002

## 🎯 Deployment Options

We'll cover **3 deployment methods** for beginners:

1. **EC2 Single Instance** (Easiest - All services on one server)
2. **EC2 Multi-Instance** (Recommended - Each service on separate server)
3. **AWS Elastic Beanstalk** (Advanced - Auto-scaling)

---

## 📋 Prerequisites

Before starting, you need:
- AWS Account (create at https://aws.amazon.com)
- Credit card for AWS billing
- Basic terminal/command line knowledge
- The service ZIP files (instructions below)

**Estimated AWS Costs:**
- EC2 Single Instance: ~$10-20/month (t2.micro/t2.small)
- EC2 Multi-Instance: ~$40-80/month (4x t2.micro)
- Free tier eligible for first 12 months!

---

## 📁 Step 1: Prepare Your Deployment Files

### Directory Structure You Need:

```
three-tier-auth-services/
├── kgaas/
│   ├── app.py
│   └── requirements.txt
├── uidaaas/
│   ├── app.py
│   └── requirements.txt
├── dmiuaas/
│   ├── app.py
│   └── requirements.txt
├── lacryptaas/
│   ├── app.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── key_manager.py
│   │   └── encryption_engine.py
│   └── requirements.txt
├── deploy/
│   ├── setup_all_services.sh
│   ├── systemd_services/
│   │   ├── kgaas.service
│   │   ├── uidaaas.service
│   │   ├── dmiuaas.service
│   │   └── lacryptaas.service
│   └── nginx/
│       └── three-tier-auth.conf
└── README.md
```

### Create requirements.txt for each service:

**kgaas/requirements.txt:**
```
flask==3.0.0
```

**uidaaas/requirements.txt:**
```
flask==3.0.0
flask-sqlalchemy==3.0.5
bcrypt==4.1.2
requests==2.31.0
```

**dmiuaas/requirements.txt:**
```
flask==3.0.0
flask-sqlalchemy==3.0.5
cryptography==41.0.7
```

**lacryptaas/requirements.txt:**
```
flask==3.0.0
requests==2.31.0
cryptography==41.0.7
```

---

## 🚀 Method 1: EC2 Single Instance Deployment (EASIEST)

### Step 1.1: Launch EC2 Instance

1. **Log in to AWS Console**: https://console.aws.amazon.com
2. **Go to EC2 Dashboard**: Search "EC2" in top search bar
3. **Click "Launch Instance"**

4. **Configure Instance**:
   - **Name**: `three-tier-auth-server`
   - **AMI**: Select "Ubuntu Server 22.04 LTS"
   - **Instance Type**: `t2.small` (2GB RAM minimum)
   - **Key Pair**: Click "Create new key pair"
     - Name: `auth-services-key`
     - Type: RSA
     - Format: .pem (for Mac/Linux) or .ppk (for Windows PuTTY)
     - **DOWNLOAD AND SAVE THIS FILE!** You can't download it again.
   
5. **Network Settings**:
   - Click "Edit"
   - Auto-assign public IP: **Enable**
   - Security Group: Click "Create security group"
     - Name: `three-tier-auth-sg`
     - Add these rules:
       ```
       Type: SSH, Port: 22, Source: My IP (or 0.0.0.0/0 for testing)
       Type: Custom TCP, Port: 5000, Source: 0.0.0.0/0
       Type: Custom TCP, Port: 6000, Source: 0.0.0.0/0
       Type: Custom TCP, Port: 8001, Source: 0.0.0.0/0
       Type: Custom TCP, Port: 8002, Source: 0.0.0.0/0
       Type: HTTP, Port: 80, Source: 0.0.0.0/0
       ```

6. **Storage**: 20 GB gp3 (default is fine)

7. **Click "Launch Instance"**

8. **Wait 2-3 minutes** for instance to start

### Step 1.2: Connect to Your Instance

**For Mac/Linux:**
```bash
# Make key file secure
chmod 400 ~/Downloads/auth-services-key.pem

# Connect (replace with YOUR instance IP)
ssh -i ~/Downloads/auth-services-key.pem ubuntu@YOUR_INSTANCE_IP
```

**For Windows:**
- Use PuTTY with your .ppk file
- Or use Windows PowerShell with .pem file (same command as above)

**Find Your Instance IP:**
- In EC2 Console → Instances → Click your instance
- Copy "Public IPv4 address"

### Step 1.3: Upload Your Code

**Option A: Using SCP (Mac/Linux):**
```bash
# From your local machine (not in SSH session)
# Navigate to where you have the services folder

# Zip the services
zip -r three-tier-auth.zip kgaas/ uidaaas/ dmiuaas/ lacryptaas/ deploy/

# Upload to EC2
scp -i ~/Downloads/auth-services-key.pem three-tier-auth.zip ubuntu@YOUR_INSTANCE_IP:~/
```

**Option B: Using Git (Easier):**
```bash
# On your EC2 instance (after SSH)
git clone YOUR_GITHUB_REPO_URL
cd YOUR_REPO_NAME
```

**Option C: Direct Copy-Paste (For testing):**
```bash
# Create directories manually and copy file contents
mkdir -p ~/three-tier-auth/kgaas
mkdir -p ~/three-tier-auth/uidaaas
mkdir -p ~/three-tier-auth/dmiuaas
mkdir -p ~/three-tier-auth/lacryptaas/core
mkdir -p ~/three-tier-auth/deploy

# Create files using nano editor
nano ~/three-tier-auth/kgaas/app.py
# Paste the code, press Ctrl+X, Y, Enter to save
```

### Step 1.4: Install Everything (Automated Script)

**Create setup script on EC2:**
```bash
cat > setup.sh << 'EOF'
#!/bin/bash
set -e

echo "=== Three-Tier Auth Services Setup ==="
echo "This will install Python, dependencies, and configure services"

# Update system
sudo apt update
sudo apt upgrade -y

# Install Python and essentials
sudo apt install -y python3 python3-pip python3-venv nginx

# Navigate to project
cd ~/three-tier-auth

# Setup each service
for service in kgaas uidaaas dmiuaas lacryptaas; do
    echo "Setting up $service..."
    cd $service
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    deactivate
    cd ..
done

echo "=== Installation Complete ==="
echo "Next: Configure environment variables and start services"
EOF

chmod +x setup.sh
./setup.sh
```

### Step 1.5: Configure Environment Variables

```bash
cat > ~/three-tier-auth/.env << 'EOF'
# KGaaS Configuration
KGAAS_API_KEY=your-secure-kgaas-key-here-change-this
DEMO_API_KEY=demo-secret-token-change-this
LACRYPTAAS_API_KEY=lacrypt-token-change-this
UIDAAAS_API_KEY=uidaas-token-change-this

# Lacryptaas Configuration
KGAAS_URL=http://localhost:8001
KG_AAS_APIKEY=your-secure-kgaas-key-here-change-this
SERVICE_NAME=lacryptaas

# UIDAaaS Configuration
KG_AAS_URL=http://localhost:8001
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
FROM_EMAIL=no-reply@yourapp.local
DEV_KG_KEY=

# DMIUAaas Configuration
PATTERN_ENCRYPTION_KEY=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
CHALLENGE_TTL_SECONDS=300
CHALLENGE_MAX_ATTEMPTS=5
GRID_ROWS=4
GRID_COLS=4
EOF

echo "Environment file created. PLEASE EDIT .env and change default passwords!"
```

### Step 1.6: Create Systemd Services

```bash
# Create service for KGaaS
sudo tee /etc/systemd/system/kgaas.service > /dev/null << EOF
[Unit]
Description=KGaaS - Key Generation Service
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/three-tier-auth/kgaas
Environment="PATH=/home/ubuntu/three-tier-auth/kgaas/venv/bin"
EnvironmentFile=/home/ubuntu/three-tier-auth/.env
ExecStart=/home/ubuntu/three-tier-auth/kgaas/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create service for UIDAaaS
sudo tee /etc/systemd/system/uidaaas.service > /dev/null << EOF
[Unit]
Description=UIDAaaS - User Authentication Service
After=network.target kgaas.service
Requires=kgaas.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/three-tier-auth/uidaaas
Environment="PATH=/home/ubuntu/three-tier-auth/uidaaas/venv/bin"
EnvironmentFile=/home/ubuntu/three-tier-auth/.env
ExecStart=/home/ubuntu/three-tier-auth/uidaaas/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create service for DMIUAaas
sudo tee /etc/systemd/system/dmiuaas.service > /dev/null << EOF
[Unit]
Description=DMIUAaas - Image Authentication Service
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/three-tier-auth/dmiuaas
Environment="PATH=/home/ubuntu/three-tier-auth/dmiuaas/venv/bin"
EnvironmentFile=/home/ubuntu/three-tier-auth/.env
ExecStart=/home/ubuntu/three-tier-auth/dmiuaas/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create service for Lacryptaas
sudo tee /etc/systemd/system/lacryptaas.service > /dev/null << EOF
[Unit]
Description=Lacryptaas - Encryption Service
After=network.target kgaas.service
Requires=kgaas.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/three-tier-auth/lacryptaas
Environment="PATH=/home/ubuntu/three-tier-auth/lacryptaas/venv/bin"
Environment="PYTHONPATH=/home/ubuntu/three-tier-auth/lacryptaas"
EnvironmentFile=/home/ubuntu/three-tier-auth/.env
ExecStart=/home/ubuntu/three-tier-auth/lacryptaas/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload
```

### Step 1.7: Start All Services

```bash
# Enable services to start on boot
sudo systemctl enable kgaas uidaaas dmiuaas lacryptaas

# Start all services
sudo systemctl start kgaas
sleep 2  # Wait for KGaaS to start first
sudo systemctl start uidaaas
sudo systemctl start dmiuaas
sudo systemctl start lacryptaas

# Check status
sudo systemctl status kgaas
sudo systemctl status uidaaas
sudo systemctl status dmiuaas
sudo systemctl status lacryptaas
```

**Expected output:** All should show `Active: active (running)` in green

### Step 1.8: Test Your Deployment

```bash
# Test each service
curl http://localhost:8001/ping  # KGaaS
curl http://localhost:5000/ping  # UIDAaaS
curl http://localhost:6000/ping  # DMIUAaas
curl http://localhost:8002/ping  # Lacryptaas

# Test from your computer (replace with your EC2 IP)
curl http://YOUR_EC2_IP:8001/ping
curl http://YOUR_EC2_IP:5000/ping
curl http://YOUR_EC2_IP:6000/ping
curl http://YOUR_EC2_IP:8002/ping
```

### Step 1.9: Configure Nginx (Optional but Recommended)

```bash
# Create nginx config
sudo tee /etc/nginx/sites-available/three-tier-auth << 'EOF'
server {
    listen 80;
    server_name YOUR_DOMAIN_OR_IP;

    # KGaaS
    location /kgaas/ {
        proxy_pass http://localhost:8001/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # UIDAaaS
    location /uidaaas/ {
        proxy_pass http://localhost:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # DMIUAaas
    location /dmiuaas/ {
        proxy_pass http://localhost:6000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Lacryptaas
    location /lacryptaas/ {
        proxy_pass http://localhost:8002/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/three-tier-auth /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

Now you can access services at:
- `http://YOUR_EC2_IP/kgaas/ping`
- `http://YOUR_EC2_IP/uidaaas/ping`
- `http://YOUR_EC2_IP/dmiuaas/ping`
- `http://YOUR_EC2_IP/lacryptaas/ping`

---

## 🔧 Troubleshooting

### Service Won't Start
```bash
# Check logs
sudo journalctl -u kgaas -f
sudo journalctl -u uidaaas -f
sudo journalctl -u dmiuaas -f
sudo journalctl -u lacryptaas -f

# Check if port is already in use
sudo netstat -tulpn | grep :5000
```

### Can't Connect from Internet
- Check EC2 Security Group allows your ports
- Verify instance has public IP
- Check if AWS firewall is blocking

### Database Errors
```bash
# Recreate databases
cd ~/three-tier-auth/uidaaas
rm -f uidaaas.db
source venv/bin/activate
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

---

## 📊 Monitoring Your Services

### Check Service Status
```bash
sudo systemctl status kgaas uidaaas dmiuaas lacryptaas
```

### View Logs
```bash
# Real-time logs
sudo journalctl -u uidaaas -f

# Last 100 lines
sudo journalctl -u uidaaas -n 100
```

### Restart a Service
```bash
sudo systemctl restart uidaaas
```

### Stop All Services
```bash
sudo systemctl stop kgaas uidaaas dmiuaas lacryptaas
```

---

## 🔒 Security Hardening (Production)

1. **Change All Default API Keys** in `.env` file
2. **Use HTTPS** with Let's Encrypt:
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com
   ```
3. **Restrict Security Group**: Change 0.0.0.0/0 to specific IPs
4. **Use RDS Database** instead of SQLite for production
5. **Enable AWS CloudWatch** for monitoring
6. **Set up AWS Backup** for your EC2 instance
7. **Use AWS Secrets Manager** for storing API keys

---

## 💰 Cost Optimization

- **Use t2.micro** (free tier eligible) for testing
- **Stop instances when not in use** (still charges for storage)
- **Use Reserved Instances** for 1-3 year commitments (40-60% discount)
- **Monitor with AWS Cost Explorer**

---

## 🎉 You're Done!

Your three-tier authentication services are now running on AWS!

### Quick Test Workflow:

```bash
# 1. Request access
curl -X POST http://YOUR_EC2_IP:5000/request_access \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "username": "testuser"}'

# 2. Register image pattern (DMIUAaas)
curl -X POST http://YOUR_EC2_IP:6000/register_user_secret \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "pattern": [[0,1], [2,3], [1,2]]}'

# 3. Test encryption (Lacryptaas)
curl -X POST http://YOUR_EC2_IP:8002/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "Hello World"}'
```

---

## 📞 Need Help?

- Check logs: `sudo journalctl -u SERVICE_NAME -f`
- Verify network: `curl localhost:PORT/ping`
- Review AWS Security Groups
- Check service status: `sudo systemctl status SERVICE_NAME`

**Common Issues:**
- Port already in use: Change port in app.py
- Permission denied: Check file ownership with `ls -la`
- Module not found: Reinstall requirements in venv

---

## Next Steps

1. Set up monitoring with CloudWatch
2. Configure automated backups
3. Add load balancer for high availability
4. Set up CI/CD pipeline with GitHub Actions
5. Implement proper database (RDS PostgreSQL)
6. Add API Gateway for unified access
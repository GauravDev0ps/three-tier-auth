# 📋 Deployment Checklist

## Pre-Deployment (On Your Computer)

- [ ] Create project directory structure
- [ ] Copy all Python files (app.py for each service)
- [ ] Create all requirements.txt files
- [ ] Create lacryptaas/core/__init__.py (empty file)
- [ ] Copy deployment scripts to deploy/ folder
- [ ] Make scripts executable (`chmod +x deploy/*.sh`)
- [ ] Verify Python syntax (`python3 -m py_compile app.py`)
- [ ] Create ZIP/tar package
- [ ] Test extraction of package locally

**Files Checklist:**
```
□ kgaas/app.py
□ kgaas/requirements.txt
□ uidaaas/app.py
□ uidaaas/requirements.txt
□ dmiuaas/app.py
□ dmiuaas/requirements.txt
□ lacryptaas/app.py
□ lacryptaas/requirements.txt
□ lacryptaas/core/__init__.py
□ lacryptaas/core/key_manager.py
□ lacryptaas/core/encryption_engine.py
□ deploy/setup_all_services.sh
□ deploy/test_all_services.sh
□ deploy/start_all_services.sh
□ deploy/stop_all_services.sh
□ README.md
```

---

## AWS Setup

### EC2 Instance Creation
- [ ] Log into AWS Console
- [ ] Navigate to EC2 Dashboard
- [ ] Click "Launch Instance"
- [ ] Name: `three-tier-auth-server`
- [ ] AMI: Ubuntu Server 22.04 LTS
- [ ] Instance Type: t2.small (recommended) or t2.micro
- [ ] Create new key pair: `auth-services-key`
- [ ] Download and save .pem/.ppk file
- [ ] Enable Auto-assign Public IP
- [ ] Create security group: `three-tier-auth-sg`

### Security Group Rules
- [ ] SSH (22) - My IP
- [ ] Custom TCP (5000) - 0.0.0.0/0 (UIDAaaS)
- [ ] Custom TCP (6000) - 0.0.0.0/0 (DMIUAaas)
- [ ] Custom TCP (8001) - 0.0.0.0/0 (KGaaS)
- [ ] Custom TCP (8002) - 0.0.0.0/0 (Lacryptaas)
- [ ] HTTP (80) - 0.0.0.0/0 (Nginx)

### Storage
- [ ] 20 GB gp3
- [ ] Launch instance
- [ ] Wait for "Running" state
- [ ] Note down Public IPv4 address

---

## Connection & Upload

- [ ] Make key file secure: `chmod 400 auth-services-key.pem`
- [ ] Connect via SSH: `ssh -i auth-services-key.pem ubuntu@YOUR_IP`
- [ ] Upload ZIP file (via SCP/WinSCP/git)
- [ ] Extract: `unzip three-tier-auth-services.zip`
- [ ] Navigate: `cd three-tier-auth-services`
- [ ] Make scripts executable: `chmod +x deploy/*.sh`

---

## Installation

- [ ] Run setup script: `./deploy/setup_all_services.sh`
- [ ] Wait 5-10 minutes for completion
- [ ] Verify "SETUP COMPLETE" message

### Manual Checks
- [ ] Check services running: `sudo systemctl status kgaas uidaaas dmiuaas lacryptaas`
- [ ] All show "active (running)" in green
- [ ] Check logs for errors: `sudo journalctl -u kgaas -n 20`

---

## Testing

### Local Tests (on server)
- [ ] `curl http://localhost:8001/ping` → {"message": "pong"}
- [ ] `curl http://localhost:5000/ping` → {"message": "pong"}
- [ ] `curl http://localhost:6000/ping` → {"message": "pong"}
- [ ] `curl http://localhost:8002/ping` → {"message": "pong"}

### Remote Tests (from your computer)
- [ ] `http://YOUR_IP:8001/ping` → Works in browser
- [ ] `http://YOUR_IP:5000/ping` → Works in browser
- [ ] `http://YOUR_IP:6000/ping` → Works in browser
- [ ] `http://YOUR_IP:8002/ping` → Works in browser

### Integration Tests
- [ ] Run: `./deploy/test_all_services.sh`
- [ ] All tests pass (0 failed)
- [ ] Review test output for errors

---

## Nginx Configuration

- [ ] Nginx installed and running
- [ ] Configuration file created: `/etc/nginx/sites-available/three-tier-auth`
- [ ] Symbolic link created: `/etc/nginx/sites-enabled/three-tier-auth`
- [ ] Nginx config test: `sudo nginx -t` → "test successful"
- [ ] Nginx restarted: `sudo systemctl restart nginx`

### Test Nginx Proxying
- [ ] `http://YOUR_IP/kgaas/ping` → Works
- [ ] `http://YOUR_IP/uidaaas/ping` → Works
- [ ] `http://YOUR_IP/dmiuaas/ping` → Works
- [ ] `http://YOUR_IP/lacryptaas/ping` → Works

---

## Functional Testing

### UIDAaaS Workflow
- [ ] Request access: `POST /request_access`
- [ ] Create OTP: `POST /create_user_from_request`
- [ ] Finalize registration: `POST /finalize_registration`
- [ ] Login: `POST /login`
- [ ] List users: `GET /list_users`

### DMIUAaas Workflow
- [ ] Register pattern: `POST /register_user_secret`
- [ ] Initialize challenge: `POST /init_image_challenge`
- [ ] Verify challenge: `POST /verify_image_challenge`
- [ ] Get pattern info: `GET /get_user_pattern_info`

### KGaaS Workflow
- [ ] Create key: `POST /v1/keys`
- [ ] Get key: `GET /v1/keys/:id`
- [ ] List keys: `GET /v1/keys`
- [ ] Rotate key: `POST /v1/keys/:id/rotate`

### Lacryptaas Workflow
- [ ] Encrypt (CBC): `POST /encrypt` with mode=cbc
- [ ] Decrypt (CBC): `POST /decrypt` with mode=cbc
- [ ] Encrypt (GCM): `POST /encrypt` with mode=gcm
- [ ] Decrypt (GCM): `POST /decrypt` with mode=gcm

---

## Configuration Review

- [ ] Review `.env` file
- [ ] Change default API keys (IMPORTANT!)
- [ ] Set SMTP settings (if using email)
- [ ] Verify service URLs are correct
- [ ] Save `.env` backup

### Environment Variables to Check
```
□ KGAAS_API_KEY - Changed from default
□ DEMO_API_KEY - Changed from default
□ LACRYPTAAS_API_KEY - Changed from default
□ UIDAAAS_API_KEY - Changed from default
□ PATTERN_ENCRYPTION_KEY - Auto-generated (OK)
□ SMTP settings - Configured if using email
```

---

## Service Management

### Know These Commands
- [ ] Check status: `sudo systemctl status SERVICE_NAME`
- [ ] Start service: `sudo systemctl start SERVICE_NAME`
- [ ] Stop service: `sudo systemctl stop SERVICE_NAME`
- [ ] Restart service: `sudo systemctl restart SERVICE_NAME`
- [ ] View logs: `sudo journalctl -u SERVICE_NAME -f`
- [ ] View last N lines: `sudo journalctl -u SERVICE_NAME -n 50`

### Test Service Management
- [ ] Stop a service: `sudo systemctl stop uidaaas`
- [ ] Verify stopped: `sudo systemctl status uidaaas`
- [ ] Start service: `sudo systemctl start uidaaas`
- [ ] Verify running: `sudo systemctl status uidaaas`

---

## Security Hardening (Production Only)

**⚠️ Skip for testing, REQUIRED for production:**

- [ ] Change all API keys in `.env`
- [ ] Install SSL certificate (Let's Encrypt)
- [ ] Update Security Groups (restrict to specific IPs)
- [ ] Use AWS RDS instead of SQLite
- [ ] Enable CloudWatch monitoring
- [ ] Set up CloudWatch alarms
- [ ] Configure automated backups
- [ ] Use AWS Secrets Manager for credentials
- [ ] Enable AWS GuardDuty
- [ ] Set up VPC with private subnets
- [ ] Configure NAT Gateway
- [ ] Enable AWS WAF
- [ ] Set up rate limiting
- [ ] Review and harden systemd services
- [ ] Disable root SSH login
- [ ] Set up fail2ban
- [ ] Configure automatic security updates

---

## Documentation

- [ ] Document your Public IP address
- [ ] Document API endpoints
- [ ] Save SSH key in secure location
- [ ] Document Security Group ID
- [ ] Note AWS region used
- [ ] Document any customizations made
- [ ] Create API usage examples
- [ ] Document service dependencies

---

## Monitoring Setup

- [ ] Enable CloudWatch Logs
- [ ] Create CloudWatch dashboard
- [ ] Set up billing alerts
- [ ] Configure SNS topics for alerts
- [ ] Test alert notifications
- [ ] Set up log rotation
- [ ] Configure disk space monitoring
- [ ] Set up uptime monitoring

---

## Backup & Disaster Recovery

- [ ] Create EC2 AMI snapshot
- [ ] Document snapshot ID
- [ ] Test restore from snapshot
- [ ] Export `.env` file securely
- [ ] Backup database files
- [ ] Document recovery procedures
- [ ] Test full recovery process
- [ ] Set up automated snapshots

---

## Performance Optimization

- [ ] Review service response times
- [ ] Check database query performance
- [ ] Monitor CPU/memory usage
- [ ] Optimize slow endpoints
- [ ] Enable caching if needed
- [ ] Configure Nginx caching
- [ ] Review connection pooling
- [ ] Test under load

---

## Final Verification

- [ ] All 4 services respond to health checks
- [ ] All integration tests pass
- [ ] Can create and login users
- [ ] Can complete image challenges
- [ ] Can encrypt/decrypt data
- [ ] Services restart on reboot
- [ ] Nginx proxying works
- [ ] Logs are accessible
- [ ] No critical errors in logs
- [ ] Documentation is complete

---

## Cost Management

- [ ] Review AWS billing dashboard
- [ ] Set up billing alert ($10 threshold)
- [ ] Tag resources for cost tracking
- [ ] Review instance pricing
- [ ] Consider Reserved Instances
- [ ] Stop instance when not needed
- [ ] Delete unused snapshots
- [ ] Monitor data transfer costs

---

## Troubleshooting Checklist

If something doesn't work:

1. **Service won't start**
   - [ ] Check logs: `sudo journalctl -u SERVICE_NAME -n 50`
   - [ ] Check port availability: `sudo netstat -tulpn | grep PORT`
   - [ ] Verify dependencies installed
   - [ ] Check `.env` file exists and is readable

2. **Can't connect from internet**
   - [ ] Check Security Group allows port
   - [ ] Verify service is listening: `sudo netstat -tulpn`
   - [ ] Check firewall: `sudo ufw status`
   - [ ] Verify instance has public IP

3. **Service crashes**
   - [ ] Check memory: `free -h`
   - [ ] Check disk space: `df -h`
   - [ ] Review crash logs
   - [ ] Verify Python dependencies

4. **Database errors**
   - [ ] Check database file permissions
   - [ ] Verify database file exists
   - [ ] Check disk space
   - [ ] Review migration logs

---

## Sign Off

**Deployment Date:** _______________

**Deployed By:** _______________

**Instance ID:** _______________

**Public IP:** _______________

**Environment:** [ ] Testing  [ ] Production

**All Tests Passed:** [ ] Yes  [ ] No

**Documentation Complete:** [ ] Yes  [ ] No

**Ready for Use:** [ ] Yes  [ ] No

**Notes:**
_________________________________
_________________________________
_________________________________

---

## Quick Commands Reference

```bash
# Connect
ssh -i auth-services-key.pem ubuntu@YOUR_IP

# Check all services
sudo systemctl status kgaas uidaaas dmiuaas lacryptaas

# Restart all
sudo systemctl restart kgaas uidaaas dmiuaas lacryptaas

# View logs
sudo journalctl -u uidaaas -f

# Test health
curl http://localhost:5000/ping

# Run integration tests
./deploy/test_all_services.sh

# Update code
cd ~/three-tier-auth-services
git pull  # if using git
sudo systemctl restart kgaas uidaaas dmiuaas lacryptaas
```

---

**Print this checklist and check off items as you complete them!**
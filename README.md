# 🚀 Complete Beginner's Guide to AWS Deployment

## What You'll Build

A complete three-tier authentication system with:
- Password-based login
- Image pattern verification
- Secure encryption services
- Key management

**Time Required:** 30-60 minutes  
**Cost:** $10-20/month (Free for first year with AWS Free Tier)

---

## 📋 Before You Start

### What You Need:

1. **AWS Account** 
   - Create at: https://aws.amazon.com
   - Credit card required (for verification)
   - Free tier available!

2. **Computer with Internet**
   - Windows, Mac, or Linux - all work!

3. **Your Code Files**
   - The ZIP file you created following PACKAGE_CREATION_GUIDE.md

4. **30-60 Minutes**
   - Most time is waiting for installation

---

## 🎯 Step-by-Step Deployment

### PART 1: Create Your AWS Server (EC2 Instance)

#### Step 1.1: Log Into AWS

1. Go to https://console.aws.amazon.com
2. Click "Sign In to the Console"
3. Enter your email and password

#### Step 1.2: Find EC2 Service

1. In the top search bar, type: `EC2`
2. Click on **EC2** (Virtual Servers in the Cloud)
3. You'll see the EC2 Dashboard

#### Step 1.3: Launch Your Server

1. Look for the orange button: **"Launch Instance"**
2. Click it!

#### Step 1.4: Name Your Server

- **Name your instance:** Type `three-tier-auth-server`
  - This is just a label so you can find it later

#### Step 1.5: Choose Operating System

1. Under "Application and OS Images (Amazon Machine Image)"
2. **Select:** Ubuntu Server 22.04 LTS
   - Make sure it says "Free tier eligible"
   - Should be the first option

#### Step 1.6: Choose Server Size

1. Under "Instance type"
2. **Select:** `t2.small`
   - t2.micro (1GB RAM) might work but is tight
   - t2.small (2GB RAM) is recommended
   - Costs about $17/month or FREE if you have AWS credits

> 💡 **Tip:** If you're on free tier, you get 750 hours/month of t2.micro FREE

#### Step 1.7: Create Security Key (IMPORTANT!)

1. Under "Key pair (login)"
2. Click **"Create new key pair"**
3. Settings:
   - **Name:** `auth-services-key`
   - **Key pair type:** RSA
   - **File format:** 
     - Mac/Linux: Choose `.pem`
     - Windows: Choose `.ppk` (if using PuTTY)
4. Click **"Create key pair"**
5. **⚠️ SAVE THIS FILE!** It downloads automatically
   - Move it somewhere safe (like Documents folder)
   - You CANNOT download it again!

#### Step 1.8: Configure Network (Firewall)

1. Under "Network settings", click **"Edit"**
2. Check **"Auto-assign public IP"** is **Enabled**
3. Under "Firewall (security groups)":
   - Click **"Create security group"**
   - **Name:** `three-tier-auth-sg`
4. **Add these rules** (click "Add security group rule" for each):

| Type | Port | Source | Why? |
|------|------|--------|------|
| SSH | 22 | My IP | To connect to server |
| Custom TCP | 5000 | Anywhere (0.0.0.0/0) | UIDAaaS |
| Custom TCP | 6000 | Anywhere (0.0.0.0/0) | DMIUAaas |
| Custom TCP | 8001 | Anywhere (0.0.0.0/0) | KGaaS |
| Custom TCP | 8002 | Anywhere (0.0.0.0/0) | Lacryptaas |
| HTTP | 80 | Anywhere (0.0.0.0/0) | Web access |

> 💡 **Tip:** "My IP" is more secure than "Anywhere" for SSH, but "Anywhere" is easier for testing

#### Step 1.9: Configure Storage

1. Under "Configure storage"
2. **Size:** 20 GB (default is fine)
3. **Type:** gp3 (default is fine)

#### Step 1.10: Launch!

1. Review your settings on the right
2. Click the orange **"Launch instance"** button
3. You'll see "Success!" message
4. Click **"View all instances"**

#### Step 1.11: Wait for Server to Start

- Your instance will show:
  - **Instance state:** Initially "Pending" → Wait until "Running" (green)
  - **Status check:** 2/2 checks passed (takes 2-3 minutes)

#### Step 1.12: Get Your Server's IP Address

1. Click on your instance (the checkbox)
2. Look at details at bottom
3. Find **"Public IPv4 address"** 
4. **Write this down!** Example: `54.123.45.67`
   - This is how you'll access your services

---

### PART 2: Connect to Your Server

Now you need to connect to your server using SSH (Secure Shell).

#### For Mac/Linux Users:

1. Open **Terminal**
   - Mac: Applications → Utilities → Terminal
   - Linux: Ctrl+Alt+T

2. Make your key file secure:
   ```bash
   chmod 400 ~/Downloads/auth-services-key.pem
   ```

3. Connect (replace `YOUR_IP` with your actual IP):
   ```bash
   ssh -i ~/Downloads/auth-services-key.pem ubuntu@YOUR_IP
   ```

4. Type `yes` when asked "Are you sure?"

5. You're in! You should see:
   ```
   ubuntu@ip-xxx-xxx-xxx:~$
   ```

#### For Windows Users:

**Option 1: Using Windows PowerShell (Easiest)**

1. Press `Windows + X`, select "Windows PowerShell"

2. Navigate to where your key is:
   ```powershell
   cd Downloads
   ```

3. Connect:
   ```powershell
   ssh -i .\auth-services-key.pem ubuntu@YOUR_IP
   ```

4. Type `yes` when asked

**Option 2: Using PuTTY**

1. Download PuTTY from https://putty.org
2. Open PuTTY
3. **Host Name:** `ubuntu@YOUR_IP`
4. **Port:** 22
5. **Connection → SSH → Auth:** Browse to your `.ppk` file
6. Click **Open**
7. Click **Yes** to accept key

---

### PART 3: Upload Your Code

You have 3 options (choose ONE):

#### Option A: Using SCP (Easiest for Mac/Linux)

**From your LOCAL computer** (NOT in SSH session):

```bash
# Make sure you're in the directory with your ZIP file
cd ~/Downloads  # or wherever your ZIP is

# Upload (replace YOUR_IP)
scp -i auth-services-key.pem three-tier-auth-services.zip ubuntu@YOUR_IP:~/
```

#### Option B: Using WinSCP (Windows)

1. Download WinSCP from https://winscp.net
2. Install and open it
3. **File protocol:** SCP
4. **Host name:** YOUR_IP
5. **User name:** ubuntu
6. **Advanced → SSH → Authentication:** Select your `.ppk` file
7. Click **Login**
8. Drag and drop your ZIP file to the right panel

#### Option C: Using GitHub (Any OS)

**On your local computer:**
```bash
cd three-tier-auth-services
git init
git add .
git commit -m "Initial deployment"
# Create a repo on github.com first, then:
git remote add origin YOUR_GITHUB_URL
git push -u origin main
```

**On your EC2 server:**
```bash
git clone YOUR_GITHUB_URL
```

---

### PART 4: Install and Run Everything

Now you're connected to your server via SSH. Let's install everything!

#### Step 4.1: Extract Your Code

```bash
# If you uploaded a ZIP file:
unzip three-tier-auth-services.zip
cd three-tier-auth-services

# If you used git clone:
cd three-tier-auth-services
```

#### Step 4.2: Make Scripts Executable

```bash
chmod +x deploy/*.sh
```

#### Step 4.3: Run the Automated Setup (Magic! ✨)

```bash
./deploy/setup_all_services.sh
```

**What this does:**
- Updates Ubuntu
- Installs Python 3
- Installs all dependencies
- Creates databases
- Configures services
- Sets up auto-start
- Installs Nginx web server

**This takes 5-10 minutes.** Go get coffee! ☕

You'll see lots of text scrolling. At the end, you should see:

```
═══════════════════════════════════════════════════════════════════
                    SETUP COMPLETE!
═══════════════════════════════════════════════════════════════════
```

---

### PART 5: Test Your Services

#### Step 5.1: Check Services Are Running

```bash
sudo systemctl status kgaas uidaaas dmiuaas lacryptaas
```

You should see **green "active (running)"** for all services.

If not running:
```bash
sudo systemctl start kgaas uidaaas dmiuaas lacryptaas
```

#### Step 5.2: Test From Server

```bash
curl http://localhost:5000/ping
curl http://localhost:6000/ping
curl http://localhost:8001/ping
curl http://localhost:8002/ping
```

Each should respond with `{"message": "pong"}`.

#### Step 5.3: Test From Your Computer

Open a web browser and visit (replace YOUR_IP):

- `http://YOUR_IP:5000/ping` - Should show: `{"message":"pong"}`
- `http://YOUR_IP:6000/ping` - Should show: `{"message":"pong","service":"dmiuaas"}`
- `http://YOUR_IP:8001/ping` - Should show: `{"message":"pong","service":"kgaas"}`
- `http://YOUR_IP:8002/ping` - Should show: `{"message":"pong","service":"lacryptaas"}`

**🎉 If all four work, YOUR SERVICES ARE LIVE!**

---

### PART 6: Run Integration Tests

```bash
./deploy/test_all_services.sh
```

This tests:
- ✅ All services are reachable
- ✅ User registration works
- ✅ Login works
- ✅ Image challenges work
- ✅ Encryption/decryption works
- ✅ All services talk to each other

You should see:
```
Tests Passed:  25+
Tests Failed:  0
✓ ALL TESTS PASSED!
```

---

## 🎓 Using Your Services

### Create a Test User

```bash
# 1. Request access
curl -X POST http://YOUR_IP:5000/request_access \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "username": "testuser"}'

# Response will include request_id (e.g., 1)

# 2. Admin creates OTP (in real app, admin would do this)
curl -X POST http://YOUR_IP:5000/create_user_from_request \
  -H "Content-Type: application/json" \
  -d '{"request_id": 1}'

# Response includes token (copy this)

# 3. Finalize registration with password
curl -X POST http://YOUR_IP:5000/finalize_registration \
  -H "Content-Type: application/json" \
  -d '{"token": "TOKEN_FROM_ABOVE", "password": "MySecure123!", "username": "testuser"}'

# 4. Login
curl -X POST http://YOUR_IP:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "MySecure123!"}'
```

### Set Up Image Pattern

```bash
curl -X POST http://YOUR_IP:6000/register_user_secret \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "pattern": [[0,1], [2,3], [1,2]]}'
```

### Encrypt Some Data

```bash
curl -X POST http://YOUR_IP:8002/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "Hello World!"}'
```

---

## 🛑 Common Problems and Solutions

### Problem: "Connection refused"

**Solution:**
```bash
# Check if services are running
sudo systemctl status kgaas uidaaas dmiuaas lacryptaas

# Check logs
sudo journalctl -u uidaaas -n 50

# Restart a service
sudo systemctl restart uidaaas
```

### Problem: "Permission denied" when connecting

**Solution:**
```bash
# Make sure key has correct permissions
chmod 400 auth-services-key.pem

# Use correct username (ubuntu, not ec2-user)
ssh -i auth-services-key.pem ubuntu@YOUR_IP
```

### Problem: Can't access from browser

**Solution:**
1. Check AWS Security Group allows the port
2. Check service is running: `sudo systemctl status SERVICE_NAME`
3. Check if port is listening: `sudo netstat -tulpn | grep :5000`

### Problem: "Module not found" error

**Solution:**
```bash
cd ~/three-tier-auth-services/SERVICE_NAME
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🔒 Security: Before Going to Production

⚠️ **The default setup is for TESTING ONLY!**

For production, you MUST:

1. **Change API Keys**
   ```bash
   nano ~/three-tier-auth-services/.env
   # Change all the secret keys
   ```

2. **Enable HTTPS**
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com
   ```

3. **Restrict Security Group**
   - Change `0.0.0.0/0` to specific IPs
   - Only allow port 22 from your IP

4. **Use Real Database**
   - SQLite is for testing
   - Use AWS RDS (PostgreSQL/MySQL) for production

5. **Set Up Monitoring**
   - Enable AWS CloudWatch
   - Set up alerts

---

## 💰 Managing Costs

### Stop Your Instance When Not Using

```bash
# From AWS Console:
Actions → Instance State → Stop
```

**Cost while stopped:** Only storage (~$2/month for 20GB)

### Completely Delete Everything

```bash
# From AWS Console:
1. Select instance
2. Instance State → Terminate
3. Delete the security group
4. Delete the key pair (optional)
```

**Cost after termination:** $0

---

## 📊 Monitoring Your Services

### View Logs

```bash
# Real-time logs
sudo journalctl -u uidaaas -f

# Last 100 lines
sudo journalctl -u uidaaas -n 100

# All logs since boot
sudo journalctl -u uidaaas -b
```

### Check Resource Usage

```bash
# CPU and Memory
htop

# Disk space
df -h

# Network connections
sudo netstat -tulpn
```

### Restart Services

```bash
# Restart one service
sudo systemctl restart uidaaas

# Restart all services
sudo systemctl restart kgaas uidaaas dmiuaas lacryptaas

# Stop all services
sudo systemctl stop kgaas uidaaas dmiuaas lacryptaas

# Start all services
sudo systemctl start kgaas uidaaas dmiuaas lacryptaas
```

---

## 🎉 You Did It!

Congratulations! You now have a complete three-tier authentication system running on AWS!

### Your Services Are At:

- **UIDAaaS:** `http://YOUR_IP:5000` (User authentication)
- **DMIUAaas:** `http://YOUR_IP:6000` (Image challenges)
- **KGaaS:** `http://YOUR_IP:8001` (Key management)
- **Lacryptaas:** `http://YOUR_IP:8002` (Encryption)

### What You Learned:

✅ How to create an AWS EC2 instance  
✅ How to connect via SSH  
✅ How to deploy Python applications  
✅ How to manage Linux services  
✅ How to configure a firewall  
✅ How to read logs and debug  

---

## 📚 Next Steps

1. **Build a frontend** to interact with these services
2. **Add a database** (AWS RDS) for production
3. **Set up CI/CD** with GitHub Actions
4. **Add monitoring** with AWS CloudWatch
5. **Scale up** with load balancers
6. **Secure it** with HTTPS and proper authentication

---

## 🆘 Need Help?

**Check logs first:**
```bash
sudo journalctl -u SERVICE_NAME -n 100
```

**Common commands:**
```bash
# Check status
sudo systemctl status SERVICE_NAME

# Restart
sudo systemctl restart SERVICE_NAME

# View config
cat ~/three-tier-auth-services/.env

# Test connectivity
curl http://localhost:5000/ping
```

**Still stuck?**
- Check AWS Security Groups
- Verify services are running
- Look at logs for error messages
- Make sure .env file has correct values

---

## 🎯 Quick Reference Card

```bash
# Connect to server
ssh -i auth-services-key.pem ubuntu@YOUR_IP

# Check all services
sudo systemctl status kgaas uidaaas dmiuaas lacryptaas

# Restart all services
./deploy/stop_all_services.sh
./deploy/start_all_services.sh

# View logs
sudo journalctl -u uidaaas -f

# Test services
./deploy/test_all_services.sh

# Stop instance to save money
# (Do this from AWS Console)
```

**Save this guide!** You'll need it for managing your deployment.

---

**Happy deploying! 🚀**
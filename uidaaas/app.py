# uidaaas/app.py - UIDAaaS with LACryptaaS Integration
import os
import base64
import json
import hmac
import hashlib
import secrets
import smtplib
import time
import re
from email.message import EmailMessage
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import requests

app = Flask(__name__)
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "uidaaas.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Service URLs
KGAAS_URL = os.environ.get("KG_AAS_URL", "http://localhost:8001")
KGAAS_API_KEY = os.environ.get("KG_AAS_APIKEY", "uidaas-secret-token")
LACRYPTAAS_URL = os.environ.get("LACRYPTAAS_URL", "http://localhost:8002")

class RequestAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), nullable=False, index=True)
    username = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(50), default="pending")
    note = db.Column(db.Text, nullable=True)

class OTPToken(db.Model):
    token = db.Column(db.String(128), primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("request_access.id"), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    
    # Encrypted email storage
    email_ciphertext = db.Column(db.Text, nullable=False)
    email_nonce = db.Column(db.Text, nullable=False)
    email_tag = db.Column(db.Text, nullable=False)
    email_key_id = db.Column(db.String(128), nullable=False)
    
    password_hash = db.Column(db.LargeBinary, nullable=False)
    previous_hashes_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    request_id = db.Column(db.Integer, db.ForeignKey('request_access.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Encrypted metadata storage
    metadata_ciphertext = db.Column(db.Text, nullable=True)
    metadata_nonce = db.Column(db.Text, nullable=True)
    metadata_tag = db.Column(db.Text, nullable=True)
    metadata_key_id = db.Column(db.String(128), nullable=True)

    def get_previous_hashes(self):
        if not self.previous_hashes_json:
            return []
        return json.loads(self.previous_hashes_json)

    def push_previous_hash(self, h: bytes):
        arr = self.get_previous_hashes()
        arr.insert(0, base64.b64encode(h).decode('ascii'))
        arr = arr[:3]
        self.previous_hashes_json = json.dumps(arr)

    def previous_hashes_bytes(self):
        return [base64.b64decode(s) for s in self.get_previous_hashes()]

class UsedNonce(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(256), nullable=False, index=True)
    username = db.Column(db.String(150), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

PASSWORD_POLICY_MIN_LEN = 10
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 900))
NONCE_WINDOW = int(os.environ.get("AUTH_NONCE_WINDOW_SECONDS", 120))

# ============================================================================
# LACRYPTAAS & KGAAS INTEGRATION FUNCTIONS
# ============================================================================

def create_encryption_key():
    """Create a new encryption key via KGaaS"""
    try:
        response = requests.post(
            f"{KGAAS_URL}/v1/keys",
            headers={"X-Api-Key": KGAAS_API_KEY},
            json={"allowed_services": ["uidaaas", "lacryptaas"]},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        print(f"✓ Created encryption key: {data['key_id']}")
        return data['key_id']
    except Exception as e:
        print(f"✗ Failed to create key in KGaaS: {e}")
        raise RuntimeError(f"Key creation failed: {e}")

def encrypt_data(plaintext: str, key_id: str = None):
    """Encrypt data using LACryptaaS with GCM mode"""
    try:
        payload = {
            "plaintext": plaintext,
            "mode": "gcm"
        }
        if key_id:
            payload["key_id"] = key_id
        
        response = requests.post(
            f"{LACRYPTAAS_URL}/encrypt",
            json=payload,
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "ciphertext": data["ciphertext_b64"],
            "nonce": data["nonce_b64"],
            "tag": data["tag_b64"],
            "key_id": data["key_id"]
        }
    except Exception as e:
        print(f"✗ Encryption failed: {e}")
        raise RuntimeError(f"Encryption failed: {e}")

def decrypt_data(ciphertext: str, nonce: str, tag: str, key_id: str):
    """Decrypt data using LACryptaaS with GCM mode"""
    try:
        response = requests.post(
            f"{LACRYPTAAS_URL}/decrypt",
            json={
                "key_id": key_id,
                "ciphertext_b64": ciphertext,
                "nonce_b64": nonce,
                "tag_b64": tag,
                "mode": "gcm"
            },
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        return data["plaintext"]
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        raise RuntimeError(f"Decryption failed: {e}")

def get_user_email(user):
    """Decrypt and return user's email"""
    try:
        return decrypt_data(
            user.email_ciphertext,
            user.email_nonce,
            user.email_tag,
            user.email_key_id
        )
    except Exception as e:
        print(f"✗ Failed to decrypt email for user {user.username}: {e}")
        return None

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def is_valid_email(email: str) -> bool:
    """Validate email format"""
    if not email or len(email) > 254:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_policy(password: str):
    if len(password) < PASSWORD_POLICY_MIN_LEN:
        return False, f"Password must be at least {PASSWORD_POLICY_MIN_LEN} characters"
    if not any(c.islower() for c in password):
        return False, "Password must contain a lowercase letter"
    if not any(c.isupper() for c in password):
        return False, "Password must contain an uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain a digit"
    special = set("!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~")
    if not any(c in special for c in password):
        return False, "Password must contain at least one special character"
    return True, None

def bcrypt_hash(plain: str) -> bytes:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt())

def bcrypt_check(plain: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed)

def send_otp_email(to_email: str, token: str):
    smtp_host = os.environ.get("SMTP_HOST")
    from_addr = os.environ.get("FROM_EMAIL", "no-reply@authaas.local")
    if not smtp_host:
        print(f"\n{'='*60}")
        print(f"📧 OTP EMAIL NOTIFICATION")
        print(f"{'='*60}")
        print(f"To: {to_email}")
        print(f"Subject: Verify Your Email - Authentication as a Service")
        print(f"\nYour OTP Token: {token}")
        print(f"\nThis token will expire in {OTP_TTL_SECONDS//60} minutes.")
        print(f"{'='*60}\n")
        return True
    try:
        smtp_port = int(os.environ.get("SMTP_PORT", 587))
        smtp_user = os.environ.get("SMTP_USER")
        smtp_pass = os.environ.get("SMTP_PASS")
        msg = EmailMessage()
        msg["Subject"] = "Verify Your Email - Authentication as a Service"
        msg["From"] = from_addr
        msg["To"] = to_email
        body = f"""
Hello,

Welcome to Authentication as a Service!

Your email verification token is: {token}

This token will expire in {OTP_TTL_SECONDS//60} minutes.

Please use this token to complete your registration.

Best regards,
Authentication as a Service Team
        """
        msg.set_content(body)
        s = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        s.starttls()
        if smtp_user and smtp_pass:
            s.login(smtp_user, smtp_pass)
        s.send_message(msg)
        s.quit()
        return True
    except Exception as e:
        print("[EMAIL SEND FAILED]", e)
        return False

def _get_kgaas_key_for_user(user_identifier: str) -> bytes:
    kgaas_url = os.environ.get("KG_AAS_URL")
    api_key = os.environ.get("KG_AAS_APIKEY")
    if kgaas_url:
        try:
            resp = requests.get(kgaas_url + "/v1/keys", params={"user": user_identifier}, timeout=5,
                                headers={"Authorization": f"Bearer {api_key}"} if api_key else {})
            resp.raise_for_status()
            b64 = resp.json().get("key") or resp.json().get("key_material_b64")
            return base64.b64decode(b64)
        except Exception as e:
            print("[KG_AAS_CALL_FAILED]", e)
    dev = os.environ.get("DEV_KG_KEY")
    if dev:
        try:
            return base64.b64decode(dev)
        except Exception:
            return bytes.fromhex(dev)
    raise RuntimeError("No KG key available")

def akg_derive_auth_key(user_identifier: str, nonce_with_ts: str) -> str:
    kg_key = _get_kgaas_key_for_user(user_identifier)
    msg = (f"{user_identifier}|{nonce_with_ts}").encode("utf-8")
    mac = hmac.new(kg_key, msg, digestmod=hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")

def _parse_nonce_ts(nonce_with_ts: str):
    try:
        ts_str, nonce = nonce_with_ts.split("|", 1)
        return int(ts_str), nonce
    except Exception:
        return None, None

def is_nonce_replayed(username: str, nonce: str) -> bool:
    return UsedNonce.query.filter_by(username=username, nonce=nonce).first() is not None

def mark_nonce_used(username: str, nonce: str):
    u = UsedNonce(username=username, nonce=nonce)
    db.session.add(u)
    db.session.commit()

def auth_v_verify(username: str, presented_auth_key_b64: str, nonce_with_ts: str):
    ts, nonce = _parse_nonce_ts(nonce_with_ts)
    if ts is None or nonce is None:
        return False, "invalid nonce format"
    now = int(time.time())
    if abs(now - ts) > NONCE_WINDOW:
        return False, "nonce timestamp outside allowed window"
    if is_nonce_replayed(username, nonce):
        return False, "nonce already used (replay)"
    try:
        expected = akg_derive_auth_key(username, nonce_with_ts)
    except Exception as e:
        return False, "akg failure: " + str(e)
    if not hmac.compare_digest(expected, presented_auth_key_b64):
        return False, "auth key mismatch"
    mark_nonce_used(username, nonce)
    return True, "ok"

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"message": "pong", "service": "uidaaas"}), 200

@app.route("/request_access", methods=["POST"])
def request_access():
    data = request.json or {}
    email = data.get("email")
    username = data.get("username")
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    # Validate email format
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format. Please enter a valid email address"}), 400
    
    # Check for duplicate pending requests
    existing_request = RequestAccess.query.filter_by(email=email, processed=False).first()
    if existing_request:
        return jsonify({
            "error": "A pending registration request already exists for this email",
            "request_id": existing_request.id,
            "status": "pending"
        }), 409
    
    # Check if email is already registered (need to check encrypted emails)
    all_users = User.query.all()
    for user in all_users:
        try:
            user_email = get_user_email(user)
            if user_email and user_email.lower() == email.lower():
                return jsonify({
                    "error": "This email is already registered",
                    "suggestion": "Please login with your existing account or use a different email"
                }), 409
        except:
            continue
    
    # Check username uniqueness if provided
    if username:
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            return jsonify({
                "error": f"Username '{username}' is already taken",
                "suggestion": "Please choose a different username"
            }), 409
    
    r = RequestAccess(email=email, username=username)
    db.session.add(r)
    db.session.commit()
    return jsonify({
        "message": "Registration request created successfully",
        "request_id": r.id,
        "email": email
    }), 201

@app.route("/create_user_from_request", methods=["POST"])
def create_user_from_request():
    data = request.json or {}
    rid = data.get("request_id")
    if not rid:
        return jsonify({"error": "request_id required"}), 400
    req = RequestAccess.query.get(rid)
    if not req:
        return jsonify({"error": "Registration request not found"}), 404
    if req.processed:
        return jsonify({"error": "This registration request has already been processed"}), 400
    
    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    expires_at = datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)
    otp = OTPToken(token=token, request_id=req.id, expires_at=expires_at)
    db.session.add(otp)
    req.processed = True
    req.status = "otp_sent"
    db.session.commit()
    sent = send_otp_email(req.email, token)
    return jsonify({
        "message": "OTP sent successfully" if sent else "OTP generated (email sending failed)",
        "email_sent": sent,
        "token": token,
        "expires_in_seconds": OTP_TTL_SECONDS,
        "warning": None if sent else "Email delivery failed - check console for OTP"
    }), 201

@app.route("/finalize_registration", methods=["POST"])
def finalize_registration():
    data = request.json or {}
    token = data.get("token")
    password = data.get("password")
    username_override = data.get("username")
    if not token or not password:
        return jsonify({"error": "Token and password are required"}), 400
    
    otp = OTPToken.query.get(token)
    if not otp:
        return jsonify({"error": "Invalid token. Please check your token and try again"}), 400
    if otp.used:
        return jsonify({"error": "This token has already been used"}), 400
    if otp.expires_at < datetime.utcnow():
        return jsonify({"error": "Token has expired. Please request a new one"}), 400
    
    req = RequestAccess.query.get(otp.request_id)
    
    # Check if email is already registered (double-check with encrypted emails)
    all_users = User.query.all()
    for user in all_users:
        try:
            user_email = get_user_email(user)
            if user_email and user_email.lower() == req.email.lower():
                return jsonify({
                    "error": "This email is already registered",
                    "suggestion": "Please login with your existing account"
                }), 409
        except:
            continue
    
    username = username_override or (req.username or req.email.split("@")[0])
    
    # Check username uniqueness
    existing_username = User.query.filter_by(username=username).first()
    if existing_username:
        base_username = username
        for i in range(1, 100):
            alt_username = f"{base_username}{i}"
            if not User.query.filter_by(username=alt_username).first():
                username = alt_username
                break
        else:
            return jsonify({"error": "Unable to generate unique username. Please specify a custom username"}), 400
    
    ok, msg = validate_password_policy(password)
    if not ok:
        return jsonify({"error": msg}), 400
    
    # Encrypt email using LACryptaaS
    try:
        print(f"🔐 Encrypting email for user: {username}")
        encrypted_email = encrypt_data(req.email)
        print(f"✓ Email encrypted with key: {encrypted_email['key_id']}")
    except Exception as e:
        return jsonify({"error": f"Failed to encrypt user data: {str(e)}"}), 500
    
    h = bcrypt_hash(password)
    user = User(
        username=username,
        email_ciphertext=encrypted_email['ciphertext'],
        email_nonce=encrypted_email['nonce'],
        email_tag=encrypted_email['tag'],
        email_key_id=encrypted_email['key_id'],
        password_hash=h,
        previous_hashes_json=json.dumps([]),
        request_id=req.id
    )
    db.session.add(user)
    otp.used = True
    req.status = "approved"
    db.session.commit()
    
    return jsonify({
        "message": "Registration completed successfully",
        "username": username,
        "email": req.email,
        "encryption_key_id": encrypted_email['key_id']
    }), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    want_server_authkey = bool(data.get("want_server_authkey", False))
    nonce_with_ts = data.get("nonce_with_ts", "")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401
    
    if not user.is_active:
        return jsonify({"error": "Account is inactive. Please contact support"}), 403
    
    if not bcrypt_check(password, user.password_hash):
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Decrypt email for response
    try:
        decrypted_email = get_user_email(user)
    except:
        decrypted_email = None
    
    resp = {
        "message": "Login successful",
        "username": username,
        "email": decrypted_email
    }
    if want_server_authkey:
        if not nonce_with_ts:
            return jsonify({"error": "nonce_with_ts required"}), 400
        try:
            resp["auth_key"] = akg_derive_auth_key(username, nonce_with_ts)
        except Exception as e:
            resp["auth_key_error"] = str(e)
    return jsonify(resp), 200

@app.route("/auth_verify", methods=["POST"])
def auth_verify():
    data = request.json or {}
    username = data.get("username")
    presented = data.get("presented_auth_key")
    nonce_with_ts = data.get("nonce_with_ts")
    if not username or not presented or not nonce_with_ts:
        return jsonify({"error": "username, presented_auth_key, nonce_with_ts required"}), 400
    ok, reason = auth_v_verify(username, presented, nonce_with_ts)
    return jsonify({"success": ok, "reason": reason}), 200

@app.route("/change_password", methods=["POST"])
def change_password():
    data = request.json or {}
    username = data.get("username")
    old = data.get("old_password")
    new = data.get("new_password")
    if not username or not old or not new:
        return jsonify({"error": "username, old_password, new_password required"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt_check(old, user.password_hash):
        return jsonify({"error": "Invalid credentials"}), 403
    ok, msg = validate_password_policy(new)
    if not ok:
        return jsonify({"error": msg}), 400
    for ph in user.previous_hashes_bytes():
        if bcrypt_check(new, ph):
            return jsonify({"error": "New password must not match any of last 3 passwords"}), 400
    if bcrypt_check(new, user.password_hash):
        return jsonify({"error": "New password must not match current password"}), 400
    user.push_previous_hash(user.password_hash)
    user.password_hash = bcrypt_hash(new)
    db.session.commit()
    return jsonify({"message": "Password changed successfully"}), 200

@app.route("/list_users", methods=["GET"])
def list_users():
    users = User.query.all()
    out = []
    for u in users:
        try:
            email = get_user_email(u)
        except:
            email = "[encrypted]"
        out.append({
            "username": u.username,
            "email": email,
            "created_at": u.created_at.isoformat(),
            "is_active": u.is_active,
            "encryption_key_id": u.email_key_id
        })
    return jsonify(out), 200

@app.route("/check_availability", methods=["POST"])
def check_availability():
    """Check if username or email is available"""
    data = request.json or {}
    username = data.get("username")
    email = data.get("email")
    
    result = {}
    
    if username:
        existing = User.query.filter_by(username=username).first()
        result["username_available"] = existing is None
        if existing:
            result["username_message"] = "Username is already taken"
    
    if email:
        if not is_valid_email(email):
            result["email_valid"] = False
            result["email_message"] = "Invalid email format"
        else:
            result["email_valid"] = True
            # Check encrypted emails
            all_users = User.query.all()
            email_exists = False
            for user in all_users:
                try:
                    user_email = get_user_email(user)
                    if user_email and user_email.lower() == email.lower():
                        email_exists = True
                        break
                except:
                    continue
            result["email_available"] = not email_exists
            if email_exists:
                result["email_message"] = "Email is already registered"
    
    return jsonify(result), 200

@app.route("/get_user_info", methods=["GET"])
def get_user_info():
    """Get decrypted user information"""
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username parameter required"}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    try:
        decrypted_email = get_user_email(user)
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt email: {str(e)}"}), 500
    
    return jsonify({
        "username": user.username,
        "email": decrypted_email,
        "created_at": user.created_at.isoformat(),
        "is_active": user.is_active,
        "encryption_key_id": user.email_key_id
    }), 200

@app.route("/reject_request", methods=["POST"])
def reject_request():
    data = request.json or {}
    rid = data.get("request_id")
    note = data.get("note", "")
    req = RequestAccess.query.get(rid)
    if not req:
        return jsonify({"error": "no such request"}), 404
    req.processed = True
    req.status = "rejected"
    req.note = note
    db.session.commit()
    return jsonify({"message": "request rejected"}), 200

@app.route("/prune_old_nonces", methods=["POST"])
def prune_old_nonces():
    cutoff = datetime.utcnow() - timedelta(seconds=NONCE_WINDOW * 5)
    deleted = UsedNonce.query.filter(UsedNonce.created_at < cutoff).delete()
    db.session.commit()
    return jsonify({"deleted": deleted}), 200

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print("=" * 60)
    print("🔐 UIDAaaS - Authentication as a Service")
    print("=" * 60)
    print(f"Starting on port 5000...")
    print(f"KGaaS: {KGAAS_URL}")
    print(f"LACryptaaS: {LACRYPTAAS_URL}")
    print(f"OTP TTL: {OTP_TTL_SECONDS} seconds")
    print("🔒 User data encryption: ENABLED via LACryptaaS")
    print("=" * 60)
    app.run(port=5000, debug=True)
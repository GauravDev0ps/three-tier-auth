# uidaaas/app.py - UIDAaaS prototype (demo only)
import os
import base64
import json
import hmac
import hashlib
import secrets
import smtplib
import time
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

class RequestAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), nullable=False)
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
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(254), nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    previous_hashes_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    request_id = db.Column(db.Integer, db.ForeignKey('request_access.id'), nullable=True)

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
    from_addr = os.environ.get("FROM_EMAIL", "no-reply@uidaaas.local")
    if not smtp_host:
        print(f"[OTP EMAIL] To: {to_email}\nToken: {token}\nUse /finalize_registration to POST token and set password.")
        return True
    try:
        smtp_port = int(os.environ.get("SMTP_PORT", 587))
        smtp_user = os.environ.get("SMTP_USER")
        smtp_pass = os.environ.get("SMTP_PASS")
        msg = EmailMessage()
        msg["Subject"] = "UIDAaaS: finalize your registration"
        msg["From"] = from_addr
        msg["To"] = to_email
        body = f"Hello,\n\nToken: {token}\n\nPOST this to /finalize_registration.\n"
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

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"message": "pong"}), 200

@app.route("/request_access", methods=["POST"])
def request_access():
    data = request.json or {}
    email = data.get("email")
    username = data.get("username")
    if not email:
        return jsonify({"error": "email required"}), 400
    r = RequestAccess(email=email, username=username)
    db.session.add(r)
    db.session.commit()
    return jsonify({"message": "request created", "request_id": r.id}), 201

@app.route("/create_user_from_request", methods=["POST"])
def create_user_from_request():
    data = request.json or {}
    rid = data.get("request_id")
    if not rid:
        return jsonify({"error": "request_id required"}), 400
    req = RequestAccess.query.get(rid)
    if not req or req.processed:
        return jsonify({"error": "invalid or already processed request"}), 400
    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    expires_at = datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)
    otp = OTPToken(token=token, request_id=req.id, expires_at=expires_at)
    db.session.add(otp)
    req.processed = True
    req.status = "otp_sent"
    db.session.commit()
    sent = send_otp_email(req.email, token)
    return jsonify({
        "message": "otp created",
        "email_sent": sent,
        "token": token,
        "warning": None if sent else "email sending failed"
    }), 201

@app.route("/finalize_registration", methods=["POST"])
def finalize_registration():
    data = request.json or {}
    token = data.get("token")
    password = data.get("password")
    username_override = data.get("username")
    if not token or not password:
        return jsonify({"error": "token and password required"}), 400
    otp = OTPToken.query.get(token)
    if not otp or otp.used or otp.expires_at < datetime.utcnow():
        return jsonify({"error": "invalid or expired token"}), 400
    req = RequestAccess.query.get(otp.request_id)
    username = username_override or (req.username or req.email.split("@")[0])
    if User.query.filter_by(username=username).first():
        username = f"{username}{secrets.randbelow(9999)}"
    ok, msg = validate_password_policy(password)
    if not ok:
        return jsonify({"error": msg}), 400
    h = bcrypt_hash(password)
    user = User(username=username, email=req.email, password_hash=h, previous_hashes_json=json.dumps([]), request_id=req.id)
    db.session.add(user)
    otp.used = True
    req.status = "approved"
    db.session.commit()
    return jsonify({"message": "user created", "username": username}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    want_server_authkey = bool(data.get("want_server_authkey", False))
    nonce_with_ts = data.get("nonce_with_ts", "")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt_check(password, user.password_hash):
        return jsonify({"error": "invalid credentials"}), 401
    resp = {"message": "login successful"}
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
        return jsonify({"error": "invalid credentials"}), 403
    ok, msg = validate_password_policy(new)
    if not ok:
        return jsonify({"error": msg}), 400
    for ph in user.previous_hashes_bytes():
        if bcrypt_check(new, ph):
            return jsonify({"error": "new password must not match any of last 3 passwords"}), 400
    if bcrypt_check(new, user.password_hash):
        return jsonify({"error": "new password must not match current password"}), 400
    user.push_previous_hash(user.password_hash)
    user.password_hash = bcrypt_hash(new)
    db.session.commit()
    return jsonify({"message": "password changed"}), 200

@app.route("/list_users", methods=["GET"])
def list_users():
    users = User.query.all()
    out = [{"username": u.username, "email": u.email, "created_at": u.created_at.isoformat()} for u in users]
    return jsonify(out), 200

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
    app.run(port=5000, debug=True)

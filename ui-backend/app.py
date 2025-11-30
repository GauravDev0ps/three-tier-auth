# ui-backend/app.py - UI Backend Integration Service Enhanced
import os
import json
import requests
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

app = Flask(__name__, static_folder='../frontend')
CORS(app)

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "ui_sessions.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Service URLs
UIDAAAS_URL = os.environ.get("UIDAAAS_URL", "http://localhost:5000")
DMIUAAS_URL = os.environ.get("DMIUAAS_URL", "http://localhost:6000")
KGAAS_URL = os.environ.get("KGAAS_URL", "http://localhost:8001")
LACRYPTAAS_URL = os.environ.get("LACRYPTAAS_URL", "http://localhost:8002")

# Database Models
class UserSession(db.Model):
    """Track user sessions and authentication flow"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, index=True)
    session_id = db.Column(db.String(128), unique=True, nullable=False, index=True)
    password_verified = db.Column(db.Boolean, default=False)
    pattern_verified = db.Column(db.Boolean, default=False)
    fully_authenticated = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

class AuthenticationLog(db.Model):
    """Log all authentication attempts"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, index=True)
    action = db.Column(db.String(50), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    service = db.Column(db.String(50), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class UserProfile(db.Model):
    """Extended user profile information"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    login_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    metadata_json = db.Column(db.Text, nullable=True)

# Helper Functions
def log_auth_attempt(username, action, success, service=None, details=None):
    """Log authentication attempt to database"""
    log_entry = AuthenticationLog(
        username=username,
        action=action,
        success=success,
        service=service,
        ip_address=request.remote_addr,
        details=json.dumps(details) if details else None
    )
    db.session.add(log_entry)
    db.session.commit()

def call_service(service_url, endpoint, method='GET', data=None):
    """Make API call to backend services"""
    url = f"{service_url}{endpoint}"
    
    try:
        if method == 'POST':
            response = requests.post(url, json=data, timeout=10)
        elif method == 'GET':
            response = requests.get(url, params=data, timeout=10)
        else:
            response = requests.request(method, url, json=data, timeout=10)
        
        return response.json(), response.status_code
    
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}, 500

# Serve Frontend
@app.route('/')
def serve_frontend():
    """Serve the main HTML page"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    services_status = {}
    
    for name, url in [
        ('uidaaas', UIDAAAS_URL),
        ('dmiuaas', DMIUAAS_URL),
        ('kgaas', KGAAS_URL),
        ('lacryptaas', LACRYPTAAS_URL)
    ]:
        try:
            response = requests.get(f"{url}/ping", timeout=3)
            services_status[name] = response.status_code == 200
        except:
            services_status[name] = False
    
    all_healthy = all(services_status.values())
    
    return jsonify({
        "status": "healthy" if all_healthy else "degraded",
        "services": services_status,
        "timestamp": datetime.utcnow().isoformat()
    }), 200 if all_healthy else 503

# REGISTRATION FLOW
@app.route('/api/register', methods=['POST'])
def register():
    """Complete registration flow with email verification"""
    data = request.json or {}
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    
    if not email or not username or not password:
        return jsonify({"error": "Email, username, and password are required"}), 400
    
    try:
        # Check if email/username already exists in our profiles first
        existing_profile_email = UserProfile.query.filter_by(email=email).first()
        if existing_profile_email:
            log_auth_attempt(username, 'registration', False, 'ui-backend', 
                           {"reason": "email_exists"})
            return jsonify({
                "error": "This email is already registered",
                "suggestion": "Please login with your existing account or use a different email"
            }), 409
        
        existing_profile_username = UserProfile.query.filter_by(username=username).first()
        if existing_profile_username:
            log_auth_attempt(username, 'registration', False, 'ui-backend', 
                           {"reason": "username_exists"})
            return jsonify({
                "error": f"Username '{username}' is already taken",
                "suggestion": "Please choose a different username"
            }), 409
        
        # Step 1: Request access (with email validation)
        result1, status1 = call_service(UIDAAAS_URL, '/request_access', 'POST', {
            'email': email,
            'username': username
        })
        
        if status1 != 201:
            log_auth_attempt(username, 'registration', False, 'uidaaas', result1)
            return jsonify(result1), status1
        
        request_id = result1['request_id']
        
        # Step 2: Create OTP and send email
        result2, status2 = call_service(UIDAAAS_URL, '/create_user_from_request', 'POST', {
            'request_id': request_id
        })
        
        if status2 != 201:
            log_auth_attempt(username, 'registration', False, 'uidaaas', result2)
            return jsonify(result2), status2
        
        token = result2['token']
        
        # Step 3: Finalize registration
        result3, status3 = call_service(UIDAAAS_URL, '/finalize_registration', 'POST', {
            'token': token,
            'password': password,
            'username': username
        })
        
        if status3 != 201:
            log_auth_attempt(username, 'registration', False, 'uidaaas', result3)
            return jsonify(result3), status3
        
        # Create user profile
        profile = UserProfile(
            username=result3['username'],
            email=email
        )
        db.session.add(profile)
        db.session.commit()
        
        log_auth_attempt(username, 'registration', True, 'uidaaas', result3)
        
        return jsonify({
            "success": True,
            "message": "Registration completed successfully!",
            "username": result3['username'],
            "email": email,
            "next_step": "pattern_setup"
        }), 201
    
    except Exception as e:
        log_auth_attempt(username or 'unknown', 'registration', False, 'ui-backend', 
                        {"error": str(e)})
        return jsonify({
            "error": "Registration failed due to an internal error",
            "details": str(e)
        }), 500

@app.route('/api/check-availability', methods=['POST'])
def check_availability():
    """Check if username or email is available"""
    data = request.json or {}
    username = data.get('username')
    email = data.get('email')
    
    result = {}
    
    if username:
        existing = UserProfile.query.filter_by(username=username).first()
        result['username_available'] = existing is None
        if existing:
            result['username_message'] = f"Username '{username}' is already taken"
    
    if email:
        existing = UserProfile.query.filter_by(email=email).first()
        result['email_available'] = existing is None
        if existing:
            result['email_message'] = "This email is already registered"
    
    return jsonify(result), 200

@app.route('/api/pattern/setup', methods=['POST'])
def setup_pattern():
    """Register user's image pattern"""
    data = request.json or {}
    username = data.get('username')
    pattern = data.get('pattern')
    
    if not username or not pattern:
        return jsonify({"error": "Username and pattern are required"}), 400
    
    try:
        result, status = call_service(DMIUAAS_URL, '/register_user_secret', 'POST', {
            'username': username,
            'pattern': pattern
        })
        
        success = status == 201
        log_auth_attempt(username, 'pattern_setup', success, 'dmiuaas', result)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Pattern registered successfully!",
                "username": username
            }), 201
        else:
            return jsonify(result), status
    
    except Exception as e:
        log_auth_attempt(username, 'pattern_setup', False, 'ui-backend', 
                        {"error": str(e)})
        return jsonify({"error": str(e)}), 500

# LOGIN FLOW
@app.route('/api/login', methods=['POST'])
def login():
    """Step 1: Password authentication"""
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    try:
        # Authenticate password
        result, status = call_service(UIDAAAS_URL, '/login', 'POST', {
            'username': username,
            'password': password
        })
        
        success = status == 200
        log_auth_attempt(username, 'login_password', success, 'uidaaas', result)
        
        if not success:
            return jsonify(result), status
        
        # Create session
        import secrets
        session_id = secrets.token_urlsafe(32)
        
        session = UserSession(
            username=username,
            session_id=session_id,
            password_verified=True,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(session)
        
        # Update user profile
        profile = UserProfile.query.filter_by(username=username).first()
        if profile:
            profile.last_login = datetime.utcnow()
            profile.login_count += 1
        
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Password verified successfully",
            "session_id": session_id,
            "next_step": "pattern_verification",
            "username": username
        }), 200
    
    except Exception as e:
        log_auth_attempt(username or 'unknown', 'login_password', False, 
                        'ui-backend', {"error": str(e)})
        return jsonify({"error": str(e)}), 500

@app.route('/api/pattern/challenge', methods=['POST'])
def init_pattern_challenge():
    """Step 2: Initialize pattern challenge"""
    data = request.json or {}
    username = data.get('username')
    session_id = data.get('session_id')
    
    if not username or not session_id:
        return jsonify({"error": "Username and session_id required"}), 400
    
    # Verify session
    session = UserSession.query.filter_by(
        session_id=session_id,
        username=username,
        password_verified=True
    ).first()
    
    if not session:
        return jsonify({"error": "Invalid session"}), 401
    
    try:
        result, status = call_service(DMIUAAS_URL, '/init_image_challenge', 'POST', {
            'username': username
        })
        
        if status == 201:
            return jsonify({
                "success": True,
                "message": "Challenge created",
                "challenge_token": result['token'],
                "grid": result['grid'],
                "grid_size": result.get('grid_size'),
                "expires_at": result['expires_at'],
                "instructions": result.get('instructions')
            }), 201
        else:
            return jsonify(result), status
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/pattern/verify', methods=['POST'])
def verify_pattern():
    """Step 3: Verify pattern and complete authentication"""
    data = request.json or {}
    username = data.get('username')
    session_id = data.get('session_id')
    challenge_token = data.get('challenge_token')
    selected_positions = data.get('selected_positions')
    
    if not all([username, session_id, challenge_token, selected_positions]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Verify session
    session = UserSession.query.filter_by(
        session_id=session_id,
        username=username,
        password_verified=True
    ).first()
    
    if not session:
        return jsonify({"error": "Invalid session"}), 401
    
    try:
        result, status = call_service(DMIUAAS_URL, '/verify_image_challenge', 'POST', {
            'token': challenge_token,
            'selected_positions': selected_positions
        })
        
        success = result.get('success', False)
        log_auth_attempt(username, 'pattern_verification', success, 'dmiuaas', result)
        
        if success:
            # Update session
            session.pattern_verified = True
            session.fully_authenticated = True
            session.last_activity = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                "success": True,
                "message": "Authentication completed successfully!",
                "session_id": session_id,
                "username": username
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": result.get('message', 'Pattern verification failed'),
                "attempts_remaining": result.get('attempts_remaining', 0)
            }), 401
    
    except Exception as e:
        log_auth_attempt(username, 'pattern_verification', False, 
                        'ui-backend', {"error": str(e)})
        return jsonify({"error": str(e)}), 500

# SESSION & PROFILE MANAGEMENT
@app.route('/api/session/<session_id>', methods=['GET'])
def get_session(session_id):
    """Get session information"""
    session = UserSession.query.filter_by(session_id=session_id).first()
    
    if not session:
        return jsonify({"error": "Session not found"}), 404
    
    return jsonify({
        "username": session.username,
        "password_verified": session.password_verified,
        "pattern_verified": session.pattern_verified,
        "fully_authenticated": session.fully_authenticated,
        "created_at": session.created_at.isoformat(),
        "last_activity": session.last_activity.isoformat()
    }), 200

@app.route('/api/session/<session_id>', methods=['DELETE'])
def logout(session_id):
    """Logout - delete session"""
    session = UserSession.query.filter_by(session_id=session_id).first()
    
    if session:
        log_auth_attempt(session.username, 'logout', True, 'ui-backend')
        db.session.delete(session)
        db.session.commit()
    
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/profile/<username>', methods=['GET'])
def get_profile(username):
    """Get user profile"""
    profile = UserProfile.query.filter_by(username=username).first()
    
    if not profile:
        return jsonify({"error": "Profile not found"}), 404
    
    return jsonify({
        "username": profile.username,
        "email": profile.email,
        "full_name": profile.full_name,
        "phone": profile.phone,
        "created_at": profile.created_at.isoformat(),
        "last_login": profile.last_login.isoformat() if profile.last_login else None,
        "login_count": profile.login_count,
        "is_active": profile.is_active
    }), 200

@app.route('/api/profile/<username>', methods=['PUT'])
def update_profile(username):
    """Update user profile"""
    profile = UserProfile.query.filter_by(username=username).first()
    
    if not profile:
        return jsonify({"error": "Profile not found"}), 404
    
    data = request.json or {}
    
    if 'full_name' in data:
        profile.full_name = data['full_name']
    if 'phone' in data:
        profile.phone = data['phone']
    if 'metadata' in data:
        profile.metadata_json = json.dumps(data['metadata'])
    
    db.session.commit()
    
    return jsonify({"message": "Profile updated successfully"}), 200

# ANALYTICS & REPORTING
@app.route('/api/analytics/auth-logs', methods=['GET'])
def get_auth_logs():
    """Get authentication logs"""
    username = request.args.get('username')
    action = request.args.get('action')
    limit = int(request.args.get('limit', 100))
    
    query = AuthenticationLog.query
    
    if username:
        query = query.filter_by(username=username)
    if action:
        query = query.filter_by(action=action)
    
    logs = query.order_by(AuthenticationLog.timestamp.desc()).limit(limit).all()
    
    return jsonify([{
        "id": log.id,
        "username": log.username,
        "action": log.action,
        "success": log.success,
        "service": log.service,
        "ip_address": log.ip_address,
        "timestamp": log.timestamp.isoformat()
    } for log in logs]), 200

@app.route('/api/analytics/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    total_users = UserProfile.query.count()
    active_sessions = UserSession.query.filter_by(fully_authenticated=True).count()
    total_logins = db.session.query(AuthenticationLog).filter_by(
        action='login_password',
        success=True
    ).count()
    
    failed_logins = db.session.query(AuthenticationLog).filter_by(
        action='login_password',
        success=False
    ).count()
    
    return jsonify({
        "total_users": total_users,
        "active_sessions": active_sessions,
        "total_logins": total_logins,
        "failed_logins": failed_logins,
        "success_rate": (total_logins / (total_logins + failed_logins) * 100) if (total_logins + failed_logins) > 0 else 0
    }), 200

# ADMIN ENDPOINTS
@app.route('/api/admin/users', methods=['GET'])
def list_all_users():
    """List all users"""
    users = UserProfile.query.all()
    
    return jsonify([{
        "username": user.username,
        "email": user.email,
        "created_at": user.created_at.isoformat(),
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "login_count": user.login_count,
        "is_active": user.is_active
    } for user in users]), 200

@app.route('/api/admin/sessions', methods=['GET'])
def list_active_sessions():
    """List all active sessions"""
    sessions = UserSession.query.filter_by(fully_authenticated=True).all()
    
    return jsonify([{
        "username": s.username,
        "session_id": s.session_id,
        "created_at": s.created_at.isoformat(),
        "last_activity": s.last_activity.isoformat(),
        "ip_address": s.ip_address
    } for s in sessions]), 200

@app.route('/api/admin/user/<username>/deactivate', methods=['POST'])
def deactivate_user(username):
    """Deactivate a user account"""
    profile = UserProfile.query.filter_by(username=username).first()
    
    if not profile:
        return jsonify({"error": "User not found"}), 404
    
    profile.is_active = False
    
    # Terminate all sessions
    UserSession.query.filter_by(username=username).delete()
    
    db.session.commit()
    
    log_auth_attempt(username, 'deactivate', True, 'ui-backend')
    
    return jsonify({"message": f"User {username} deactivated"}), 200

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    print("=" * 60)
    print("🌐 UI Backend - Authentication as a Service")
    print("=" * 60)
    print(f"Starting on port 3000")
    print(f"UIDAaaS: {UIDAAAS_URL}")
    print(f"DMIUAaas: {DMIUAAS_URL}")
    print(f"KGaaS: {KGAAS_URL}")
    print(f"Lacryptaas: {LACRYPTAAS_URL}")
    print("=" * 60)
    app.run(host='0.0.0.0', port=3000, debug=True)
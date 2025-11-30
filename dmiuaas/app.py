# dmiuaas/app.py - DMIUAaaS with LACryptaaS Integration
import os
import json
import base64
import secrets
import hashlib
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "dmiuaas.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Service URLs
KGAAS_URL = os.environ.get("KG_AAS_URL", "http://localhost:8001")
KGAAS_API_KEY = os.environ.get("KG_AAS_APIKEY", "demo-secret-token")
LACRYPTAAS_URL = os.environ.get("LACRYPTAAS_URL", "http://localhost:8002")

# Configuration
CHALLENGE_TTL_SECONDS = int(os.environ.get("CHALLENGE_TTL_SECONDS", 300))
MAX_ATTEMPTS = int(os.environ.get("CHALLENGE_MAX_ATTEMPTS", 5))
GRID_ROWS = int(os.environ.get("GRID_ROWS", 4))
GRID_COLS = int(os.environ.get("GRID_COLS", 4))

# ============================================================================
# DATABASE MODELS
# ============================================================================

class UserImageSecret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    
    # Encrypted pattern storage using LACryptaaS
    pattern_ciphertext = db.Column(db.Text, nullable=False)
    pattern_nonce = db.Column(db.Text, nullable=False)
    pattern_tag = db.Column(db.Text, nullable=False)
    pattern_key_id = db.Column(db.String(128), nullable=False)
    
    pattern_hash = db.Column(db.String(256), nullable=False)  # For verification
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ImageChallenge(db.Model):
    token = db.Column(db.String(128), primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    grid_layout_json = db.Column(db.Text, nullable=False)
    correct_positions_hash = db.Column(db.String(256), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============================================================================
# LACRYPTAAS & KGAAS INTEGRATION
# ============================================================================

def create_encryption_key():
    """Create a new encryption key via KGaaS"""
    try:
        response = requests.post(
            f"{KGAAS_URL}/v1/keys",
            headers={"X-Api-Key": KGAAS_API_KEY},
            json={"allowed_services": ["dmiuaas", "lacryptaas"]},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        print(f"✓ Created encryption key: {data['key_id']}")
        return data['key_id']
    except Exception as e:
        print(f"✗ Failed to create key in KGaaS: {e}")
        raise RuntimeError(f"Key creation failed: {e}")

def encrypt_pattern(pattern_string: str, key_id: str = None):
    """Encrypt pattern using LACryptaaS with GCM mode"""
    try:
        payload = {
            "plaintext": pattern_string,
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
        print(f"✗ Pattern encryption failed: {e}")
        raise RuntimeError(f"Encryption failed: {e}")

def decrypt_pattern(ciphertext: str, nonce: str, tag: str, key_id: str):
    """Decrypt pattern using LACryptaaS with GCM mode"""
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
        print(f"✗ Pattern decryption failed: {e}")
        raise RuntimeError(f"Decryption failed: {e}")

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def hash_pattern(pattern: str) -> str:
    """Create SHA-256 hash of pattern"""
    return hashlib.sha256(pattern.encode("utf-8")).hexdigest()

def generate_token() -> str:
    """Generate secure random token"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")

def validate_grid_positions(positions: list) -> bool:
    """Validate grid positions format: [(row, col), ...]"""
    if not positions or not isinstance(positions, list):
        return False
    
    for pos in positions:
        if not isinstance(pos, (list, tuple)) or len(pos) != 2:
            return False
        row, col = pos
        if not (0 <= row < GRID_ROWS and 0 <= col < GRID_COLS):
            return False
    
    return True

def positions_to_string(positions: list) -> str:
    """Convert positions list to string: "0,1;2,3;1,2" (sorted)"""
    sorted_positions = sorted(positions)
    return ";".join(f"{r},{c}" for r, c in sorted_positions)

def string_to_positions(pos_string: str) -> list:
    """Convert string back to positions list"""
    if not pos_string:
        return []
    return [tuple(map(int, pos.split(','))) for pos in pos_string.split(';')]

def generate_challenge_grid(username: str):
    """Generate a challenge grid with images randomly distributed"""
    user_secret = UserImageSecret.query.filter_by(username=username).first()
    if not user_secret:
        raise ValueError("User secret not found")
    
    # Decrypt user's secret pattern
    try:
        decrypted_pattern = decrypt_pattern(
            user_secret.pattern_ciphertext,
            user_secret.pattern_nonce,
            user_secret.pattern_tag,
            user_secret.pattern_key_id
        )
        correct_positions = string_to_positions(decrypted_pattern)
        print(f"✓ Decrypted pattern for user {username}")
    except Exception as e:
        print(f"✗ Failed to decrypt pattern for {username}: {e}")
        raise
    
    # Create pool of images
    total_images = 20
    image_pool = [f"img{i:02d}" for i in range(1, total_images + 1)]
    
    # Randomly select images for the grid
    grid_size = GRID_ROWS * GRID_COLS
    selected_images = secrets.SystemRandom().sample(image_pool, grid_size)
    
    # Create 2D grid layout
    grid = []
    img_idx = 0
    for row in range(GRID_ROWS):
        grid_row = []
        for col in range(GRID_COLS):
            grid_row.append({
                "position": [row, col],
                "image": selected_images[img_idx]
            })
            img_idx += 1
        grid.append(grid_row)
    
    return grid, correct_positions

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route("/ping", methods=["GET"])
def ping():
    """Health check"""
    return jsonify({"message": "pong", "service": "dmiuaas"}), 200

@app.route("/register_user_secret", methods=["POST"])
def register_user_secret():
    """Register or update user's secret grid pattern"""
    data = request.json or {}
    username = data.get("username")
    pattern = data.get("pattern")
    
    if not username or not pattern:
        return jsonify({"error": "username and pattern required"}), 400
    
    # Validate pattern format
    if not validate_grid_positions(pattern):
        return jsonify({
            "error": f"Invalid pattern. Must be list of [row, col] positions within {GRID_ROWS}x{GRID_COLS} grid"
        }), 400
    
    # Require at least 3 positions
    if len(pattern) < 3:
        return jsonify({"error": "Pattern must contain at least 3 positions"}), 400
    
    # Require no more than half the grid
    max_positions = (GRID_ROWS * GRID_COLS) // 2
    if len(pattern) > max_positions:
        return jsonify({"error": f"Pattern cannot exceed {max_positions} positions"}), 400
    
    # Convert to string and hash
    pattern_string = positions_to_string(pattern)
    pattern_hash = hash_pattern(pattern_string)
    
    # Encrypt pattern using LACryptaaS
    try:
        print(f"🔐 Encrypting pattern for user: {username}")
        encrypted = encrypt_pattern(pattern_string)
        print(f"✓ Pattern encrypted with key: {encrypted['key_id']}")
    except Exception as e:
        return jsonify({"error": f"Failed to encrypt pattern: {str(e)}"}), 500
    
    # Store or update
    user = UserImageSecret.query.filter_by(username=username).first()
    if user:
        user.pattern_ciphertext = encrypted['ciphertext']
        user.pattern_nonce = encrypted['nonce']
        user.pattern_tag = encrypted['tag']
        user.pattern_key_id = encrypted['key_id']
        user.pattern_hash = pattern_hash
        user.updated_at = datetime.utcnow()
        message = "Pattern updated successfully"
    else:
        user = UserImageSecret(
            username=username,
            pattern_ciphertext=encrypted['ciphertext'],
            pattern_nonce=encrypted['nonce'],
            pattern_tag=encrypted['tag'],
            pattern_key_id=encrypted['key_id'],
            pattern_hash=pattern_hash
        )
        db.session.add(user)
        message = "Pattern registered successfully"
    
    db.session.commit()
    
    return jsonify({
        "message": message,
        "username": username,
        "pattern_length": len(pattern),
        "grid_size": f"{GRID_ROWS}x{GRID_COLS}",
        "encryption_key_id": encrypted['key_id']
    }), 201

@app.route("/init_image_challenge", methods=["POST"])
def init_image_challenge():
    """Initialize an image challenge for a user"""
    data = request.json or {}
    username = data.get("username")
    
    if not username:
        return jsonify({"error": "username required"}), 400
    
    # Check if user has registered pattern
    user = UserImageSecret.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User has no registered pattern"}), 404
    
    try:
        # Generate challenge grid
        grid, correct_positions = generate_challenge_grid(username)
    except Exception as e:
        return jsonify({"error": f"Failed to create challenge: {str(e)}"}), 500
    
    # Create challenge token
    token = generate_token()
    expires_at = datetime.utcnow() + timedelta(seconds=CHALLENGE_TTL_SECONDS)
    
    # Hash the correct positions for verification
    correct_hash = hash_pattern(positions_to_string(correct_positions))
    
    # Store challenge
    challenge = ImageChallenge(
        token=token,
        username=username,
        grid_layout_json=json.dumps(grid),
        correct_positions_hash=correct_hash,
        expires_at=expires_at
    )
    db.session.add(challenge)
    db.session.commit()
    
    return jsonify({
        "message": "Challenge created",
        "token": token,
        "grid": grid,
        "grid_size": {
            "rows": GRID_ROWS,
            "cols": GRID_COLS
        },
        "expires_at": expires_at.isoformat(),
        "instructions": "Select the grid positions matching your secret pattern"
    }), 201

@app.route("/verify_image_challenge", methods=["POST"])
def verify_image_challenge():
    """Verify user's response to image challenge"""
    data = request.json or {}
    token = data.get("token")
    selected_positions = data.get("selected_positions")
    
    if not token or selected_positions is None:
        return jsonify({"error": "token and selected_positions required"}), 400
    
    # Validate positions format
    if not validate_grid_positions(selected_positions):
        return jsonify({"error": "Invalid position format"}), 400
    
    # Get challenge
    challenge = ImageChallenge.query.get(token)
    if not challenge:
        return jsonify({"error": "Invalid or expired token"}), 400
    
    # Check expiration
    if challenge.expires_at < datetime.utcnow():
        return jsonify({
            "success": False,
            "error": "Challenge expired",
            "attempts_remaining": 0
        }), 400
    
    # Check max attempts
    if challenge.attempts >= MAX_ATTEMPTS:
        return jsonify({
            "success": False,
            "error": "Maximum attempts exceeded",
            "attempts_remaining": 0
        }), 403
    
    # Increment attempts
    challenge.attempts += 1
    db.session.commit()
    
    attempts_remaining = MAX_ATTEMPTS - challenge.attempts
    
    # Verify the pattern
    selected_string = positions_to_string(selected_positions)
    selected_hash = hash_pattern(selected_string)
    
    if selected_hash == challenge.correct_positions_hash:
        return jsonify({
            "success": True,
            "message": "Image challenge passed",
            "username": challenge.username,
            "attempts_used": challenge.attempts
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "Incorrect pattern selection",
            "attempts_remaining": attempts_remaining
        }), 401

@app.route("/get_user_pattern_info", methods=["GET"])
def get_user_pattern_info():
    """Get information about a user's registered pattern (without revealing it)"""
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username parameter required"}), 400
    
    user = UserImageSecret.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({
            "username": username,
            "has_pattern": False
        }), 200
    
    # Decrypt to get length but don't reveal positions
    try:
        decrypted = decrypt_pattern(
            user.pattern_ciphertext,
            user.pattern_nonce,
            user.pattern_tag,
            user.pattern_key_id
        )
        positions = string_to_positions(decrypted)
        pattern_length = len(positions)
    except:
        pattern_length = 0
    
    return jsonify({
        "username": username,
        "has_pattern": True,
        "pattern_length": pattern_length,
        "grid_size": f"{GRID_ROWS}x{GRID_COLS}",
        "created_at": user.created_at.isoformat(),
        "updated_at": user.updated_at.isoformat(),
        "encryption_key_id": user.pattern_key_id
    }), 200

@app.route("/list_users", methods=["GET"])
def list_users():
    """List all users with registered patterns"""
    users = UserImageSecret.query.all()
    
    result = []
    for u in users:
        try:
            decrypted = decrypt_pattern(
                u.pattern_ciphertext,
                u.pattern_nonce,
                u.pattern_tag,
                u.pattern_key_id
            )
            positions = string_to_positions(decrypted)
            pattern_length = len(positions)
        except:
            pattern_length = 0
        
        result.append({
            "username": u.username,
            "pattern_length": pattern_length,
            "created_at": u.created_at.isoformat(),
            "encryption_key_id": u.pattern_key_id
        })
    
    return jsonify(result), 200

@app.route("/delete_user_pattern", methods=["DELETE"])
def delete_user_pattern():
    """Delete a user's pattern"""
    data = request.json or {}
    username = data.get("username")
    
    if not username:
        return jsonify({"error": "username required"}), 400
    
    user = UserImageSecret.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({
        "message": "User pattern deleted",
        "username": username
    }), 200

@app.route("/cleanup_expired_challenges", methods=["POST"])
def cleanup_expired_challenges():
    """Remove expired challenges from database"""
    cutoff = datetime.utcnow()
    deleted = ImageChallenge.query.filter(ImageChallenge.expires_at < cutoff).delete()
    db.session.commit()
    
    return jsonify({
        "message": "Cleanup complete",
        "deleted": deleted
    }), 200

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print("=" * 60)
    print("🎨 DMIUAaaS - Image Pattern Authentication Service")
    print("=" * 60)
    print(f"Starting on port 6000")
    print(f"Grid size: {GRID_ROWS}x{GRID_COLS}")
    print(f"KGaaS: {KGAAS_URL}")
    print(f"LACryptaaS: {LACRYPTAAS_URL}")
    print("🔒 Pattern encryption: ENABLED via LACryptaaS")
    print("=" * 60)
    app.run(host='0.0.0.0', port=6000, debug=True)
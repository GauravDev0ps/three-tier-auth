# kgaas/app.py - Enhanced KGaaS with TTL enforcement (demo only)
from flask import Flask, request, jsonify, abort
import uuid
import base64
import os
import time
from functools import wraps
from datetime import datetime

app = Flask(__name__)

# In-memory storage (use database in production)
KEY_STORE = {}
AUDIT_LOG = []

# API key management (move to environment variables or database)
API_KEYS = {
    "demo-client": os.environ.get("DEMO_API_KEY", "demo-secret-token"),
    "lacryptaas": os.environ.get("LACRYPTAAS_API_KEY", "lacrypt-secret-token"),
    "uidaaas": os.environ.get("UIDAAAS_API_KEY", "uidaas-secret-token")
}

def require_api_key(f):
    """Decorator to enforce API key authentication"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Support both X-Api-Key and Authorization Bearer token
        token = request.headers.get("X-Api-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
        
        if not token or token not in API_KEYS.values():
            return jsonify({"error": "Invalid or missing API key"}), 401
        
        # Store caller identity for audit logging
        caller = next((k for k, v in API_KEYS.items() if v == token), "unknown")
        request.caller_id = caller
        
        return f(*args, **kwargs)
    return wrapper

def audit(action, details=None):
    """Log audit event with caller information"""
    caller = getattr(request, 'caller_id', 'unknown')
    AUDIT_LOG.append({
        "ts": time.time(),
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "caller": caller,
        "details": details or {}
    })
    
    # Keep only last 1000 audit entries (for demo)
    if len(AUDIT_LOG) > 1000:
        AUDIT_LOG.pop(0)

def is_key_expired(key_meta):
    """Check if a key has expired based on TTL"""
    ttl = key_meta.get("ttl_seconds")
    if not ttl:
        return False
    
    created_at = key_meta.get("created_at", 0)
    return time.time() > (created_at + ttl)

def cleanup_expired_keys():
    """Remove expired keys from storage"""
    expired_keys = []
    for key_id, meta in KEY_STORE.items():
        if is_key_expired(meta):
            expired_keys.append(key_id)
    
    for key_id in expired_keys:
        del KEY_STORE[key_id]
        audit("auto_delete_expired_key", {"key_id": key_id})
    
    return len(expired_keys)

@app.route("/ping", methods=["GET"])
def ping():
    """Health check endpoint"""
    return jsonify({"message": "pong", "service": "kgaas"}), 200

@app.route("/v1/keys", methods=["POST"])
@require_api_key
def create_key():
    """
    Create a new encryption key
    
    Request body:
    {
        "allowed_services": ["service1", "service2"],  // Optional
        "ttl_seconds": 3600  // Optional
    }
    
    Response:
    {
        "key_id": "uuid",
        "version": 1,
        "created_at": timestamp,
        "key_material_b64": "base64_key"
    }
    """
    payload = request.get_json() or {}
    allowed_services = payload.get("allowed_services", [])
    ttl = payload.get("ttl_seconds")
    
    # Validate TTL if provided
    if ttl is not None:
        try:
            ttl = int(ttl)
            if ttl <= 0:
                return jsonify({"error": "ttl_seconds must be positive"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "ttl_seconds must be an integer"}), 400
    
    # Generate key
    key_bytes = os.urandom(32)  # 256-bit key for AES-256
    key_b64 = base64.b64encode(key_bytes).decode()
    key_id = str(uuid.uuid4())
    
    # Store key metadata
    meta = {
        "key_id": key_id,
        "version": 1,
        "created_at": time.time(),
        "status": "active",
        "allowed_services": allowed_services,
        "ttl_seconds": ttl,
        "key_material_b64": key_b64
    }
    KEY_STORE[key_id] = meta
    
    audit("create_key", {
        "key_id": key_id,
        "allowed_services": allowed_services,
        "ttl_seconds": ttl
    })
    
    return jsonify({
        "key_id": key_id,
        "version": 1,
        "created_at": meta["created_at"],
        "key_material_b64": key_b64
    }), 201

@app.route("/v1/keys/<key_id>", methods=["GET"])
@require_api_key
def get_key(key_id):
    """
    Retrieve a key by ID
    
    Query parameters:
    - user: Optional user identifier for key derivation
    
    Response: Key metadata including key_material_b64
    """
    meta = KEY_STORE.get(key_id)
    if not meta:
        return jsonify({"error": "Key not found"}), 404
    
    # Check if key has expired
    if is_key_expired(meta):
        return jsonify({"error": "Key has expired"}), 410  # 410 Gone
    
    # Check service authorization
    allowed_services = meta.get("allowed_services", [])
    caller = getattr(request, 'caller_id', 'unknown')
    
    if allowed_services and caller not in allowed_services:
        audit("unauthorized_key_access_attempt", {
            "key_id": key_id,
            "caller": caller,
            "allowed_services": allowed_services
        })
        return jsonify({
            "error": f"Service '{caller}' not authorized to access this key"
        }), 403
    
    # Support user-specific key derivation (for UIDAaaS integration)
    user = request.args.get("user")
    if user:
        # Derive user-specific key using HKDF or similar
        # For demo, we just return the same key
        audit("get_key_for_user", {"key_id": key_id, "user": user})
    else:
        audit("get_key", {"key_id": key_id})
    
    return jsonify(meta)

@app.route("/v1/keys/<key_id>/rotate", methods=["POST"])
@require_api_key
def rotate_key(key_id):
    """
    Rotate a key (generate new key material, increment version)
    
    Response:
    {
        "key_id": "uuid",
        "version": 2,
        "key_material_b64": "new_key"
    }
    """
    meta = KEY_STORE.get(key_id)
    if not meta:
        return jsonify({"error": "Key not found"}), 404
    
    if is_key_expired(meta):
        return jsonify({"error": "Cannot rotate expired key"}), 410
    
    # Generate new key material
    new_key_bytes = os.urandom(32)
    new_b64 = base64.b64encode(new_key_bytes).decode()
    new_version = meta["version"] + 1
    
    # Update metadata
    meta["version"] = new_version
    meta["key_material_b64"] = new_b64
    meta["created_at"] = time.time()
    meta["status"] = "active"
    
    audit("rotate_key", {
        "key_id": key_id,
        "new_version": new_version
    })
    
    return jsonify({
        "key_id": key_id,
        "version": new_version,
        "key_material_b64": new_b64,
        "created_at": meta["created_at"]
    })

@app.route("/v1/keys/<key_id>", methods=["DELETE"])
@require_api_key
def delete_key(key_id):
    """
    Delete/revoke a key
    
    Response:
    {
        "message": "Key deleted",
        "key_id": "uuid"
    }
    """
    meta = KEY_STORE.get(key_id)
    if not meta:
        return jsonify({"error": "Key not found"}), 404
    
    del KEY_STORE[key_id]
    
    audit("delete_key", {"key_id": key_id})
    
    return jsonify({
        "message": "Key deleted",
        "key_id": key_id
    })

@app.route("/v1/keys", methods=["GET"])
@require_api_key
def list_keys():
    """
    List all keys, optionally filtered by service
    
    Query parameters:
    - service: Filter by allowed service name
    
    Response: Array of key metadata (without key_material)
    """
    service = request.args.get("service")
    
    # Clean up expired keys first
    cleanup_expired_keys()
    
    results = []
    for k, meta in KEY_STORE.items():
        # Skip expired keys
        if is_key_expired(meta):
            continue
        
        # Filter by service if requested
        if not service or service in meta.get("allowed_services", []):
            results.append({
                "key_id": k,
                "version": meta["version"],
                "status": meta["status"],
                "created_at": meta["created_at"],
                "allowed_services": meta.get("allowed_services", []),
                "ttl_seconds": meta.get("ttl_seconds")
            })
    
    audit("list_keys", {"service_filter": service, "count": len(results)})
    
    return jsonify(results)

@app.route("/v1/audit", methods=["GET"])
@require_api_key
def get_audit_log():
    """
    Retrieve audit log entries
    
    Query parameters:
    - limit: Max number of entries to return (default: 100)
    
    Response: Array of audit entries
    """
    limit = int(request.args.get("limit", 100))
    
    # Return most recent entries
    entries = AUDIT_LOG[-limit:] if len(AUDIT_LOG) > limit else AUDIT_LOG
    
    return jsonify({
        "total": len(AUDIT_LOG),
        "returned": len(entries),
        "entries": entries
    })

@app.route("/v1/cleanup", methods=["POST"])
@require_api_key
def cleanup():
    """
    Manually trigger cleanup of expired keys
    
    Response:
    {
        "deleted": 5
    }
    """
    deleted = cleanup_expired_keys()
    
    return jsonify({
        "message": "Cleanup complete",
        "deleted": deleted
    })

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    print("Starting KGaaS on port 8001")
    print("Loaded API keys for:", list(API_KEYS.keys()))
    app.run(host='0.0.0.0', port=8001, debug=True)
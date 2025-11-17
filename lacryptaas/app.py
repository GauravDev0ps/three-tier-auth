# lacryptaas/app.py - Enhanced LAcryptaaS (demo only)
import os
import base64
from flask import Flask, request, jsonify, abort
from core.key_manager import create_key, get_key, KeyManagerError
from core.encryption_engine import (
    encrypt_aes_cbc, decrypt_aes_cbc,
    encrypt_aes_gcm, decrypt_aes_gcm
)

app = Flask(__name__)

# Configuration
SERVICE_NAME = os.environ.get("SERVICE_NAME", "lacryptaas")
ALLOW_AUTO_KEY_CREATION = os.environ.get("ALLOW_AUTO_KEY_CREATION", "true").lower() == "true"

@app.route("/ping", methods=["GET"])
def ping():
    """Health check endpoint"""
    return jsonify({
        "service": SERVICE_NAME,
        "status": "operational",
        "message": "pong"
    }), 200

@app.route("/encrypt", methods=["POST"])
def encrypt():
    """
    Encrypt plaintext using AES-CBC
    
    Request body:
    {
        "plaintext": "string to encrypt",
        "key_id": "optional_key_uuid",  // If not provided, creates new key
        "mode": "cbc"  // Optional: "cbc" (default) or "gcm"
    }
    
    Response:
    {
        "key_id": "uuid",
        "iv_b64": "base64_iv",
        "ciphertext_b64": "base64_ciphertext",
        "mode": "cbc"
    }
    """
    try:
        body = request.get_json() or {}
        plaintext_str = body.get("plaintext", "")
        key_id = body.get("key_id")
        mode = body.get("mode", "cbc").lower()
        
        if not plaintext_str:
            return jsonify({"error": "plaintext is required"}), 400
        
        if mode not in ["cbc", "gcm"]:
            return jsonify({"error": "mode must be 'cbc' or 'gcm'"}), 400
        
        plaintext = plaintext_str.encode('utf-8')
        
        # Get or create key
        try:
            if not key_id:
                if not ALLOW_AUTO_KEY_CREATION:
                    return jsonify({"error": "key_id required (auto key creation disabled)"}), 400
                
                k = create_key(allowed_services=[SERVICE_NAME])
                key_b64 = k["key_material_b64"]
                key_id = k["key_id"]
            else:
                k = get_key(key_id)
                key_b64 = k.get("key_material_b64")
                
        except KeyManagerError as e:
            return jsonify({
                "error": "Key management error",
                "details": str(e)
            }), 502
        
        # Decode key
        try:
            key_bytes = base64.b64decode(key_b64)
        except Exception as e:
            return jsonify({
                "error": "Invalid key material",
                "details": str(e)
            }), 500
        
        # Encrypt based on mode
        try:
            if mode == "gcm":
                result = encrypt_aes_gcm(key_bytes, plaintext)
                result["mode"] = "gcm"
            else:
                result = encrypt_aes_cbc(key_bytes, plaintext)
                result["mode"] = "cbc"
            
            result["key_id"] = key_id
            return jsonify(result), 200
            
        except Exception as e:
            return jsonify({
                "error": "Encryption failed",
                "details": str(e)
            }), 500
    
    except Exception as e:
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route("/decrypt", methods=["POST"])
def decrypt():
    """
    Decrypt ciphertext using AES-CBC or AES-GCM
    
    For CBC mode:
    {
        "key_id": "uuid",
        "iv_b64": "base64_iv",
        "ciphertext_b64": "base64_ciphertext",
        "mode": "cbc"  // Optional, defaults to cbc
    }
    
    For GCM mode:
    {
        "key_id": "uuid",
        "nonce_b64": "base64_nonce",
        "ciphertext_b64": "base64_ciphertext",
        "tag_b64": "base64_tag",
        "mode": "gcm"
    }
    
    Response:
    {
        "plaintext": "decrypted string"
    }
    """
    try:
        body = request.get_json() or {}
        key_id = body.get("key_id")
        ciphertext_b64 = body.get("ciphertext_b64")
        mode = body.get("mode", "cbc").lower()
        
        if not key_id or not ciphertext_b64:
            return jsonify({"error": "key_id and ciphertext_b64 required"}), 400
        
        if mode not in ["cbc", "gcm"]:
            return jsonify({"error": "mode must be 'cbc' or 'gcm'"}), 400
        
        # Get key
        try:
            k = get_key(key_id)
            key_b64 = k.get("key_material_b64")
        except KeyManagerError as e:
            return jsonify({
                "error": "Key management error",
                "details": str(e)
            }), 502
        
        # Decode key
        try:
            key_bytes = base64.b64decode(key_b64)
        except Exception as e:
            return jsonify({
                "error": "Invalid key material",
                "details": str(e)
            }), 500
        
        # Decrypt based on mode
        try:
            if mode == "gcm":
                nonce_b64 = body.get("nonce_b64")
                tag_b64 = body.get("tag_b64")
                
                if not nonce_b64 or not tag_b64:
                    return jsonify({"error": "nonce_b64 and tag_b64 required for GCM mode"}), 400
                
                plaintext = decrypt_aes_gcm(key_bytes, nonce_b64, ciphertext_b64, tag_b64)
            else:
                iv_b64 = body.get("iv_b64")
                
                if not iv_b64:
                    return jsonify({"error": "iv_b64 required for CBC mode"}), 400
                
                plaintext = decrypt_aes_cbc(key_bytes, iv_b64, ciphertext_b64)
            
            return jsonify({
                "plaintext": plaintext.decode('utf-8')
            }), 200
            
        except UnicodeDecodeError:
            return jsonify({
                "error": "Decryption succeeded but result is not valid UTF-8 text"
            }), 500
        except Exception as e:
            return jsonify({
                "error": "Decryption failed",
                "details": str(e)
            }), 500
    
    except Exception as e:
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route("/keys", methods=["GET"])
def list_service_keys():
    """
    List all keys available to this service
    
    Response:
    [
        {
            "key_id": "uuid",
            "version": 1,
            "status": "active"
        }
    ]
    """
    try:
        from core.key_manager import list_keys
        keys = list_keys(service_filter=SERVICE_NAME)
        return jsonify(keys), 200
    except KeyManagerError as e:
        return jsonify({
            "error": "Failed to list keys",
            "details": str(e)
        }), 502

@app.route("/keys/<key_id>/rotate", methods=["POST"])
def rotate_service_key(key_id):
    """
    Rotate a key (generate new key material)
    
    Response:
    {
        "key_id": "uuid",
        "version": 2,
        "key_material_b64": "new_base64_key"
    }
    """
    try:
        from core.key_manager import rotate_key
        result = rotate_key(key_id)
        return jsonify(result), 200
    except KeyManagerError as e:
        return jsonify({
            "error": "Failed to rotate key",
            "details": str(e)
        }), 502

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    print(f"Starting {SERVICE_NAME} on port 8002")
    app.run(host='0.0.0.0', port=8002, debug=True)
# lacryptaas/core/key_manager.py
import os
import requests
import base64
from typing import Dict, List, Optional

# Configuration
KGAAS_URL = os.environ.get("KGAAS_URL", "http://localhost:8001")
KGAAS_API_KEY = os.environ.get("KGAAS_API_KEY", "demo-secret-token")
SERVICE_NAME = os.environ.get("SERVICE_NAME", "lacryptaas")

class KeyManagerError(Exception):
    """Custom exception for key manager errors"""
    pass

def _make_kgaas_request(method: str, endpoint: str, json_data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict:
    """
    Make authenticated request to KGaaS
    
    Args:
        method: HTTP method (GET, POST)
        endpoint: API endpoint path
        json_data: JSON payload for POST requests
        params: Query parameters for GET requests
    
    Returns:
        Response JSON as dictionary
        
    Raises:
        KeyManagerError: If request fails
    """
    url = f"{KGAAS_URL}{endpoint}"
    headers = {
        "X-Api-Key": KGAAS_API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, params=params, timeout=5)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=json_data, timeout=5)
        else:
            raise KeyManagerError(f"Unsupported HTTP method: {method}")
        
        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.Timeout:
        raise KeyManagerError("KGaaS request timed out")
    except requests.exceptions.ConnectionError:
        raise KeyManagerError("Cannot connect to KGaaS service")
    except requests.exceptions.HTTPError as e:
        raise KeyManagerError(f"KGaaS returned error: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        raise KeyManagerError(f"Unexpected error communicating with KGaaS: {str(e)}")

def create_key(allowed_services: Optional[List[str]] = None, ttl_seconds: Optional[int] = None) -> Dict:
    """
    Create a new encryption key in KGaaS
    
    Args:
        allowed_services: List of service names allowed to use this key
        ttl_seconds: Time-to-live for the key in seconds
    
    Returns:
        Dictionary containing key metadata:
        {
            "key_id": "uuid",
            "version": 1,
            "created_at": timestamp,
            "key_material_b64": "base64_encoded_key"
        }
    
    Raises:
        KeyManagerError: If key creation fails
    """
    if allowed_services is None:
        allowed_services = [SERVICE_NAME]
    
    payload = {
        "allowed_services": allowed_services,
    }
    
    if ttl_seconds is not None:
        payload["ttl_seconds"] = ttl_seconds
    
    try:
        result = _make_kgaas_request("POST", "/v1/keys", json_data=payload)
        return result
    except KeyManagerError as e:
        raise KeyManagerError(f"Failed to create key: {str(e)}")

def get_key(key_id: str) -> Dict:
    """
    Retrieve an existing key from KGaaS
    
    Args:
        key_id: UUID of the key to retrieve
    
    Returns:
        Dictionary containing key metadata including key_material_b64
    
    Raises:
        KeyManagerError: If key retrieval fails or key not found
    """
    try:
        result = _make_kgaas_request("GET", f"/v1/keys/{key_id}")
        
        # Verify key is active
        if result.get("status") != "active":
            raise KeyManagerError(f"Key {key_id} is not active (status: {result.get('status')})")
        
        # Check if key has expired (if TTL is set)
        if result.get("ttl_seconds"):
            import time
            created_at = result.get("created_at", 0)
            ttl = result.get("ttl_seconds")
            if time.time() > (created_at + ttl):
                raise KeyManagerError(f"Key {key_id} has expired")
        
        # Verify service is authorized to use this key
        allowed_services = result.get("allowed_services", [])
        if allowed_services and SERVICE_NAME not in allowed_services:
            raise KeyManagerError(f"Service '{SERVICE_NAME}' not authorized to use key {key_id}")
        
        return result
    
    except KeyManagerError:
        raise
    except Exception as e:
        raise KeyManagerError(f"Failed to retrieve key: {str(e)}")

def rotate_key(key_id: str) -> Dict:
    """
    Rotate an existing key (generate new key material)
    
    Args:
        key_id: UUID of the key to rotate
    
    Returns:
        Dictionary with new key metadata including updated version
    
    Raises:
        KeyManagerError: If rotation fails
    """
    try:
        result = _make_kgaas_request("POST", f"/v1/keys/{key_id}/rotate")
        return result
    except KeyManagerError as e:
        raise KeyManagerError(f"Failed to rotate key: {str(e)}")

def list_keys(service_filter: Optional[str] = None) -> List[Dict]:
    """
    List all keys, optionally filtered by service
    
    Args:
        service_filter: Only return keys allowed for this service
    
    Returns:
        List of key metadata dictionaries
    
    Raises:
        KeyManagerError: If listing fails
    """
    params = {}
    if service_filter:
        params["service"] = service_filter
    
    try:
        result = _make_kgaas_request("GET", "/v1/keys", params=params)
        return result
    except KeyManagerError as e:
        raise KeyManagerError(f"Failed to list keys: {str(e)}")

def validate_key_material(key_material_b64: str) -> bytes:
    """
    Validate and decode base64 key material
    
    Args:
        key_material_b64: Base64 encoded key material
    
    Returns:
        Raw key bytes
    
    Raises:
        KeyManagerError: If key material is invalid
    """
    try:
        key_bytes = base64.b64decode(key_material_b64)
        
        # AES-256 requires 32 bytes
        if len(key_bytes) != 32:
            raise KeyManagerError(f"Invalid key length: expected 32 bytes, got {len(key_bytes)}")
        
        return key_bytes
    except Exception as e:
        raise KeyManagerError(f"Invalid key material: {str(e)}")
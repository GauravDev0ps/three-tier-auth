# lacryptaas/core/encryption_engine.py
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def encrypt_aes_cbc(key_bytes: bytes, plaintext: bytes) -> dict:
    """
    Encrypt data using AES-256 in CBC mode with PKCS7 padding
    
    Args:
        key_bytes: 32-byte AES key
        plaintext: Data to encrypt
    
    Returns:
        Dictionary containing:
        {
            "iv_b64": "base64_encoded_iv",
            "ciphertext_b64": "base64_encoded_ciphertext"
        }
    
    Raises:
        ValueError: If key length is invalid
        Exception: For encryption failures
    """
    if len(key_bytes) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key_bytes)} bytes")
    
    # Generate random IV (16 bytes for AES)
    iv = os.urandom(16)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Apply PKCS7 padding (AES block size is 128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return base64-encoded results
    return {
        "iv_b64": base64.b64encode(iv).decode('ascii'),
        "ciphertext_b64": base64.b64encode(ciphertext).decode('ascii')
    }

def decrypt_aes_cbc(key_bytes: bytes, iv_b64: str, ciphertext_b64: str) -> bytes:
    """
    Decrypt data encrypted with AES-256 CBC
    
    Args:
        key_bytes: 32-byte AES key (same key used for encryption)
        iv_b64: Base64-encoded initialization vector
        ciphertext_b64: Base64-encoded ciphertext
    
    Returns:
        Decrypted plaintext as bytes
    
    Raises:
        ValueError: If parameters are invalid
        Exception: For decryption failures (wrong key, corrupted data, etc.)
    """
    if len(key_bytes) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key_bytes)} bytes")
    
    try:
        # Decode base64 inputs
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        if len(iv) != 16:
            raise ValueError(f"Invalid IV length: expected 16 bytes, got {len(iv)}")
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    except ValueError as e:
        raise ValueError(f"Decryption parameter error: {str(e)}")
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}. This may indicate wrong key, corrupted data, or invalid ciphertext.")

def encrypt_aes_gcm(key_bytes: bytes, plaintext: bytes, associated_data: bytes = None) -> dict:
    """
    Encrypt data using AES-256 in GCM mode (authenticated encryption)
    
    GCM mode provides both confidentiality and authenticity, making it superior
    to CBC mode for most applications. It doesn't require padding.
    
    Args:
        key_bytes: 32-byte AES key
        plaintext: Data to encrypt
        associated_data: Optional additional data to authenticate (but not encrypt)
    
    Returns:
        Dictionary containing:
        {
            "nonce_b64": "base64_encoded_nonce",
            "ciphertext_b64": "base64_encoded_ciphertext",
            "tag_b64": "base64_encoded_authentication_tag"
        }
    """
    if len(key_bytes) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key_bytes)} bytes")
    
    # Generate random nonce (12 bytes is standard for GCM)
    nonce = os.urandom(12)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Add associated data if provided
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    
    # Encrypt (no padding needed for GCM)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Get authentication tag
    tag = encryptor.tag
    
    return {
        "nonce_b64": base64.b64encode(nonce).decode('ascii'),
        "ciphertext_b64": base64.b64encode(ciphertext).decode('ascii'),
        "tag_b64": base64.b64encode(tag).decode('ascii')
    }

def decrypt_aes_gcm(key_bytes: bytes, nonce_b64: str, ciphertext_b64: str, tag_b64: str, associated_data: bytes = None) -> bytes:
    """
    Decrypt data encrypted with AES-256 GCM
    
    Args:
        key_bytes: 32-byte AES key
        nonce_b64: Base64-encoded nonce
        ciphertext_b64: Base64-encoded ciphertext
        tag_b64: Base64-encoded authentication tag
        associated_data: Optional additional authenticated data (must match encryption)
    
    Returns:
        Decrypted plaintext as bytes
    
    Raises:
        Exception: If authentication fails or decryption fails
    """
    if len(key_bytes) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key_bytes)} bytes")
    
    try:
        # Decode base64 inputs
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Add associated data if provided
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        # Decrypt and verify
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    except Exception as e:
        raise Exception(f"Decryption or authentication failed: {str(e)}")
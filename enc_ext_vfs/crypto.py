import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoEngine:
    """
    AES-256-GCM encryption for all data.
    """
    _AES_KEY_BYTES = 32
    _GCM_NONCE_BYTES = 12
    _GCM_TAG_BYTES = 16

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new AES-256 key."""
        return os.urandom(CryptoEngine._AES_KEY_BYTES)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """Encrypt data with AES-256-GCM. Returns nonce + ciphertext + tag."""
        if len(key) != CryptoEngine._AES_KEY_BYTES:
            raise ValueError(f"Invalid key length. Expected {CryptoEngine._AES_KEY_BYTES} bytes, got {len(key)}.")

        aesgcm = AESGCM(key)
        nonce = os.urandom(CryptoEngine._GCM_NONCE_BYTES)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """Decrypt AES-256-GCM data. Raises on auth failure."""
        if len(key) != CryptoEngine._AES_KEY_BYTES:
            raise ValueError(f"Invalid key length. Expected {CryptoEngine._AES_KEY_BYTES} bytes, got {len(key)}.")

        if len(data) < CryptoEngine._GCM_NONCE_BYTES + CryptoEngine._GCM_TAG_BYTES:
            raise ValueError("Invalid encrypted data format: too short.")

        nonce = data[:CryptoEngine._GCM_NONCE_BYTES]
        ciphertext = data[CryptoEngine._GCM_NONCE_BYTES:]

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    @staticmethod
    def key_hash(key: bytes) -> str:
        """SHA-256 hash of key for identification (not the key itself)."""
        return hashlib.sha256(key).hexdigest()

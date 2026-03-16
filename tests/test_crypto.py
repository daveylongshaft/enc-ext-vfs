import pytest
from cryptography.exceptions import InvalidTag

from enc_ext_vfs.crypto import CryptoEngine

def test_generate_key():
    """Test that a key of the correct length is generated."""
    key = CryptoEngine.generate_key()
    assert len(key) == 32  # AES-256 key size

def test_encrypt_decrypt_roundtrip():
    """Test that data can be encrypted and then decrypted successfully."""
    key = CryptoEngine.generate_key()
    plaintext = b"This is a secret message."
    
    encrypted = CryptoEngine.encrypt(plaintext, key)
    decrypted = CryptoEngine.decrypt(encrypted, key)
    
    assert plaintext == decrypted
    assert encrypted != plaintext

def test_decrypt_with_wrong_key():
    """Test that decryption fails with an incorrect key."""
    key1 = CryptoEngine.generate_key()
    key2 = CryptoEngine.generate_key()
    plaintext = b"This will not be revealed."
    
    encrypted = CryptoEngine.encrypt(plaintext, key1)
    
    with pytest.raises(InvalidTag):
        CryptoEngine.decrypt(encrypted, key2)

def test_tampered_data_fails_decryption():
    """Test that any modification to the ciphertext causes decryption to fail."""
    key = CryptoEngine.generate_key()
    plaintext = b"inviolate data"
    
    encrypted = CryptoEngine.encrypt(plaintext, key)
    
    # Flip a single bit in the ciphertext
    tampered_encrypted = bytearray(encrypted)
    tampered_encrypted[15] ^= 0x01 # Tamper with a byte in the middle
    
    with pytest.raises(InvalidTag):
        CryptoEngine.decrypt(bytes(tampered_encrypted), key)

def test_key_hash():
    """Test that the key hash is a consistent SHA-256 hash."""
    key = CryptoEngine.generate_key()
    key_hash = CryptoEngine.key_hash(key)
    
    assert isinstance(key_hash, str)
    assert len(key_hash) == 64 # SHA-256 hex digest length
    
    # Test that the same key produces the same hash
    assert CryptoEngine.key_hash(key) == key_hash

def test_invalid_key_length():
    """Test that encrypt/decrypt raise errors on invalid key lengths."""
    short_key = b"12345"
    plaintext = b"some data"
    
    with pytest.raises(ValueError):
        CryptoEngine.encrypt(plaintext, short_key)

    # Need valid encrypted data to test decrypt
    valid_key = CryptoEngine.generate_key()
    encrypted = CryptoEngine.encrypt(plaintext, valid_key)
    with pytest.raises(ValueError):
        CryptoEngine.decrypt(encrypted, short_key)

import pytest
from enc_ext_vfs.key_manager import KeyManager
from enc_ext_vfs.crypto import CryptoEngine

@pytest.fixture
def km(tmp_path):
    """Fixture to create a KeyManager instance with a temporary storage path."""
    return KeyManager(str(tmp_path))

def test_initial_global_key_generation(km, tmp_path):
    """Test that a global key is created automatically."""
    assert (tmp_path / "global.key").exists()
    key = km.get_global_key()
    assert isinstance(key, bytes)
    assert len(key) == 32

def test_register_and_get_key(km):
    """Test registering a new private key and retrieving it by hash."""
    owner = "test_owner"
    key_hash = km.register_key(owner, friendly_name="test_key")
    
    key = km.get_key_by_hash(key_hash)
    assert key is not None
    assert CryptoEngine.key_hash(key) == key_hash

    # Check metadata was saved
    keys = km.list_keys()
    assert len(keys) == 1
    assert keys[0]["hash"] == key_hash
    assert keys[0]["owner"] == owner
    assert keys[0]["name"] == "test_key"

def test_get_key_for_read_as_owner(km):
    """Test that the owner can always retrieve a key for reading."""
    owner = "key_owner"
    key_hash = km.register_key(owner)
    
    key = km.get_key_for_read(key_hash, owner)
    assert key is not None

def test_get_key_for_read_unauthorized(km):
    """Test that an unauthorized user cannot retrieve a key for reading."""
    owner = "key_owner"
    unauthorized_user = "snooper"
    key_hash = km.register_key(owner)
    
    with pytest.raises(PermissionError):
        km.get_key_for_read(key_hash, unauthorized_user)

def test_authorize_and_read(km):
    """Test authorizing a user and then having them read the key."""
    owner = "owner"
    authorized_user = "guest"
    key_hash = km.register_key(owner)
    
    # Authorize
    km.authorize_user(key_hash, owner, authorized_user)
    
    # Now the guest should be able to get the key
    key = km.get_key_for_read(key_hash, authorized_user)
    assert key is not None

    # Test that owner can still read
    owner_key = km.get_key_for_read(key_hash, owner)
    assert owner_key == key

def test_revoke_and_fail_read(km):
    """Test that a revoked user can no longer access the key."""
    owner = "owner"
    user = "temp_user"
    key_hash = km.register_key(owner)
    
    km.authorize_user(key_hash, owner, user)
    assert km.get_key_for_read(key_hash, user) is not None
    
    km.revoke_user(key_hash, owner, user)
    with pytest.raises(PermissionError):
        km.get_key_for_read(key_hash, user)

def test_global_key_lock(km):
    """Test that the global key cannot be changed when locked."""
    original_key = km.get_global_key()
    new_key = CryptoEngine.generate_key()
    
    km.lock_global_key()
    
    with pytest.raises(PermissionError):
        km.set_global_key(new_key)
        
    # Verify the key was not changed
    assert km.get_global_key() == original_key

def test_set_global_key_unlocked(km):
    """Test that the global key can be changed when not locked."""
    original_key = km.get_global_key()
    new_key = CryptoEngine.generate_key()
    
    km.set_global_key(new_key)
    
    assert km.get_global_key() == new_key
    assert km.get_global_key() != original_key
    
def test_authorization_by_non_owner_fails(km):
    """Test that only the owner can authorize or revoke users."""
    owner = "owner"
    imposter = "imposter"
    user = "user"
    key_hash = km.register_key(owner)
    
    with pytest.raises(PermissionError):
        km.authorize_user(key_hash, imposter, user)
        
    with pytest.raises(PermissionError):
        km.revoke_user(key_hash, imposter, user)


def test_save_key_metadata_is_atomic_on_write_failure(km, tmp_path, monkeypatch):
    key_hash = km.register_key("owner", friendly_name="stable")
    original_content = km.key_metadata_path.read_text(encoding="utf-8")

    def partial_dump(payload, handle, **kwargs):
        handle.write('{"broken"')
        handle.flush()
        raise RuntimeError("simulated crash during key metadata save")

    monkeypatch.setattr("enc_ext_vfs.key_manager.json.dump", partial_dump)
    km._keys["new-key"] = {"owner": "owner", "name": "new", "description": ""}

    with pytest.raises(RuntimeError, match="simulated crash"):
        km._save_key_metadata()

    assert km.key_metadata_path.read_text(encoding="utf-8") == original_content
    assert not km.key_metadata_path.with_suffix(".json.tmp").exists()

    reloaded = KeyManager(str(tmp_path))
    reloaded_keys = {entry["hash"] for entry in reloaded.list_keys()}
    assert key_hash in reloaded_keys
    assert "new-key" not in reloaded_keys

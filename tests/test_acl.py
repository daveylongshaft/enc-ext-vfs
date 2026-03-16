import pytest
from enc_ext_vfs.acl import AccessControl

@pytest.fixture
def acl(tmp_path):
    """Fixture to create an AccessControl instance with a temporary storage path."""
    return AccessControl(str(tmp_path))

def test_grant_and_check(acl):
    """Test that granting access works and is reflected in checks."""
    key_hash = "key_hash_1"
    user = "test_user"
    
    assert not acl.check(key_hash, user)
    
    acl.grant(key_hash, user)
    assert acl.check(key_hash, user)

def test_revoke(acl):
    """Test that revoking access works."""
    key_hash = "key_hash_2"
    user = "user_to_revoke"
    
    acl.grant(key_hash, user)
    assert acl.check(key_hash, user)
    
    acl.revoke(key_hash, user)
    assert not acl.check(key_hash, user)

def test_get_users(acl):
    """Test listing users for a key."""
    key_hash = "key_hash_3"
    users = ["user1", "user2", "user3"]
    
    for u in users:
        acl.grant(key_hash, u)
        
    retrieved_users = acl.get_users(key_hash)
    assert sorted(users) == sorted(retrieved_users)

def test_persistence(tmp_path):
    """Test that ACL state is persisted between instances."""
    key_hash = "persistent_key"
    user = "persistent_user"
    
    # First instance
    acl1 = AccessControl(str(tmp_path))
    acl1.grant(key_hash, user)
    
    # Second instance, should load the state from the first
    acl2 = AccessControl(str(tmp_path))
    assert acl2.check(key_hash, user)

def test_is_ircop_placeholder(acl):
    """Test that the is_ircop placeholder returns False."""
    # This test is to confirm the placeholder behavior.
    # It should be updated if the is_ircop logic is ever implemented.
    assert not acl.is_ircop("any_user")

def test_multiple_keys(acl):
    """Test that permissions for different keys are isolated."""
    kh1, kh2 = "key1", "key2"
    u1, u2 = "user1", "user2"
    
    acl.grant(kh1, u1)
    acl.grant(kh2, u2)
    
    assert acl.check(kh1, u1)
    assert not acl.check(kh1, u2)
    
    assert acl.check(kh2, u2)
    assert not acl.check(kh2, u1)

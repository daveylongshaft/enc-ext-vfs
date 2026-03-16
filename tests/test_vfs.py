import pytest
from enc_ext_vfs.vfs import VirtualFileSystem

@pytest.fixture
def vfs(tmp_path):
    """Fixture to create a fresh VirtualFileSystem instance for each test."""
    return VirtualFileSystem(str(tmp_path))

def test_create_and_read_file(vfs):
    """Test creating a file and reading it back."""
    path = "/test.txt"
    content = b"hello world"
    
    assert not vfs.exists(path)
    
    vfs.create(path, content)
    
    assert vfs.exists(path)
    read_content = vfs.read(path, "root")
    assert read_content == content

    # Test stat
    header = vfs.stat(path)
    assert header is not None
    assert header.filename == path
    assert header.file_size == len(content)

def test_write_overwrite(vfs):
    """Test that writing to an existing file overwrites it."""
    path = "/overwrite.txt"
    vfs.create(path, b"initial content")
    
    new_content = b"new content"
    vfs.write(path, new_content)
    
    read_content = vfs.read(path, "root")
    assert read_content == new_content

def test_append(vfs):
    """Test appending data to a file."""
    path = "/append.txt"
    vfs.create(path, b"part1")
    vfs.append(path, b"part2")
    
    read_content = vfs.read(path, "root")
    assert read_content == b"part1part2"

def test_delete(vfs):
    """Test deleting a file."""
    path = "/to_delete.txt"
    vfs.create(path, b"data")
    
    assert vfs.exists(path)
    
    vfs.delete(path)
    assert not vfs.exists(path)
    with pytest.raises(FileNotFoundError):
        vfs.read(path, "root")

def test_rename(vfs):
    """Test renaming a file."""
    old_path = "/old_name.txt"
    new_path = "/new_name.txt"
    content = b"some data"
    vfs.create(old_path, content)
    
    vfs.rename(old_path, new_path)
    
    assert not vfs.exists(old_path)
    assert vfs.exists(new_path)
    assert vfs.read(new_path, "root") == content

def test_copy(vfs):
    """Test copying a file."""
    src_path = "/source.txt"
    dst_path = "/destination.txt"
    content = b"copy me"
    vfs.create(src_path, content)
    
    vfs.copy(src_path, dst_path)
    
    assert vfs.exists(src_path)
    assert vfs.exists(dst_path)
    assert vfs.read(dst_path, "root") == content
    
    # Check they are separate files (different headers)
    h1 = vfs.stat(src_path)
    h2 = vfs.stat(dst_path)
    assert h1.block_addresses[0] != h2.block_addresses[0]

def test_read_acl(vfs):
    """Test ACL enforcement for read operations."""
    owner = "file_owner"
    authorized_user = "guest"
    unauthorized_user = "hacker"
    path = "/secure.txt"
    
    # Register a key for the owner
    key_hash = vfs._key_manager.register_key(owner, "secure_key")
    
    # Create a file with that key
    vfs.create(path, b"secret data", key_hash=key_hash)
    
    # 1. Owner can read
    assert vfs.read(path, owner) == b"secret data"
    
    # 2. Unauthorized user cannot read
    with pytest.raises(PermissionError):
        vfs.read(path, unauthorized_user)
        
    # 3. Authorize guest
    vfs._key_manager.authorize_user(key_hash, owner, authorized_user)
    
    # 4. Guest can now read
    assert vfs.read(path, authorized_user) == b"secret data"

def test_integrity_verification(vfs):
    """Test that the integrity check runs."""
    vfs.create("/healthy.txt", b"good data")
    
    issues = vfs.verify_integrity()
    assert len(issues) == 0

def test_hard_link(vfs):
    """Test creating and using a hard link."""
    target = "/target_file.txt"
    link = "/link_file.txt"
    content = b"linked content"
    
    vfs.create(target, content)
    vfs.hard_link(target, link)
    
    assert vfs.exists(link)
    assert vfs.read(link, "root") == content
    
    # Stat info should show they point to the same header block
    h1 = vfs.stat(target)
    h2 = vfs.stat(link)
    assert h1.block_addresses[0] == h2.block_addresses[0]
    
    # Deleting the target should not affect the link
    vfs.delete(target)
    assert vfs.read(link, "root") == content

def test_soft_link(vfs):
    """Test creating and reading a soft link."""
    target = "/real_file.txt"
    link = "/symlink"
    content = b"pointed content"
    
    vfs.create(target, content)
    vfs.soft_link(target, link)
    
    link_header = vfs.stat(link)
    assert link_header.mime_type == "inode/symlink"
    
    # Reading the link should give the target path
    assert vfs.read(link, "root") == target.encode('utf-8')

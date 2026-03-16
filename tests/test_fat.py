import pytest
from enc_ext_vfs.fat import FileAllocationTable
from enc_ext_vfs.key_manager import KeyManager
from enc_ext_vfs.block_store import BlockStore
from enc_ext_vfs.vfs import VirtualFileSystem

@pytest.fixture
def km(tmp_path):
    return KeyManager(str(tmp_path))

@pytest.fixture
def block_store(tmp_path):
    return BlockStore(str(tmp_path))

@pytest.fixture
def fat(km, block_store):
    return FileAllocationTable(km, block_store)

def test_register_lookup_remove(fat):
    """Test the basic lifecycle of a file entry."""
    filename = "/my/file.txt"
    header_addr = "header:address:1"
    
    # Lookup non-existent
    assert fat.lookup(filename) is None
    
    # Register and lookup
    fat.register_file(filename, header_addr)
    assert fat.lookup(filename) == header_addr
    
    # Remove and lookup
    fat.remove(filename)
    assert fat.lookup(filename) is None

def test_list_files(fat):
    """Test that list_files returns all registered files."""
    files = ["/f1.txt", "/f2.log", "/dir/f3.dat"]
    for i, f in enumerate(files):
        fat.register_file(f, f"addr:{i}")
        
    listed_files = fat.list_files()
    assert sorted(files) == sorted(listed_files)

def test_persistence(tmp_path, km, block_store):
    """Test that FAT state is persisted and reloaded."""
    filename = "/persisted.txt"
    header_addr = "persisted:addr"
    
    # First instance
    fat1 = FileAllocationTable(km, block_store)
    fat1.register_file(filename, header_addr)
    fat1.save() # Explicit save to be sure
    
    # Second instance should load the state
    fat2 = FileAllocationTable(km, block_store)
    assert fat2.lookup(filename) == header_addr

@pytest.fixture
def vfs(tmp_path):
    """Fixture to create a full VFS instance for integration-style tests."""
    return VirtualFileSystem(str(tmp_path / "vfs_storage"))

def test_rebuild_from_headers(vfs):
    """Test the self-healing rebuild mechanism."""
    # 1. Create some files using the VFS, which will create valid blocks
    file1_content = b"content of file 1"
    file2_content = b"content of file 2"
    vfs.create("/file1.txt", file1_content)
    vfs.create("/subdir/file2.log", file2_content)

    # 2. Create a new FAT instance pointing to the same storage
    new_fat = FileAllocationTable(vfs._key_manager, vfs._block_store)
    
    # 3. Corrupt the new FAT's in-memory state to ensure it's empty
    new_fat._fat = {}
    assert not new_fat.list_files()
    
    # 4. Trigger the rebuild
    new_fat.rebuild_from_headers()
    
    # 5. Verify the FAT is now populated correctly
    rebuilt_files = new_fat.list_files()
    assert len(rebuilt_files) == 2
    assert "/file1.txt" in rebuilt_files
    assert "/subdir/file2.log" in rebuilt_files
    
    # Check that the header addresses are correct
    h1_addr = new_fat.lookup("/file1.txt")
    h2_addr = new_fat.lookup("/subdir/file2.log")
    
    assert h1_addr is not None
    assert h2_addr is not None
    
    # A final check: read the file through the VFS using the rebuilt FAT
    vfs._fat = new_fat # Swap in the rebuilt FAT
    assert vfs.read("/file1.txt", "root") == file1_content

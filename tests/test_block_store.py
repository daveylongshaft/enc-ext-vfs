import pytest
from enc_ext_vfs.block_store import BlockStore

@pytest.fixture
def block_store(tmp_path):
    """Fixture to create a BlockStore instance with a temporary root path."""
    return BlockStore(str(tmp_path))

def test_allocate_block(block_store):
    """Test block allocation creates the correct directory structure."""
    address = block_store.allocate_block()
    
    assert isinstance(address, str)
    assert len(address.split('-')) == 8
    
    path = block_store._get_path_from_address(address)
    assert path.parent.exists()
    assert path.parent.is_dir()

def test_write_read_block(block_store):
    """Test that data can be written to and read from a block."""
    address = block_store.allocate_block()
    data = b"some block data"
    
    block_store.write_block(address, data)
    read_data = block_store.read_block(address)
    
    assert read_data == data

def test_read_nonexistent_block(block_store):
    """Test that reading a nonexistent block raises FileNotFoundError."""
    address = "00-11-22-33-44-55-66-77"
    with pytest.raises(FileNotFoundError):
        block_store.read_block(address)

def test_delete_block(block_store):
    """Test that deleting a block removes the file and empty parent dirs."""
    address = block_store.allocate_block()
    path = block_store._get_path_from_address(address)
    
    block_store.write_block(address, b"data")
    assert path.exists()
    
    block_store.delete_block(address)
    assert not path.exists()
    
    # Check that parent directories are removed
    assert not path.parent.exists()
    assert not path.parent.parent.exists()
    assert not path.parent.parent.parent.exists()

def test_list_blocks(block_store):
    """Test listing all allocated blocks."""
    addresses = [block_store.allocate_block() for _ in range(5)]
    for addr in addresses:
        block_store.write_block(addr, b"data")
        
    listed_blocks = block_store.list_blocks()
    
    assert len(listed_blocks) == 5
    assert sorted(addresses) == sorted(listed_blocks)

def test_delete_block_shared_parent(block_store):
    """Test that deleting a block does not remove a parent dir if it's not empty."""
    # Create two addresses that share the same parent directory
    address1_parts = ["01", "02", "03"] + [f"{i:02x}" for i in range(5)]
    address1 = "-".join(address1_parts)
    path1 = block_store._get_path_from_address(address1)
    path1.parent.mkdir(parents=True, exist_ok=True)
    block_store.write_block(address1, b"data1")

    address2_parts = ["01", "02", "03"] + [f"{i+5:02x}" for i in range(5)]
    address2 = "-".join(address2_parts)
    path2 = block_store._get_path_from_address(address2)
    block_store.write_block(address2, b"data2")
    
    assert path1.parent == path2.parent
    
    # Delete one block
    block_store.delete_block(address1)
    
    # The file should be gone, but the parent directory should remain
    assert not path1.exists()
    assert path2.exists()
    assert path1.parent.exists()
    assert path1.parent.is_dir()

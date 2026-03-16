import time
import pytest
from enc_ext_vfs.header import FileHeader

@pytest.fixture
def sample_header_data():
    """Fixture to provide sample data for creating a FileHeader."""
    return {
        "filename": "/test.txt",
        "file_size": 123,
        "block_size": 4096,
        "mime_type": "text/plain",
        "node_id": "test_node",
        "key_hash": "a_key_hash",
        "block_addresses": ["addr1", "addr2"],
    }

def test_header_creation_and_defaults(sample_header_data):
    """Test basic header creation and default timestamp values."""
    before = time.time()
    header = FileHeader(**sample_header_data)
    after = time.time()

    assert header.filename == "/test.txt"
    assert header.created >= before
    assert header.created <= after
    assert header.accessed == header.created
    assert header.modified == header.created

def test_json_serialization_roundtrip(sample_header_data):
    """Test that a header can be serialized to JSON and back without data loss."""
    header1 = FileHeader(**sample_header_data)
    
    json_str = header1.to_json()
    header2 = FileHeader.from_json(json_str)
    
    # Compare dictionaries to ensure all attributes are the same
    assert header1.__dict__ == header2.__dict__

def test_checksum_verification(sample_header_data):
    """Test the checksum calculation and verification."""
    header = FileHeader(**sample_header_data)
    data = b"some file content for checksum"
    
    header.update_checksum(data)
    assert header.checksum is not None
    assert len(header.checksum) == 64 # SHA-256
    
    assert header.verify_checksum(data)
    
    # Test with wrong data
    assert not header.verify_checksum(b"different content")

def test_repr(sample_header_data):
    """Test the __repr__ method for a clean representation."""
    header = FileHeader(**sample_header_data)
    assert repr(header) == "<FileHeader(filename='/test.txt', size=123)>"

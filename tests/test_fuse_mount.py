import pytest
import sys
from unittest.mock import MagicMock

# Mock fuse before importing our module to bypass libfuse missing error
import sys
sys.modules['fuse'] = MagicMock()
sys.modules['fuse'].Operations = object
sys.modules['fuse'].FUSE = MagicMock()
sys.modules['fuse'].FuseOSError = Exception

from enc_ext_vfs.fuse_mount import EncExtVfsFuse
from enc_ext_vfs.vfs import VirtualFileSystem

@pytest.fixture
def vfs(tmp_path):
    return VirtualFileSystem(str(tmp_path))

@pytest.fixture
def fuse_vfs(vfs):
    return EncExtVfsFuse(vfs, "root")

def test_fuse_getattr(fuse_vfs):
    fuse_vfs.vfs.create("/test.txt", b"data")
    attrs = fuse_vfs.getattr("/test.txt")
    assert attrs['st_size'] == 4
    assert 'st_mode' in attrs

def test_fuse_readdir(fuse_vfs):
    fuse_vfs.vfs.create("/file1.txt", b"")
    fuse_vfs.vfs.create("/file2.txt", b"")

    entries = list(fuse_vfs.readdir("/", None))
    assert "." in entries
    assert ".." in entries
    assert "/file1.txt" in entries
    assert "/file2.txt" in entries

def test_fuse_read(fuse_vfs):
    content = b"fuse content"
    fuse_vfs.vfs.create("/read.txt", content)
    read_data = fuse_vfs.read("/read.txt", len(content), 0, None)
    assert read_data == content

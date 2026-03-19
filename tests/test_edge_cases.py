import pytest
from enc_ext_vfs.vfs import VirtualFileSystem

@pytest.fixture
def vfs(tmp_path):
    return VirtualFileSystem(str(tmp_path))

def test_empty_file(vfs):
    path = "/empty.txt"
    vfs.create(path, b"")
    assert vfs.exists(path)
    assert vfs.read(path, "root") == b""

def test_file_not_found(vfs):
    with pytest.raises(FileNotFoundError):
        vfs.read("/nonexistent.txt", "root")

def test_delete_nonexistent(vfs):
    with pytest.raises(FileNotFoundError):
        vfs.delete("/nonexistent.txt")

def test_create_existing(vfs):
    path = "/exists.txt"
    vfs.create(path, b"data")
    with pytest.raises(FileExistsError):
        vfs.create(path, b"more data")

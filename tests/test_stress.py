import pytest
from enc_ext_vfs.vfs import VirtualFileSystem
import os

@pytest.fixture
def vfs(tmp_path):
    return VirtualFileSystem(str(tmp_path))

def test_many_small_files(vfs):
    num_files = 100
    for i in range(num_files):
        vfs.create(f"/file_{i}.txt", b"data " * 10)

    assert len(vfs.list_dir("/")) == num_files
    for i in range(num_files):
        assert vfs.read(f"/file_{i}.txt", "root") == b"data " * 10

def test_large_file(vfs):
    path = "/large.bin"
    # Create a 1MB file
    content = os.urandom(1024 * 1024)
    vfs.create(path, content)

    assert vfs.exists(path)
    assert vfs.read(path, "root") == content

def test_rapid_append(vfs):
    path = "/rapid.txt"
    vfs.create(path, b"start")

    for i in range(50):
        vfs.append(path, f"_{i}".encode('utf-8'))

    expected = b"start" + b"".join(f"_{i}".encode('utf-8') for i in range(50))
    assert vfs.read(path, "root") == expected

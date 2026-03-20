import stat

from enc_ext_vfs.fuse_layer import CSCFUSEAdapter
from enc_ext_vfs.vfs import VFS


def test_fuse_adapter_readdir_read_write_and_chmod(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    vfs.create_file("logs::current::app.log", b"hello")

    adapter = CSCFUSEAdapter(vfs)
    file_inode = adapter._path_to_inode("logs::current::app.log")
    root_entries = adapter.readdir(1)
    assert "logs" in root_entries

    attrs = adapter.getattr(file_inode)
    assert attrs.st_size == 5

    info = adapter.open(file_inode)
    assert adapter.read(info.fh, 0, 5) == b"hello"

    adapter.write(info.fh, 5, b" world")
    assert vfs.read_file("logs::current::app.log", "root") == b"hello world"

    updated = adapter.setattr(file_inode, stat.S_IRUSR)
    assert updated.st_mode & stat.S_IRUSR
    assert not (vfs.get_fat_entry("logs::current::app.log").permissions & 0o200)


def test_fuse_adapter_zero_fills_sparse_writes(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    vfs.create_file("logs::current::sparse.log", b"abc")

    adapter = CSCFUSEAdapter(vfs)
    file_inode = adapter._path_to_inode("logs::current::sparse.log")
    info = adapter.open(file_inode)

    adapter.write(info.fh, 6, b"z")
    assert vfs.read_file("logs::current::sparse.log", "root") == b"abc\0\0\0z"

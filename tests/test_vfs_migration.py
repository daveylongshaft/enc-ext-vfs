import logging

from enc_ext_vfs.vfs import VFS


def test_rebuild_fat_from_headers_restores_entries_and_refcounts(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    inode = vfs.create_file("logs::current::app.log", b"hello")
    vfs.create_hardlink("logs::current::app.log", "logs::backup::app.log", "root")

    vfs.fat_file.unlink()
    vfs.fat = {}
    vfs.inode_manager.inodes = {}

    vfs.rebuild_fat_from_headers()

    assert sorted(vfs.fat) == ["logs::backup::app.log", "logs::current::app.log"]
    rebuilt_inode = vfs.inode_manager.get_inode(inode.inode_id)
    assert rebuilt_inode is not None
    assert rebuilt_inode.ref_count == 2
    assert vfs.read_file("logs::backup::app.log", "root") == b"hello"


def test_rebuild_logs_unreadable_headers(tmp_path, caplog):
    caplog.set_level(logging.WARNING)
    vfs = VFS(str(tmp_path / "vfs"))
    inode = vfs.create_file("logs::current::app.log", b"hello")
    header_path = vfs.block_store.header_path(inode.block_id)
    header_path.write_bytes(b"broken header")
    vfs.block_store.header_parity_path(inode.block_id).write_text("bad parity packet")

    vfs.rebuild_fat_from_headers()

    assert "Skipping unreadable header" in caplog.text

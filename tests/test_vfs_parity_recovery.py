import logging

from enc_ext_vfs.vfs import VFS


def test_missing_block_recovers_from_parity(tmp_path, caplog):
    caplog.set_level(logging.WARNING)
    vfs = VFS(str(tmp_path / "vfs"))
    inode = vfs.create_file("logs::current::app.log", b"recover me")
    block_path = vfs.block_store.block_path(inode.block_id)
    parity_path = vfs.block_store.parity_path(inode.block_id)
    assert parity_path.exists()

    block_path.unlink()
    assert vfs.read_file("logs::current::app.log", "root") == b"recover me"
    assert block_path.exists()
    assert "Recovering" in caplog.text


def test_corrupt_block_is_recovered_from_reed_solomon_parity(tmp_path, caplog):
    caplog.set_level(logging.WARNING)
    vfs = VFS(str(tmp_path / "vfs"))
    inode = vfs.create_file("logs::current::app.log", b"recover me twice")
    block_path = vfs.block_store.block_path(inode.block_id)

    block_path.write_bytes(b"bad ciphertext")
    assert vfs.read_file("logs::current::app.log", "root") == b"recover me twice"
    assert "payload checksum does not match parity packet" in caplog.text

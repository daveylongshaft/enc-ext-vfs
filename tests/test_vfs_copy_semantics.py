from enc_ext_vfs.crypto import CryptoEngine
from enc_ext_vfs.vfs import VFS


def test_copy_file_creates_new_inode_block_and_key(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    src_key_hash = vfs.key_manager.register_key("owner")
    src_inode = vfs.create_file("docs::src.txt", b"copy me", src_key_hash, permissions=0o400)

    dst_key = CryptoEngine.generate_key()
    dst_inode = vfs.copy_file("docs::src.txt", "docs::copy.txt", "owner", dst_key=dst_key, permissions=0o600)

    assert dst_inode.inode_id != src_inode.inode_id
    assert dst_inode.block_id != src_inode.block_id
    assert dst_inode.key_hash != src_inode.key_hash
    assert vfs.get_fat_entry("docs::copy.txt").permissions == 0o600
    assert vfs.read_file("docs::src.txt", "owner") == b"copy me"
    assert vfs.read_file("docs::copy.txt", "root") == b"copy me"

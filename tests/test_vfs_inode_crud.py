import pytest

from enc_ext_vfs.vfs import IntegrityError, VFS


def test_create_read_permissions_and_checksum(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    owner_key_hash = vfs.key_manager.register_key("owner", friendly_name="owner-key")

    inode = vfs.create_file("docs::report.txt", b"classified", owner_key_hash, permissions=0o600)
    assert inode.size == 10
    assert vfs.read_file("docs::report.txt", "owner") == b"classified"

    with pytest.raises(PermissionError):
        vfs.read_file("docs::report.txt", "outsider")

    fat_entry = vfs.get_fat_entry("docs::report.txt")
    fat_entry.permissions = 0o200
    vfs.save_fat()
    vfs._sync_inode_header(fat_entry.inode_id)
    with pytest.raises(PermissionError):
        vfs.read_file("docs::report.txt", "owner")

    fat_entry.permissions = 0o600
    vfs.save_fat()
    vfs._sync_inode_header(fat_entry.inode_id)
    inode.checksum = "not-the-real-checksum"
    with pytest.raises(IntegrityError):
        vfs.read_file("docs::report.txt", "owner")


def test_read_file_not_found(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    with pytest.raises(FileNotFoundError):
        vfs.read_file("missing::file.txt", "root")

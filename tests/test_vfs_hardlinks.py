from enc_ext_vfs.vfs import VFS


def test_hardlinks_reference_count_and_permissions(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    key_hash = vfs.key_manager.register_key("owner")
    original = vfs.create_file("logs::current::app.log", b"hello", key_hash, permissions=0o600)

    vfs.create_hardlink("logs::current::app.log", "logs::backup::app.log", "owner", permissions=0o400)

    backup_entry = vfs.get_fat_entry("logs::backup::app.log")
    current_entry = vfs.get_fat_entry("logs::current::app.log")
    assert backup_entry.inode_id == current_entry.inode_id == original.inode_id
    assert vfs.inode_manager.get_inode(original.inode_id).ref_count == 2
    assert backup_entry.permissions == 0o400
    assert vfs.inode_manager.get_inode(backup_entry.inode_id).key_hash == key_hash

    vfs.delete_file("logs::current::app.log", "owner")
    assert vfs.inode_manager.get_inode(original.inode_id).ref_count == 1
    assert vfs.block_store.block_path(original.block_id).exists()

    backup_entry.permissions = 0o600
    vfs.save_fat()
    vfs._sync_inode_header(backup_entry.inode_id)
    vfs.delete_file("logs::backup::app.log", "owner")
    assert vfs.inode_manager.get_inode(original.inode_id) is None
    assert not vfs.block_store.block_path(original.block_id).exists()

import json

import pytest

from enc_ext_vfs.inode_manager import InodeManager
from enc_ext_vfs.vfs import VFS


def test_fat_persistence_listing_and_sorting(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    manager = InodeManager()
    inode = manager.create_inode("1/2/3/4-5", vfs.key_manager.get_default_key_hash(), 0, "checksum")
    vfs.inode_manager.inodes[inode.inode_id] = inode

    vfs.create_fat_entry("logs::zeta::debug.log", inode.inode_id)
    vfs.create_fat_entry("logs::alpha::app.log", inode.inode_id)
    vfs.create_fat_entry("logs::alpha::error.log", inode.inode_id)

    assert list(vfs.fat) == [
        "logs::alpha::app.log",
        "logs::alpha::error.log",
        "logs::zeta::debug.log",
    ]
    assert vfs.list_dir("logs") == ["alpha", "zeta"]
    assert vfs.list_dir("logs::alpha") == ["app.log", "error.log"]

    reloaded = VFS(str(tmp_path / "vfs"))
    assert reloaded.get_fat_entry("logs::alpha::app.log").inode_id == inode.inode_id

    reloaded.delete_fat_entry("logs::alpha::app.log")
    assert reloaded.get_fat_entry("logs::alpha::app.log") is None


def test_legacy_fat_entries_are_upgraded_on_load(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    inode = vfs.create_file("logs::legacy::app.log", b"legacy-data")

    with open(vfs.fat_file, "w", encoding="utf-8") as handle:
        json.dump({"logs::legacy::app.log": inode.block_id}, handle)

    reloaded = VFS(str(tmp_path / "vfs"))
    fat_entry = reloaded.get_fat_entry("logs::legacy::app.log")
    assert fat_entry is not None
    assert fat_entry.inode_id == inode.inode_id
    assert reloaded.read_file("logs::legacy::app.log", "root") == b"legacy-data"


def test_delete_fat_entry_updates_refcounts_and_removes_last_block(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    inode = vfs.create_file("logs::current::app.log", b"hello")
    vfs.create_hardlink("logs::current::app.log", "logs::backup::app.log", "root")

    vfs.delete_fat_entry("logs::current::app.log")
    remaining_inode = vfs.inode_manager.get_inode(inode.inode_id)
    assert remaining_inode is not None
    assert remaining_inode.ref_count == 1

    vfs.delete_fat_entry("logs::backup::app.log")
    assert vfs.inode_manager.get_inode(inode.inode_id) is None
    assert not vfs.block_store.block_path(inode.block_id).exists()


def test_save_fat_is_atomic_on_write_failure(tmp_path, monkeypatch):
    vfs = VFS(str(tmp_path / "vfs"))
    inode = vfs.create_file("logs::current::app.log", b"stable-data")
    original_content = vfs.fat_file.read_text(encoding="utf-8")

    def partial_dump(payload, handle):
        handle.write('{"logs::broken"')
        handle.flush()
        raise RuntimeError("simulated crash during FAT save")

    monkeypatch.setattr("enc_ext_vfs.vfs.json_dump", partial_dump)

    vfs.fat["logs::new::app.log"] = vfs.get_fat_entry("logs::current::app.log")

    with pytest.raises(RuntimeError, match="simulated crash"):
        vfs.save_fat()

    assert vfs.fat_file.read_text(encoding="utf-8") == original_content
    assert not vfs.fat_file.with_suffix(".json.tmp").exists()

    reloaded = VFS(str(tmp_path / "vfs"))
    assert reloaded.get_fat_entry("logs::current::app.log").inode_id == inode.inode_id
    assert reloaded.get_fat_entry("logs::new::app.log") is None

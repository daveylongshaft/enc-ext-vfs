import os

from enc_ext_vfs.benchmarks import benchmark_vfs_roundtrip, run_benchmarks
from enc_ext_vfs.fsck import run_fsck
from enc_ext_vfs.vfs import VFS


def test_benchmark_reports_storage_breakdown():
    result = benchmark_vfs_roundtrip([256, 1024])
    assert result.bytes_written == 1280
    assert result.storage.raw_encrypted_bytes > 0
    assert result.storage.header_bytes > 0
    assert result.storage.recovery_bytes > 0
    assert result.storage.compression_enabled is False


def test_benchmark_aggregate_report_has_expected_fields():
    report = run_benchmarks(2, [128, 512])
    assert report["iterations"] == 2
    assert report["payload_sizes"] == [128, 512]
    assert report["storage"]["raw_encrypted_bytes"] > 0
    assert report["storage"]["recovery_bytes"] > 0


def test_stress_many_small_files_roundtrip(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    for index in range(50):
        payload = f"payload-{index}".encode()
        vfs.create_file(f"stress::{index}.txt", payload)

    for index in range(50):
        assert vfs.read_file(f"stress::{index}.txt", "root") == f"payload-{index}".encode()


def test_stress_hardlink_fanout_cleanup(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    inode = vfs.create_file("stress::src.txt", b"fanout")
    for index in range(10):
        vfs.create_hardlink("stress::src.txt", f"stress::link::{index}.txt", "root")

    assert vfs.inode_manager.get_inode(inode.inode_id).ref_count == 11
    for index in range(10):
        vfs.delete_file(f"stress::link::{index}.txt", "root")
    assert vfs.inode_manager.get_inode(inode.inode_id).ref_count == 1


def test_fsck_repairs_missing_payload_offline(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    inode = vfs.create_file("stress::repair.txt", b"repair me")
    vfs.block_store.block_path(inode.block_id).unlink()

    report = run_fsck(str(tmp_path / "vfs"), requester="root")
    assert report.ok
    assert report.repaired_paths == ["stress::repair.txt"]


def test_fsck_uses_requester_from_environment(tmp_path, monkeypatch):
    vfs = VFS(str(tmp_path / "vfs"))
    key_hash = vfs.key_manager.register_key("alice", friendly_name="alice-key")
    vfs.create_file("stress::secure.txt", b"classified", key_hash=key_hash)
    monkeypatch.setenv("ENC_EXT_VFS_REQUESTER_NICK", "alice")

    report = run_fsck(str(tmp_path / "vfs"))
    assert report.ok
    assert report.requester == "alice"

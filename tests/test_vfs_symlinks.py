from enc_ext_vfs.vfs import VFS


def test_symlink_metadata_roundtrip(tmp_path):
    vfs = VFS(str(tmp_path / "vfs"))
    vfs.write_symlink(
        "meta::current",
        "vfs://logs::current::app.log",
        env_vars={"LOG_LEVEL": "DEBUG", "REGION": "us-east"},
        setup_script="export LOG_DIR=/var/log/csc\necho ready",
    )

    parsed = vfs.read_symlink("meta::current", "root")
    assert parsed["target_uri"] == "vfs://logs::current::app.log"
    assert parsed["env_vars"] == {"LOG_LEVEL": "DEBUG", "REGION": "us-east"}
    assert parsed["setup_script"] == "export LOG_DIR=/var/log/csc\necho ready"
    assert vfs.stat("meta::current").mime_type == "inode/symlink"
    assert vfs.read_file("meta::current", "root").startswith(b"vfs://")

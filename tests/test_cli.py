import pytest
from unittest.mock import patch
import sys
from enc_ext_vfs.cli import main
from enc_ext_vfs.vfs import VirtualFileSystem

@pytest.fixture
def vfs(tmp_path):
    return VirtualFileSystem(str(tmp_path))

def test_cli_create_key(tmp_path, capsys):
    test_args = ["cli.py", str(tmp_path), "create-key", "alice", "--name", "alices-key"]
    with patch.object(sys, 'argv', test_args):
        main()

    captured = capsys.readouterr()
    assert "Key created successfully!" in captured.out
    assert "Owner: alice" in captured.out

def test_cli_list_keys(tmp_path, capsys):
    vfs_inst = VirtualFileSystem(str(tmp_path))
    vfs_inst._key_manager.register_key("bob", "bobs-key")

    test_args = ["cli.py", str(tmp_path), "list-keys", "--owner", "bob"]
    with patch.object(sys, 'argv', test_args):
        main()

    captured = capsys.readouterr()
    assert "Owner: bob" in captured.out
    assert "Name: 'bobs-key'" in captured.out

def test_cli_grant_list_revoke(tmp_path, capsys):
    vfs_inst = VirtualFileSystem(str(tmp_path))
    key_hash = vfs_inst._key_manager.register_key("charlie", "charlies-key")

    # Grant
    test_args = ["cli.py", str(tmp_path), "grant", key_hash, "charlie", "dave"]
    with patch.object(sys, 'argv', test_args):
        main()
    captured = capsys.readouterr()
    assert "Successfully granted 'dave'" in captured.out

    # List
    test_args = ["cli.py", str(tmp_path), "list-users", key_hash]
    with patch.object(sys, 'argv', test_args):
        main()
    captured = capsys.readouterr()
    assert "Explicitly authorized users: charlie, dave" in captured.out # owner is in list in test env or explicitly added

    # Revoke
    test_args = ["cli.py", str(tmp_path), "revoke", key_hash, "charlie", "dave"]
    with patch.object(sys, 'argv', test_args):
        main()
    captured = capsys.readouterr()
    assert "Successfully revoked 'dave'" in captured.out

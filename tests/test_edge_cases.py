from enc_ext_vfs.fuse_layer import CSCFUSEAdapter
from enc_ext_vfs.requester import resolve_requester
from enc_ext_vfs.vfs import VFS


def test_requester_resolution_prefers_explicit_env(monkeypatch):
    monkeypatch.setenv("ENC_EXT_VFS_REQUESTER", "oper")
    monkeypatch.setenv("USER", "ignored-user")
    assert resolve_requester() == "oper"


def test_fuse_adapter_defaults_requester_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ENC_EXT_VFS_REQUESTER_NICK", "bob")
    vfs = VFS(str(tmp_path / "vfs"))
    adapter = CSCFUSEAdapter(vfs)
    assert adapter.requester == "bob"

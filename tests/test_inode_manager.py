from enc_ext_vfs.inode import Inode
from enc_ext_vfs.inode_manager import InodeManager


def test_inode_manager_lifecycle():
    manager = InodeManager()

    inode = manager.create_inode(
        block_id="1/2/3/4-5-6-7",
        key_hash="abc123",
        size=4096,
        checksum="deadbeef",
    )

    assert isinstance(inode, Inode)
    assert inode.block_id == "1/2/3/4-5-6-7"
    assert inode.ref_count == 1
    assert inode.key_hash == "abc123"
    assert inode.size == 4096
    assert inode.mime_type == "application/octet-stream"
    assert inode.checksum == "deadbeef"
    assert inode.created_time > 0

    assert manager.get_inode(inode.inode_id) == inode

    manager.increment_ref_count(inode.inode_id)
    assert manager.get_inode(inode.inode_id).ref_count == 2

    remaining = manager.decrement_ref_count(inode.inode_id)
    assert remaining == 1
    remaining = manager.decrement_ref_count(inode.inode_id)
    assert remaining == 0

    manager.delete_inode(inode.inode_id)
    assert manager.get_inode(inode.inode_id) is None

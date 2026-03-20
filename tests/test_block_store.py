import logging

import pytest
from cryptography.exceptions import InvalidTag

from enc_ext_vfs.block_store import BlockStore
from enc_ext_vfs.key_manager import KeyManager


@pytest.fixture
def key_manager(tmp_path):
    return KeyManager(str(tmp_path / "keys"))


@pytest.fixture
def block_store(tmp_path, key_manager):
    return BlockStore(str(tmp_path / "vfs"), key_manager=key_manager)


def test_block_store_roundtrip_and_header_ops(block_store, key_manager):
    key_hash = key_manager.register_key("owner", friendly_name="phase3")
    block_id = block_store.allocate_block_id()
    payload = b"phase3 data"

    block_store.write_block(block_id, payload, key_hash)
    assert block_store.read_block(block_id, key_hash) == payload
    assert block_store.parity_path(block_id).exists()

    header = {"inode_id": "inode-1", "block_id": block_id, "key_hash": key_hash, "size": len(payload)}
    block_store.write_header(block_id, header)
    assert block_store.read_header(block_id) == header
    assert block_store.header_parity_path(block_id).exists()

    wrong_key_hash = key_manager.register_key("intruder", friendly_name="wrong")
    with pytest.raises(InvalidTag):
        block_store.read_block(block_id, wrong_key_hash)

    block_store.delete_block(block_id)
    assert not block_store.block_path(block_id).exists()
    assert not block_store.header_path(block_id).exists()
    assert not block_store.parity_path(block_id).exists()
    assert not block_store.header_parity_path(block_id).exists()


def test_allocate_block_ids_are_unique(block_store):
    block_ids = {block_store.allocate_block_id() for _ in range(20)}
    assert len(block_ids) == 20


def test_reed_solomon_recovery_handles_missing_and_corrupt_payloads(block_store, key_manager, caplog):
    caplog.set_level(logging.WARNING)
    key_hash = key_manager.register_key("owner", friendly_name="resilient")
    block_id = block_store.allocate_block_id()
    payload = b"recover me from corruption"

    block_store.write_block(block_id, payload, key_hash)
    block_path = block_store.block_path(block_id)

    block_path.unlink()
    assert block_store.read_block(block_id, key_hash) == payload
    assert "Recovering" in caplog.text

    block_path.write_bytes(b"totally broken ciphertext")
    assert block_store.read_block(block_id, key_hash) == payload
    assert "payload checksum does not match parity packet" in caplog.text


def test_corrupt_header_is_recovered_from_header_parity(block_store, key_manager, caplog):
    caplog.set_level(logging.WARNING)
    block_id = block_store.allocate_block_id()
    header = {"inode_id": "inode-2", "block_id": block_id, "key_hash": key_manager.get_default_key_hash(), "size": 1}

    block_store.write_header(block_id, header)
    header_path = block_store.header_path(block_id)
    header_path.write_bytes(b"corrupt header bytes")

    assert block_store.read_header(block_id) == header
    assert "Recovering" in caplog.text


def test_reed_solomon_parity_tolerates_multiple_corrupt_shards(block_store, key_manager):
    key_hash = key_manager.register_key("owner", friendly_name="multi-block")
    block_id = block_store.allocate_block_id()
    payload = b"multi shard recovery works" * 8

    block_store.write_block(block_id, payload, key_hash)
    parity_path = block_store.parity_path(block_id)
    parity_bytes = bytearray(parity_path.read_bytes())
    packet = block_store.parity_recovery.inspect_parity_data(bytes(parity_bytes), block_id)
    block_id_size = len(block_id.encode("utf-8"))
    shard_group_size = block_store.parity_recovery._CHECKSUM_SIZE + packet["shard_size"]
    shard_base_offset = (
        block_store.parity_recovery._PACKET_HEADER.size
        + block_id_size
        + block_store.parity_recovery._CHECKSUM_SIZE
    )
    for shard_index in (0, 4):
        shard_offset = shard_base_offset + (shard_index * shard_group_size) + block_store.parity_recovery._CHECKSUM_SIZE
        parity_bytes[shard_offset] ^= 0xFF
    parity_path.write_bytes(parity_bytes)

    block_store.block_path(block_id).unlink()
    assert block_store.read_block(block_id, key_hash) == payload


def test_corrupt_parity_packet_is_rebuilt_from_valid_payload(block_store, key_manager, caplog):
    caplog.set_level(logging.WARNING)
    key_hash = key_manager.register_key("owner", friendly_name="valid-payload")
    block_id = block_store.allocate_block_id()
    payload = b"payload remains readable"

    block_store.write_block(block_id, payload, key_hash)
    parity_path = block_store.parity_path(block_id)
    parity_path.write_text("not json at all")

    assert block_store.read_block(block_id, key_hash) == payload
    assert "Rebuilt parity" in caplog.text

    block_store.block_path(block_id).unlink()
    assert block_store.read_block(block_id, key_hash) == payload


def test_missing_parity_sidecar_is_rebuilt_from_valid_payload(block_store, key_manager, caplog):
    caplog.set_level(logging.WARNING)
    key_hash = key_manager.register_key("owner", friendly_name="missing-parity")
    block_id = block_store.allocate_block_id()

    block_store.write_block(block_id, b"secret data", key_hash)
    block_store.parity_path(block_id).unlink()

    assert block_store.read_block(block_id, key_hash) == b"secret data"
    assert block_store.parity_path(block_id).exists()
    assert "parity sidecar is missing" in caplog.text


def test_wrong_key_does_not_trigger_recovery_when_payload_is_valid(block_store, key_manager, caplog):
    caplog.set_level(logging.WARNING)
    owner_key_hash = key_manager.register_key("owner", friendly_name="owner-key")
    wrong_key_hash = key_manager.register_key("guest", friendly_name="guest-key")
    block_id = block_store.allocate_block_id()

    block_store.write_block(block_id, b"secret", owner_key_hash)
    with pytest.raises(InvalidTag):
        block_store.read_block(block_id, wrong_key_hash)
    assert "Decrypt failed" in caplog.text
    assert "attempting parity recovery" not in caplog.text

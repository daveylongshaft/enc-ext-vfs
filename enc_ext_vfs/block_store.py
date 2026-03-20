from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from .crypto import CryptoEngine
from .parity_recovery import ParityRecovery

logger = logging.getLogger(__name__)


class BlockStore:
    """Read and write encrypted VFS data blocks and headers on disk."""

    def __init__(self, root_path: str, key_manager=None, parity_recovery: Optional[ParityRecovery] = None):
        self.root_path = Path(root_path)
        self.root_path.mkdir(parents=True, exist_ok=True)
        self.key_manager = key_manager
        self.parity_recovery = parity_recovery or ParityRecovery()

    def allocate_block(self) -> str:
        return self.allocate_block_id().replace("/", "-")

    def allocate_block_id(self) -> str:
        block_uuid = str(uuid4())
        parts = block_uuid.split("-")
        return f"{parts[0]}/{parts[1]}/{parts[2]}/{parts[3]}-{parts[4]}"

    def block_path(self, block_id: str) -> Path:
        normalized = block_id.strip("/")
        if "/" in normalized:
            return self.root_path / normalized
        return self._get_path_from_address(normalized)

    def header_path(self, block_id: str) -> Path:
        return Path(f"{self.block_path(block_id)}.h")

    def parity_path(self, block_id: str) -> Path:
        return Path(f"{self.block_path(block_id)}.parity")

    def header_parity_path(self, block_id: str) -> Path:
        return Path(f"{self.header_path(block_id)}.parity")

    def _get_path_from_address(self, address: str) -> Path:
        parts = address.split("-")
        if len(parts) != 8:
            raise ValueError(f"Invalid block address format: {address}")
        return self.root_path.joinpath(*parts[:3]) / "-".join(parts[3:])

    def _get_address_from_path(self, path: Path) -> str:
        relative_path = path.relative_to(self.root_path)
        parts = list(relative_path.parts)
        if len(parts) != 4:
            raise ValueError(f"Invalid block path: {path}")
        return f"{parts[0]}/{parts[1]}/{parts[2]}/{parts[3]}"

    def _resolve_storage_bytes(self, payload: bytes, key_hash: Optional[str]) -> bytes:
        if key_hash is None:
            return payload
        if self.key_manager is None:
            raise ValueError("Encrypted block operations require a key manager.")
        key = self.key_manager.get_key(key_hash)
        return CryptoEngine.encrypt(payload, key)

    def _decode_storage_bytes(self, payload: bytes, key_hash: Optional[str]) -> bytes:
        if key_hash is None:
            return payload
        if self.key_manager is None:
            raise ValueError("Encrypted block operations require a key manager.")
        key = self.key_manager.get_key(key_hash)
        return CryptoEngine.decrypt(payload, key)

    def _write_payload_with_parity(self, path: Path, parity_path: Path, parity_label: str, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(payload)
        with open(parity_path, "wb") as handle:
            handle.write(self.parity_recovery.create_parity_data(payload, parity_label))
        logger.debug("Wrote payload %s and parity %s", path, parity_path)

    def _repair_parity_from_payload(self, parity_path: Path, parity_label: str, payload: bytes, reason: str) -> None:
        parity_path.parent.mkdir(parents=True, exist_ok=True)
        with open(parity_path, "wb") as handle:
            handle.write(self.parity_recovery.create_parity_data(payload, parity_label))
        logger.warning("Rebuilt parity for %s because %s", parity_label, reason)

    def _recover_payload_from_parity(self, path: Path, parity_path: Path, parity_label: str, reason: str) -> bytes:
        if not parity_path.exists():
            raise FileNotFoundError(f"Parity not found for {parity_label}")
        with open(parity_path, "rb") as handle:
            parity_bytes = handle.read()
        logger.warning("Recovering %s from parity because %s", parity_label, reason)
        recovered = self.parity_recovery.recover_payload(parity_bytes, parity_label)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(recovered)
        return recovered

    def _read_payload_with_parity(self, path: Path, parity_path: Path, parity_label: str) -> tuple[bytes, bool]:
        try:
            with open(path, "rb") as handle:
                payload = handle.read()
        except FileNotFoundError:
            recovered = self._recover_payload_from_parity(path, parity_path, parity_label, "payload file is missing")
            return recovered, True

        if parity_path.exists():
            with open(parity_path, "rb") as handle:
                parity_bytes = handle.read()
            parity_match = self.parity_recovery.payload_matches_packet(payload, parity_bytes, parity_label)
            if parity_match is False:
                recovered = self._recover_payload_from_parity(path, parity_path, parity_label, "payload checksum does not match parity packet")
                return recovered, True
            if parity_match is None:
                self._repair_parity_from_payload(parity_path, parity_label, payload, "existing parity packet is unreadable")
                return payload, True
            return payload, True

        self._repair_parity_from_payload(parity_path, parity_label, payload, "parity sidecar is missing")
        return payload, True

    def write_block(self, block_id: str, payload: bytes, key_hash: Optional[str] = None) -> None:
        stored = self._resolve_storage_bytes(payload, key_hash)
        self._write_payload_with_parity(self.block_path(block_id), self.parity_path(block_id), block_id, stored)

    def read_block(self, block_id: str, key_hash: Optional[str] = None) -> bytes:
        stored, payload_validated = self._read_payload_with_parity(self.block_path(block_id), self.parity_path(block_id), block_id)
        try:
            return self._decode_storage_bytes(stored, key_hash)
        except Exception as exc:
            logger.warning("Decrypt failed for %s with validated=%s payload: %s", block_id, payload_validated, exc)
            raise

    def write_header(self, block_id: str, header_dict: dict) -> None:
        if self.key_manager is None:
            raise ValueError("Header operations require a key manager.")
        server_key = self.key_manager.get_server_key()
        encrypted = CryptoEngine.encrypt(json.dumps(header_dict, sort_keys=True).encode("utf-8"), server_key)
        self._write_payload_with_parity(
            self.header_path(block_id),
            self.header_parity_path(block_id),
            f"{block_id}.h",
            encrypted,
        )

    def read_header(self, block_id: str) -> dict:
        if self.key_manager is None:
            raise ValueError("Header operations require a key manager.")
        path = self.header_path(block_id)
        parity_path = self.header_parity_path(block_id)
        encrypted, _ = self._read_payload_with_parity(path, parity_path, f"{block_id}.h")
        for server_key in self.key_manager.get_all_server_keys():
            try:
                plaintext = CryptoEngine.decrypt(encrypted, server_key)
                return json.loads(plaintext.decode("utf-8"))
            except Exception as exc:
                logger.debug("Header decrypt attempt failed for %s: %s", block_id, exc)
                continue

        logger.error("Cannot decrypt header for %s even after parity validation", block_id)
        raise ValueError(f"Cannot decrypt header: {block_id}")

    def delete_block(self, block_id: str) -> None:
        for path in [
            self.block_path(block_id),
            self.parity_path(block_id),
            self.header_path(block_id),
            self.header_parity_path(block_id),
        ]:
            if path.exists():
                path.unlink()
                self._cleanup_empty_dirs(path.parent)

    def _cleanup_empty_dirs(self, start: Path) -> None:
        current = start
        while current != self.root_path:
            try:
                next(current.iterdir())
                break
            except StopIteration:
                current.rmdir()
                current = current.parent
            except FileNotFoundError:
                current = current.parent
            except OSError:
                break

    def list_blocks(self) -> List[str]:
        block_ids: List[str] = []
        for path in self.root_path.rglob("*"):
            if not path.is_file():
                continue
            if path.name.endswith(".h") or path.name.endswith(".parity"):
                continue
            try:
                block_ids.append(self._get_address_from_path(path))
            except ValueError:
                continue
        return sorted(block_ids)

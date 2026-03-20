from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Union

from .acl import AccessControl
from .crypto import CryptoEngine


class KeyManager:
    """Manage global/server keys and per-key access control."""

    _GLOBAL_KEY_FILENAME = "global.key"
    _KEY_METADATA_FILENAME = "keys.json"

    def __init__(self, storage_path: str):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.global_key_path = self.storage_path / self._GLOBAL_KEY_FILENAME
        self.key_metadata_path = self.storage_path / self._KEY_METADATA_FILENAME

        self._acl = AccessControl(storage_path)
        self._keys = self._load_key_metadata()
        self._global_key_locked = False

        if not self.global_key_path.exists():
            self._generate_global_key()

    def _load_key_metadata(self) -> Dict[str, Dict[str, str]]:
        if self.key_metadata_path.exists():
            with open(self.key_metadata_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        return {}

    def _save_key_metadata(self) -> None:
        tmp_path = self.key_metadata_path.with_suffix(f"{self.key_metadata_path.suffix}.tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(self._keys, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            tmp_path.replace(self.key_metadata_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def _generate_global_key(self) -> None:
        if self._global_key_locked:
            raise PermissionError("Global key is locked and cannot be changed.")
        self.set_global_key(CryptoEngine.generate_key())

    def _store_key(self, key_hash: str, key: bytes, owner: str, friendly_name: str = "", description: str = "") -> str:
        key_path = self.storage_path / f"{key_hash}.key"
        with open(key_path, "wb") as handle:
            handle.write(key)

        self._keys[key_hash] = {
            "owner": owner,
            "name": friendly_name,
            "description": description,
        }
        self._save_key_metadata()
        self._acl.grant(key_hash, owner)
        return key_hash

    def get_global_key(self) -> bytes:
        with open(self.global_key_path, "rb") as handle:
            return handle.read()

    def get_server_key(self) -> bytes:
        return self.get_global_key()

    def get_all_server_keys(self) -> List[bytes]:
        return [self.get_global_key()]

    def get_default_key_hash(self) -> str:
        return CryptoEngine.key_hash(self.get_global_key())

    def register_key(self, owner: str, friendly_name: str = "", description: str = "") -> str:
        key = CryptoEngine.generate_key()
        return self.register_external_key(owner, key, friendly_name=friendly_name, description=description)

    def register_external_key(
        self,
        owner: str,
        key: bytes,
        friendly_name: str = "",
        description: str = "",
    ) -> str:
        if len(key) != CryptoEngine._AES_KEY_BYTES:
            raise ValueError("External keys must be 32 bytes for AES-256-GCM.")
        key_hash = CryptoEngine.key_hash(key)
        return self._store_key(key_hash, key, owner, friendly_name, description)

    def get_key_by_hash(self, key_hash: str) -> Optional[bytes]:
        if key_hash == self.get_default_key_hash():
            return self.get_global_key()

        key_path = self.storage_path / f"{key_hash}.key"
        if key_path.exists():
            with open(key_path, "rb") as handle:
                return handle.read()
        return None

    def get_key(self, key_ref: Union[str, bytes]) -> bytes:
        if isinstance(key_ref, bytes):
            return key_ref

        key = self.get_key_by_hash(key_ref)
        if key is None:
            raise FileNotFoundError(f"Key not found: {key_ref}")
        return key

    def get_key_for_read(self, key_hash: str, requester: str) -> bytes:
        if requester == "root":
            return self.get_key(key_hash)

        global_key_hash = self.get_default_key_hash()
        if key_hash == global_key_hash:
            return self.get_global_key()

        metadata = self._keys.get(key_hash)
        if not metadata:
            raise PermissionError("Key not found.")

        is_owner = metadata["owner"] == requester
        has_acl = self._acl.check(key_hash, requester)
        if not (is_owner or has_acl):
            raise PermissionError(f"User '{requester}' is not authorized for key '{key_hash}'.")

        return self.get_key(key_hash)

    def can_access(self, key_hash: str, requester: Union[str, bytes, None]) -> bool:
        if requester is None:
            return False
        if isinstance(requester, bytes):
            return CryptoEngine.key_hash(requester) == key_hash
        if requester == "root" or requester == key_hash:
            return True
        try:
            self.get_key_for_read(key_hash, requester)
            return True
        except (PermissionError, FileNotFoundError):
            return False

    def authorize_user(self, key_hash: str, owner: str, user: str) -> None:
        metadata = self._keys.get(key_hash)
        if not metadata:
            raise PermissionError("Key not found.")
        if metadata["owner"] != owner and owner != "root":
            raise PermissionError("Only the key owner can grant access.")
        self._acl.grant(key_hash, user)

    def revoke_user(self, key_hash: str, owner: str, user: str) -> None:
        metadata = self._keys.get(key_hash)
        if not metadata:
            raise PermissionError("Key not found.")
        if metadata["owner"] != owner and owner != "root":
            raise PermissionError("Only the key owner can revoke access.")
        self._acl.revoke(key_hash, user)

    def list_keys(self, owner: Optional[str] = None) -> List[dict]:
        keys: List[dict] = []
        for key_hash, metadata in sorted(self._keys.items()):
            if owner is None or metadata["owner"] == owner:
                keys.append(
                    {
                        "hash": key_hash,
                        "name": metadata.get("name", ""),
                        "description": metadata.get("description", ""),
                        "owner": metadata.get("owner", ""),
                    }
                )
        return keys

    def set_global_key(self, key: bytes) -> None:
        if self._global_key_locked:
            raise PermissionError("Global key is locked and cannot be changed.")
        if len(key) != CryptoEngine._AES_KEY_BYTES:
            raise ValueError("Invalid key length for global key.")
        with open(self.global_key_path, "wb") as handle:
            handle.write(key)

    def lock_global_key(self) -> None:
        self._global_key_locked = True

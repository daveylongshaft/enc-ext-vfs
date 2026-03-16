import json
from pathlib import Path
from typing import Optional, List, Dict

from .crypto import CryptoEngine
from .acl import AccessControl

class KeyManager:
    """
    Manages the key hierarchy: global key, server keys, private keys with ACLs.
    """
    _GLOBAL_KEY_FILENAME = "global.key"
    _KEY_METADATA_FILENAME = "keys.json"

    def __init__(self, storage_path: str):
        """Initialize key manager. Generates global key if none exists."""
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.global_key_path = self.storage_path / self._GLOBAL_KEY_FILENAME
        self.key_metadata_path = self.storage_path / self._KEY_METADATA_FILENAME

        self._acl = AccessControl(storage_path)
        self._keys = self._load_key_metadata()
        self._global_key_locked = False

        if not self.global_key_path.exists():
            self._generate_global_key()

    def _load_key_metadata(self) -> Dict[str, Dict]:
        """Loads key metadata from its JSON file."""
        if self.key_metadata_path.exists():
            with open(self.key_metadata_path, "r") as f:
                return json.load(f)
        return {}

    def _save_key_metadata(self) -> None:
        """Saves key metadata to its JSON file."""
        with open(self.key_metadata_path, "w") as f:
            json.dump(self._keys, f, indent=2)

    def _generate_global_key(self) -> None:
        """Generates and persists a new global key."""
        if self._global_key_locked:
            raise PermissionError("Global key is locked and cannot be changed.")
        key = CryptoEngine.generate_key()
        with open(self.global_key_path, "wb") as f:
            f.write(key)

    def get_global_key(self) -> bytes:
        """Return the global key (generated on first call, persisted)."""
        with open(self.global_key_path, "rb") as f:
            return f.read()

    def register_key(self, owner: str, friendly_name: str = "", description: str = "") -> str:
        """Generate a new private key for owner. Returns key hash."""
        key = CryptoEngine.generate_key()
        key_hash = CryptoEngine.key_hash(key)
        key_path = self.storage_path / f"{key_hash}.key"
        with open(key_path, "wb") as f:
            f.write(key)

        self._keys[key_hash] = {
            "owner": owner,
            "name": friendly_name,
            "description": description,
        }
        self._save_key_metadata()
        self._acl.grant(key_hash, owner) # Owner always has access
        return key_hash

    def get_key_by_hash(self, key_hash: str) -> Optional[bytes]:
        """Retrieve key by its hash. Returns None if not found."""
        key_path = self.storage_path / f"{key_hash}.key"
        if key_path.exists():
            with open(key_path, "rb") as f:
                return f.read()
        return None

    def get_key_for_read(self, key_hash: str, requester: str) -> Optional[bytes]:
        """
        Get key for decryption if requester is authorized.
        Checks: is requester the owner, in the ACL, or an ircop?
        Global key is always accessible to all requesters.
        Returns key bytes or raises PermissionError.
        """
        # Global key is accessible to everyone
        global_key = self.get_global_key()
        if CryptoEngine.key_hash(global_key) == key_hash:
            return global_key

        metadata = self._keys.get(key_hash)
        if not metadata:
            raise PermissionError("Key not found.")

        is_owner = metadata["owner"] == requester
        has_acl = self._acl.check(key_hash, requester)

        if is_owner or has_acl:
            key = self.get_key_by_hash(key_hash)
            if key:
                return key
            else:
                raise FileNotFoundError("Key data not found on disk.")
        
        raise PermissionError(f"User '{requester}' is not authorized for key '{key_hash}'.")

    def authorize_user(self, key_hash: str, owner: str, user: str) -> None:
        """Owner grants user access to use this key."""
        metadata = self._keys.get(key_hash)
        if not metadata:
            raise PermissionError("Key not found.")
        if metadata["owner"] != owner:
            raise PermissionError("Only the key owner can grant access.")
        self._acl.grant(key_hash, user)

    def revoke_user(self, key_hash: str, owner: str, user: str) -> None:
        """Owner revokes user access to this key."""
        metadata = self._keys.get(key_hash)
        if not metadata:
            raise PermissionError("Key not found.")
        if metadata["owner"] != owner:
            raise PermissionError("Only the key owner can revoke access.")
        self._acl.revoke(key_hash, user)

    def list_keys(self, owner: Optional[str] = None) -> List[dict]:
        """
        List keys, optionally filtered by owner.
        Returns: [{"hash": ..., "name": ..., "description": ..., "owner": ...}]
        """
        key_list = []
        for key_hash, metadata in self._keys.items():
            if owner is None or metadata["owner"] == owner:
                key_list.append({
                    "hash": key_hash,
                    "name": metadata.get("name", ""),
                    "description": metadata.get("description", ""),
                    "owner": metadata.get("owner", ""),
                })
        return key_list

    def set_global_key(self, key: bytes) -> None:
        """
        Set global key (used when slave adopts master's key).
        Refuses if global key is locked.
        """
        if self._global_key_locked:
            raise PermissionError("Global key is locked and cannot be changed.")
        if len(key) != CryptoEngine._AES_KEY_BYTES:
            raise ValueError(f"Invalid key length for global key.")
        
        with open(self.global_key_path, "wb") as f:
            f.write(key)

    def lock_global_key(self) -> None:
        """
        Lock the global key. Prevents set_global_key from changing it.
        Used when master establishes itself.
        """
        self._global_key_locked = True

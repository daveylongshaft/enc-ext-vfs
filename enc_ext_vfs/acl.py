import json
from pathlib import Path

class AccessControl:
    """
    Access control for key-based authorization.
    This is a simplified implementation. A real system might use a proper database
    or integrate with an existing user management system.
    """
    def __init__(self, storage_path: str):
        """Initialize ACL storage."""
        self.storage_file = Path(storage_path) / "acl.json"
        self._acls = self._load()

    def _load(self) -> dict:
        """Load ACLs from the storage file."""
        if self.storage_file.exists():
            with open(self.storage_file, "r") as f:
                return json.load(f)
        return {}

    def _save(self) -> None:
        """Save the current ACLs to the storage file."""
        with open(self.storage_file, "w") as f:
            json.dump(self._acls, f, indent=2)

    def grant(self, key_hash: str, user: str) -> None:
        """Grant user access to key."""
        if key_hash not in self._acls:
            self._acls[key_hash] = []
        if user not in self._acls[key_hash]:
            self._acls[key_hash].append(user)
        self._save()

    def revoke(self, key_hash: str, user: str) -> None:
        """Revoke user access to key."""
        if key_hash in self._acls and user in self._acls[key_hash]:
            self._acls[key_hash].remove(user)
            if not self._acls[key_hash]:
                del self._acls[key_hash]
            self._save()

    def check(self, key_hash: str, user: str) -> bool:
        """Check if user has access to key."""
        if self.is_ircop(user):
            return True
        return key_hash in self._acls and user in self._acls[key_hash]

    def get_users(self, key_hash: str) -> list[str]:
        """List all users authorized for this key."""
        return self._acls.get(key_hash, [])

    def is_ircop(self, user: str) -> bool:
        """
        Check if user is an IRC operator (has elevated access).
        This is a placeholder. In the actual CSC system, this would query the server.
        For this standalone module, we'll use a simple convention.
        """
        # A real implementation would involve a call to the IRC server state.
        # For now, we assume a user string might contain a flag or be in a predefined list.
        # Let's keep it simple: for now, no one is an IRCOP in this standalone module.
        # This method is here to match the required interface.
        return False

import json
import time
import hashlib
from typing import List, Optional, Dict, Any

class FileHeader:
    """
    Self-describing file headers / metadata.
    This class represents the metadata of a file, which is stored in the first
    block of the file's block chain. It can be serialized to and from JSON.
    """
    def __init__(self,
                 filename: str,
                 file_size: int,
                 block_size: int,
                 mime_type: str,
                 node_id: str,
                 key_hash: str,
                 block_addresses: List[str],
                 created: Optional[float] = None,
                 accessed: Optional[float] = None,
                 modified: Optional[float] = None,
                 linked_files: Optional[List[str]] = None,
                 link_type: Optional[str] = None,
                 checksum: Optional[str] = None):
        self.filename = filename
        self.file_size = file_size
        self.block_size = block_size
        self.mime_type = mime_type
        self.node_id = node_id
        self.key_hash = key_hash
        self.block_addresses = block_addresses
        
        current_time = time.time()
        self.created = created if created is not None else current_time
        self.accessed = accessed if accessed is not None else current_time
        self.modified = modified if modified is not None else current_time

        self.linked_files = linked_files if linked_files is not None else []
        self.link_type = link_type
        self.checksum = checksum if checksum is not None else ""

    def to_json(self) -> str:
        """Serializes the header to a JSON string."""
        return json.dumps(self.__dict__, sort_keys=True)

    @classmethod
    def from_json(cls, json_str: str) -> 'FileHeader':
        """Deserializes a header from a JSON string."""
        data = json.loads(json_str)
        return cls(**data)

    def update_checksum(self, plaintext_data: bytes):
        """Calculates and updates the SHA-256 checksum of the plaintext data."""
        self.checksum = hashlib.sha256(plaintext_data).hexdigest()

    def verify_checksum(self, plaintext_data: bytes) -> bool:
        """Verifies the integrity of the plaintext data against the stored checksum."""
        return self.checksum == hashlib.sha256(plaintext_data).hexdigest()

    def __repr__(self) -> str:
        return f"<FileHeader(filename='{self.filename}', size={self.file_size})>"

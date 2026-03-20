from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Inode:
    """In-memory inode metadata for a single encrypted VFS block."""

    inode_id: str
    block_id: str
    ref_count: int
    key_hash: str
    size: int
    mime_type: str
    checksum: str
    created_time: float

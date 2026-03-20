from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FATEntry:
    """Per-link metadata stored in the VFS file allocation table."""

    path: str
    inode_id: str
    permissions: int
    created_time: float
    modified_time: float

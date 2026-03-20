from __future__ import annotations

import time
from typing import Dict, Optional
from uuid import uuid4

from .inode import Inode


class InodeManager:
    """Manage the lifecycle of in-memory inode records."""

    def __init__(self) -> None:
        self.inodes: Dict[str, Inode] = {}

    def create_inode(
        self,
        block_id: str,
        key_hash: str,
        size: int,
        checksum: str,
        mime_type: str = "application/octet-stream",
    ) -> Inode:
        inode = Inode(
            inode_id=str(uuid4()),
            block_id=block_id,
            ref_count=1,
            key_hash=key_hash,
            size=size,
            mime_type=mime_type,
            checksum=checksum,
            created_time=time.time(),
        )
        self.inodes[inode.inode_id] = inode
        return inode

    def get_inode(self, inode_id: str) -> Optional[Inode]:
        return self.inodes.get(inode_id)

    def delete_inode(self, inode_id: str) -> None:
        self.inodes.pop(inode_id, None)

    def increment_ref_count(self, inode_id: str) -> Inode:
        inode = self.inodes[inode_id]
        inode.ref_count += 1
        return inode

    def decrement_ref_count(self, inode_id: str) -> int:
        inode = self.inodes[inode_id]
        if inode.ref_count == 0:
            raise ValueError(f"Inode {inode_id} already has zero references")

        inode.ref_count -= 1
        return inode.ref_count

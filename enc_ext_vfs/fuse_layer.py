from __future__ import annotations

import stat
import time
from dataclasses import dataclass
from typing import Dict, List

from .requester import resolve_requester
from .vfs import VFS


@dataclass
class EntryAttributes:
    st_ino: int = 0
    st_mode: int = 0
    st_size: int = 0
    st_mtime_ns: int = 0
    st_ctime_ns: int = 0


@dataclass
class FileInfo:
    fh: int


class CSCFUSEAdapter:
    """Small FUSE-like adapter used for unit testing the VFS mount layer."""

    def __init__(self, vfs: VFS, requester: str | None = None):
        self.vfs = vfs
        self.requester = requester or resolve_requester()
        self.path_inode_cache: Dict[str, int] = {}
        self.inode_path_cache: Dict[int, str] = {1: "/"}

    def getattr(self, inode: int):
        path = self._inode_to_path(inode)
        if path == "/":
            return EntryAttributes(st_ino=1, st_mode=stat.S_IFDIR | 0o755)
        fat_entry = self.vfs.get_fat_entry(path)
        inode_obj = self.vfs.inode_manager.get_inode(fat_entry.inode_id) if fat_entry else None
        if fat_entry is None or inode_obj is None:
            raise FileNotFoundError(path)
        return EntryAttributes(
            st_ino=inode,
            st_mode=self._mode_from_permissions(fat_entry.permissions),
            st_size=inode_obj.size,
            st_mtime_ns=int(fat_entry.modified_time * 1e9),
            st_ctime_ns=int(fat_entry.created_time * 1e9),
        )

    def readdir(self, inode: int) -> List[str]:
        path = self._inode_to_path(inode)
        return self.vfs.list_dir(path)

    def open(self, inode: int, flags: int = 0):
        return FileInfo(fh=inode)

    def read(self, fh: int, offset: int, size: int) -> bytes:
        path = self._inode_to_path(fh)
        plaintext = self.vfs.read_file(path, self.requester)
        return plaintext[offset : offset + size]

    def write(self, fh: int, offset: int, data: bytes) -> int:
        path = self._inode_to_path(fh)
        try:
            existing = self.vfs.read_file(path, self.requester)
        except FileNotFoundError:
            existing = b""
        if offset > len(existing):
            existing = existing + (b"\0" * (offset - len(existing)))
        merged = existing[:offset] + data + existing[offset + len(data) :]
        self.vfs.write(path, merged)
        return len(data)

    def setattr(self, inode: int, mode: int):
        path = self._inode_to_path(inode)
        fat_entry = self.vfs.get_fat_entry(path)
        if fat_entry is None:
            raise FileNotFoundError(path)
        fat_entry.permissions = self._mode_to_permissions(mode)
        fat_entry.modified_time = time.time()
        self.vfs.save_fat()
        self.vfs._sync_inode_header(fat_entry.inode_id)
        return self.getattr(inode)

    def _inode_to_path(self, inode: int) -> str:
        if inode in self.inode_path_cache:
            return self.inode_path_cache[inode]
        raise FileNotFoundError(f"Unknown inode: {inode}")

    def _path_to_inode(self, path: str) -> int:
        if path not in self.path_inode_cache:
            inode_number = max(self.inode_path_cache) + 1
            self.path_inode_cache[path] = inode_number
            self.inode_path_cache[inode_number] = path
        return self.path_inode_cache[path]

    def _mode_from_permissions(self, perms: int) -> int:
        mode = stat.S_IFREG
        if perms & 0o400:
            mode |= stat.S_IRUSR
        if perms & 0o200:
            mode |= stat.S_IWUSR
        return mode

    def _mode_to_permissions(self, mode: int) -> int:
        perms = 0
        if mode & stat.S_IRUSR:
            perms |= 0o400
        if mode & stat.S_IWUSR:
            perms |= 0o200
        return perms

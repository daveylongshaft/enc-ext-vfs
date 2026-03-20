from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
import time
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Union

from .block_store import BlockStore
from .fat_entry import FATEntry
from .header import FileHeader
from .inode import Inode
from .inode_manager import InodeManager
from .key_manager import KeyManager
from .parity_recovery import ParityRecovery

logger = logging.getLogger(__name__)


class IntegrityError(IOError):
    """Raised when stored file contents fail checksum validation."""


class VFS:
    """Inode-based encrypted virtual filesystem."""

    def __init__(self, vfs_root: str, node_id: str = "local", key_manager: Optional[KeyManager] = None):
        self.node_id = node_id
        self.vfs_root = Path(vfs_root)
        self.vfs_root.mkdir(parents=True, exist_ok=True)
        self.fat_file = self.vfs_root / "fat.json"
        self.key_manager = key_manager or KeyManager(str(self.vfs_root))
        self._key_manager = self.key_manager
        self.parity_recovery = ParityRecovery()
        self.block_store = BlockStore(str(self.vfs_root), key_manager=self.key_manager, parity_recovery=self.parity_recovery)
        self._block_store = self.block_store
        self.inode_manager = InodeManager()
        self.fat: Dict[str, FATEntry] = {}
        self.load_fat()
        self._load_inodes_from_headers()
        self._recount_refs()

    def load_fat(self) -> None:
        self.fat = {}
        if self.fat_file.exists():
            with open(self.fat_file, "r", encoding="utf-8") as handle:
                loaded = json_load(handle)
            for path, entry in loaded.items():
                if isinstance(entry, dict):
                    self.fat[path] = FATEntry(**entry)
                    continue

                if isinstance(entry, str):
                    fat_entry = self._load_legacy_fat_entry(path, entry)
                    if fat_entry is not None:
                        self.fat[path] = fat_entry
        self.fat = dict(sorted(self.fat.items()))

    def _load_legacy_fat_entry(self, path: str, block_id: str) -> Optional[FATEntry]:
        try:
            header = self.block_store.read_header(block_id)
        except (FileNotFoundError, ValueError, KeyError):
            return None

        entry = header.get("entries", {}).get(path)
        if entry is None:
            now = header.get("created_time", time.time())
            permissions = 0o600
            created_time = now
            modified_time = now
        else:
            permissions = entry.get("permissions", 0o600)
            created_time = entry.get("created_time", header.get("created_time", time.time()))
            modified_time = entry.get("modified_time", created_time)

        return FATEntry(
            path=path,
            inode_id=header["inode_id"],
            permissions=permissions,
            created_time=created_time,
            modified_time=modified_time,
        )

    def save_fat(self) -> None:
        payload = {path: dataclasses.asdict(entry) for path, entry in sorted(self.fat.items())}
        tmp_file = self.fat_file.with_suffix(f"{self.fat_file.suffix}.tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as handle:
                json_dump(payload, handle)
                handle.flush()
                os.fsync(handle.fileno())
            tmp_file.replace(self.fat_file)
        finally:
            if tmp_file.exists():
                tmp_file.unlink()

    def create_fat_entry(self, path: str, inode_id: str, permissions: int = 0o600) -> FATEntry:
        now = time.time()
        entry = FATEntry(path=path, inode_id=inode_id, permissions=permissions, created_time=now, modified_time=now)
        self.fat[path] = entry
        self.fat = dict(sorted(self.fat.items()))
        self._sync_inode_header(inode_id)
        logger.info("Created FAT entry %s -> %s", path, inode_id)
        self.save_fat()
        return entry

    def get_fat_entry(self, path: str) -> Optional[FATEntry]:
        return self.fat.get(path)

    def delete_fat_entry(self, path: str) -> None:
        entry = self.fat.pop(path, None)
        if entry is None:
            return
        self.fat = dict(sorted(self.fat.items()))
        inode = self.inode_manager.get_inode(entry.inode_id)
        if inode is not None:
            ref_count = self.inode_manager.decrement_ref_count(entry.inode_id)
            if ref_count == 0:
                self.block_store.delete_block(inode.block_id)
                self.inode_manager.delete_inode(entry.inode_id)
            else:
                self._sync_inode_header(entry.inode_id, save_fat=False)
        self.save_fat()
        logger.info("Deleted FAT entry %s", path)

    def _load_inodes_from_headers(self) -> None:
        self.inode_manager.inodes = {}
        for header_path in self.vfs_root.rglob("*.h"):
            try:
                block_id = self._block_id_from_header_path(header_path)
                header = self.block_store.read_header(block_id)
                inode = Inode(
                    inode_id=header["inode_id"],
                    block_id=header["block_id"],
                    ref_count=header.get("ref_count", 0),
                    key_hash=header["key_hash"],
                    size=header["size"],
                    mime_type=header["mime_type"],
                    checksum=header["checksum"],
                    created_time=header["created_time"],
                )
                self.inode_manager.inodes[inode.inode_id] = inode
            except Exception as exc:
                logger.warning("Skipping unreadable header %s during inode load: %s", header_path, exc)
                continue

    def _block_id_from_header_path(self, header_path: Path) -> str:
        relative = header_path.relative_to(self.vfs_root)
        parts = list(relative.parts)
        parts[-1] = parts[-1][:-2]
        return "/".join(parts)

    def _recount_refs(self) -> None:
        counts: Dict[str, int] = {inode_id: 0 for inode_id in self.inode_manager.inodes}
        for entry in self.fat.values():
            counts[entry.inode_id] = counts.get(entry.inode_id, 0) + 1
        for inode_id, inode in list(self.inode_manager.inodes.items()):
            inode.ref_count = counts.get(inode_id, 0)
            self._sync_inode_header(inode_id, save_fat=False)

    def _header_entries_for_inode(self, inode_id: str) -> Dict[str, dict]:
        return {
            path: {
                "permissions": entry.permissions,
                "created_time": entry.created_time,
                "modified_time": entry.modified_time,
            }
            for path, entry in self.fat.items()
            if entry.inode_id == inode_id
        }

    def _sync_inode_header(self, inode_id: str, save_fat: bool = True) -> None:
        inode = self.inode_manager.get_inode(inode_id)
        if inode is None:
            return
        entries = self._header_entries_for_inode(inode_id)
        header = {
            "inode_id": inode.inode_id,
            "block_id": inode.block_id,
            "key_hash": inode.key_hash,
            "size": inode.size,
            "checksum": inode.checksum,
            "mime_type": inode.mime_type,
            "created_time": inode.created_time,
            "ref_count": inode.ref_count,
            "entries": entries,
            "parity_data": {"method": "reed_solomon_shards_v1", "block_checksum": hashlib.sha256(inode.block_id.encode()).hexdigest()},
        }
        self.block_store.write_header(inode.block_id, header)
        if save_fat:
            self.save_fat()

    def create_file(
        self,
        path: str,
        plaintext: bytes,
        key_hash: Optional[str] = None,
        permissions: int = 0o600,
        mime_type: str = "application/octet-stream",
    ) -> Inode:
        if path in self.fat:
            raise FileExistsError(f"File already exists: {path}")
        file_key_hash = key_hash or self.key_manager.get_default_key_hash()
        block_id = self.block_store.allocate_block_id()
        checksum = hashlib.md5(plaintext).hexdigest()
        self.block_store.write_block(block_id, plaintext, file_key_hash)
        inode = self.inode_manager.create_inode(block_id, file_key_hash, len(plaintext), checksum, mime_type=mime_type)
        self.fat[path] = FATEntry(path=path, inode_id=inode.inode_id, permissions=permissions, created_time=time.time(), modified_time=time.time())
        self.fat = dict(sorted(self.fat.items()))
        self._sync_inode_header(inode.inode_id)
        logger.info("Created VFS file %s -> inode %s", path, inode.inode_id)
        return inode

    def read_file(self, path: str, requester: Union[str, bytes]) -> bytes:
        fat_entry = self.get_fat_entry(path)
        if fat_entry is None:
            raise FileNotFoundError(f"File not found: {path}")
        if not (fat_entry.permissions & 0o400):
            raise PermissionError(f"No read permission: {path}")
        inode = self.inode_manager.get_inode(fat_entry.inode_id)
        if inode is None:
            raise FileNotFoundError(f"Inode not found: {fat_entry.inode_id}")
        if not self.key_manager.can_access(inode.key_hash, requester):
            raise PermissionError(f"Cannot access key: {inode.key_hash}")
        plaintext = self.block_store.read_block(inode.block_id, inode.key_hash)
        if hashlib.md5(plaintext).hexdigest() != inode.checksum:
            logger.error("Checksum mismatch for %s (inode=%s)", path, inode.inode_id)
            raise IntegrityError(f"Checksum mismatch for {path}")
        logger.debug("Read VFS file %s", path)
        return plaintext

    def create_hardlink(
        self,
        src_path: str,
        dst_path: str,
        requester: Union[str, bytes],
        permissions: int = 0o600,
    ) -> FATEntry:
        if dst_path in self.fat:
            raise FileExistsError(f"Destination already exists: {dst_path}")
        src_fat = self.get_fat_entry(src_path)
        if src_fat is None:
            raise FileNotFoundError(f"Source not found: {src_path}")
        if not (src_fat.permissions & 0o400):
            raise PermissionError(f"Cannot read source: {src_path}")
        inode = self.inode_manager.get_inode(src_fat.inode_id)
        if inode is None:
            raise FileNotFoundError(f"Inode not found: {src_fat.inode_id}")
        if not self.key_manager.can_access(inode.key_hash, requester):
            raise PermissionError("Cannot access source key")
        self.inode_manager.increment_ref_count(inode.inode_id)
        entry = FATEntry(path=dst_path, inode_id=inode.inode_id, permissions=permissions, created_time=time.time(), modified_time=time.time())
        self.fat[dst_path] = entry
        self.fat = dict(sorted(self.fat.items()))
        self._sync_inode_header(inode.inode_id)
        logger.info("Created hardlink %s -> %s", dst_path, inode.inode_id)
        return entry

    def delete_file(self, path: str, requester: Union[str, bytes]) -> None:
        fat_entry = self.get_fat_entry(path)
        if fat_entry is None:
            raise FileNotFoundError(f"File not found: {path}")
        if not (fat_entry.permissions & 0o200):
            raise PermissionError(f"No write permission: {path}")
        inode = self.inode_manager.get_inode(fat_entry.inode_id)
        if inode is None:
            raise FileNotFoundError(f"Inode not found: {fat_entry.inode_id}")
        del self.fat[path]
        self.fat = dict(sorted(self.fat.items()))
        ref_count = self.inode_manager.decrement_ref_count(inode.inode_id)
        if ref_count == 0:
            self.block_store.delete_block(inode.block_id)
            self.inode_manager.delete_inode(inode.inode_id)
        else:
            self._sync_inode_header(inode.inode_id)
        self.save_fat()
        logger.info("Deleted VFS path %s", path)

    def copy_file(
        self,
        src_path: str,
        dst_path: str,
        src_requester: Union[str, bytes],
        dst_key: Optional[Union[str, bytes]] = None,
        permissions: int = 0o600,
    ) -> Inode:
        src_fat = self.get_fat_entry(src_path)
        if src_fat is None:
            raise FileNotFoundError(f"Source not found: {src_path}")
        if not (src_fat.permissions & 0o400):
            raise PermissionError(f"Cannot read source: {src_path}")
        src_inode = self.inode_manager.get_inode(src_fat.inode_id)
        if src_inode is None:
            raise FileNotFoundError(f"Inode not found: {src_fat.inode_id}")
        if not self.key_manager.can_access(src_inode.key_hash, src_requester):
            raise PermissionError("Cannot access source key")
        plaintext = self.block_store.read_block(src_inode.block_id, src_inode.key_hash)
        if isinstance(dst_key, bytes):
            dst_key_hash = self.key_manager.register_external_key(f"copy:{dst_path}", dst_key, friendly_name=dst_path)
        elif isinstance(dst_key, str):
            dst_key_hash = dst_key
        else:
            dst_key_hash = src_inode.key_hash
        return self.create_file(dst_path, plaintext, key_hash=dst_key_hash, permissions=permissions, mime_type=src_inode.mime_type)

    def write_symlink(
        self,
        path: str,
        target_uri: str,
        env_vars: Optional[Dict[str, str]] = None,
        setup_script: Optional[str] = None,
        key_hash: Optional[str] = None,
    ) -> Inode:
        lines = [target_uri]
        for key, value in (env_vars or {}).items():
            lines.append(f"env::{key}={value}")
        if setup_script:
            lines.append("setup::")
            lines.extend(setup_script.splitlines())
        content = ("\n".join(lines) + "\n").encode("utf-8")
        return self.create_file(path, content, key_hash=key_hash, permissions=0o400, mime_type="inode/symlink")

    def read_symlink(self, path: str, requester: Union[str, bytes]) -> dict:
        content = self.read_file(path, requester).decode("utf-8")
        lines = content.rstrip("\n").split("\n") if content else [""]
        target_uri = lines[0]
        env_vars: Dict[str, str] = {}
        setup_script_lines: List[str] = []
        in_setup = False
        for line in lines[1:]:
            if in_setup:
                setup_script_lines.append(line)
                continue
            if line.startswith("env::"):
                key, value = line[5:].split("=", 1)
                env_vars[key] = value
            elif line == "setup::":
                in_setup = True
        return {
            "target_uri": target_uri,
            "env_vars": env_vars,
            "setup_script": "\n".join(setup_script_lines) if setup_script_lines else None,
        }

    def rebuild_fat_from_headers(self) -> None:
        self.fat = {}
        self.inode_manager.inodes = {}
        for header_path in self.vfs_root.rglob("*.h"):
            try:
                block_id = self._block_id_from_header_path(header_path)
                header = self.block_store.read_header(block_id)
                inode = Inode(
                    inode_id=header["inode_id"],
                    block_id=header["block_id"],
                    ref_count=0,
                    key_hash=header["key_hash"],
                    size=header["size"],
                    mime_type=header["mime_type"],
                    checksum=header["checksum"],
                    created_time=header["created_time"],
                )
                self.inode_manager.inodes[inode.inode_id] = inode
                for path, entry in header.get("entries", {}).items():
                    self.fat[path] = FATEntry(
                        path=path,
                        inode_id=inode.inode_id,
                        permissions=entry["permissions"],
                        created_time=entry["created_time"],
                        modified_time=entry["modified_time"],
                    )
            except Exception as exc:
                logger.warning("Skipping unreadable header %s during FAT rebuild: %s", header_path, exc)
                continue
        self.fat = dict(sorted(self.fat.items()))
        self._recount_refs()
        self.save_fat()

    def exists(self, path: str) -> bool:
        return path in self.fat

    def stat(self, path: str) -> Optional[FileHeader]:
        fat_entry = self.get_fat_entry(path)
        if fat_entry is None:
            return None
        inode = self.inode_manager.get_inode(fat_entry.inode_id)
        if inode is None:
            return None
        return FileHeader(
            filename=path,
            file_size=inode.size,
            block_size=4096,
            mime_type=inode.mime_type,
            node_id=self.node_id,
            key_hash=inode.key_hash,
            block_addresses=[inode.block_id],
            created=inode.created_time,
            accessed=fat_entry.modified_time,
            modified=fat_entry.modified_time,
            checksum=inode.checksum,
        )

    def list_dir(self, prefix: str = "/") -> List[str]:
        if any("::" in path for path in self.fat) or "::" in prefix:
            normalized = prefix[:-2] if prefix.endswith("::") else prefix
            if normalized in {"", "/"}:
                normalized = ""
            normalized = normalized.strip(":")
            scan_prefix = f"{normalized}::" if normalized else ""
            results = []
            for path in sorted(self.fat):
                if scan_prefix and not path.startswith(scan_prefix):
                    continue
                relative = path[len(scan_prefix):] if scan_prefix else path
                child = relative.split("::", 1)[0]
                if child and child not in results:
                    results.append(child)
            return results

        if prefix in {"", "/"}:
            base = PurePosixPath("/")
        else:
            base = PurePosixPath(prefix)
        children = []
        for path in sorted(self.fat):
            candidate = PurePosixPath(path)
            try:
                relative = candidate.relative_to(base)
            except ValueError:
                continue
            if not relative.parts:
                continue
            child = relative.parts[0]
            if child not in children:
                children.append(child)
        return children

    def create(self, path: str, data: bytes, mime_type: str = "application/octet-stream", key_hash: Optional[str] = None) -> FileHeader:
        self.create_file(path, data, key_hash=key_hash, mime_type=mime_type)
        return self.stat(path)

    def read(self, path: str, requester: Union[str, bytes]) -> bytes:
        return self.read_file(path, requester)

    def write(self, path: str, data: bytes, key_hash: Optional[str] = None) -> FileHeader:
        if path in self.fat:
            existing = self.get_fat_entry(path)
            permissions = existing.permissions
            old_inode = self.inode_manager.get_inode(existing.inode_id)
            use_key_hash = key_hash or (old_inode.key_hash if old_inode else None)
            mime_type = old_inode.mime_type if old_inode else "application/octet-stream"
            self.delete_file(path, "root")
            self.create_file(path, data, key_hash=use_key_hash, permissions=permissions, mime_type=mime_type)
        else:
            self.create_file(path, data, key_hash=key_hash)
        return self.stat(path)

    def append(self, path: str, data: bytes) -> FileHeader:
        existing = self.read(path, "root") if path in self.fat else b""
        return self.write(path, existing + data)

    def delete(self, path: str) -> None:
        self.delete_file(path, "root")

    def rename(self, old_path: str, new_path: str) -> None:
        if old_path not in self.fat:
            raise FileNotFoundError(f"Source not found: {old_path}")
        if new_path in self.fat:
            raise FileExistsError(f"Destination already exists: {new_path}")
        entry = self.fat.pop(old_path)
        entry.path = new_path
        entry.modified_time = time.time()
        self.fat[new_path] = entry
        self.fat = dict(sorted(self.fat.items()))
        self._sync_inode_header(entry.inode_id)

    def copy(self, src_path: str, dst_path: str, key_hash: Optional[Union[str, bytes]] = None) -> FileHeader:
        self.copy_file(src_path, dst_path, "root", dst_key=key_hash)
        return self.stat(dst_path)

    def hard_link(self, target: str, link_name: str) -> None:
        self.create_hardlink(target, link_name, "root")

    def soft_link(self, target: str, link_name: str) -> None:
        self.create_file(link_name, target.encode("utf-8"), permissions=0o400, mime_type="inode/symlink")

    def verify_integrity(self) -> List[str]:
        issues: List[str] = []
        for path in sorted(self.fat):
            try:
                self.read_file(path, "root")
            except Exception as exc:
                issues.append(f"Error verifying '{path}': {exc}")
        return issues


VirtualFileSystem = VFS


def json_load(handle):
    import json

    return json.load(handle)


def json_dump(payload, handle):
    import json

    json.dump(payload, handle, indent=2, sort_keys=True)

from __future__ import annotations

import json
from typing import Dict, List, Optional

from .block_store import BlockStore
from .key_manager import KeyManager


class FileAllocationTable:
    """Legacy filename -> header-block mapping used by older tests and callers."""

    _FAT_FILENAME = "fat.json"

    def __init__(self, key_manager: KeyManager, block_store: BlockStore):
        self._key_manager = key_manager
        self._block_store = block_store
        self._fat: Dict[str, str] = {}
        self.load()

    def register_file(self, filename: str, header_address: str) -> None:
        self._fat[filename] = header_address
        self.save()

    def lookup(self, filename: str) -> Optional[str]:
        return self._fat.get(filename)

    def remove(self, filename: str) -> None:
        if filename in self._fat:
            del self._fat[filename]
            self.save()

    def list_files(self) -> List[str]:
        return sorted(self._fat)

    def rebuild_from_headers(self) -> None:
        self._fat = {}
        for block_id in self._block_store.list_blocks():
            try:
                header = self._block_store.read_header(block_id)
            except (FileNotFoundError, ValueError, KeyError, json.JSONDecodeError):
                continue

            entries = header.get("entries")
            if entries:
                for path in entries:
                    self._fat[path] = block_id
            elif "filename" in header:
                self._fat[header["filename"]] = block_id
        self.save()

    def save(self) -> None:
        fat_path = self._block_store.root_path / self._FAT_FILENAME
        with open(fat_path, "w", encoding="utf-8") as handle:
            json.dump(self._fat, handle, indent=2, sort_keys=True)

    def load(self) -> None:
        fat_path = self._block_store.root_path / self._FAT_FILENAME
        if fat_path.exists():
            with open(fat_path, "r", encoding="utf-8") as handle:
                try:
                    self._fat = json.load(handle)
                except json.JSONDecodeError:
                    self._fat = {}
        else:
            self._fat = {}

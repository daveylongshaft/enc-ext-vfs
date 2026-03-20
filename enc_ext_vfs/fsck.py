from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List

from .requester import resolve_requester
from .vfs import VFS


@dataclass
class FsckReport:
    requester: str
    fat_rebuilt: bool = False
    paths_checked: int = 0
    headers_checked: int = 0
    payloads_checked: int = 0
    errors: List[str] = field(default_factory=list)
    repaired_paths: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def run_fsck(vfs_root: str, requester: str | None = None, rebuild_fat: bool = False) -> FsckReport:
    resolved_requester = requester or resolve_requester()
    vfs = VFS(vfs_root)
    report = FsckReport(requester=resolved_requester)

    if rebuild_fat or not vfs.fat_file.exists():
        vfs.rebuild_fat_from_headers()
        report.fat_rebuilt = True

    for block_id in vfs.block_store.list_blocks():
        try:
            vfs.block_store.read_header(block_id)
            report.headers_checked += 1
        except Exception as exc:
            report.errors.append(f"header:{block_id}:{exc}")

    for path in sorted(vfs.fat):
        report.paths_checked += 1
        fat_entry = vfs.get_fat_entry(path)
        inode = vfs.inode_manager.get_inode(fat_entry.inode_id) if fat_entry else None
        block_path = vfs.block_store.block_path(inode.block_id) if inode else None
        existed_before = block_path.exists() if block_path else False
        try:
            vfs.read_file(path, resolved_requester)
            report.payloads_checked += 1
            if block_path and not existed_before and block_path.exists():
                report.repaired_paths.append(path)
        except Exception as exc:
            report.errors.append(f"payload:{path}:{exc}")

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline fsck and repair helper for enc-ext-vfs.")
    parser.add_argument("vfs_root")
    parser.add_argument("--requester", default=None)
    parser.add_argument("--rebuild-fat", action="store_true")
    args = parser.parse_args()

    report = run_fsck(args.vfs_root, requester=args.requester, rebuild_fat=args.rebuild_fat)
    print(json.dumps(asdict(report) | {"ok": report.ok}, indent=2, sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

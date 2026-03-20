from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List

from .vfs import VFS


@dataclass
class StorageBreakdown:
    raw_encrypted_bytes: int
    header_bytes: int
    recovery_bytes: int
    total_bytes: int
    file_count: int
    compression_enabled: bool = False


@dataclass
class BenchmarkResult:
    write_seconds: float
    read_seconds: float
    bytes_written: int
    storage: StorageBreakdown


def measure_storage_layout(vfs_root: str) -> StorageBreakdown:
    root = Path(vfs_root)
    raw_encrypted_bytes = 0
    header_bytes = 0
    recovery_bytes = 0

    for path in root.rglob("*"):
        if not path.is_file() or path.name == "fat.json":
            continue
        size = path.stat().st_size
        if path.name.endswith(".h"):
            header_bytes += size
        elif path.name.endswith(".parity"):
            recovery_bytes += size
        else:
            raw_encrypted_bytes += size

    total_bytes = raw_encrypted_bytes + header_bytes + recovery_bytes
    file_count = len([path for path in root.rglob("*") if path.is_file() and not path.name.endswith((".parity", ".h")) and path.name != "fat.json"])
    return StorageBreakdown(
        raw_encrypted_bytes=raw_encrypted_bytes,
        header_bytes=header_bytes,
        recovery_bytes=recovery_bytes,
        total_bytes=total_bytes,
        file_count=file_count,
    )


def benchmark_vfs_roundtrip(payload_sizes: Iterable[int], requester: str = "root") -> BenchmarkResult:
    payload_sizes = list(payload_sizes)
    with tempfile.TemporaryDirectory(prefix="enc-ext-vfs-bench-") as tmpdir:
        vfs = VFS(tmpdir)
        payloads = [bytes((index % 251 for index in range(size))) for size in payload_sizes]

        write_start = time.perf_counter()
        for index, payload in enumerate(payloads):
            vfs.create_file(f"bench::{index}.bin", payload)
        write_seconds = time.perf_counter() - write_start

        read_start = time.perf_counter()
        for index, payload in enumerate(payloads):
            assert vfs.read_file(f"bench::{index}.bin", requester) == payload
        read_seconds = time.perf_counter() - read_start

        storage = measure_storage_layout(tmpdir)
        return BenchmarkResult(
            write_seconds=write_seconds,
            read_seconds=read_seconds,
            bytes_written=sum(payload_sizes),
            storage=storage,
        )


def run_benchmarks(iterations: int, payload_sizes: Iterable[int], requester: str = "root") -> dict:
    results: List[BenchmarkResult] = [benchmark_vfs_roundtrip(payload_sizes, requester=requester) for _ in range(iterations)]
    return {
        "iterations": iterations,
        "payload_sizes": list(payload_sizes),
        "avg_write_seconds": statistics.mean(result.write_seconds for result in results),
        "avg_read_seconds": statistics.mean(result.read_seconds for result in results),
        "avg_bytes_written": statistics.mean(result.bytes_written for result in results),
        "storage": asdict(results[-1].storage),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run enc-ext-vfs space and latency benchmarks.")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--sizes", nargs="+", type=int, default=[512, 4096, 16384])
    parser.add_argument("--requester", default="root")
    args = parser.parse_args()

    report = run_benchmarks(args.iterations, args.sizes, requester=args.requester)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

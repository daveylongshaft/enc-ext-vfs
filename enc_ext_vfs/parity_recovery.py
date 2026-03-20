from __future__ import annotations

import hashlib
import logging
import struct
from math import ceil
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)


class ParityRecovery:
    """Reed-Solomon-style shard parity for resilient block recovery."""

    _PRIMITIVE_POLY = 0x11D
    _PACKET_HEADER = struct.Struct("!4sBBHIQ")
    _PACKET_MAGIC = b"EVP1"
    _CHECKSUM_SIZE = 32

    def __init__(self, data_shards: int = 4, parity_shards: int = 2):
        if data_shards < 1 or parity_shards < 1:
            raise ValueError("data_shards and parity_shards must be positive")
        self.data_shards = data_shards
        self.parity_shards = parity_shards
        self.total_shards = data_shards + parity_shards
        self._exp, self._log = self._build_tables()
        self._generator_rows = self._build_generator_rows()

    def _build_tables(self) -> tuple[list[int], list[int]]:
        exp = [0] * 512
        log = [0] * 256
        value = 1
        for index in range(255):
            exp[index] = value
            log[value] = index
            value <<= 1
            if value & 0x100:
                value ^= self._PRIMITIVE_POLY
        for index in range(255, 512):
            exp[index] = exp[index - 255]
        return exp, log

    def _gf_mul(self, left: int, right: int) -> int:
        if left == 0 or right == 0:
            return 0
        return self._exp[self._log[left] + self._log[right]]

    def _gf_pow(self, value: int, power: int) -> int:
        if power == 0:
            return 1
        if value == 0:
            return 0
        return self._exp[(self._log[value] * power) % 255]

    def _gf_inv(self, value: int) -> int:
        if value == 0:
            raise ZeroDivisionError("cannot invert zero in GF(256)")
        return self._exp[255 - self._log[value]]

    def _build_generator_rows(self) -> list[list[int]]:
        rows: list[list[int]] = []
        for row_index in range(self.data_shards):
            row = [0] * self.data_shards
            row[row_index] = 1
            rows.append(row)

        for parity_index in range(self.parity_shards):
            base = parity_index + 1
            rows.append([self._gf_pow(base, column) for column in range(self.data_shards)])
        return rows

    def _invert_matrix(self, matrix: Sequence[Sequence[int]]) -> list[list[int]]:
        size = len(matrix)
        working = [list(row) + [1 if column == row_index else 0 for column in range(size)] for row_index, row in enumerate(matrix)]

        for pivot_index in range(size):
            pivot_row = None
            for row_index in range(pivot_index, size):
                if working[row_index][pivot_index] != 0:
                    pivot_row = row_index
                    break
            if pivot_row is None:
                raise ValueError("matrix is singular")

            if pivot_row != pivot_index:
                working[pivot_index], working[pivot_row] = working[pivot_row], working[pivot_index]

            pivot_value = working[pivot_index][pivot_index]
            inverse_pivot = self._gf_inv(pivot_value)
            for column in range(pivot_index, size * 2):
                working[pivot_index][column] = self._gf_mul(working[pivot_index][column], inverse_pivot)

            for row_index in range(size):
                if row_index == pivot_index:
                    continue
                factor = working[row_index][pivot_index]
                if factor == 0:
                    continue
                for column in range(pivot_index, size * 2):
                    working[row_index][column] ^= self._gf_mul(factor, working[pivot_index][column])

        return [row[size:] for row in working]

    def _encode_row(self, coefficients: Sequence[int], shards: Sequence[bytes]) -> bytes:
        shard_size = len(shards[0]) if shards else 0
        output = bytearray(shard_size)
        for coefficient, shard in zip(coefficients, shards):
            if coefficient == 0:
                continue
            if coefficient == 1:
                for index, value in enumerate(shard):
                    output[index] ^= value
                continue
            for index, value in enumerate(shard):
                output[index] ^= self._gf_mul(coefficient, value)
        return bytes(output)

    def _split_data_shards(self, payload: bytes) -> tuple[list[bytes], int]:
        shard_size = max(1, ceil(len(payload) / self.data_shards))
        padded = payload.ljust(shard_size * self.data_shards, b"\0")
        shards = [padded[index * shard_size : (index + 1) * shard_size] for index in range(self.data_shards)]
        return shards, shard_size

    def _dump_packet(self, packet: dict) -> bytes:
        block_id_bytes = packet["block_id"].encode("utf-8")
        payload = bytearray(
            self._PACKET_HEADER.pack(
                self._PACKET_MAGIC,
                packet["data_shards"],
                packet["parity_shards"],
                len(block_id_bytes),
                packet["shard_size"],
                packet["original_size"],
            )
        )
        payload.extend(block_id_bytes)
        payload.extend(packet["payload_checksum"])
        for checksum, shard in zip(packet["shard_checksums"], packet["shards"]):
            payload.extend(checksum)
            payload.extend(shard)
        return bytes(payload)

    def _load_packet(self, parity_bytes: bytes, block_id: str) -> dict:
        if len(parity_bytes) < self._PACKET_HEADER.size + self._CHECKSUM_SIZE:
            raise ValueError("Parity packet too short")

        magic, data_shards, parity_shards, block_id_len, shard_size, original_size = self._PACKET_HEADER.unpack_from(parity_bytes, 0)
        if magic != self._PACKET_MAGIC:
            raise ValueError("Unsupported parity packet")
        if data_shards != self.data_shards or parity_shards != self.parity_shards:
            raise ValueError(f"Parity shard layout mismatch for {block_id}")

        offset = self._PACKET_HEADER.size
        packet_block_id = parity_bytes[offset : offset + block_id_len].decode("utf-8")
        offset += block_id_len
        if packet_block_id != block_id:
            raise ValueError(f"Parity packet block mismatch: expected {block_id}")

        payload_checksum = parity_bytes[offset : offset + self._CHECKSUM_SIZE]
        offset += self._CHECKSUM_SIZE

        total_shards = data_shards + parity_shards
        shards: list[bytes] = []
        shard_checksums: list[bytes] = []
        for _ in range(total_shards):
            checksum = parity_bytes[offset : offset + self._CHECKSUM_SIZE]
            offset += self._CHECKSUM_SIZE
            shard = parity_bytes[offset : offset + shard_size]
            offset += shard_size
            if len(checksum) != self._CHECKSUM_SIZE or len(shard) != shard_size:
                raise ValueError("Parity packet truncated")
            shard_checksums.append(checksum)
            shards.append(shard)

        return {
            "block_id": packet_block_id,
            "data_shards": data_shards,
            "parity_shards": parity_shards,
            "original_size": original_size,
            "shard_size": shard_size,
            "payload_checksum": payload_checksum,
            "shard_checksums": shard_checksums,
            "shards": shards,
        }

    def inspect_parity_data(self, parity_bytes: bytes, block_id: str) -> dict:
        packet = self._load_packet(parity_bytes, block_id)
        return {
            **packet,
            "payload_checksum": packet["payload_checksum"].hex(),
            "shard_checksums": [checksum.hex() for checksum in packet["shard_checksums"]],
        }

    def create_parity_data(self, payload: bytes, block_id: str) -> bytes:
        data_shards, shard_size = self._split_data_shards(payload)
        parity_rows = self._generator_rows[self.data_shards :]
        parity_shards = [self._encode_row(row, data_shards) for row in parity_rows]
        shards = data_shards + parity_shards

        packet = {
            "block_id": block_id,
            "data_shards": self.data_shards,
            "parity_shards": self.parity_shards,
            "original_size": len(payload),
            "shard_size": shard_size,
            "payload_checksum": hashlib.sha256(payload).digest(),
            "shard_checksums": [hashlib.sha256(shard).digest() for shard in shards],
            "shards": shards,
        }
        logger.debug("Created parity packet for %s with %s data shards and %s parity shards", block_id, self.data_shards, self.parity_shards)
        return self._dump_packet(packet)

    def recover_payload(self, parity_bytes: bytes, block_id: str) -> bytes:
        packet = self._load_packet(parity_bytes, block_id)

        available_indices: List[int] = []
        available_shards: List[bytes] = []

        for index, shard in enumerate(packet["shards"]):
            shard_checksum = hashlib.sha256(shard).digest()
            if shard_checksum != packet["shard_checksums"][index]:
                logger.warning("Detected corrupt parity shard %s for %s", index, block_id)
                continue
            available_indices.append(index)
            available_shards.append(shard)

        if len(available_shards) < self.data_shards:
            raise ValueError(f"Not enough parity shards to recover {block_id}")

        selected_indices = available_indices[: self.data_shards]
        selected_shards = available_shards[: self.data_shards]
        selected_rows = [self._generator_rows[index] for index in selected_indices]
        inverse = self._invert_matrix(selected_rows)
        recovered_data = [self._encode_row(row, selected_shards) for row in inverse]
        payload = b"".join(recovered_data)[: packet["original_size"]]

        payload_checksum = hashlib.sha256(payload).digest()
        if payload_checksum != packet["payload_checksum"]:
            raise ValueError(f"Recovered payload checksum mismatch for {block_id}")

        logger.warning("Recovered %s using Reed-Solomon shard parity", block_id)
        return payload

    def payload_matches_packet(self, payload: bytes, parity_bytes: bytes, block_id: str) -> Optional[bool]:
        try:
            packet = self._load_packet(parity_bytes, block_id)
        except Exception as exc:
            logger.warning("Cannot validate parity packet for %s: %s", block_id, exc)
            return None
        return hashlib.sha256(payload).digest() == packet.get("payload_checksum")

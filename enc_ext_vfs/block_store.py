import os
import random
from pathlib import Path

# Use dash separator for hex addresses (colon is illegal on Windows)
_SEP = "-"

class BlockStore:
    """
    On-disk representation is opaque. Real filenames and contents are invisible.
    - Files stored as encrypted blocks with hex-addressed names
    - Naming scheme: 00-11-22-33-44-55-66-77 (8 random hex octets)
    - Directory hierarchy: 00/11/22/33-44-55-66-77
      - First 3 octets become nested directories
      - Remaining 5 octets are the filename
    """
    def __init__(self, root_path: str):
        """Initialize block store at given root directory."""
        self.root_path = Path(root_path)
        self.root_path.mkdir(parents=True, exist_ok=True)

    def _get_path_from_address(self, address: str) -> Path:
        """Converts a hex address to a file path."""
        parts = address.split(_SEP)
        if len(parts) != 8:
            raise ValueError(f"Invalid block address format: {address}")

        dir_path = self.root_path.joinpath(*parts[:3])
        file_name = _SEP.join(parts[3:])
        return dir_path / file_name

    def _get_address_from_path(self, path: Path) -> str:
        """Converts a file path back to a hex address."""
        relative_path = path.relative_to(self.root_path)
        parts = list(relative_path.parts)
        dir_octets = parts[:-1]
        filename_octets = parts[-1].split(_SEP)

        all_octets = dir_octets + filename_octets
        return _SEP.join(all_octets)


    def allocate_block(self) -> str:
        """Generate random hex address, create directory structure, return address."""
        address_parts = [f"{random.randint(0, 255):02x}" for _ in range(8)]
        address = _SEP.join(address_parts)

        path = self._get_path_from_address(address)
        path.parent.mkdir(parents=True, exist_ok=True)

        return address

    def write_block(self, address: str, data: bytes) -> None:
        """Write encrypted data to block at address."""
        path = self._get_path_from_address(address)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)

    def read_block(self, address: str) -> bytes:
        """Read encrypted data from block at address."""
        path = self._get_path_from_address(address)
        if not path.exists():
            raise FileNotFoundError(f"Block not found at address: {address}")
        with open(path, "rb") as f:
            return f.read()

    def delete_block(self, address: str) -> None:
        """Remove block and clean empty parent directories."""
        path = self._get_path_from_address(address)

        if path.exists():
            path.unlink()

            # Clean up empty parent directories
            parent = path.parent
            for _ in range(3): # Max depth is 3
                try:
                    if not any(parent.iterdir()):
                        parent.rmdir()
                        parent = parent.parent
                    else:
                        break
                except OSError:
                    break


    def list_blocks(self) -> list[str]:
        """Scan all blocks in storage (for FAT rebuild from headers)."""
        block_addresses = []
        # Match pattern: xx/xx/xx/xx-xx-xx-xx-xx
        for dirpath, dirnames, filenames in os.walk(self.root_path):
            for fname in filenames:
                path = Path(dirpath) / fname
                try:
                    address = self._get_address_from_path(path)
                    # Validate it looks like a hex address
                    parts = address.split(_SEP)
                    if len(parts) == 8 and all(len(p) == 2 for p in parts):
                        block_addresses.append(address)
                except (ValueError, TypeError):
                    continue
        return block_addresses

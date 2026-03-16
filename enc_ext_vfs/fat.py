import json
from typing import Optional, List, Dict

from .block_store import BlockStore
from .key_manager import KeyManager
from .header import FileHeader
from .crypto import CryptoEngine

class FileAllocationTable:
    """
    Maps logical filenames to their block chains. Encrypted with the global key.
    """
    _FAT_FILENAME = "fat.json"

    def __init__(self, key_manager: KeyManager, block_store: BlockStore):
        """Initialize FAT backed by block store, encrypted with global key."""
        self._key_manager = key_manager
        self._block_store = block_store
        self._fat: Dict[str, str] = {}  # Maps filename -> header_block_address
        self.load()

    def register_file(self, filename: str, header_address: str) -> None:
        """Add file entry to FAT."""
        self._fat[filename] = header_address
        self.save()

    def lookup(self, filename: str) -> Optional[str]:
        """Find file by logical name, return its header's block address."""
        return self._fat.get(filename)

    def remove(self, filename: str) -> None:
        """Remove file entry from FAT."""
        if filename in self._fat:
            del self._fat[filename]
            self.save()

    def list_files(self) -> List[str]:
        """List all registered filenames."""
        return list(self._fat.keys())

    def rebuild_from_headers(self) -> None:
        """
        Scan all blocks, read headers, rebuild FAT from scratch.
        This is the self-healing mechanism.
        """
        self._fat = {}
        all_blocks = self._block_store.list_blocks()
        global_key = self._key_manager.get_global_key()

        for block_address in all_blocks:
            try:
                encrypted_data = self._block_store.read_block(block_address)
                # We need a way to distinguish header blocks from data blocks.
                # A simple heuristic is to try decrypting with the global key.
                # If it decrypts and parses as a valid FileHeader, it's a header.
                decrypted_data = CryptoEngine.decrypt(encrypted_data, global_key)
                header = FileHeader.from_json(decrypted_data.decode('utf-8'))
                
                # A crucial check: does the header think it lives at this address?
                if header.block_addresses and header.block_addresses[0] == block_address:
                    self._fat[header.filename] = block_address

            except (ValueError, json.JSONDecodeError):
                # This block is likely not a valid header, so we skip it.
                continue
        
        self.save()

    def save(self) -> None:
        """Persist FAT to block store (encrypted with global key)."""
        fat_data = json.dumps(self._fat).encode('utf-8')
        global_key = self._key_manager.get_global_key()
        encrypted_fat = CryptoEngine.encrypt(fat_data, global_key)

        # Check if we already have a block for the FAT
        # A real implementation would store this address somewhere, but for now
        # we can't easily find it without a name. We will name it ".fat"
        # and store it in the FAT itself, which is a bit of a hack.
        # A better way is a dedicated, known address or metadata field in the BlockStore.
        # For now, we will just write it to a fixed file name outside the block store.
        fat_path = self._block_store.root_path / self._FAT_FILENAME
        with open(fat_path, "wb") as f:
            f.write(encrypted_fat)


    def load(self) -> None:
        """Load FAT from block store."""
        fat_path = self._block_store.root_path / self._FAT_FILENAME
        if fat_path.exists():
            with open(fat_path, "rb") as f:
                encrypted_fat = f.read()
            
            global_key = self._key_manager.get_global_key()
            try:
                decrypted_fat = CryptoEngine.decrypt(encrypted_fat, global_key)
                self._fat = json.loads(decrypted_fat.decode('utf-8'))
            except Exception:
                # If FAT is corrupt or key is wrong, start with an empty one.
                self._fat = {}
        else:
            self._fat = {}


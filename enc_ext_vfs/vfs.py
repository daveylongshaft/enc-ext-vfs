import math
import time
from typing import List, Optional

from .block_store import BlockStore
from .crypto import CryptoEngine
from .fat import FileAllocationTable
from .header import FileHeader
from .key_manager import KeyManager

class VirtualFileSystem:
    """
    The main filesystem API. All operations go through here.
    """
    # Define a default block size (e.g., 4KB). This can be made configurable.
    DEFAULT_BLOCK_SIZE = 4096

    def __init__(self, storage_root: str, node_id: str = "local"):
        """Initialize VFS with block store, FAT, key manager."""
        self.node_id = node_id
        self._block_store = BlockStore(storage_root)
        self._key_manager = KeyManager(storage_root) # KeyManager stores its own files
        self._fat = FileAllocationTable(self._key_manager, self._block_store)

    def _read_header(self, path: str) -> Optional[FileHeader]:
        """Reads and decrypts the header for a given file path."""
        header_address = self._fat.lookup(path)
        if not header_address:
            return None
        
        # Headers are always encrypted with the global key for uniform access
        global_key = self._key_manager.get_global_key()
        encrypted_header = self._block_store.read_block(header_address)
        
        try:
            decrypted_header_json = CryptoEngine.decrypt(encrypted_header, global_key)
            return FileHeader.from_json(decrypted_header_json.decode('utf-8'))
        except Exception:
            # Could be a decryption error or JSON parsing error
            return None

    def create(self, path: str, data: bytes, mime_type: str = "application/octet-stream",
               key_hash: str = None) -> FileHeader:
        """Create a new file. Uses global key if key_hash not specified."""
        if self.exists(path):
            raise FileExistsError(f"File already exists at path: {path}")

        global_key = self._key_manager.get_global_key()
        global_key_hash = CryptoEngine.key_hash(global_key)

        file_key_hash = key_hash
        file_key = None
        if file_key_hash:
            if file_key_hash == global_key_hash:
                file_key = global_key
            else:
                file_key = self._key_manager.get_key_by_hash(file_key_hash)
                if not file_key:
                    raise ValueError(f"Specified key_hash '{file_key_hash}' not found.")
        else:
            file_key_hash = global_key_hash
            file_key = global_key
        
        # Split data into blocks
        num_blocks = math.ceil(len(data) / self.DEFAULT_BLOCK_SIZE) if data else 1
        data_blocks = [data[i*self.DEFAULT_BLOCK_SIZE:(i+1)*self.DEFAULT_BLOCK_SIZE] for i in range(num_blocks)]
        if not data_blocks:
            data_blocks.append(b'')

        # Allocate and write blocks
        all_block_addresses = [self._block_store.allocate_block() for _ in range(num_blocks + 1)] # +1 for header
        header_address = all_block_addresses[0]
        data_addresses = all_block_addresses[1:]

        for i, block_data in enumerate(data_blocks):
            encrypted_block = CryptoEngine.encrypt(block_data, file_key)
            self._block_store.write_block(data_addresses[i], encrypted_block)

        # Create and write header
        header = FileHeader(
            filename=path,
            file_size=len(data),
            block_size=self.DEFAULT_BLOCK_SIZE,
            mime_type=mime_type,
            node_id=self.node_id,
            key_hash=file_key_hash,
            block_addresses=all_block_addresses,
        )
        header.update_checksum(data)

        header_json = header.to_json().encode('utf-8')
        global_key = self._key_manager.get_global_key()
        encrypted_header = CryptoEngine.encrypt(header_json, global_key)
        self._block_store.write_block(header_address, encrypted_header)
        
        # Update FAT
        self._fat.register_file(path, header_address)
        return header

    def read(self, path: str, requester: str) -> bytes:
        """
        Read file contents. Transparently decrypts using key from header.
        Checks ACL - requester must be authorized for the file's key.
        """
        header = self._read_header(path)
        if not header:
            raise FileNotFoundError(f"File not found: {path}")

        # Check permission and get key
        file_key = self._key_manager.get_key_for_read(header.key_hash, requester)
        
        # Read and decrypt data blocks
        data_addresses = header.block_addresses[1:]
        plaintext_data = b""
        for addr in data_addresses:
            encrypted_block = self._block_store.read_block(addr)
            plaintext_data += CryptoEngine.decrypt(encrypted_block, file_key)
            
        # Truncate to original file size
        plaintext_data = plaintext_data[:header.file_size]

        if not header.verify_checksum(plaintext_data):
            raise IOError(f"File integrity check failed for: {path}. The file may be corrupt.")

        header.accessed = time.time()
        # Re-save header with updated access time (optional, can be performance intensive)
        
        return plaintext_data

    def write(self, path: str, data: bytes, requester: str = "root", key_hash: str = None) -> FileHeader:
        """Overwrite file contents (replace)."""
        if self.exists(path):
            self.delete(path, requester)
        return self.create(path, data, key_hash=key_hash)

    def append(self, path: str, data: bytes, requester: str = "root") -> FileHeader:
        """Append data to existing file."""
        # Simple implementation: read, append in memory, write back.
        try:
            current_data = self.read(path, requester)
            header = self._read_header(path)
            new_data = current_data + data
            return self.write(path, new_data, requester, key_hash=header.key_hash)
        except FileNotFoundError:
            # If file doesn't exist, append is the same as create.
            return self.create(path, data)

    def delete(self, path: str, requester: str = "root") -> None:
        """Delete file and free its blocks."""
        header = self._read_header(path)
        if not header:
            raise FileNotFoundError(f"File not found to delete: {path}")

        # Enforce ACL: must be able to read to delete (as a simple permission model)
        self._key_manager.get_key_for_read(header.key_hash, requester)

        header_address = self._fat.lookup(path)
        self._fat.remove(path)

        # Check if any other file points to this header address (hard link)
        if not any(addr == header_address for addr in self._fat._fat.values()):
            for block_address in header.block_addresses:
                self._block_store.delete_block(block_address)

    def rename(self, old_path: str, new_path: str, requester: str = "root") -> None:
        """Rename/move file (updates FAT, not block addresses)."""
        if not self.exists(old_path):
            raise FileNotFoundError(f"Source file not found for rename: {old_path}")
        if self.exists(new_path):
            raise FileExistsError(f"Destination file already exists: {new_path}")

        header = self._read_header(old_path)
        # Enforce ACL
        self._key_manager.get_key_for_read(header.key_hash, requester)

        header_address = self._fat.lookup(old_path)
        self._fat.remove(old_path)
        self._fat.register_file(new_path, header_address)
        
        # Also update the filename inside the header
        if header:
            header.filename = new_path
            header_json = header.to_json().encode('utf-8')
            global_key = self._key_manager.get_global_key()
            encrypted_header = CryptoEngine.encrypt(header_json, global_key)
            self._block_store.write_block(header.block_addresses[0], encrypted_header)


    def copy(self, src_path: str, dst_path: str, requester: str = "root", key_hash: str = None) -> FileHeader:
        """Copy file. New copy gets new blocks. Can use different key."""
        if not self.exists(src_path):
            raise FileNotFoundError(f"Source file not found for copy: {src_path}")
        
        data = self.read(src_path, requester) # Require read access to copy
        src_header = self._read_header(src_path)
        
        new_key_hash = key_hash if key_hash is not None else src_header.key_hash
        
        return self.create(dst_path, data, mime_type=src_header.mime_type, key_hash=new_key_hash)

    def hard_link(self, target: str, link_name: str, requester: str = "root") -> None:
        """Create hard link (same blocks, new FAT entry)."""
        if not self.exists(target):
            raise FileNotFoundError(f"Target for hard link does not exist: {target}")
        if self.exists(link_name):
            raise FileExistsError(f"Link name already exists: {link_name}")

        header = self._read_header(target)
        # Enforce ACL: must be able to read target to hard link it
        self._key_manager.get_key_for_read(header.key_hash, requester)
            
        header_address = self._fat.lookup(target)
        self._fat.register_file(link_name, header_address)

    def soft_link(self, target: str, link_name: str) -> None:
        """Create soft link (pointer to target path)."""
        # A soft link is essentially a special file containing the target path.
        link_data = target.encode('utf-8')
        self.create(link_name, link_data, mime_type="inode/symlink")


    def stat(self, path: str) -> Optional[FileHeader]:
        """Get file metadata without reading content."""
        return self._read_header(path)

    def list_dir(self, path: str = "/") -> List[str]:
        """List files in virtual directory."""
        # This is a simplified implementation. A real one would handle subdirectories.
        if path == "/":
            return self._fat.list_files()
        else:
            # Filter files that start with the "directory" path
            path = path.rstrip("/") + "/"
            return [f for f in self._fat.list_files() if f.startswith(path)]

    def exists(self, path: str) -> bool:
        """Check if file exists."""
        return self._fat.lookup(path) is not None

    def rebuild_fat(self) -> int:
        """Scan all blocks, rebuild FAT from headers. Returns file count."""
        self._fat.rebuild_from_headers()
        return len(self._fat.list_files())

    def verify_integrity(self) -> List[str]:
        """Check all files for corruption. Returns list of issues."""
        issues = []
        for filename in self.list_dir("/"):
            try:
                self.read(filename, "root") # Privileged read for verification
            except Exception as e:
                issues.append(f"Error verifying '{filename}': {e}")
        return issues

import errno
import stat
import time

try:
    import fuse
except ImportError:
    # A placeholder to avoid errors if fusepy is not installed,
    # allowing the rest of the VFS to be tested independently.
    class Operations:
        pass
    fuse.Operations = Operations

from .vfs import VirtualFileSystem

class EncExtVfsFuse(fuse.Operations):
    """
    FUSE interface for the encrypted VFS.
    Allows mounting with: python -m enc_ext_vfs.fuse_mount /path/to/storage /mnt/vfs
    Then standard tools work: ls, cat, cp, mv, rm, etc.
    """

    def __init__(self, vfs: VirtualFileSystem, requester: str = "root"):
        self.vfs = vfs
        self.requester = requester
        self.fd = 0

    # --- Filesystem Methods ---

    def getattr(self, path, fh=None):
        """Get file or directory attributes."""
        if path == "/":
            return dict(st_mode=(stat.S_IFDIR | 0o755), st_nlink=2)

        header = self.vfs.stat(path)
        if header:
            is_dir = header.mime_type == 'inode/directory' # A convention we can add
            is_link = header.mime_type == 'inode/symlink'

            if is_link:
                mode = stat.S_IFLNK | 0o777
            elif is_dir:
                mode = stat.S_IFDIR | 0o755
            else:
                mode = stat.S_IFREG | 0o644

            return dict(
                st_mode=mode,
                st_nlink=1,
                st_size=header.file_size,
                st_ctime=header.created,
                st_mtime=header.modified,
                st_atime=header.accessed,
            )
        else:
            raise fuse.FuseOSError(errno.ENOENT)

    def readdir(self, path, fh):
        """Read directory entries."""
        dirents = ['.', '..']
        dirents.extend(self.vfs.list_dir(path))
        for r in dirents:
            yield r

    def open(self, path, flags):
        """Open a file. No-op for now, but needed for FUSE."""
        self.fd += 1
        return self.fd

    def create(self, path, mode, fi=None):
        """Create a new file."""
        self.vfs.create(path, b'')
        self.fd += 1
        return self.fd

    def read(self, path, size, offset, fh):
        """Read from a file."""
        data = self.vfs.read(path, self.requester)
        return data[offset:offset + size]

    def write(self, path, data, offset, fh):
        """Write to a file."""
        # Inefficient, but correct for a simple implementation
        try:
            current_data = self.vfs.read(path, self.requester)
        except FileNotFoundError:
            current_data = b''
        
        new_data = current_data[:offset] + data + current_data[offset + len(data):]
        header = self.vfs.stat(path)
        
        self.vfs.write(path, new_data, key_hash=header.key_hash if header else None)
        return len(data)

    def truncate(self, path, length, fh=None):
        """Truncate a file to a specific length."""
        data = self.vfs.read(path, self.requester)
        truncated_data = data[:length]
        
        header = self.vfs.stat(path)
        self.vfs.write(path, truncated_data, key_hash=header.key_hash if header else None)

    def unlink(self, path):
        """Delete a file."""
        self.vfs.delete(path)

    def rename(self, old, new):
        """Rename a file."""
        self.vfs.rename(old, new)
        
    def symlink(self, target, source):
        """Create a symbolic link."""
        self.vfs.soft_link(source, target) # Note: FUSE has target, source arguments reversed from ln
        
    def readlink(self, path):
        """Read a symbolic link."""
        header = self.vfs.stat(path)
        if not header or header.mime_type != 'inode/symlink':
            raise fuse.FuseOSError(errno.EINVAL)
        return self.vfs.read(path, self.requester).decode('utf-8')


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mount the Encrypted FUSE VFS.")
    parser.add_argument("storage_root", help="The root directory for the block store.")
    parser.add_argument("mount_point", help="The directory where the VFS will be mounted.")
    parser.add_argument("--requester", default="root", help="The user identity for FUSE operations.")
    args = parser.parse_args()

    vfs = VirtualFileSystem(args.storage_root)
    
    print(f"Mounting VFS at {args.mount_point} with storage at {args.storage_root}")
    fuse.FUSE(EncExtVfsFuse(vfs, args.requester), args.mount_point, foreground=True)

if __name__ == '__main__':
    main()

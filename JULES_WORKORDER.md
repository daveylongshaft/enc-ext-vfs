# Improve enc-ext-vfs: Research-Backed Hardening

## Repository

https://github.com/daveylongshaft/enc-ext-vfs

## Context

This is an encrypted virtual filesystem (Python) with AES-256-GCM block-level encryption, a FAT, hex-addressed block storage, multi-key support with ACL, and a key manager. The core works (44/45 tests pass). Now it needs hardening based on techniques proven in production-grade encrypted filesystems (gocryptfs, CryFS, Cryptomator, securefs).

## Tasks (in priority order)

### 1. Per-Block AAD (Authenticated Associated Data) -- CRITICAL

**Why**: gocryptfs, securefs, and Cryptomator all include block metadata in the GCM AAD to prevent block-swap and block-copy attacks. Without this, an attacker with disk access can silently swap encrypted blocks between files or reorder blocks within a file. GCM will decrypt successfully but return wrong data.

**What to do**:
- In `crypto.py`: modify `encrypt()` and `decrypt()` to accept an optional `aad: bytes = None` parameter and pass it to GCM as associated_data
- In `vfs.py`: when encrypting each data block, pass AAD = `file_id_bytes + block_index.to_bytes(8, 'big')` where file_id is a unique random 16-byte ID stored in the FileHeader
- In `header.py`: add a `file_id: bytes` field (16 random bytes, generated on create). Serialize as hex in JSON.
- Update all encrypt/decrypt call sites (create, read, write, append, copy)
- Decryption of a block with wrong AAD must raise an error (GCM handles this automatically)

**Reference**: gocryptfs uses FileID + block number as AAD. Cryptomator uses chunk number + header nonce.

### 2. Per-File Key Derivation via HKDF -- IMPORTANT

**Why**: Using the same AES-256-GCM key for all blocks across all files risks hitting the birthday bound (~2^32 blocks per key). gocryptfs and securefs both derive per-file keys. HKDF is the standard approach (RFC 5869).

**What to do**:
- In `crypto.py`: add a static method `derive_file_key(master_key: bytes, file_id: bytes) -> bytes` using HKDF-SHA256 with the file_id as the info parameter
- In `vfs.py create()`: derive a file-specific key from the master key using the file's file_id
- In `vfs.py read()`: same derivation to get the file key for decryption
- The master key (from key_manager) is never used directly for block encryption -- only for key derivation
- Use `cryptography.hazmat.primitives.kdf.hkdf.HKDF` (already a dependency)

**Reference**: gocryptfs uses HKDF-SHA256 since v1.3 to derive separate content/filename keys.

### 3. Nonce Safety Verification

**Why**: AES-256-GCM with 96-bit nonces is catastrophically broken if a nonce is ever reused with the same key. The `cryptography` library generates random nonces by default, which is correct. But with per-file HKDF keys (task 2), the birthday bound concern is per-file rather than global, making random nonces perfectly safe.

**What to do**:
- Verify that `CryptoEngine.encrypt()` generates a fresh random nonce on every call (it should via `os.urandom(12)` or the library default)
- Add a comment documenting the nonce strategy: "Random 96-bit nonce per block. Safe because per-file HKDF keys limit the number of encryptions per key."
- If the nonce is not explicitly random, fix it to use `os.urandom(12)`

### 4. Block Reference Counting for Hard Links

**Why**: Hard links allow multiple FAT entries to point to the same blocks. The delete() method must not free blocks that are still referenced by other paths.

**What to do**:
- In `fat.py`: add a method `reference_count(header_address: str) -> int` that counts how many FAT entries point to a given header address
- In `vfs.py delete()`: only delete blocks if reference_count drops to 0
- Add tests for: create file, hard link it, delete original (link still works), delete link (blocks freed)

**Note**: Jules session 15544502619965857424 already produced a patch for this. Verify it was applied to main branch. If not, implement it.

### 5. Implement test_edge_cases.py

Add meaningful edge case tests:
- Empty file create/read/delete
- FileNotFoundError on read/delete of nonexistent file
- FileExistsError on create of existing file
- Large file (>1MB, multiple blocks) create/read roundtrip
- Binary data with null bytes
- File with exactly block_size bytes (boundary condition)
- File with block_size + 1 bytes (crosses block boundary)
- Concurrent create of same path (should raise)
- Rename to existing path (should raise)
- Delete and recreate same path
- Corrupted block detection (tamper with block on disk, verify read raises IOError)

### 6. Implement test_stress.py

Add stress/performance tests:
- Create and delete 1000 files
- Create 100 files, list_dir, verify all present
- FAT rebuild after 100 files: verify rebuild_fat() returns correct count
- verify_integrity() on filesystem with 50 files
- Large file: 10MB file, write and read back, verify checksum
- Append 100 times to same file

### 7. Implement test_fuse_mount.py

Add FUSE mount tests (mock-based if fusepy/pyfuse3 not installed):
- Test that FuseVFS class exists and has required FUSE methods (getattr, read, write, readdir, create, unlink, rename)
- Test getattr returns correct st_size and st_mode
- Test readdir returns file list
- Test read/write roundtrip through FUSE interface
- Use unittest.mock to mock the FUSE library if not available
- Skip tests with `pytest.mark.skipif` if no FUSE library installed

### 8. FUSE Mount Layer (if not already present)

Create `enc_ext_vfs/fuse_mount.py`:
- Class `FuseVFS` that wraps VirtualFileSystem and implements FUSE operations
- Use `fusepy` (pip: fuse-python) as the FUSE binding -- it is the simplest pure-Python option
- Operations to implement: getattr, readdir, read, write, create, unlink, rename, truncate, open, release
- Mount function: `mount(storage_root, mount_point, node_id="local")`
- CLI entry point: `python -m enc_ext_vfs.fuse_mount <storage_root> <mount_point>`

### 9. README.md

Write a README covering:
- What this is (encrypted virtual filesystem with block-level AES-256-GCM)
- Architecture overview (BlockStore, FAT, KeyManager, CryptoEngine, FileHeader, VFS)
- Security properties: per-block AEAD, per-file HKDF keys, AAD prevents block swap, multi-key ACL
- Installation: `pip install -e .`
- Usage: Python API and FUSE mount
- Running tests: `python -m pytest tests/`
- Design influences: gocryptfs (AAD/HKDF), CryFS (block-based), Cryptomator (per-chunk auth)

## Design Principles (from research)

These are lessons from audited, production encrypted filesystems. Follow them:

1. **Always use authenticated encryption** (AES-GCM provides this). Never strip or skip auth tags.
2. **Include block index and file identity in AAD** to prevent block swap/copy attacks (gocryptfs pattern).
3. **Derive per-file keys via HKDF** to stay well within GCM's birthday bound (gocryptfs pattern).
4. **Random nonces only** -- never deterministic or counter-based nonces for content encryption.
5. **Key separation** -- don't use the same key for different purposes. HKDF with different info strings.
6. **Accept file-size leakage** -- hiding file sizes requires CryFS-style uniform blocks (32KB overhead per file). Not worth the cost for this project.
7. **Accept access-pattern leakage** -- only ORAM prevents this and it is impractical.

## Anti-Patterns to Avoid

- Do NOT use RSA for bulk data encryption (use symmetric AES-GCM)
- Do NOT use fixed/predictable IVs/nonces
- Do NOT reuse nonces with the same key
- Do NOT skip AAD in GCM -- without it, blocks can be silently swapped
- Do NOT store keys in plaintext in the repo

## Files

Key source files in `enc_ext_vfs/`:
- `crypto.py` - CryptoEngine (AES-256-GCM encrypt/decrypt/keygen)
- `block_store.py` - BlockStore (hex-addressed block storage on disk)
- `fat.py` - FileAllocationTable (path -> header address mapping)
- `header.py` - FileHeader (file metadata, block addresses, checksum)
- `key_manager.py` - KeyManager (multi-key management with ACL)
- `vfs.py` - VirtualFileSystem (main API: create/read/write/delete/rename/copy/link)

Test files in `tests/`:
- `test_crypto.py`, `test_block_store.py`, `test_fat.py`, `test_header.py`, `test_key_manager.py`, `test_vfs.py` - existing, all pass
- `test_edge_cases.py`, `test_stress.py`, `test_fuse_mount.py` - need implementation

## Success Criteria

1. All existing tests continue to pass (44+)
2. AAD is used on every block encrypt/decrypt
3. Per-file HKDF key derivation is implemented
4. file_id field added to FileHeader
5. test_edge_cases.py has 10+ meaningful tests, all passing
6. test_stress.py has 5+ tests, all passing
7. test_fuse_mount.py has 5+ tests, all passing
8. FUSE mount layer exists and is functional
9. README.md documents architecture and security properties

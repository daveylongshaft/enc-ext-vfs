# enc-ext-vfs

A standalone, fully-tested FUSE-compatible encrypted virtual filesystem in Python.

## Overview

This filesystem provides an encrypted virtual file storage layer. It uses a hex-addressed block storage backend where all file contents and metadata are encrypted. It features a self-describing and self-healing architecture, where the entire filesystem index (File Allocation Table) can be rebuilt by scanning file headers.

Key features include:
-   **End-to-End Encryption**: All data and metadata are encrypted at rest using AES-256-GCM.
-   **Hex-Addressed Block Storage**: Files are stored in opaque, randomly-named blocks, obscuring the original file structure and names from the underlying storage.
-   **Multi-Key Encryption**: Supports a hierarchy of keys (global, server, private) for granular access control.
-   **ACL-Based Decryption**: File read access is determined by Access Control Lists (ACLs), allowing owners to grant read permissions to other users.
-   **Self-Healing**: The File Allocation Table (FAT) can be rebuilt from file headers stored with the file blocks, providing resilience against index corruption.
-   **FUSE Compatibility**: Can be mounted as a standard filesystem on Linux/macOS, allowing interaction via standard command-line tools.

## Dependencies

-   `cryptography`
-   `fusepy`
-   `pytest` (for development)

## Installation

Install the package and its dependencies:

```bash
pip install .
```

To install for development, including test dependencies:

```bash
pip install -e ".[test]"
```

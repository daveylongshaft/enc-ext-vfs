from __future__ import annotations

import os

REQUESTER_ENV_KEYS = (
    "ENC_EXT_VFS_REQUESTER",
    "ENC_EXT_VFS_REQUESTER_NICK",
    "CSC_REQUESTER",
    "CSC_NICK",
    "NICK",
    "USER",
)


def resolve_requester(default: str = "root") -> str:
    for key in REQUESTER_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            return value
    return default

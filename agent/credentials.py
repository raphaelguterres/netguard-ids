"""Local credential store for the endpoint agent.

The agent can run unattended after the first enrollment because it can
reuse a previously issued `nga_...` host key. On Windows we protect the
key with DPAPI when available; everywhere else we store a base64 value in
a file created with restrictive permissions.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("netguard.agent.credentials")


@dataclass
class AgentCredentials:
    api_key: str = ""
    host_id: str = ""
    protection: str = ""


class CredentialStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> AgentCredentials:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return AgentCredentials()

        protected = str(data.get("api_key") or "")
        protection = str(data.get("protection") or "")
        api_key = _unprotect_secret(protected, protection)
        return AgentCredentials(
            api_key=api_key,
            host_id=str(data.get("host_id") or ""),
            protection=protection,
        )

    def save(self, *, api_key: str, host_id: str = "") -> None:
        if not api_key or api_key == "CHANGE_ME":
            return
        protected, protection = _protect_secret(api_key)
        payload = {
            "version": 1,
            "host_id": host_id,
            "protection": protection,
            "api_key": protected,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _restrict_file_permissions(self.path)


def _restrict_file_permissions(path: Path) -> None:
    if sys.platform.startswith("win"):
        return
    try:
        path.chmod(0o600)
    except OSError:
        logger.debug("could not chmod credential file %s", path)


def _protect_secret(secret: str) -> tuple[str, str]:
    raw = secret.encode("utf-8")
    if _dpapi_enabled():
        try:
            return base64.b64encode(_dpapi_protect(raw)).decode("ascii"), "dpapi"
        except Exception as exc:
            logger.warning("DPAPI protect failed, falling back to file protection: %s", exc)
    return base64.b64encode(raw).decode("ascii"), "file"


def _unprotect_secret(value: str, protection: str) -> str:
    if not value:
        return ""
    try:
        raw = base64.b64decode(value.encode("ascii"))
    except Exception:
        return ""
    if protection == "dpapi":
        try:
            return _dpapi_unprotect(raw).decode("utf-8")
        except Exception as exc:
            logger.warning("DPAPI unprotect failed for stored agent credential: %s", exc)
            return ""
    return raw.decode("utf-8", errors="ignore")


def _dpapi_enabled() -> bool:
    if not sys.platform.startswith("win"):
        return False
    return os.environ.get("NETGUARD_AGENT_DISABLE_DPAPI", "").lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }


def _dpapi_protect(data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    buf = ctypes.create_string_buffer(data)
    in_blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "NetGuard Agent API key",
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    buf = ctypes.create_string_buffer(data)
    in_blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)

"""Encrypted env store: format, crypto and dotenv parsing.

Pure — no Hermes imports — so the whole thing is testable without the agent runtime.

On-disk format (both files 0600 by default):

    sealed.key    32 raw random bytes
    sealed.store  b"SEALED1\n" + base64url(nonce(12) || AES-256-GCM ciphertext)

The magic string is the AEAD associated data, so a store written by a different format
version fails authentication rather than decrypting into garbage.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

MAGIC = b"SEALED1\n"
KEY_BYTES = 32
NONCE_BYTES = 12

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SealedError(Exception):
    """Store is missing, malformed, or not decryptable."""


class WrongKey(SealedError):
    """Authentication failed: wrong key, or the file was modified."""


@dataclass
class StoreInfo:
    path: Path
    exists: bool
    mode: int | None = None
    entries: int = 0
    problem: str = ""


def is_valid_name(name: str) -> bool:
    return bool(name) and bool(_ENV_NAME_RE.match(name))


# -- keys ------------------------------------------------------------------


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def read_key(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SealedError(f"cannot read key file {path}: {exc}") from exc
    if len(raw) != KEY_BYTES:
        raise SealedError(f"key file {path} must hold exactly {KEY_BYTES} raw bytes (found {len(raw)})")
    return raw


def write_key(path: Path, key: bytes | None = None) -> bytes:
    """Create a key file with O_EXCL. Never overwrites an existing key."""
    key = key or generate_key()
    if len(key) != KEY_BYTES:
        raise SealedError(f"key must be {KEY_BYTES} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return key


# -- encryption ------------------------------------------------------------


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - declared dependency
        raise SealedError("the `cryptography` package is required (pip install cryptography)") from exc
    return AESGCM


def encrypt(key: bytes, plaintext: str) -> bytes:
    AESGCM = _aesgcm()
    if len(key) != KEY_BYTES:
        raise SealedError(f"key must be {KEY_BYTES} bytes")
    nonce = secrets.token_bytes(NONCE_BYTES)
    blob = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), MAGIC)
    return MAGIC + base64.urlsafe_b64encode(nonce + blob)


def decrypt(key: bytes, data: bytes) -> str:
    AESGCM = _aesgcm()
    if not data.startswith(MAGIC):
        raise SealedError("not a sealed store (bad magic header)")
    if len(key) != KEY_BYTES:
        raise SealedError(f"key must be {KEY_BYTES} bytes")
    try:
        raw = base64.urlsafe_b64decode(data[len(MAGIC) :])
    except (binascii.Error, ValueError) as exc:
        raise SealedError(f"store payload is not valid base64: {exc}") from exc
    if len(raw) <= NONCE_BYTES:
        raise SealedError("store payload is truncated")
    nonce, blob = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, blob, MAGIC).decode("utf-8")
    except Exception as exc:  # InvalidTag and friends
        raise WrongKey("decryption failed: wrong key or the store was modified") from exc


# -- dotenv ----------------------------------------------------------------


def parse_dotenv(text: str) -> dict[str, str]:
    """Parse ``KEY=value`` lines. Comments and blank lines ignored.

    Supports ``export`` prefixes, single/double quotes, and ``\\n``/``\\t`` escapes in
    double quotes. Multi-line values are not supported — one line per secret.
    """
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.strip()
        if not is_valid_name(name):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            quote = value[0]
            value = value[1:-1]
            if quote == '"':
                value = value.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')
        values[name] = value
    return values


def dump_dotenv(values: dict[str, str]) -> str:
    """Serialise deterministically (sorted), quoting only when needed."""
    lines = ["# sealed env store — encrypted at rest; values are never printed by the CLI"]
    for name in sorted(values):
        value = values[name]
        if value == "" or any(ch in value for ch in " \t\n#\"'\\$"):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
            lines.append(f'{name}="{escaped}"')
        else:
            lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


# -- store file ------------------------------------------------------------


def write_store(path: Path, key: bytes, values: dict[str, str]) -> None:
    """Atomic write; the file is created 0600 and replaced atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = encrypt(key, dump_dotenv(values))
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def read_store(path: Path, key: bytes) -> dict[str, str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SealedError(f"cannot read store {path}: {exc}") from exc
    return parse_dotenv(decrypt(key, data))


def replace_entry(values: dict[str, str], name: str, value: str) -> dict[str, str]:
    if not is_valid_name(name):
        raise SealedError(f"{name!r} is not a valid environment variable name")
    updated = dict(values)
    updated[name] = value
    return updated


def remove_entry(values: dict[str, str], name: str) -> dict[str, str]:
    updated = dict(values)
    updated.pop(name, None)
    return updated


# -- inspection ------------------------------------------------------------


def file_mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def mode_is_private(mode: int | None) -> bool:
    return mode is not None and (mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0


def inspect(path: Path) -> StoreInfo:
    exists = path.exists()
    mode = file_mode(path) if exists else None
    info = StoreInfo(path=path, exists=exists, mode=mode)
    if not exists:
        info.problem = "store does not exist"
    elif not mode_is_private(mode):
        info.problem = f"file mode {mode:o} is too open (want 600)"
    return info


def split_names(values: Iterable[str]) -> list[str]:
    return sorted(v for v in values if is_valid_name(v))


# -- file permissions on read ----------------------------------------------


@dataclass
class PermissionWarning:
    path: Path
    mode: int
    messages: list[str] = field(default_factory=list)

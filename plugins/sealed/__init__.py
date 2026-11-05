"""sealed — an encrypted, offline secret source for Hermes Agent.

Hermes normally keeps credentials in ``~/.hermes/.env`` as plaintext. `sealed` moves them
into a single AES-256-GCM encrypted store, unlocked by a 32-byte key file, and hands them
to the process through the sanctioned ``SecretSource`` contract at startup.

* no network, no helper binary, no daemon
* values never appear in argv, logs or ``hermes sealed list``
* the store and key are 0600; an over-permissive file is reported as a startup warning
* ``fetch()`` never raises and never prompts, per the contract

Configure under ``secrets.sealed``:

    secrets:
      sealed:
        enabled: true
        store: ~/.hermes/secrets/sealed.store   # default
        key_file: ~/.hermes/secrets/sealed.key  # default
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource

from .store import (
    SealedError,
    WrongKey,
    inspect,
    mode_is_private,
    read_key,
    read_store,
)

logger = logging.getLogger(__name__)

SOURCE_NAME = "sealed"
DEFAULT_STORE = ("secrets", "sealed.store")
DEFAULT_KEY = ("secrets", "sealed.key")


def _resolve_path(cfg: dict, key: str, default_parts: tuple[str, str], home: Path) -> Path:
    raw = str(cfg.get(key) or "").strip()
    path = Path(raw).expanduser() if raw else home.joinpath(*default_parts)
    if not path.is_absolute():
        path = (home / path).resolve()
    return path


class SealedSource(SecretSource):
    """Encrypted env-file backend."""

    name = SOURCE_NAME
    label = "Sealed"
    shape = "bulk"  # it holds whole variables, like a .env replacement
    override_existing_default = True  # the store IS the source of truth for what it holds

    # -- contract ---------------------------------------------------------

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        try:
            if not isinstance(cfg, dict):
                return result.fail("secrets.sealed must be a mapping", ErrorKind.NOT_CONFIGURED)
            store_path = _resolve_path(cfg, "store", DEFAULT_STORE, home_path)
            key_path = _resolve_path(cfg, "key_file", DEFAULT_KEY, home_path)
            result.binary_path = store_path

            if not store_path.exists():
                return result.fail(
                    f"sealed store not found at {store_path}. Run `hermes sealed init`.",
                    ErrorKind.NOT_CONFIGURED,
                )
            if not key_path.exists():
                return result.fail(
                    f"sealed key not found at {key_path}. Run `hermes sealed init`.",
                    ErrorKind.AUTH_FAILED,
                )

            for path in (key_path, store_path):
                info = inspect(path)
                if info.mode is not None and not mode_is_private(info.mode):
                    result.warnings.append(
                        f"{path} is mode {info.mode:o}; expected 600. Tighten it with: chmod 600 {path}"
                    )
                    if bool(cfg.get("strict_permissions", False)):
                        return result.fail(
                            f"{path} is readable by other users (mode {info.mode:o}) and "
                            "secrets.sealed.strict_permissions is on.",
                            ErrorKind.AUTH_FAILED,
                        )

            key = read_key(key_path)
            values = read_store(store_path, key)
            if not values:
                return result.fail(
                    f"sealed store {store_path} holds no entries. Add one with `hermes sealed set NAME`.",
                    ErrorKind.EMPTY_VALUE,
                )
            result.secrets = values
            return result
        except WrongKey as exc:
            return result.fail(f"{exc}. Wrong key file, or the store was modified.", ErrorKind.AUTH_FAILED)
        except SealedError as exc:
            return result.fail(str(exc), ErrorKind.INTERNAL)
        except Exception as exc:  # contract: never raise
            logger.warning("sealed: unexpected failure: %s", exc)
            return result.fail(f"unexpected error: {exc}", ErrorKind.INTERNAL)

    # -- optional hooks ---------------------------------------------------

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "store": {"description": "Encrypted store path", "default": "~/.hermes/secrets/sealed.store"},
            "key_file": {"description": "32-byte key file path", "default": "~/.hermes/secrets/sealed.key"},
            "strict_permissions": {
                "description": "Refuse to load when the store or key is readable by other users",
                "default": False,
            },
            "override_existing": {
                "description": "Sealed values overwrite .env / shell values",
                "default": True,
            },
        }

    def remediation(self, kind, cfg: dict) -> str:
        if kind in (ErrorKind.NOT_CONFIGURED, ErrorKind.AUTH_FAILED):
            return "Run `hermes sealed init`, then `hermes sealed set NAME`."
        if kind == ErrorKind.EMPTY_VALUE:
            return "Add a secret with `hermes sealed set NAME`."
        return "Run `hermes sealed status` to inspect the store."


def register(ctx) -> None:
    ctx.register_secret_source(SealedSource())

    def setup_fn(subparser) -> None:
        try:
            from .cli import build_parser
        except ImportError:  # pragma: no cover - loaded as a plain module
            from sealed_cli import build_parser  # type: ignore

        build_parser(subparser)

    def handler_fn(args):
        try:
            from .cli import dispatch
        except ImportError:  # pragma: no cover
            from sealed_cli import dispatch  # type: ignore

        return dispatch(args)

    try:
        ctx.register_cli_command(
            "sealed",
            "Manage the encrypted sealed secret store",
            setup_fn,
            handler_fn,
            description="Create, inspect and rotate the AES-GCM store that `secrets.sealed` loads.",
        )
    except Exception as exc:  # a CLI is a bonus, never a reason to fail the source
        logger.debug("sealed: CLI registration skipped: %s", exc)

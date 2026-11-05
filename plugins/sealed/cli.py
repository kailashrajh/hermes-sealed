"""``hermes sealed …`` — manage the encrypted store.

Every command is deliberately quiet about values: names and counts only. A secret that
reaches stdout reaches the terminal scrollback, the shell history and any transcript the
agent keeps.
"""

from __future__ import annotations

import argparse
import getpass
import os
import shutil
import sys
from pathlib import Path

try:  # loaded as <plugin>.cli
    from .store import (
        SealedError,
        dump_dotenv,
        generate_key,
        inspect,
        mode_is_private,
        parse_dotenv,
        read_key,
        read_store,
        remove_entry,
        replace_entry,
        write_key,
        write_store,
    )
except ImportError:  # pragma: no cover - direct import in tests
    from store import (  # type: ignore
        SealedError,
        dump_dotenv,
        generate_key,
        inspect,
        mode_is_private,
        parse_dotenv,
        read_key,
        read_store,
        remove_entry,
        replace_entry,
        write_key,
        write_store,
    )


def _home() -> Path:
    raw = os.environ.get("HERMES_HOME", "").strip()
    if raw:
        return Path(raw).expanduser()
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return Path.home() / ".hermes"


def _paths(args: argparse.Namespace) -> tuple[Path, Path]:
    home = _home()
    store = Path(args.store).expanduser() if getattr(args, "store", None) else home / "secrets" / "sealed.store"
    key = Path(args.key_file).expanduser() if getattr(args, "key_file", None) else home / "secrets" / "sealed.key"
    return store, key


def _load(store_path: Path, key_path: Path) -> tuple[bytes, dict[str, str]]:
    key = read_key(key_path)
    return key, read_store(store_path, key)


def _read_value(prompt: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.read().rstrip("\n")


def cmd_init(args: argparse.Namespace) -> int:
    store_path, key_path = _paths(args)
    if store_path.exists() and not args.force:
        print(f"store already exists: {store_path} (use --force to re-encrypt with a new key)")
        return 1
    if key_path.exists() and not store_path.exists() and not args.force:
        print(f"key exists but store is missing: {key_path}")
        print("  re-run with --force to re-initialise, or restore the store from a backup")
        return 1
    existing: dict[str, str] = {}
    if store_path.exists():
        try:
            _, existing = _load(store_path, key_path)
        except SealedError as exc:
            print(f"cannot read the existing store: {exc}")
            return 1
        backup = store_path.with_suffix(store_path.suffix + ".bak")
        shutil.copy2(store_path, backup)
        os.chmod(backup, 0o600)
        print(f"backup written: {backup}")
    if key_path.exists():
        old_key = key_path.with_suffix(key_path.suffix + ".bak")
        shutil.copy2(key_path, old_key)
        os.chmod(old_key, 0o600)
        key_path.unlink()
        print(f"old key saved: {old_key}")
    key = write_key(key_path)
    write_store(store_path, key, existing)
    print(f"key:   {key_path} (0600)")
    print(f"store: {store_path} (0600, {len(existing)} entries)")
    print()
    print("next:")
    print("  hermes config set secrets.sealed.enabled true")
    print("  hermes sealed set OPENAI_API_KEY")
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    store_path, key_path = _paths(args)
    try:
        key, values = _load(store_path, key_path)
    except SealedError as exc:
        print(f"{exc}\nRun `hermes sealed init` first.")
        return 1
    value = _read_value(f"value for {args.name}: ")
    if not value:
        print("empty value refused — use `hermes sealed unset` to remove a variable")
        return 1
    try:
        write_store(store_path, key, replace_entry(values, args.name, value))
    except SealedError as exc:
        print(exc)
        return 1
    print(f"set {args.name} ({len(value)} chars, stored encrypted)")
    return 0


def cmd_unset(args: argparse.Namespace) -> int:
    store_path, key_path = _paths(args)
    try:
        key, values = _load(store_path, key_path)
    except SealedError as exc:
        print(exc)
        return 1
    if args.name not in values:
        print(f"{args.name} is not in the store")
        return 1
    write_store(store_path, key, remove_entry(values, args.name))
    print(f"removed {args.name}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    store_path, key_path = _paths(args)
    try:
        _, values = _load(store_path, key_path)
    except SealedError as exc:
        print(exc)
        return 1
    for name in sorted(values):
        print(f"{name}  ({len(values[name])} chars)")
    if not values:
        print("store is empty")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    store_path, key_path = _paths(args)
    print(f"store: {store_path}")
    print(f"key:   {key_path}")
    entries = 0
    ok = True
    for path in (store_path, key_path):
        info = inspect(path)
        if not info.exists:
            print(f"  {path.name}: MISSING")
            ok = False
            continue
        mode = f"{info.mode:o}" if info.mode is not None else "?"
        flag = "ok" if mode_is_private(info.mode) else "TOO OPEN (want 600)"
        print(f"  {path.name}: mode {mode} — {flag}")
    if store_path.exists() and key_path.exists():
        try:
            _, values = _load(store_path, key_path)
            entries = len(values)
        except SealedError as exc:
            print(f"  decrypt: FAILED — {exc}")
            ok = False
    print(f"entries: {entries}")
    try:
        from hermes_cli.config import load_config

        cfg = (load_config().get("secrets") or {}).get("sealed") or {}
        print(f"enabled: {bool(cfg.get('enabled'))}")
    except Exception:
        print("enabled: (unknown — config not readable here)")
    return 0 if ok else 1


def cmd_rotate(args: argparse.Namespace) -> int:
    store_path, key_path = _paths(args)
    try:
        old_key, values = _load(store_path, key_path)
    except SealedError as exc:
        print(exc)
        return 1
    backup = key_path.with_suffix(key_path.suffix + ".bak")
    shutil.copy2(key_path, backup)
    os.chmod(backup, 0o600)
    new_key = generate_key()
    write_store(store_path, new_key, values)
    # Key last: a crash between the two leaves the store readable by the backup key.
    tmp = key_path.with_name(f".{key_path.name}.{os.getpid()}.new")
    tmp.write_bytes(new_key)
    os.chmod(tmp, 0o600)
    os.replace(tmp, key_path)
    print(f"rotated key for {len(values)} entries; previous key saved at {backup}")
    print("delete the backup once you have confirmed startup works")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    store_path, key_path = _paths(args)
    source = Path(args.path).expanduser()
    if not source.is_file():
        print(f"not a file: {source}")
        return 1
    try:
        incoming = parse_dotenv(source.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        print(f"cannot read {source}: {exc}")
        return 1
    if not incoming:
        print("no KEY=value lines found")
        return 1
    try:
        key, values = _load(store_path, key_path)
    except SealedError as exc:
        print(f"{exc}\nRun `hermes sealed init` first.")
        return 1
    merged = dict(values)
    merged.update(incoming)
    write_store(store_path, key, merged)
    added = len(set(incoming) - set(values))
    print(f"imported {len(incoming)} entries ({added} new) — now {len(merged)} total")
    print(f"the plaintext source {source} is unchanged; delete it when you are ready")
    return 0


def build_parser(subparser) -> None:
    sub = subparser.add_subparsers(dest="sealed_command")
    for name, help_text, handler in (
        ("init", "Create the key and an empty store", cmd_init),
        ("set", "Add or replace one secret (value read from the prompt or stdin)", cmd_set),
        ("unset", "Remove one secret", cmd_unset),
        ("list", "List variable names (never values)", cmd_list),
        ("status", "Show paths, permissions, entry count and enablement", cmd_status),
        ("rotate", "Re-encrypt the store under a new key", cmd_rotate),
        ("import", "Merge a plaintext .env file into the store", cmd_import),
    ):
        parser = sub.add_parser(name, help=help_text)
        parser.set_defaults(func=handler)
        if name in ("init", "rotate", "import", "status", "list", "set", "unset"):
            parser.add_argument("--store", help="Store path (default: $HERMES_HOME/secrets/sealed.store)")
            parser.add_argument("--key-file", dest="key_file", help="Key path (default: $HERMES_HOME/secrets/sealed.key)")
        if name == "init":
            parser.add_argument("--force", action="store_true", help="Re-initialise, keeping existing entries")
        if name in ("set", "unset"):
            parser.add_argument("name", help="Environment variable name")
        if name == "import":
            parser.add_argument("path", help="Path to a plaintext .env file")
    subparser.set_defaults(func=dispatch)


def dispatch(args: argparse.Namespace) -> int:
    handler = getattr(args, "func", None)
    if handler is None or handler is dispatch:
        print("usage: hermes sealed {init|set|unset|list|status|rotate|import}")
        return 1
    try:
        return handler(args)
    except SealedError as exc:
        print(exc)
        return 1

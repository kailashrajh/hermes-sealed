"""End-to-end smoke test for `sealed` against the real Hermes runtime.

    cd ~/.hermes/hermes-agent && venv/bin/python /path/to/scripts/smoke.py
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLUGIN_DIR = REPO / "plugins" / "sealed"

from plugins.plugin_loader import load_plugin_module  # noqa: E402

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {label}{'' if condition else '  ' + str(detail)}")
    if not condition:
        failures.append(label)


def main() -> int:
    logging.basicConfig(level=logging.ERROR)
    tmp = Path(tempfile.mkdtemp(prefix="sealed-smoke-"))
    home = tmp / "hermes_home"
    (home / "secrets").mkdir(parents=True)
    os.environ["HERMES_HOME"] = str(home)

    module = load_plugin_module("plugins.sealed_smoke", PLUGIN_DIR, parents=(), logger=logging.getLogger("smoke"))
    check("plugin module loads", module is not None)
    if module is None:
        return 1

    captured = {}

    class Ctx:
        def register_secret_source(self, source):
            captured["source"] = source

        def register_cli_command(self, *args, **kwargs):
            captured["cli"] = args[0] if args else kwargs.get("name")

    module.register(Ctx())
    source = captured.get("source")
    check("register() hands back a SecretSource", source is not None)
    check("CLI command registered", captured.get("cli") == "sealed", captured.get("cli"))
    if source is None:
        return 1

    check("name/label/shape", (source.name, source.label, source.shape) == ("sealed", "Sealed", "bulk"))
    check("enabled only when configured", source.is_enabled({}) is False and source.is_enabled({"enabled": True}))

    # 1. Nothing set up yet: a clear, typed failure — not an exception.
    result = source.fetch({"enabled": True}, home)
    check("missing store is NOT_CONFIGURED", result.error_kind is not None and result.error_kind.value == "not_configured", result.error)
    check("remediation names the fix", "hermes sealed init" in source.remediation(result.error_kind, {}))

    # 2. Malformed config never raises.
    for bad in (None, "nope", {"store": 5}, {"key_file": ["x"]}):
        r = source.fetch(bad, home)  # type: ignore[arg-type]
        check(f"malformed cfg {bad!r} fails closed", r.error is not None)

    # 3. Create a real store and read it back.
    from plugins.sealed_smoke.store import generate_key, write_key, write_store  # type: ignore[attr-defined]

    key_path = home / "secrets" / "sealed.key"
    store_path = home / "secrets" / "sealed.store"
    key = write_key(key_path, generate_key())
    write_store(store_path, key, {"OPENAI_API_KEY": "sk-smoke", "TELEGRAM_BOT_TOKEN": "123:abc"})

    result = source.fetch({"enabled": True}, home)
    check("fetch returns the entries", result.secrets.get("OPENAI_API_KEY") == "sk-smoke", result)
    check("fetch is clean", result.ok, result.error)
    check("store path reported", str(store_path) == str(result.binary_path))

    # 4. Wrong key fails AUTH_FAILED.
    bad_key = tmp / "bad.key"
    bad_key.write_bytes(b"\x00" * 32)
    result = source.fetch({"enabled": True, "key_file": str(bad_key)}, home)
    check("wrong key is AUTH_FAILED", result.error_kind is not None and result.error_kind.value == "auth_failed", result.error)

    # 5. Permissions: warn by default, refuse under strict.
    os.chmod(store_path, 0o644)
    result = source.fetch({"enabled": True}, home)
    check("open permissions produce a warning", any("mode 644" in w for w in result.warnings), result.warnings)
    check("open permissions still load by default", result.ok)
    result = source.fetch({"enabled": True, "strict_permissions": True}, home)
    check("strict_permissions refuses", not result.ok and result.error_kind.value == "auth_failed", result.error)
    os.chmod(store_path, 0o600)

    # 6. CLI: status, list, rotate.
    cli = sys.modules["plugins.sealed_smoke.cli"]
    args = type("A", (), {"store": None, "key_file": None, "sealed_command": "status"})()

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli.cmd_status(args)
    output = buffer.getvalue()
    check("status exits 0", code == 0, output)
    check("status never prints a value", "sk-smoke" not in output, output)
    check("status reports entries", "entries: 2" in output, output)

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli.cmd_rotate(type("A", (), {"store": None, "key_file": None})())
    check("rotate succeeds", code == 0, buffer.getvalue())
    check("fetch works after rotation", source.fetch({"enabled": True}, home).secrets.get("OPENAI_API_KEY") == "sk-smoke")

    print(f"\n{'FAILED: ' + ', '.join(failures) if failures else 'all checks passed'}")
    print(f"workspace: {tmp}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

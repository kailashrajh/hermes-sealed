# sealed — encrypted secrets for Hermes Agent

Hermes keeps credentials in `~/.hermes/.env`, in plaintext, forever. `sealed` replaces that with
one AES-256-GCM encrypted file, unlocked at startup by a 32-byte key, and hands the values to
Hermes through the sanctioned `SecretSource` contract.

No network. No helper binary. No daemon. No cloud account. The agent's shell, its command lines
and its transcripts never see a value.

```bash
hermes sealed init                       # key + empty store, both 0600
hermes sealed import ~/.hermes/.env      # migrate what you already have
hermes config set secrets.sealed.enabled true
hermes sealed set OPENAI_API_KEY         # value read from the prompt or stdin, never argv
```

## Why

- **Threat model.** A backup, a laptop image, a synced folder, a pasted dotfile, a misconfigured
  repo — anything that copies `~/.hermes/.env` copies every credential in cleartext. `sealed`
  makes that copy useless without the key, which lives in a separate file you can keep off the
  sync path (`key_file` is configurable).
- **No new trust surface.** It does not shell out, does not phone home, and does not touch
  `os.environ` itself — the Hermes orchestrator applies the values, so precedence, conflict
  detection and `(from Sealed)` provenance all behave like any other source.
- **Honest about its limits.** This is a lock on a box, not a vault against a root attacker: the
  key sits on the same machine, and a process running as you can read it. It defends against
  accidental exposure, not against a compromised host.

## Install

From the catalog (once listed):

```bash
hermes plugins install sealed
```

From source:

```bash
git clone https://github.com/kailashrajh/hermes-sealed
cp -r hermes-sealed/plugins/sealed ~/.hermes/plugins/sealed
hermes plugins enable sealed
```

Requires `cryptography` (declared as a plugin dependency and installed by Hermes).

## Configuration

```yaml
secrets:
  sources: [sealed]        # optional explicit ordering
  sealed:
    enabled: true
    store: ~/.hermes/secrets/sealed.store      # default
    key_file: ~/.hermes/secrets/sealed.key     # default
    strict_permissions: false                  # true = refuse to load if either file is group/world readable
    override_existing: true                    # the store is the source of truth for what it holds
    timeout_seconds: 120
```

`secrets.sealed` is a bulk source: every variable in the store is offered to the process. It
yields to any `mapped` source that explicitly binds a variable, as the framework defines.

## CLI

| Command | What it does |
|---|---|
| `hermes sealed init [--force]` | Create the key and an empty store (keeps existing entries on `--force`) |
| `hermes sealed set NAME` | Add or replace one variable — value from the TTY prompt or stdin |
| `hermes sealed unset NAME` | Remove one variable |
| `hermes sealed list` | Names and value lengths only, never values |
| `hermes sealed status` | Paths, file modes, entry count, whether the source is enabled |
| `hermes sealed rotate` | Re-encrypt under a new key, keeping the old key as `.bak` |
| `hermes sealed import PATH` | Merge a plaintext `.env` file (the file is left in place; delete it yourself) |

Every command prints names, counts and paths — never a value. That is deliberate: a secret that
reaches stdout reaches scrollback, shell history and any transcript of the session.

## On-disk format

```
sealed.key    32 raw random bytes, mode 0600, created with O_EXCL and never overwritten
sealed.store  b"SEALED1\n" + base64url( nonce(12) || AES-256-GCM ciphertext )
```

The magic header is the AEAD associated data, so a store from a different format version fails
authentication instead of decrypting into nonsense. Writes are atomic (`os.replace`), so a crash
cannot leave a half-written store. A wrong key and a modified file are indistinguishable by
design — both fail closed with `AUTH_FAILED`.

## Tests

```bash
python -m pytest                                        # 17 store tests, no Hermes needed
cd ~/.hermes/hermes-agent && venv/bin/python /path/to/scripts/smoke.py   # 26 contract checks
hermes plugins validate plugins/sealed --install-deps
```

It also passes Hermes's own contract kit (`tests/secret_sources/conformance.py`, 10 checks) —
subclass `SecretSourceConformance` with a `source` fixture returning `SealedSource()` and run it
from a hermes-agent checkout.

## Disclosure

- **Network:** none.
- **Reads:** the configured `store` and `key_file` only, at startup, once per process.
- **Writes:** only from the CLI, only to the store/key paths (plus `.bak` copies on `init --force`
  and `rotate`). `import` reads the plaintext file you name and never modifies it.
- **No telemetry, no self-updater, no background process.**

## License

MIT — see [LICENSE](LICENSE).

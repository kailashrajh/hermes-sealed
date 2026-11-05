# 60-second demo — sealed

Under 90 s, show the plugin actually working, post on X tagging `@NousResearch`.
No slides, no voice-over intro. Screen recording only.

Prepare once: `hermes sealed init --store ~/.hermes/sealed/scratchpad.enc --key ~/.hermes/sealed/key.bin`
Terminal: large font, dark theme, no notifications. Record at 1080p.

| Time | On screen | Caption |
|---|---|---|
| 0:00–0:08 | `ls ~/.hermes/sealed/` (key.bin mode 600, store enc) | "One secret, encrypted at rest. No plaintext .env." |
| 0:08–0:20 | `hermes sealed set OPENAI_API_KEY` (paste, then `hermes sealed list`) | "Value never printed, never in argv." |
| 0:20–0:35 | `hermes status` → `Sealed: applied 1 secret` | "Hermes's secret orchestrator applies it at startup." |
| 0:35–0:50 | `hermes sealed rotate` (one line) + `hermes sealed status` | "Rotate re-encrypts in place; old key no longer decrypts." |
| 0:50–1:00 | `hermes sealed import ~/.hermes/.env` (dry-run) | "Migrate from plaintext in one command." |

Closing card (3 s): `sealed — secrets encrypted at rest` + repo URL.

## Post copy

> Hermes plugin: sealed. AES-256-GCM store, one 32-byte key file, no network, no daemon.
> Replaces the plaintext `~/.hermes/.env` habit. Passes Hermes's own secret-source
> conformance kit. `hermes plugins install sealed` @NousResearch

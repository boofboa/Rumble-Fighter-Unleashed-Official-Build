# Preservation build status

The repository starts from the active **v1.28** code in the October 21, 2026 preservation backup. This import adds a repeatable development/build workflow. It does not establish new Windows gameplay results.

## Current validation scope

The Linux workflow compiles the three active C# sources (`RFHandshakeProbe.cs`, `RFAccount.cs`, and `RFPlaza.cs`) and exercises their protocol, plaza handshake, and persistence checks. Python tests cover the separate local account backend and capture evidence; JavaScript tests cover the trace sanitizer. The backend smoke test starts the Python server in a separate process and checks encrypted protocol responses with disposable data.

Private capture/fixture checks require the locally retained `private/` directory. They are distinct from synthetic checks that can run in a fresh source-only clone. Windows GUI/client runs, Windows adapter ownership/cleanup, and actual gameplay cannot be validated by these Linux checks.

Validation performed on October 28, 2026 in the Linux cloud workspace:

| Check | Result |
| --- | --- |
| SDK installation and repeated installation | Verified SHA-512; repeat reused SDK 10.0.403 successfully |
| C# Release build | Passed, zero warnings and zero errors |
| Python with preserved evidence | 67 passed, zero skipped |
| JavaScript trace sanitizer | All 22 groups passed |
| C# full runner | Six groups passed, including 14 plaza checks and 48 account checks |
| Persistent C# lobby reconnect | Two sessions with 3,000 and 10 polls; persistence and shutdown checks passed |
| Separate Python server process | Encrypted version/login/avatar/currency/inventory/equipment smoke passed |
| Imported source integrity | All 134 imported source/evidence files matched original archive SHA-256 hashes |
| Clean source-only copy | 37 Python tests passed, 30 evidence tests skipped; 22 JavaScript groups, two C# groups, Release build and backend smoke passed |

These checks use temporary accounts and loopback clients. They do not establish real-client gameplay or GitHub Actions results.

## What the backup records

These are historical reports preserved in [the project notes](archive/preservation-notes.md) and [task tracker](archive/preservation-tasks.md), not new results from this repository import.

| Version | Reported result | Qualification |
| --- | --- | --- |
| v1.23 | Persistent lobby reconnects, menu, My Info, and Store | The client still used the official plaza service |
| v1.25 | Local lobby/plaza startup, menu, My Info equipment changes, Store, and client-side Sunset Valley tutorial | Tutorial return logged `GameFinish Query fail`; the square button still contacted an official service |
| v1.26 | Ten Store purchases persisted and unlimited balances displayed | Level 90 did not display; package unpacking timed out |
| v1.27 | Explicit refusal responses for unpack/open-box requests and improved request logging | Those response forms were not verified in the real client |
| v1.28 | Startup regression fix: unrecognized ADD_ITEM requests receive the observed failure form instead of no response | Backup records automated checks; this revision was pending a real-client test |

## Available implementation

- Windows C# lobby server with persistent account profiles, inventory pagination, equipment changes, own-profile information, reconnect handling, and atomic account updates.
- Free local purchases for profiles configured with unlimited currency; an admin/item tool operates on local profiles.
- Plaza connection handshake, ping/heartbeat handling, bounded framing, and connection diagnostics.
- Separate Python SQLite account laboratory with salted password hashes and encrypted protocol integration tests.
- Protocol/capture analysis utilities and a browser-based startup-trace sanitizer.

## Remaining gaps

| Area | Current limitation |
| --- | --- |
| Room creation and matches | Room creation, match start/map-load flow, and a complete local gameplay loop are not implemented |
| Multiplayer | Room/P2P group handling, relay, and UDP hole punching remain incomplete |
| Full offline operation | Square service redirection, independent name resolution, launcher/update contacts, and ongoing GameGuard behavior remain unresolved |
| Authentication compatibility | The preserved Windows experiment replays one initialization fixture; it does not implement fresh GameGuard authentication |
| Store economy | Paid purchases need a price table; package contents, box rewards, and successful unpack/open-box replies are unresolved |
| Levels/catalog | Level 90 experience mapping and the complete item catalog are unresolved |
| Unsupported requests | Several requests remain unanswered or refused; client errors and timeouts remain possible |
| Full game assets | The uploaded preservation ZIP is not the complete game installation |

The Windows runtime remains a preservation experiment with incomplete protocol support. Future gameplay work should use captured evidence and real-client validation for each newly supported flow.

## Source provenance and local data

[import-manifest.json](import-manifest.json) identifies the uploaded archive and original imported file hashes. Active source paths retain the backup's `work/protocol-lab` layout so existing relative fixture paths still work. Historical documents are kept under `docs/archive` for reference.

Private captures, account files, client binaries, and raw run logs are retained locally under ignored paths. A Git checkout alone therefore cannot reproduce private-evidence tests or the Windows runtime without the user's separately retained inputs.

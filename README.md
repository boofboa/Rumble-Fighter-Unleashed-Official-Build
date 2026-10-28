# Rumble Fighter Unleashed — Preservation Build

Development repository restored from `RumbleFighter-Preservation-Backup-2026-10-21_160241.zip`, using its active **v1.28** preservation code. It contains the Windows lobby/plaza experiment, persistent local account tools, protocol research utilities, and automated checks. [Current status](docs/STATUS.md) describes the working scope and remaining gameplay gaps.

## Build and check on Linux

Requirements: Python 3.10 or newer, Node.js 22 or newer, and the .NET SDK selected by `global.json` (10.0.403). Python and C# use their standard libraries; no pip or NuGet packages are required.

From the repository root:

```bash
./scripts/install-dotnet.sh
./scripts/check.sh
```

The installer verifies the SDK against its pinned SHA-512 checksum. Its default installation directory is `.dotnet/`; set `RF_DOTNET_ROOT` to choose another location. The check script runs the Python tests, JavaScript trace-sanitizer tests, C# protocol/plaza checks, and backend process smoke test. Socket-based checks need permission to open local loopback connections.

With your preservation backup's `private/` directory restored locally:

```bash
./scripts/check.sh --with-private
```

Private checks add capture-backed protocol assertions, scripted lobby sessions, reconnect/persistence checks, and account serialization tests. A checkout without private data intentionally skips the Python evidence tests; `--with-private` requires the fixtures and reports missing inputs as an error. Test account writes use temporary directories.

To build the C# checks explicitly:

```bash
.dotnet/dotnet build tools/Preservation.Checks/Preservation.Checks.csproj -c Release
.dotnet/dotnet run --project tools/Preservation.Checks -c Release --no-build
.dotnet/dotnet run --project tools/Preservation.Checks -c Release --no-build -- --private-root "$PWD/private"
```

Use your installed `dotnet` executable instead of `.dotnet/dotnet` if you selected another SDK location. The SDK project compiles the preserved C# sources directly; it is a test runner, while the Windows harness below starts the game-facing server.

## Run the Python account laboratory

This smaller backend supports synthetic account/login/profile/inventory exchanges on `127.0.0.1`. It is separate from the Windows C# preservation server.

```bash
python3 work/protocol-lab/local_backend.py --db private/dev.sqlite3 create-account
python3 work/protocol-lab/local_backend.py --db private/dev.sqlite3 serve --port 17000
```

Account creation prompts for a new local test password and stores a salted password hash. Stop the server with Ctrl+C. `python3 scripts/smoke_backend.py` exercises the server in a separate process using disposable test data and shuts it down afterward.

## Run the preserved Windows harness

The game-facing harness requires Windows PowerShell 5.1, administrator access, a compatible complete Rumble Fighter installation, and your local preservation fixtures. This ZIP includes a client executable for research, but **does not include the complete game installation**. The expected client identity is recorded in [work/build-identity.json](work/build-identity.json).

1. Restore `private/` from your own backup beside `work/`. The primary runtime inputs are `private/captures/rf-startup.pcapng`, `private/fixtures/lobby-boss-v2.bin`, and local account profiles under `private/accounts/`.
2. Close Rumble Fighter and its launcher. Run `work\protocol-lab\RunLocalHandshake.cmd` as administrator; the default account profile is `baseline`.
3. Follow the harness's preflight and READY messages, then use the local test login it displays. The harness expects the game installation at `C:\PlayRedFox\RumbleFighter`.
4. Close the game and stop the harness with Q or Ctrl+C. Confirm that cleanup completes. If interrupted, run `work\protocol-lab\CleanupLocalHandshake.cmd` as administrator from the same checkout and retain its ownership journal until cleanup succeeds.

The harness temporarily adds its two service addresses to Windows software loopback and records ownership for cleanup. It does not provide complete offline isolation: the square service, DNS resolution, launcher/update contacts, and parts of GameGuard remain external dependencies. Room creation and multiplayer matches remain unfinished. See [STATUS.md](docs/STATUS.md) before interpreting a successful startup as playable multiplayer.

## Repository layout

| Path | Purpose |
| --- | --- |
| `work/protocol-lab/` | Active v1.28 C#/PowerShell harness, Python tools, codecs, and tests |
| `work/schemas/`, `work/capture/` | Preserved protocol findings and aggregate evidence |
| `tools/Preservation.Checks/` | Portable .NET build and automated test entry point |
| `scripts/` | SDK installation, checks, and backend smoke test |
| `docs/archive/` | Historical project notes and Windows research setup records |
| `docs/import-manifest.json` | Source archive identity and SHA-256 hashes of imported files |
| `private/` | Local-only accounts, captures, fixtures, and binaries; excluded from Git |

Historical notes describe earlier sessions and may contain superseded steps. The latest source and [current status](docs/STATUS.md) take precedence for this repository's documented workflow. Duplicate version/checkpoint trees, old run reports, caches, and raw private material remain in the original backup rather than the tracked source tree. In particular, the archived checkpoint-restore helper requires checkpoint directories from that backup.

The original backup and its complete extracted copy are retained outside this checkout in the prepared cloud workspace. Git clones contain the tracked source and documentation, not those private files or the cloud workspace itself.

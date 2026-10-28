# Reverse-Engineering Environment Setup

Set up on 2026-10-20 on Windows 11 Home 10.0.26200 (x64), following
https://github.com/morluto/rea/blob/main/docs/installation.md and the installed
release's own `rea setup --help` / `rea doctor --help`.

## Installed components

| Component | Version | Path | Source |
|---|---|---|---|
| REA (`rea-agents`, npm global) | 6.7.0 (skill identity 42, 207 MCP tools) | `C:\Users\volk\AppData\Roaming\npm\node_modules\rea-agents` | `npm install -g rea-agents@6.7.0` |
| Ghidra | 12.1.4 (`ghidra_12.1.4_PUBLIC_20260921`) | `C:\Users\volk\tools\ghidra_12.1.4_PUBLIC` | GitHub release `NationalSecurityAgency/ghidra` tag `Ghidra_12.1.4_build` |
| JDK | Eclipse Temurin 21.0.12.1+1 LTS, x64, full JDK | `C:\Users\volk\tools\jdk-21.0.12.1+1` | Adoptium (`adoptium/temurin21-binaries`, `jdk-21.0.12.1+1`) |
| Node.js (already present) | 22.19.0 | `C:\Program Files\nodejs` | — (meets REA's requirement of 22.x ≥ 22.19) |
| Claude Code (already present) | 2.1.304 | `C:\Users\volk\.local\bin\claude.exe` | — |

### Why these versions

- REA 6.7.0 pins `SUPPORTED_GHIDRA_VERSION = "12.1.4"` and accepts the 12.1.x line
  (`dist/ghidra/GhidraReleasePolicy.js`). Its verified JDK major is 21.
- Ghidra 12.1.4's `application.properties` declares `application.java.min=21`
  with no maximum, so JDK 21 is within bounds.
- Windows Ghidra support in REA is **experimental and read-only** (per the install docs).

### Download integrity (SHA-256)

| File | SHA-256 | Matches official |
|---|---|---|
| `ghidra_12.1.4_PUBLIC_20260921.zip` | `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` | Yes (GitHub release asset digest) |
| `OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip` | `f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e` | Yes (Adoptium API checksum) |

## Configuration

User environment variables (persistent, `HKCU\Environment`):

```
JAVA_HOME          = C:\Users\volk\tools\jdk-21.0.12.1+1
GHIDRA_INSTALL_DIR = C:\Users\volk\tools\ghidra_12.1.4_PUBLIC
Path               = C:\Users\volk\tools\jdk-21.0.12.1+1\bin;<previous user Path>
```

Open a new terminal to pick these up. REA does not rely on them alone: setup
also wrote both values into the MCP server's own `env` block.

## Claude Code registration

Command run: `rea setup --client claude_code --yes` (after checking the plan with `--dry-run`).
`CLAUDE_CONFIG_DIR` was unset, so the default user-wide profile was used.

- MCP server `rea`, user scope, in `C:\Users\volk\.claude.json` (backup: `C:\Users\volk\.claude.json.rea.backup`)
  - Command: `"C:\Program Files\nodejs\node.exe" C:\Users\volk\AppData\Roaming\npm\node_modules\rea-agents\scripts\rea.mjs mcp`
  - Env: `GHIDRA_INSTALL_DIR`, `JAVA_HOME` as above
- Skill: `reverse-engineer-anything` at `C:\Users\volk\.claude\skills\reverse-engineer-anything` (version 42, aligned with the CLI)
- Only Claude Code was configured. REA also detected Claude Desktop and Codex; it did not change them.

## Verification results

### `rea doctor --client claude_code --provider ghidra --skill --format json`

Exit code 0, `healthy: true`. Every scoped check passed:

| Check | Result |
|---|---|
| node | 22.19.0 |
| ghidra | `C:\Users\volk\tools\ghidra_12.1.4_PUBLIC` |
| ghidra-platform / architecture | win32 / x64 |
| ghidra-installation | `...\Ghidra\application.properties` found |
| ghidra-version | 12.1.4 (verified build) |
| ghidra-headless | `...\support\analyzeHeadless.bat` |
| ghidra-native_decompiler | `decompile.exe` is PE x86_64, matches host |
| ghidra-java | 21.0.12.1, 64-bit, full JDK, accepted |
| ghidra-native_authority | Windows Job Object, private DACL, reparse-safe handles verified (local NTFS only) |
| registration:claude_code | aligned |
| skill:identity | aligned (version 42, 207 tools) |

Not configured, and outside this setup's scope: Hopper (no Windows install), IDA,
JADX, Kuna. The report also shows `installations: multiple`. Those are the two
npm shims (`rea` and `rea.cmd`) for the same global install, not two separate copies.

### `claude mcp get rea`

`Scope: User config`, `Status: √ Connected`, stdio, with the env vars shown above.

### Functional smoke test

`rea analyze <copy of C:\Windows\System32\whoami.exe> --provider ghidra --format json`
ran on a copy in the session scratchpad. It finished with exit 0 in about 93 s and
returned a `binary_overview` evidence record from Ghidra 12.1.4. The record had
PE/x86_64 detection, image base `0x140000000` and the segment map. This confirms
headless Ghidra analysis works on this host.

## Restart required

The running Claude Code session started before REA was registered, so it does not
have the `rea` MCP tools or the `reverse-engineer-anything` skill. Restart it once:

1. Exit the current session with `/exit`, or press Ctrl+C twice.
2. Open a new PowerShell window so it has the new `JAVA_HOME` and `Path`.
3. Run `cd C:\Users\volk\RumbleFighter-Preservation`, then `claude`. Use
   `claude --continue` instead to resume this conversation.
4. To confirm, run `/mcp`, where `rea` should show as connected. The
   `reverse-engineer-anything` skill should also appear in Claude's list of
   available skills.

## Maintenance

- Re-check: `rea doctor --client claude_code --provider ghidra --skill --format json`
- Update REA: `rea update`. After updating, run `rea setup --client claude_code`
  again so the skill matches, and check Ghidra compatibility, because each REA
  release pins a Ghidra line.
- Remove: `rea uninstall` removes REA-owned registrations and skill files.
  Add `--purge-data` to also remove `~/.rea`.

# Rumble Fighter Preservation — Project Notes

Resumable state of the private-server project. Update this file at every step.
Last updated: 2026-10-20.

## Goal

Host our own server that real, unmodified Rumble Fighter clients can use:
accounts and characters that persist, full multiplayer matches, and play from
other networks.

## Workspace layout

| Path | Contents |
|---|---|
| `checkpoint-14-original/` | Byte-for-byte copy of `Desktop\Rumble-Fighter-Analysis (14)`, read-only. Never edit. |
| `work/` | Working copy. All code changes happen here. |
| `work/protocol-lab/` | Harness, codecs and tests (see "Code" below). |
| `work/reports/` | Metadata-only reports (headers and lengths; no bodies). |
| `private/` | **Never share or upload.** Raw captures (they contain the real login), body dumps, the binary copy and the REA snapshot. |
| `SETUP.md` | REA, Ghidra and JDK installation record. |

The originals are left untouched: game install `C:\PlayRedFox\RumbleFighter`,
checkpoint `Desktop\Rumble-Fighter-Analysis (14)`, captures in
`Documents\Downloads\rf-*.pcapng`.

## Client identity (reproduced 2026-10-20)

| File | SHA-256 | Matches `build-identity.json` |
|---|---|---|
| `rumblefighter.exe` (4,217,600 B, "GEM Fighter Client" 0.9; the log prints `GemVer0.9_00385_SRCERR-FINAL`) | `94194afa…4d593a59` | yes |
| `RumbleLauncher.exe` (1,739,064 B) | `21dd6e1e…1b77b` | yes |

## Evidence register

R = reproduced here. P = previously reported by checkpoint 14, not yet reproduced.

| Claim | Status | How |
|---|---|---|
| rf-startup framing: RC4 key `abcde` per direction; headers are BE16 type, BE16 total, LE16 action; C 72 frames / 1,119 B, S 70 frames / 46,191 B, no tail | **R** | `analyze_rf_capture.py`; output identical to `checkpoint/capture/protocol-report.json` |
| Same framing on rf-empty-buddy (C 52 / S 51 frames) and on the rf-boss-baseline port-7000 flow (C 202 / S 203), complete, no gaps | **R** (new captures) | `analyze_rf_capture.py`, `work/reports/*-framing.json` |
| Python protocol-lab tests: 27 | **R**: 27/27 on Windows / Py 3.14 after fixing a Windows-only test bug (below). The original reported 27/27 on Linux / Py 3.12. | `python -m unittest discover` |
| `trace_sanitizer` JS tests: 22 | **R** 22/22 (Node 22.19) | `node test_trace_sanitizer.js` |
| v1.8 C# probe self-test | **R** passes (original file) | `Add-Type` + `[RFLocalHandshake.Probe]::SelfTest()` |
| v1.8 real-client run reached the gift lists, then stopped at buddy list 10/A8; screenshot "FUNC_Q_GET_BUDDY_LIST … NULL" | **P** (user's Windows runs of 2026-10-16; JSON logs present in `protocol-lab/rf-local-handshake-*.json`) | screenshot not on disk |
| Stage-1 unpacking (8 blocks, output SHA `674441d3…`) | **P** | `inspect_client_stage1.py` not yet rerun |
| 104-ID observed item catalog | **P** | |
| 2026-10-16 cleanup: temporary address 5.188.32.117 removed | **R** (2026-10-20): no address or route present | `Get-NetIPAddress` / `Get-NetRoute` |

Fixed test bug: `test_backend.py` used `with sqlite3.connect(...)`. That commits
but does not close, so on Windows the temp directory cannot be deleted
(2 errors). It now uses `contextlib.closing`. Product code was unchanged.

## Step 1: the buddy-list stop (v1.8 → v1.9)

### Failing transition (established from evidence)

The client sends `0x10/0xA8`, total 10 bytes, with a 4-byte body. The v1.8
probe classified this as `unsupported_header` and stopped without replying.
The client then showed "FUNC_Q_GET_BUDDY_LIST … NULL" (user screenshot,
reported). In both official captures this request comes immediately after
the two gift lists (`0x30/0x92` → `0x30/0x90`), and the server answers once
with `0x10/0xA9`, total 3,008 bytes.

### Expected structure (from the official replies)

- Request body: 4 bytes, all zero in both captures.
- Reply body (3,002 B) = LE16 count + **100 fixed records of 30 B**:
  LE32 id, char[24] NUL-padded name, 2 trailing bytes.
  - rf-startup: count = 6. All 6 records parse, and every trailing field is
    `4E 46` ("NF"; meaning unknown).
  - rf-empty-buddy: **count = 0**, followed by 3,000 bytes of server
    uninitialized memory. After it the client continued with `0x30/0x86`.
- State: no session state change was observed. In rf-empty-buddy, the guild
  queries (`0x33/0x84, 8A, 90, 8E`) that follow the buddy list in rf-startup
  were absent. What makes the client skip them is not yet established.

### Change (smallest supported correction)

`work/protocol-lab/RFHandshakeProbe.cs` and `Test-RF-LocalHandshake.ps1` → version **1.9**:

- `0x10/0xA8` (length 10) is accepted only after both gift replies, and only once.
- The 4-byte body is read and decrypted so the cipher stays aligned. Whether it
  was all zero is recorded.
- The reply is `BuildEmptyBuddyList()`: count 0 and 100 zeroed records (3,008 B).
- The header limit went from 12 to 14 so the *next* request gets recorded.
- The report gains `buddy_request_body_zero`, `buddy_reply_written` and
  `buddy_reply_bytes`, plus new status values.
- Byte bounds: client ≤ 238 B (was 222); server ≤ 22,302 B (was 19,280).
- The GameGuard fixture is now also found at `private/captures/rf-startup.pcapng`.

### Regression tests

- **C# `SelfTestBuddyList()`**, run by the harness on every start. It checks:
  - the reply layout and the empty body;
  - the order rules across all 8 startup × 4 gift × 2 buddy states;
  - length validation;
  - **cipher alignment**: after header + 4-byte body, the next header must
    decode, and skipping the body must not.

  **R**: passes. Two deliberate breakages (wrong classification; non-zero
  count) both make it fail.
- **Python `test_lobby_wire.py`** (with the codec in `lobby_wire.py`):
  synthetic layout and round-trip, plus official-capture checks. Populated
  reply: 6 valid records. Empty reply: count 0, then the client sends
  `0x30/0x86`. The capture checks skip if `private/captures` is missing.
  **R**: 31/31 Python tests.

### Real-client result of v1.9 (2026-10-20): buddy step NOT reached

Three reports are in `work/protocol-lab/` (all `script_version` 1.9, so the
current harness ran them):

| Report | Outcome |
|---|---|
| `…150944-1e88198e` | The game connected at 104 s of the 120 s window and sent no bytes; `idle_timeout`. Cleanup was left pending (game still running). |
| `…151526-7a9ff4cd` | `cleanup_only`: address, route and journal verified removed. |
| `…151545-0809fdd4` | The version exchange completed (26 B in, 6 B out). The 91-byte login frame was received, but `local_fixture_matched=false`, so the probe sent `BuildLoginFailure()`: 520 B, the "ASTER LOCAL SERVER: login message received. Gameplay is not enabled yet." banner. 0 post-login headers; buddy request/reply did **not** occur. Cleanup is pending: the journal `rf-local-handshake-state.json` is still present, while the address is already absent (checked). |

"(701)" does not appear in any source or in the banner bytes. The client adds
it when showing the banner; the 2026-10-16 fourth run showed the identical
text. The banner is the probe's **intentional fixed rejection for
non-matching login fields**. It exists unchanged in v1.8 and v1.9; it is not
an older server or a fallback. Likely cause (not provable, because the
credentials are deliberately not logged): the registry has `SaveID=1`, so the
ID box is pre-filled with the saved real login. v1.10 records whether each
field matched (yes/no only) and tells the user to clear the ID box.

### Real-client result of v1.10 (2026-10-20, `…152535-b44785cd`): rejected at login again

- `…152519`: `cleanup_only`; the stale journal was verified removed.
- `…152535` (v1.10, build verified): the version exchange and 91-byte login
  completed. `login_email_field_matched=false`, `login_password_field_matched=true`
  → fixed rejection banner. 0 post-login headers; cleanup verified.
- The same exact-match check passed in five 2026-10-16 runs (handshake 5–9,
  same client hash), so the check works. The ID box content differed this time.

**v1.11 change:** the invented password alone admits the local profile
(`AcceptsLocalLogin`). The password is what keeps real credentials out; the ID
is not needed for that. The report adds `local_login_accepted` plus yes/no ID
facts (`login_id_empty`, `_has_at`, `_case_insensitive_match`,
`_contains_invented`); the value itself is never kept. Self-tests cover these;
removing the password gate is detected (`login_password_gate_selftest_failed`).

## MILESTONE 1 REACHED: real client passed the v1.8 stop (v1.11, 2026-10-20 15:31Z)

Report `work/protocol-lab/rf-local-handshake-20261020-153110-763687ac.json`
(build verified, cleanup verified). Login was accepted (the ID box matched
exactly this time). The real client's post-login request order:

```
10/92 48/80 10/D0 31/88 10/92 30/84(17) 30/92 30/90 10/A8(10) 30/86(10) 40/A0 30/88(10) 40/A6(11)
                                                    ^buddy    ^avatar list ^equipped ^equipment  ^NEW stop
```

Established by this run:
- The buddy request had an all-zero body, as in the captures. After our empty
  list the client continued: **the buddy stop is resolved**.
- The client then sent `30/86` with account ID 1 (the body check passed), so
  it accepted the login profile's account ID.
- After the one-avatar list it sent `40/A0`; after equipped=1 it sent exactly
  one `30/88` for avatar 1 (the body check passed). **The client used our
  invented avatar list.**
- After the empty-equipment reply it sent **`40/A6` (11 B)**. That is not
  the `30/A0` seen in the official sessions. Stop reason: `unsupported_header`
  (body not read). Whether it is a reaction to the empty equipment or a
  first-login behaviour is not established.

No screenshot of this run is on disk.

## Step 3: avatar update acks (v1.12, built 2026-10-20; real-client result PENDING)

Evidence (`rf_40a6_check.py`, `test_lobby_wire.OfficialAvatarUpdateCaptureTests`):
- `40/A6` occurs once in rf-boss-baseline (t=156 s): body = LE32 avatar ID
  (the 10th listed, not the equipped one) + one byte (0x0A). The reply `40/A7`
  is header-only (6 B).
- The family `40/A2` (body 4), `40/A4` (body 9), `40/A6` (body 5): across all
  captures 3 + 23 + 1 requests, each answered by exactly one header-only ack
  (A3/A5/A7). Every request's first LE32 is a listed avatar ID.
- What A2/A4/A6 change (slot or appearance settings?) is **not established**;
  the ack persists nothing.

Change: these three requests are accepted only after the full avatar chain,
with exact lengths, and only if their first LE32 is local avatar 1
(`avatar_update_mismatch` otherwise). The reply is the header-only ack. The
report gains `avatar_a2/a4/a6_ack_count` and `avatar_a6_trailing_byte` (one
byte; -1 if not seen). The header limit is 24. Tests: C# chain alignment now
runs through A6/A4/A2 to `30/A0`, with order/length/body checks; two
deliberate breakages are detected. Python 36/36.

Expected next (hypothesis from the official sessions): `30/A0` (6 B) → `30/A1`
(397/423/1255 B).

## Step 4: game exits after login (v1.12 result) → v1.13 class fixture + exit diagnostics

### v1.12 real-client result (`…153829-215978f2`, 2026-10-20 15:38:29Z)

The headers matched v1.11 up to `40/A6(11)`. The probe wrote `40/A7`, then got
`peer_closed_before_header`. `avatar_a6_trailing_byte = 0` (the captured A6 had 0x0A).
`30/A0` was never sent. Cleanup was verified with no game process left, so the
game ended within about a second.

Game log (`C:\PlayRedFox\RumbleFighter\RumbleFighter.log`, overwritten every
launch; it was read on 2026-10-20 before any newer launch):
- `11:39:20.929 DirectLogin.cpp(990)` official-version auth succeeded (launcher path)
- `11:39:30.252 ProudManager.cpp(98) P2P Connected : 20` (**the client source
  names ProudNet**, which supports the 33343/UDP hypothesis)
- `11:39:30.252 GameTask.cpp(13425) GGuard_start` (info sent to GameGuard)
- `11:39:30.253 GameTask.cpp(10732) login(AsterLocal) ok` (**our login profile accepted**)
- `11:39:30.254 GameTask.cpp(10753)` "Game Start Time (criterion: server) = 2026/10/20 08:39:30"
  (our UTC−7 clock reply was used)
- 13 × `GameTask.cpp(5809) Item_BuildPartfrom -- [NN] <item>`, the last being
  `[43] Ruby of Power` at 11:39:30.256. **The log stops there with no shutdown
  line.** The listed items (skill book, scrolls, enchant cards, gems) are not
  in our empty inventory, so their source is unknown.

Crash vs. exit evidence available for v1.12 (no instrumentation yet):
- No Application Error / WER / Hang event for the game after 15:00Z.
  Application Error logging works on this host (other apps' crashes on 10/17–18).
- No `RumbleFighter.DMP`, `RumbleFighter_Copy.DMP` or `RumbleDump.zip` (the
  names embedded in the game's own crash handler `GemDumpLoader.exe`).
- GameGuard's `.erl` logs are encrypted (`00 FC CC 00` header, about 38%
  printable) and rotate per session (`npg*`, `0npg*`, `1npg*`). Every
  session's last writes coincide with game exit, including user-closed
  sessions, so their timing alone does not prove GameGuard killed the game.
- **Not determined: crash vs. intentional exit vs. GameGuard termination.**

### Reference consistency (reproduced; `rf_inventory_check.py`, `rf_inventory_facts.py`)

- 40/40 equipment replies: slot 0 non-zero and resolves to an inventory
  instance; all non-zero refs resolve; 16 avatars populate only slot 0.
- Slot-0 catalogs: 1000175 Striker (M) ×37, 1000176 Soul Fighter (M) ×3. All
  avatars of an account share one class instance (10→1, 10→1, 20→2).
- Class record profiles `(catalog, +8, end, stat, opaque-zero?)`:
  `(1000175, 85593, 1000, 0, no)` ×20, `(1000175, 20046, 0, 0, no)` ×17,
  **`(1000176, 20046, 0, 0, all zero)` ×3**. That last profile is the only one
  reproducible without inventing or replaying opaque bytes.
- `+8` behaves as a shared category-like code: 15–19 distinct values per
  account; 20046 is on 192 of 1157 records.
- Pagination: the client requests another page while count == 80
  (3/3/15 requests for 80,80,44 / 80,80,4 / 14×80+37).

### REA (2026-10-20)

- The on-disk PE contains none of the runtime strings (`Item_BuildPartfrom`,
  `GameTask.cpp`, `ProudManager`, `FUNC_Q_GET_BUDDY_LIST`); only `JamFighter`
  appears once.
- Stage 1 was reproduced (`inspect_client_stage1.py --derived-output`); SHA-256
  `674441d3…e9cd5` matches the checkpoint (**P → R**). It also contains none of
  these strings: it is the protector's `.winlice` region.
- `rea search` on the stage-1 raw image: refused. "Windows Ghidra P0 accepts
  native PE and explicitly selected raw 6502 targets only."
- **Conclusion:** the slot-0 lookup, the A6 send condition and the A7 handler
  are not statically reachable with REA on this host and executable. Dumping
  the live GameGuard-protected process is out of scope (it would mean
  defeating anti-tamper). The runtime evidence has to decide.

### v1.13 (built 2026-10-20; real-client result PENDING)

v1.12 is preserved byte-for-byte in `work/versions/v1.12/`; the same scenario
can be rerun with `RunLocalHandshake-EmptyCharacter.cmd` (`-EmptyCharacter`).

Fixture (default): inventory page count 1, record = instance **1001** (local),
catalog 1000176, +8 20046, end 0, stat 0, all else zero. Equipment slot 0 =
**1001** (instance, not catalog), all else zero. Every other reply is unchanged.
Unresolved and kept zero: +12..28, +37..48, the 180-byte equipment tail. The
meaning of item_end 0 is unconfirmed.

Instrumentation added:
- per post-login header: `at_ms`, `reply_at_ms`, `reply_bytes`;
- `probe_started_utc`, `login_reply_at_ms`, `connection_ended_at_ms`, `fixture_kind`;
- `game_diagnostics`: process start/exit UTC, exit code;
- Application Error/WER/Hang events naming the game or GameGuard (codes and
  file names only);
- GameGuard `.erl` size and time at GAME CONNECTED vs. after;
- game crash-dump presence;
- a game-log summary (lines, last line time and source, tail sources,
  `login ok` present, `Item_BuildPartfrom` count). The full logs are copied to
  `private/run-logs/<test_id>/`.

Tests:
- C# `SelfTestClassFixture`: layout, slot 0 resolves to an inventory instance,
  slot 0 ≠ catalog, zero elsewhere, and the empty fixture equals v1.12. The
  catalog-ID-in-slot-0 mutation is detected.
- Python 38/38, including `OfficialClassReferenceTests`: 40 replies, the
  reference rule, and the fixture profile present in the captures.
- The diagnostics collector was tested with a stand-in process (exit code 3
  read correctly) and the real game log (the v1.12 summary was reproduced).

Expected outcomes of the v1.13 run:
- **H1 supported (missing class was the cause):** the game survives past
  `Item_BuildPartfrom`. The log continues past `GameTask.cpp(5809)`, a new
  request is recorded (the official sessions suggest `30/A0`; A6 may or may
  not appear), and the game stays open until closed.
- **H1 not supported:** the same `peer_closed_before_header` about 1 s after
  the last reply, the log again ending at `GameTask.cpp(5809)`, and the exit
  code / Windows events showing the kind of exit.

### v1.13 real-client result (`…155736-ee795414`, 2026-10-20 15:57:36Z): HYPOTHESIS SUPPORTED

Fixture `local_class_item`. The probe started 15:57:40.214Z; times below are ms after that.

- Login reply at 54,531. Post-login headers as before up to the avatar
  chain; the equipment reply was written at 63,821.
- **No `40/A6`.** The next request was **`31/C6` (6 B, no body)** at 63,821:
  unsupported, so the probe stopped and closed the connection
  (`connection_ended_at_ms` 63,821).
- **The game did not exit** (`has_exited=false`): no Windows error events, no
  crash dumps. It stayed open, and the user's screenshot (11:59:53 local)
  shows `ServerErr: FUNC_Q_GET_GRADE … NULL`.
- Game log (private copy `private/run-logs/ee7954148ddc4e3cb2fd19324080aefa/`)
  continued past `Item_BuildPartfrom` (unlike v1.12):
  `11:58:49 GServerAccess.cpp(8201..8215) GameGuardResponse … 124` (the
  GameGuard answer was attempted after our close),
  `11:59:14 GServerAccess.cpp(8943) FUNC_Q_REQ_FISHING_ROD query error (return NULL)`
  (30 s after the close), `11:59:44 GServerAccess.cpp(1626) query error (return NULL)` (60 s).
- Cleanup was left pending (the game stayed open past the 60 s wait). The
  address 5.188.32.117 is **still present**, and the journal is present →
  the user must run `CleanupLocalHandshake.cmd`.

Interpretation:
- The class item changed the outcome: no A6, no exit, progress to a new query.
  The missing class was very likely why v1.12 ended (one A/B pair; v1.12 vs v1.13).
- `31/C6` is **probably the fishing-rod request**. Gemnet names `31/C6`
  `UNKNOWN_10` and names `30/A0` `GET_GRADE`. The rod query error fired 30 s
  after the close, GET_GRADE 30 s later (queued behind it). Every official
  inventory holds exactly one rod (5135224); no official session sent `31/C6`.
  Inference, not proof.

### v1.14 (built 2026-10-20; real-client result PENDING)

Snapshot: `work/versions/v1.14/`. (v1.13 was not snapshotted separately;
v1.13 = v1.14 without the rod record and without the grade/B4/48-42 handling.)

| Change | Evidence | Status |
|---|---|---|
| Rod record: instance 1002, catalog 5135224, +8 85582, end 1000, stat 0, opaque zero; not equipped | 3/3 inventories have exactly one rod with this (+8,end,stat); none equipped; 187 records with the same profile are all-zero opaque, while the captured rods have +23..28 non-zero | candidate |
| `30/A0` → `30/A1` count 0 (7 B), up to 4× | 13/13 replies are `1 + 13·N` with a u8 N | candidate (N=0 never seen) |
| `30/B4` (LE32 index 1..5, in order) → `30/B5` 19 zero bytes | indices 1..5 in order in 3/3; all-zero bodies sent by the official server in 3/3 | observed value |
| `48/42` (≤512 B) read and discarded, no reply, ≤2× | 3/3: no server reply; the client continues | observed behaviour |

Tests: C# `SelfTestLobbyQueries` (layouts, order/length/count bounds, a
cipher-alignment chain with a 124-byte GG answer between B4s) and the updated
`SelfTestClassFixture` (exact two-record page; rod never equipped). Mutations
detected: no B4 index check, B4 before grade, missing rod item_end. Python
43/43 incl. `OfficialV114EvidenceTests`.

Expected v1.14 result:
- **If the rod hypothesis holds:** no `31/C6`. The client sends `30/A0` → empty
  grade → `30/B4` ×5 → (maybe `48/42`) → stop at the next unsupported request
  (the captures suggest `30/B2`). No FISHING_ROD error in the game log.
- **If `31/C6` still appears:** the rod hypothesis is refuted (or the rod
  record is rejected). The report shows which.
- If the empty grade list is rejected, expect a GET_GRADE-related error or no
  `30/B4` after `30/A0`.

### v1.14 real-client result (`…161532-3da86813`, 2026-10-20 16:15:32Z): ROD SUPPORTED, empty grade list NOT accepted

Probe start 16:15:35.708Z; ms after that:
- Login reply 61,584. Avatar chain at 73,569, then **`30/A0` at 73,569 →
  our empty grade list (7 B)**.
- **No `31/C6`**, and no FISHING_ROD error in the game log → the rod
  hypothesis is supported (A/B: v1.13 without rod sent 31/C6; v1.14 with rod did not).
- Next request: **`31/8C` (7 B, 1-byte body)** at 73,570 → unsupported, stop.
  No `30/B4` and no `48/42` reached the probe.
- Screenshot `private/screenshots/Screenshot 2026-10-20 121727.png`:
  **`ServerErr: FUNC_Q_GRADE_UP … NULL`**. So **31/8C = FUNC_Q_GRADE_UP**
  (Gemnet: commented-out `GRADE_UP = 0x8c` under type 0x31).
- Game log (private `run-logs/3da86813…`): `12:16:49 GServerAccess.cpp(1556)
  메달 생성 요청 : 1` ("medal creation request: 1"), 3 s after the empty grade
  list; 12:17:19 query error (30 s); 12:17:34 `메달 생성 요청 : 2`;
  12:17:34.814 `TaskManager.cpp(306) CTaskManager::EndProcess` (normal
  shutdown; the user closed the game). Exit code 0; no events, no dumps.
  `ExitTime` read as 1601-01-01 (unavailable) → fixed in v1.15.
- Cleanup pending again: the 60 s wait expired while the game was still shutting
  down. The address and journal are still present (checked 2026-10-20).
  v1.15 waits 120 s.

Interpretation: the empty grade list is a missing-state condition, like the
rod. The client asked the server to create grade/medal entries 1, then 2.

### Grade list evidence (`rf_grade_records.py`, `rf_grade_common.py`; private dumps)

- `30/A1` body = u8 N + N × (u8 ID, LE32, LE32, LE32); IDs ascending.
  Per-account N = 32 / 30 / 96.
- 30 IDs are common to all three captures:
  1,2,3,5,10,11,12,30,31,32,33,34,35,50,55,56,80,81,90,93,94,95,96,99,100,108,109,121,122,123.
- 25 of them were observed with all three values zero. The 5 that never
  were: 35, 95, 108, 121, 122.

### v1.15 (built 2026-10-20; real-client result PENDING). Snapshot `work/versions/v1.15/`

- `30/A0` → 25 records (the common zero-observed IDs, values zero), 332 B.
  **Every record equals an observed record byte-for-byte** (Python test).
- `31/8C` → the 1-byte requested ID is recorded as `grade_up_requested_id`,
  then the probe stops (no reply; format unknown). This names any still-missing
  ID (expected candidates: the 5 omitted IDs).
- Unchanged from v1.14: rod, B4 rule, 48/42 rule (not yet exercised by the real client).
- Harness: cleanup wait 120 s; `exit_utc` = "unavailable" when Windows returns
  a pre-2000 time; `exit_observed_by_utc` added.
- Tests: C# grade layout/IDs/values plus the grade-up rule (mutations: adding
  ID 108 and non-zero values, both detected). Python 44/44.

Expected v1.15 result:
- **Grade list accepted:** no `31/8C`; next requests `30/B4` ×5 (zero
  replies), possibly `48/42`, then a stop at the next unsupported request
  (captures: `30/B2`).
- **A required ID still missing:** `31/8C` with `grade_up_requested_id` = that
  ID (likely one of 35/95/108/121/122).

### v1.15 real-client result (`…162321-035ad841`, started 16:23:21Z; `…162305` is cleanup-only)

- Cleanup **verified** (address, route and journal removed; no game process;
  rechecked 2026-10-20).
- Final sequence (ms after probe start 16:23:25.393Z): avatar chain at
  78,256 → `30/A0` at 78,257 → our 25-record list (332 B) → `31/8C` (7 B) at
  78,257 → **`grade_up_requested_id = 95`** → no reply; the probe closed the
  connection (`connection_ended_at_ms` 78,257). Still no `30/B4` and no `48/42`.
- 95 is **one of the five omitted common IDs** (35, 95, 108, 121, 122).
- Game log (private `run-logs/035ad841…`): `메달 생성 요청 : N`
  ("medal creation request") for **90, 100, 30, 31, 32, 33, 34, 93**, each
  followed by `이미 존재하는 메달채널 입니다` ("medal channel already exists"),
  then **95** with no "exists" line → `31/8C` → 12:25:13 query error (30 s) →
  dialog `FUNC_Q_GRADE_UP NULL` (screenshot `Screenshot 2026-10-20 122526.png`)
  → after OK: 96 and 94 "already exist" → the user closed the game
  (EndProcess; exit 0 at 16:25:47.506Z; no events, no dumps).
- Our own non-reply (plus closing the connection) explains the dialog; it does
  not show that the grade list itself was rejected.

Grade-update semantics (established):
- **`31/8C` = "create medal channel N"**, 1-byte body N. The client walks a
  fixed list (order seen: 90,100,30,31,32,33,34,93,95,96,94) and checks only
  presence in the `30/A1` list. The list may continue after 94 (the game was
  closed); 35, 108, 121 and 122 may also be required.
- v1.14 (empty list) logged requests for 1 and then 2 instead. That is a
  different path when no channels exist; 1 and 2 were not logged in v1.15.
- Every ID the client checked is in the 30-ID common set; all three accounts
  have all 30, which fits the client creating them.
- No capture contains `31/8C` or `31/8D`: **reply format underivable**. A
  header-only ack is not assumed.

Values (`rf_grade_values.py`, private `grade-values.txt`): records are live
counters. Within rf-startup, 94 went (0,0,0) → (1,0,0) and 95 went
(0,0,2) → (1,1,2) between replies. The omitted IDs differ per account: 35
(15|8|25,0,0); 95 (0,0,2)/(10,1,0)/(7,1,21); 108 (1,12,4)/(1,3,1)/(1,30,10);
121 (1,0,0)/(1,18,6)/(1,24,8); 122 (1,0,0)/(1,0,0)/(1,30,10). The v1.15 rule
that "never all-zero ⇒ omit" was wrong; a fresh channel's initial values are
not observable.

**Exact remaining blocker:** medal channel 95 (possibly more) is absent from
our `30/A1`, and the only way the client asks for it (`31/8C`) has no
derivable reply.

### v1.16 controlled experiment (built 2026-10-20; PENDING). Snapshot `work/versions/v1.16/`

One fixture variable: **+ channel 95 = (0,0,2)** (exact first-observed record
in rf-startup). 26 records, 345 B; every record is an observed record
(Python test). 35/108/121/122 deliberately not added.

Instrumentation (no new replies):
- `31/8C` no longer closes the connection. Each requested ID is appended to
  `grade_up_requested_ids` (≤8) and observation continues; still no reply.
- Probe budget 120 → 240 s (self-test arithmetic updated); PowerShell monitor
  245 s; window message "four-minute".
- The report is saved before cleanup (`report_phase =
  probe_result_saved_before_cleanup`) and replaced afterwards
  (`final_with_cleanup_and_diagnostics`). The save/replace sequence was tested
  in isolation.

Tests: C# self-test passes. Mutations detected: 95 values zeroed, 95 removed,
grade-up limit removed. Python 44/44.

Expected:
- **95 was the last missing required channel:** no `31/8C`; the log shows 95
  "already exists"; next `30/B4` ×5 (zero replies; first real exercise of that
  rule), possibly `48/42`, then a stop at the next unsupported request
  (captures: `30/B2`).
- **More channels are required:** `31/8C` with the next ID in
  `grade_up_requested_ids` (likely 35/108/121/122). The connection stays open,
  so the report and game log also show what the client does after its own 30 s
  timeout.

### v1.16 real-client result (`…163603-27ffa8a5`, 16:36:03Z): 95 RESOLVED; stop at ADD_ITEM caused by our own close

- Report saved before cleanup (16:37:09Z), replaced afterwards; cleanup
  **verified**; exit code 0 at 16:38:12.555Z; no events, no dumps.
- **No `31/8C`** (`grade_up_requested_ids` empty). The game log shows all 11
  checked channels "already exist": 90, 100, 30, 31, 32, 33, 34, 93, 95, 96,
  94. **The check list ends at 94; 35/108/121/122 are not required by it.**
- `48/42` (116 B) at 59,422 ms was received and discarded with no reply, and
  the client continued: **first real exercise of the 48/42 rule, OK.**
  `30/B4` still never sent.
- Actual stop: `30/A0` → our 26-record list (62,064 ms) → **`31/8A` (16 B)
  at 62,064 → `unsupported_header` → the probe closed the connection without
  reading the body** (`connection_ended_at_ms` 62,064). The client sent it at
  12:37:09.075 local; `GServerAccess.cpp(3194)` query error at 12:37:39
  (+30 s) → dialog **`FUNC_Q_ADD_ITEM … NULL`**
  (`Screenshot 2026-10-20 123750.png`); the user closed the game at 12:37:55.
- **The server received ADD_ITEM. The dialog was caused by our close/no reply,
  not by an earlier disconnect.**

### ADD_ITEM evidence (`rf_additem_check.py`, private `additem-check.txt`)

| Capture | Request body | Reply |
|---|---|---|
| all 3, first 31/8A | `02 64 00 00 00 00 00 00 00 00` | 31/18B code 10001 `FAIL(unknown)` |
| boss ×2 | `02 5a 00…` | 31/18B code 9003 `FAIL(unknown)` |
| startup, 3.4 s after its failure | `02 5f 00…` | **31/8B success**, 47 B, starting `02 5f` |

- Body byte 1 = **medal-channel ID** (0x64 = 100, 0x5f = 95, 0x5a = 90);
  byte 0 = 2. So "ADD_ITEM" here is a medal-channel reward claim, not an Exo
  or missing-item request.
- After startup's successful claim for 95, its grade record went (0,0,2) →
  (1,1,2). The success body's other fields are unidentified.
- Channel 100 was (0,0,0) before every failed claim, as in our list.
- Failure frame (5/5 identical apart from the code): `00 31 02 08 8b 01`, LE16
  code, `FAIL(unknown)`, NUL, zeros through body 32, then uninitialized memory.
- In all captures, the **first** `30/A0` after login was followed by `30/B4`
  ×5; ADD_ITEM followed a **later** `30/A0`. Our client sends ADD_ITEM right
  after its first grade reply and never sends `30/B4`. **Unexplained difference.**
- Claim of 95 happened **iff** 95's first value a == 0 (startup (0,0,2) →
  claimed; (10,1,0), (7,1,21) → not). Python test.

### v1.17 controlled run (built 2026-10-20; PENDING). Snapshot `work/versions/v1.17/`

- **Disconnect fix:** after the avatar chain, an unsupported request (body
  ≤1024 B, ≤8 requests) is read and discarded (cipher aligned), recorded
  (`first_unanswered_request`, `unanswered_request_count`), not answered, and
  the **connection stays open**.
- `31/8A` (16 B, after a grade reply): the body is recorded in
  `add_item_bodies` (claim data only). **Only** `02 64 00…` (channel 100) gets
  the observed 520-byte failure, code 10001. No inventory change (a failure
  grants nothing). Any other body gets no reply (success fields underivable).
- Tests: C# `SelfTestAddItem` (byte-exact failure frame, matcher, order and
  length, cipher chain grade → ADD(100) → unsupported 30/BC with an 8-byte body
  → ADD(95) → next header). Mutations detected: code 9003, any-channel match,
  truncated text. Python 46/46 incl. capture byte comparison and the 95-claim
  rule.

**Expected next request:** `31/8A` with body `02 5f 00 00 00 00 00 00 00 00`
(claim channel 95), as in rf-startup, where 95 was (0,0,2) like ours. v1.17
records it and does not answer. If instead the client moves on (as in the other
two captures: `30/BC` or `40/A4`), that is recorded too, and the prediction is
wrong.

### v1.17 real-client result (`…164901-3b79ba75`, 16:49:01Z): our ADD_ITEM differs from the official one

FUNC_Q_ADD_ITEM facts:
- **Received:** yes, `31/8A` (16 B) at 63,375 ms, right after the first grade reply.
- **Body:** `00 00 e3 20 1f 00 e8 03 00 00` = LE32 **2040035** (Soul Fighter
  (M) default Exo) + LE16 **1000**. This does **not** match the recurring
  official body `02 64 00…` (channel-100 claim).
- **Our response:** none (`add_item_failure_replies` 0, `reply_at_ms` −1).
  v1.17 answers only the channel-100 body.
- **Connection:** stayed open. The client timed out after 30 s
  (12:50:39 `GServerAccess.cpp(3194)` query error), then sent `30/B4` ×5. We
  wrote 5 zero replies and the log shows `보스전 클리어정보 받기 성공1..5`
  ("boss-battle clear info received: success"), so **the B4 rule is accepted**.
  Then `CGameTask::EndTask` / EndProcess (the ServerErr dialog's OK ends the
  game, as in earlier runs), and the client closed (`peer_closed_before_header`
  at 97,448). Exit 0; cleanup verified.
- Classification: **"no usable reply"**, not "addition rejected correctly".

### Profile comparison (`rf_profile_compare.py`, `work/reports/profile-invariants.txt`)

Coherent profile reconstructed from ONE session (rf-startup): 204 inventory
records, 10 avatars, equipped avatar, 10 equipment sets, first grade list (32).
Saved **privately** to `private/profiles/rf-startup-session-profile.json`. No
login reply, tokens or account fields were extracted. All relationships hold
(refs resolve, equipped ∈ list, equipment per avatar). Unresolved fields are
listed in the file.

| Invariant | startup | empty-buddy | boss | local v1.17 | local v1.18 |
|---|---|---|---|---|---|
| slot0 → owned class; refs resolve; equipped listed | ✓ | ✓ | ✓ | ✓ | ✓ |
| exactly one rod | ✓ | ✓ | ✓ | ✓ | ✓ |
| **each in-use class owns its default Exo** | ✓ | ✓ | ✓ | **✗** | ✓ |
| grade has the 11 client-checked channels | ✓ | ✓ | ✓ | ✓ | ✓ |
| grade has all 30 common channels | ✓ | ✓ | ✓ | ✗ | ✗ |
| avatars / items | 10/204 | 10/164 | 20/1157 | 1/2 | 1/3 |

`rf_exo_check.py`: every in-use class owns **exactly one** default Exo
(Striker 2040034; Soul Fighter (M) 2040035 in boss), **never equipped**
(0/10, 0/10, 0/17, 0/3 in ExoA). Boss's 2040035 record: +8 85582, end 1000,
stat 0, **all opaque zero**.

**Cause (identified):** the minimal account lacks its class's default Exo. The
client asks the server to grant it (`31/8A` item-grant body, catalog 2040035,
1000) and we cannot answer (no captured success reply for an item grant).
Official accounts own the Exo, so they never send this, and their only startup
ADD_ITEM is the channel-100 claim, which is rejected (10001) and harmless. The
missing 30-channel invariant and the avatar/item counts are not implicated by
any request so far.

### v1.18 controlled run (built 2026-10-20; PENDING). Snapshot `work/versions/v1.18/`

One variable: **+ default Exo record** (instance 1003, catalog 2040035,
+8 85582, end 1000, stat 0, opaque zero; the boss session's exact profile for
this class); owned, not equipped. Everything else = v1.17.
Tests: C# expected page is byte-exact (3 records); runtime mutations (wrong
catalog, colliding instance ID, count 2) detected. Python 48/48 incl. the
default-Exo invariant in all sessions, the fixture profile observed, and the
v1.17 body decoding to the missing Exo.

**Expected next request:** no item-grant `31/8A`. After our grade list the
client sends `30/B4` ×5 immediately (zero replies, accepted in v1.17), as in
every official session. The first request we do not handle should then be
**`30/B2` (6 B)**, the next request in all three captures (via the passive
path: recorded, not answered). A later `30/A0` may be followed by the
channel-100 claim (`02 64…`), which v1.18 answers with the observed failure 10001.

If an item-grant `31/8A` still appears: the Exo record is wrong or
insufficient. Second arm: serve the reconstructed rf-startup profile (needs
multi-avatar and multi-page serving in the probe).

### MILESTONE 2: intro played, main-menu stage entered (v1.18, two runs)

**Best-known checkpoint preserved:** `work/checkpoints/best-known-v1.18-intro/`
(code, both v1.18 reports, SHA-256 prefixes). Game log in private
`run-logs/7c094067…`.

Runs `…165813-59df5b2c` and `…170035-7c094067` behaved identically:
- **Default Exo fixed the item-grant request:** no `31/8A` at all.
- `30/B4` ×5 answered; the log says `보스전 클리어정보 받기 성공1..5`.
  `48/42` was discarded and the client continued.

Correlated timeline (`…170035`; probe start 17:00:39.419Z = 13:00:39.419 local):

| Local | Game log | Probe |
|---|---|---|
| 13:01:37 | login(AsterLocal) ok | |
| 13:01:42–13:02:10 | window activate/deactivate (intro animation) | |
| 13:02:10.159 | `GotoStage - GS_UIMENU`, `UI_MainMenu로 변경`, packet clear | |
| 13:02:10.198 | `dxWnd_MainMenu.cpp(501) LoginCheck Start` | **`30/B2` at 90,780 → unanswered (passive path)** |
| 13:02:40.205 | `GServerAccess.cpp(8379) Login Complete Error.(return NULL)` | (client 30 s timeout) → blank ServerErr |
| 13:02:43.263 | `LoginCheck 1st--- OK` (after OK) | `30/BA` at 123,845 → unanswered |
| 13:02:43.285 | `CGameTask::EndTask()` | client closed at 124,140 (`peer_closed_before_header`) |

Findings:
1. **First failure:** `30/B2` (main-menu LoginCheck, "Login Complete") had no
   reply. The client had already reached `GS_UIMENU`.
2. **Probe limits did not fire:** budget 240 s, headers 21/32; the client
   closed the socket. The passive handler kept the connection open but sends
   nothing by design. The ~124 s end in both runs is when the dialog's OK was
   clicked, followed by EndTask.
3. Not applicable (no probe disconnect).
4. **We wrote no error frame.** The blank dialog is the client's own message
   for a NULL query result (screenshot `Screenshot 2026-10-20 130044.png`, the
   earlier run). Another image in `private/screenshots`, "ChatGPT Image Oct 20,
   2026, 01_02_50 PM.png", shows a title screen. Its name indicates it came
   through another tool, so it is not used as evidence.

### Main-menu evidence (`rf_menu_check.py`, `rf_cc_check.py`, `rf_cc_text.py`, `rf_lobby_poll_check.py`)

- `30/B2`, `30/BA`, `30/BC` have no body. Replies: `30/B3` = 10 × LE32 (field 8 =
  **0x03381018 in all 3 sessions**; the others are per-account counters, some
  never zero); `30/BB` = 2 × LE32; `30/BD` (41 B) begins with `BB`'s 8 bytes.
- Guild-less sessions (empty-buddy, boss): `B2 → BA → BC → CC×5 → clock →
  A0 → 8A(100) fail → …`. rf-startup inserts `30/BE`, `31/C8` (guild).
- `30/CC` body = (u32 category, u32 cursor) → `30/CD` 1804 B = u32 count + up to
  30 × 60-byte records. Category 3 pages with the last ID as the cursor. The
  records are numeric only (no text) and their IDs are identical across
  accounts, so this is **global data**.
- After CC (empty-buddy): …, `10/B6`(1) → `0x210/B7`(1), body `01` in all 11
  occurrences. Then **`40/84` → `40/85` every 2 s = the lobby room list**.
  `40/85` = 12 + 223 × N bytes (N = 1–4 observed) and **contains other
  players' room names → must never be replayed**. N = 0 has never been observed.
- **rf-startup order: with channel 95 at (0,0,2) (like ours), the 95 claim
  `31/8A 02 5f…` follows the channel-100 failure immediately and precedes
  `30/BC`, `10/B6` and `40/84`.** (Python test.)

### v1.19 (built 2026-10-20; PENDING). Snapshot `work/versions/v1.19/`

Account fixture **unchanged** (class, rod, default Exo; 26-channel grade list).
- Main menu: `30/B2`, `30/BA`, `30/BC` (repeatable ≤16) and `30/CC` pages are
  answered with the **exact frames from ONE session (rf-boss-baseline)**, built
  by `rf_make_lobby_fixture.py` into `private/fixtures/lobby-boss-v1.bin`
  (9,237 B, SHA-256 `36cf36f8…704d`, deterministic and **pinned in the
  probe**). Order rules: B2 after a grade reply, once; BA after B2; BC after BA;
  CC after BC. An unmatched CC body is recorded and not answered. If the
  fixture is missing or altered, these requests are only observed.
- Limits: headers 32 → 64; grade repeats 4 → 16 (the boss session has 8).
- Tests: C# `SelfTestMainMenu` (parser and rejection of bad magic, missing BD,
  duplicate page, truncation and wrong BD length; order rules; cipher chain
  B2/BA/BC/CC/CC-unmatched/BC/next). Mutations detected: BA order, BD length.
  The duplicate-page mutation is also caught by the page-count check. The real
  fixture loads (5 pages). Python 51/51 incl. fixture = boss frames byte-exact,
  menu flow, BD/BB relation, constant B3 field, and the 95-claim ordering.

**Expected v1.19 result:**
- No `Login Complete Error`.
- `30/B2` → B3, `30/BA` → BB, `30/BC` → BD, `30/CC` ×5 → 5 matched pages,
  clock, `30/A0` → grade, `31/8A 02 64…` → failure 10001.
- **Then `31/8A 02 5f 00…` (channel-95 claim): unanswered.** That is the
  predicted next blocker, before the lobby (`10/B6`, `40/84`).
- Lobby **not** expected yet. The fix for 95 is an account-fixture decision
  deferred by instruction: set 95 to its observed post-claim value (1,1,2) from
  the same rf-startup session, or derive a grant reply.

### v1.20 complete lobby attempt (built 2026-10-20; real-client result PENDING). Snapshot `work/versions/v1.20/`

Reversibility: best-known `work/checkpoints/best-known-v1.18-intro/` untouched;
v1.19 in `versions/v1.19`; fixture v1 kept (`private/fixtures/lobby-boss-v1.bin`);
`-Unclaimed95` restores the v1.19 account state.

**Channel 95 (controlled experiment, user-approved; not a proven fix):**
- Grade 95 = **(1,1,2)**, rf-startup's value right after its official claim
  (last `30/A1` of that session). The v1.19 value (0,0,2) is preserved behind
  `-Unclaimed95`.
- **Consistency check:** rf-startup's 95-claim success reply (`31/8B`) names
  catalog **3043117**. That item is owned (never equipped) in **both** sessions
  whose 95 is claimed (empty-buddy, boss) and absent from rf-startup's pre-claim
  inventory. Python test: claimed ⇔ reward owned, in all 3 sessions. → The
  claimed state includes the reward record: rf-boss-baseline's **exact** 49-byte
  record (+8 87118, end 1176, stat 0, non-zero opaque bytes, meaning unknown);
  only the instance ID is local (1004). It is loaded from the private fixture v2
  (`lobby-boss-v2.bin`, SHA-256 `4605704f…72b6`, pinned), not from source. If the
  record is unavailable the probe serves the unclaimed state instead, so grade
  and inventory can never disagree.

**Lobby (from evidence):**
- `10/B6` (body `01`) → `0x210/B7` body `01`: identical in 11/11 captured
  occurrences. Observed reply.
- Room list `40/84` (body `0a00000000000046` in all 42 polls) → `40/85`.
  Structure fits all 40+ captured lists: 10-byte header `u16 0 | u16 first room
  no. | u16 0 | u16 0x8000|last room no. | u16 N` + N × 223-byte rooms (they
  hold other players' names: **never replayed**). Our reply is **16 bytes:
  header zeros, N = 0. UNVERIFIED**: N = 0 was never observed, and what the
  first/last fields should be with no rooms is unknown.
- Idle guild-less lobby (empty-buddy): after entry the client sends **only**
  `40/84` (Python test). The boss lobby's other requests are user actions
  (rooms, matches). No server-initiated GameGuard frames in 370 s of lobby.

**Session lifetime (separated from startup):**
- Startup: the 240 s budget and 64-request cap as before.
- The **first answered room poll = lobby entry**. From then the deadline is
  **15 min** and the request cap is **20,000**. Clock, grade (`30/A0`), BC and
  B6 may each repeat up to 64×; polls are unlimited within the lifetime.
- Logging stays bounded: the first 64 headers, a rolling last 32 and per-type
  counts; `lobby_entered_at_ms`, `room_list_replies`, `last_room_list_at_ms`,
  `lobby_connected_seconds`, `last_request_at_ms`.
- Harness: 20-min wall limit; **Q in the test window = explicit stop**; game
  exit also stops. A status line every 30 s in the lobby and a "5-MINUTE TARGET
  REACHED" prompt. `session_end_reason` ∈ {user_stop_key, game_exited,
  probe_completed, wall_limit}. Report saved before cleanup, then finalized.
  Cleanup waits ≤120 s for the game to close.

**Automated startup-to-lobby check** (`Run-ScriptedLobby.ps1`, offline): the
real `ObservePostLogin` is driven through a scripted stream (7-byte
fragments), replaying the real client's post-login sequence + guild-less
continuation + **160 polls with 16 clocks (~5.3 min of real polling)**.
Result: 208 requests → 207 replies (none for `48/42`), **0 unanswered**,
every reply type/length as expected, the menu frames byte-identical to the
fixture, the claimed-95 inventory and grade consistent. The `-Unclaimed95`
variant passes too.

Tests: C# `SelfTestLobbySession` (reward fixture required and checked, the
4-record page copies the reward exactly except the instance, grade-95 variants
isolated, B6/room-list layouts and bodies, order, session-deadline arithmetic,
lobby cipher chain). Mutations detected: reward instance not replaced, grade
95 b not set, B6 type byte, room list allowed before the menu, session budget
capped at startup. Python 56/56.

**Expected real-client sequence:** … B2/BA/BC/CC×5 → clock → A0 → 8A(100)
failure → **no 95 claim** → BC → 10/B6 → **40/84 every ~2 s** (lobby). Status
lines show the lobby time; the target is ≥300 s.

**Remaining genuine gaps (observed by the same run):**
1. The empty room list (N = 0) is unverified. If wrong, expect an error right
   after the first poll or no second poll; the report shows `room_list_replies`
   and the next unanswered request.
2. Any lobby request never seen in an idle guild-less capture (e.g. a periodic
   query) gets no reply. `first_unanswered_request`, the recent headers and the
   game log identify it.
3. Long-session GameGuard behaviour with a replayed init was never exercised
   beyond ~2 min. The exit code, the game log and the GameGuard log timing in
   `game_diagnostics` will show a GameGuard-driven exit.

### MILESTONE 3: main menu rendered (v1.20, three runs); closed after an unanswered GetLevelUpItem

Preserved: `work/checkpoints/v1.20-level1-rewards-notice/` (code, report
`…173346-2ee43c07`, fixture SHA). Runs `…172940`, `…173200` and `…173346`
behaved identically.

Correlated (`…173346`; probe start 17:33:49.823Z; game log private `run-logs/2ee43c07…`):

| Local | Game log | Probe |
|---|---|---|
| 13:34:45.716 | `GS_UIMENU` → main menu | |
| 13:34:45.907 | `LoginCheck Start`, **`GetLevelUpItem -- 호출`** | `30/B2` → B3; **`31/8A` `01 00 61 a6 4c 00 e8 03 00 00` unanswered** (56,083 ms) |
| 13:35:15.912 | query error (30 s) → **FUNC_Q_ADD_ITEM NULL** (screenshot `…133138.png`) | |
| 13:35:17.297–.300 | LoginCheck 1st/2nd OK, RuneStone, Buff; quests daily 14 / normal 1 / achievement 72 | BA, BC, CC×5, clock, A0 answered |
| 13:35:17.301 | `아이템 지급 에러 10001, FAIL(unknown)!` / `아이템 Add 실패` | channel-100 claim → our 10001 failure |
| 13:35:17.301 | **`LoginCheck All Green`** | |
| 13:35:17.316 | **`CGameTask::EndTask()`** → exit 0 at 17:35:20.608Z | client closed (87,731 ms) |

- **First unanswered request:** `31/8A` **kind 1** = **GetLevelUpItem**,
  catalog **5023329**, u16 1000. It is **not** channel 95 or any medal claim;
  it is identical in all 3 runs.
- **Closure trigger:** the NULL query error. In v1.17, v1.18 and v1.20,
  EndTask/EndProcess follows a NULL dialog once queued startup work finishes.
  The 10001 failure for the channel-100 claim was logged and tolerated (also in
  official sessions).
- `30/CC` = **quest lists** (14/1/72 = our 5 pages), accepted.
- The "Congratulations!! You are now Level 1" notice is client-side
  (`Screenshot 2026-10-20 133528.png`).

Consistency check (`rf_level_check.py`, `rf_grant_format.py`; private outputs):
- **Experience:** the current probe still sends **0** (login frame 34; the
  builder never writes it). The client derives "Level 1" from it: consistent
  with a fresh account, so this is genuine first-login behaviour. **Experience
  was NOT raised.**
- The three captures are **three different accounts** (exp 65,934 / 9,337 /
  1,763,532). **None owns 5023329**, and none sent a kind-1 `31/8A`. So the
  level reward is not an inventory-ownership check, and there is **no captured
  kind-1 success**.
- The unresolved login range 42..96 holds a guild name (rf-startup), flags and
  a FILETIME. No level or reward field is identifiable.
- The only `31/8B` success (kind-2, channel 95) does not map onto an inventory
  record (`+8` 3190 vs 87118; fields 164033816, 2304, 340 unexplained; record
  opaque bytes contain a FILETIME). **A grant reply is not derivable.**
- Grade/reward state (95 claimed + reward item 3043117) is unchanged and
  consistent. There is no inventory refresh in any official lobby.

### v1.21 (built 2026-10-20; real-client result PENDING). Snapshot `work/versions/v1.21/`

- The exact GetLevelUpItem body gets the **observed failure frame** (`31/18B`,
  10001, `FAIL(unknown)`). **UNVERIFIED:** the code a real server uses for
  kind 1. Other kind-1 bodies stay unanswered (recorded).
- **No account change:** experience 0, inventory and grade unchanged, nothing
  granted. Repeats and reconnects get the same rejection, so nothing can be
  duplicated (scripted test: two rejections, identical inventory).
- Automated `Run-ScriptedLobby.ps1`: GetLevelUpItem inserted right after B2 (the
  real-client order) and repeated mid-lobby; 210 requests → 209 replies,
  **0 unanswered**, 160 polls; the unclaimed variant passes. Mutations (wrong
  matcher body, handler not wired) detected. Python 58/58.

**Expected v1.21 result:** no FUNC_Q_ADD_ITEM NULL. The game log shows the
grant error for 5023329 (code 10001) and continues; LoginCheck All Green →
BC → 10/B6 → 40/84 polling; lobby for ≥300 s.

**If the client still ends after All Green with no NULL dialog**, the
rejection itself is fatal for kind 1, and only a real grant would help. That
needs evidence we do not have: a capture of a fresh account's first login
(level 1) on the official server. A brand-new official account logging in once
while capturing would provide exactly that.

### MILESTONE 4: main menu stable (v1.21); Lobby click hung behind an unanswered UpdateQuest

Preserved: `work/checkpoints/v1.21-main-menu-working/` (code, report
`…200059-3a984674`, fixture SHA).

Correlated (probe start 20:01:03.967Z = 16:01:03.967 local; private `run-logs/3a984674…`):

| Local | Game log | Probe |
|---|---|---|
| 16:03:51.099–.102 | GetLevelUpItem → `아이템 Add 실패`; channel-100 → 10001; **`LoginCheck All Green`, no EndTask** (v1.21 fix held) | both answered with the failure frame |
| **16:03:51.784** | | **`30/CE` (18 B) → unanswered** (`first_unanswered_request`) |
| 16:03:52.052 | GameGuard notified of the user ID | |
| 16:04:14.141 | **Lobby click**: packet clear, UI 0 → 1 | **nothing sent** (no BC/B6/40/84) |
| **16:04:21.787** | **`Send_Request_UpdateQuest Error.(return NULL)`**: 30 s after `30/CE` | |
| 16:04:21–:59 | blank ServerErr, "(Not Responding)" (`Screenshot …160436/160455.png`) | `socket_reset` at 236,130 ms (game closed; exit 0, no events) |

1. **First failed exchange: `30/CE` = UpdateQuest, unanswered.** The client's
   query was still pending at the Lobby click, so the UI blocked and no lobby
   request went out. The room list was **not reached**; `40/85` is untested.
2. Response types: the `10/B6` reply is `02 10 00 07 b7 00 01` (type 0x0210,
   action 0x00B7), byte-equal to all 11 captured replies (Python test).
   B3/BB/BD/CD are exact fixture frames.
3. **Latent limit bug (fixed):** the session lifetime started at the first room
   poll, so the main menu (reached at 167 s) still ran on the 240 s startup
   budget and the 64-request startup cap. Mutation test: without the fix the
   scripted run dies at 63 replies during main-menu idle.
4. Room-list prefix re-checked: total = 16 + 223·N (frame), body 10 + 223·N;
   `u16 count` at body 8 (a u32 count would make the last record overrun);
   first/last u16 room fields, `0x8000` on the last room. The prefix for N = 0
   (zeros vs 0x8000 sentinels) is still **unverified**.

### v1.22 (built 2026-10-20; PENDING). Snapshot `work/versions/v1.22/`

Account fixture unchanged.
- **`30/CE` UpdateQuest → `30/CF` echoing the 12-byte body**: the rule in
  2/2 captured exchanges (rf-boss-baseline, small sample). Quest progress is not
  persisted. Bodies are recorded (`quest_update_bodies`).
- **The session starts at main-menu entry** (LoginCheck answered): 20-min
  lifetime, session request cap. Lobby entry re-extends it. `main_menu_entered_at_ms`
  is reported. Harness wall limit 25 min.
- Lobby entry/re-entry: every captured entry (≥10) is `30/BC` → `10/B6` → polls
  (Python test); return to the menu is `30/BC`, `30/A0`. All are supported and
  repeatable (≤64; polls unlimited).
- Automated `Run-ScriptedLobby.ps1`: UpdateQuest after All Green, 70 idle clocks
  on the main menu, lobby entry, 160 polls (+ a repeated level grant), return
  to the menu, re-entry + 5 polls: **290 requests → 289 replies, 0 unanswered**.
  The unclaimed variant passes. Mutations detected: no main-menu session start,
  no echo, quest not routed. Python 60/60.

**Target run:** enter the empty lobby, stay ≥5 min, return to the main menu.
**Remaining unverified:** the empty room list (N = 0) prefix, and any request
outside the captured idle-lobby set (recorded unanswered → NULL after 30 s →
EndTask).

**v1.22 real-client result** (`rf-local-handshake-20261020-201413-6049bb9d.json`):
lobby entered (6 polls answered, 3 quest acks); **My Info works** (reward item
"Black Cheshire", Lv1 0/500). Checkpoint preserved:
`work/checkpoints/v1.22-lobby-myinfo-working`. Store click → client sent
`31/88` Get_Cash at 104,775 ms; the v1.22 startup-only rule classified it
`startup_out_of_order` and closed the connection → client log "Disconnected",
then `dxWnd_ItemShop.cpp(961) Get_Cash Query Fail` → Not Responding. So the
Store failure was our server closing the socket, not a client exception. No
capture contains a Store visit (`31/88` occurs once per capture).

### v1.23 (built 2026-10-20; PENDING real-client test). Snapshot `work/versions/v1.23/`

Account fixture unchanged. Persistent server:
- **No runtime or cumulative request limit**; no time-based session expiry (an
  idle connection never expires). Kept: per-frame size limits, 5 s budget for an
  incomplete frame, clock replies, polling, state transitions.
- **Accept loop**: a client disconnect ends only that client session
  (`client_session_end` line in `private/run-logs/server-<testid>.jsonl`); the
  listener keeps accepting. Each connection: fresh ciphers + protocol state, peer
  check (exact game build), GG init replay again (master kept until shutdown).
- **Store**: `31/88` Get_Cash is answered with the same zero-balance `31/89` any
  time after startup (evidence: v1.22 run). Further Store requests: unknown,
  recorded unanswered.
- **Shutdown**: Q or Ctrl+C (console handler; Ctrl+C no longer kills PowerShell
  mid-cleanup) → stop accepting, close sockets, one `server_shutdown` line, report,
  verified cleanup. Window X / logoff / shutdown → handler stops the server
  directly; a **hidden watchdog** (`-WatchdogFor <pid> -WatchdogTestId <id>`,
  own console) waits for the test process to exit, takes the mutex, and runs the
  same journal-verified cleanup (only its own test_id; waits for the game to close
  without limit), writing a `-watchdog` report. **Startup journal recovery**: a
  stale journal whose owner has exited is cleaned with the verified cleanup
  before a new run (`previous_journal_recovery` in the report).
- Automated checks `work/protocol-lab/Run-PersistenceChecks.ps1` (admin, game
  closed; uses `Send-ConsoleCtrl.ps1`): offline self-test, two-session reconnect
  through `ServeStream` (3000 polls, Get_Cash ×3 per session, log lines,
  console-close/Ctrl+C handlers), scripted lobby; live loopback: A) two TCP
  reconnects + real Ctrl+C → graceful stop, verified cleanup; B) harness killed →
  watchdog cleanup verified; C) harness + watchdog killed → next run recovers the
  journal. **All 35 checks pass** (`work/reports/persistence-checks/20261020-204757/`).
  Earlier failing attempts in the same folder were check-script bugs (one
  moved the journal by a too-broad filter; it was restored with its identity
  intact and cleaned via the watchdog/CleanupOnly).
- Not tested live: the real window-X close (handler covered offline by
  simulation; the killed-process case, which is harsher, is covered live).

**v1.23 real-client result** (`rf-local-handshake-20261020-205130-374519e9.json`,
checkpoint `work/checkpoints/v1.23-store-lobby-persistent`): 2 client sessions, Ctrl+C,
verified cleanup. Store browsing + try-on work (Get_Cash 31/88 answered 3x). Session 1:
My Info equip sent **30/D6** (unanswered) and stopped. Session 2: 228 room polls (5-min
milestone), 1F/10 every ~60 s (unanswered, harmless), **Create Room -> 30/80** (20-byte
body) unanswered -> 30 s later `FUNC_Q_GET_USER_INFO ... NULL` (screenshot 170638).

**Isolation finding:** every local run's client log shows `ProudManager.cpp(98): P2P
Connected : <n>` right after login. rf-boss-baseline shows the client opening TCP
**5.188.32.116:33343** at login (+13 s) and keeping it all session. v1.9-v1.23 redirected
only .117, so those clients reached the **live official plaza server**. Fixed in v1.24.

### v1.24 (built 2026-10-20; PENDING real-client test). Snapshot `work/versions/v1.24/`

Tracker: `work/TASKS.md`. Evidence scripts: `rf_equip_trace.py`, `rf_userinfo_fields.py`,
`rf_property_pages.py`, `rf_item_records.py`, `rf_proudnet_frames.py`,
`rf_proudnet_handshake.py`; tests `test_v124_evidence.py` (7).
- **Account state** (`RFAccount.cs`): profile files `private/accounts/<profile>.txt`
  (`baseline` = v1.18-v1.23 fixture, byte-identical wire; `loadout` = baseline + 14
  observed records worn by a class-1000176 avatar in rf-boss-baseline + Exo 2040138 whose
  class compatibility is unknown). Atomic writes under a mutex; admin `RFAdmin.ps1/.cmd`.
- **Pagination** (3 captures): 30/84 body = account | ff ff ff | cursor; cursor 1, then
  last instance + 1; 30/85 = 80 ascending records, last page short.
- **My Info** (rf-boss-baseline): 40/A2 avatar (select) -> A3; 30/D6 (catalog, item_end
  of the owned record) -> 30/D7 `01` (4/4); 40/A6 (avatar, slot) -> A7; 40/A4 (avatar,
  slot, **instance**) -> A5. 30/8E (instance) -> 30/8F 8 bytes (FILETIME-like, 1 sample;
  not implemented). Slot families observed: 100->0, 105->1/34, 106->3/35, 107->4/36,
  108->5/37, 109->6/38, 102->7, 103->8, 104->9, 203 (scroll)->10, 204 (Exo)->11/12,
  301->14/39, 303->15/40, 302->16/41, 305->17/42, 306->18/43, 304->19/44, 503->22,
  508->23-25, 206->27, 308->31, 309->32.
- **GET_USER_INFO**: 30/80 body = 20-byte name -> 30/81 (1561-byte body): +0 account ID,
  +4 name, +24 level, +28 experience (both equal the login reply's +24/+28), +32 45 equipped
  **catalog** IDs, +1521 country, +1529 region; other bytes zero (unidentified).
- **Plaza** (`RFPlaza.cs`, .116:33343): ProudNet core frames `13 57 | scalar size |
  payload`. 2E -> policy XML + 04 hint (captured settings + our RSA-1024 key); 05 -> 06;
  07 -> 0A (host ID, GUID, client address); 1A -> 1C; RMI FA01 -> FBFC; 1B, RMI FA13: no
  reply. Game RMIs are plaintext (room join RMI 0x03EC with the room number, leave 0x03EB;
  server P2P member RMI 0xFBF6, relay 0x14/0x17, UDP 34162 hole punching 0x0B/0x0E/0x0F/0x12).
  TCP 3416 (opaque) and UDP 34162 recorded only.
- Harness: owns .117 + .116 (journal v2, v1 still recoverable), `-Profile`, plaza in the
  report and session log. Automated: `Run-PersistenceChecks.ps1` 42/42
  (`work/reports/persistence-checks/20261020-214109`); Python 67/67.
- Client data: `res/*.nsz` (3147 files, `NSZ!` archives); `100000_table.nsz` has no
  `NSZ!` header (obfuscated). Catalog/exp-table recovery is an open research item.

**v1.24 real-client result: black screen before the main menu** (report
`rf-local-handshake-20261020-214640-f41b0839.json`, profile `loadout`; checkpoint
`work/checkpoints/v1.24-black-screen`). Timeline (UTC, harness start 21:46:40):
lobby login reply written at +53.6 s; plaza TCP accepted (peer `game_verified`), client
sent 2E, server sent policy XML + 04 hint, **client closed 55 ms later without sending
05**; no further lobby request; client log stops after `ResetServerStatus()` with no
`P2P Connected` and no `login(AsterLocal) ok` (v1.23: both 0.5 s after ResetServerStatus).
**First divergence: the client rejects our 04 hint.** Byte comparison with the captured
hint: settings block wrong at offsets 13-34 (two zero bytes inserted before the 10.0
double, two dropped at the end; hand transcription). Account data was not reached (the
client processes the login reply only after the plaza connects: in rf-boss-baseline the
first post-login lobby request follows 0A ConnectSuccess by 7 ms).
Other startup facts: TCP 3416 = `rumble-fighter.gchat.playredfox.net` (chat), server
speaks first (16 B at +0.19 s), opened 0.26 s after the lobby resumed: not a startup
gate. UDP 34162 starts only at room join. DNS: lobby/plaza/chat names resolve through
normal DNS to .117/.116; launcher/GameGuard also contact `rumble-fighter.cdn`,
`gameguard.cdn.playredfox.net` and `mgr.gameguard.co.kr`.

### v1.25 (built 2026-10-20; PENDING). Snapshot `work/versions/v1.25/`
- **One correction:** plaza hint settings = captured bytes 1..38 (generated, not typed);
  new check: our hint equals the captured hint outside the modulus (fails on v1.24 code
  at exactly offsets 13-34).
- Diagnostics only: plaza stage timeline per connection + live `plaza_connect_success`;
  independence audit (game-folder processes' external TCP endpoints, filtered DNS cache).
- `baseline` profile file created; equals the v1.23 baseline state.
- Checks: `Run-PersistenceChecks.ps1` 43/43 (`work/reports/persistence-checks/20261020-215856`).

## Step 2: avatar chain (built in v1.10; confirmed by the v1.11 real-client run above)

Evidence (all three captures, checked by `rf_avatar_check.py` and
`test_lobby_wire.OfficialAvatarCaptureTests`):
- `30/86` body = LE32 login account ID. Reply `30/87` (87 B) = count byte +
  20 LE32 avatar IDs; active IDs non-zero. Counts 10/10/20 (20 = full capacity).
- `40/A0` (no body) → `40/A1` (10 B) = LE32 equipped ID, always among the listed IDs.
- `30/88` is sent once per listed ID, in list order, body = that ID. Reply `30/89`
  (366 B) = 45 LE32 item-instance refs + a 180 B tail (zero in every capture).
- The next client request is `30/A0` in all three captures.

Candidate (labelled experimental): one invented avatar ID 1, listed and
equipped; its equipment reply is all zero, because the local inventory is
empty. Body checks: `30/86` must carry account 1, `30/88` must carry avatar 1;
otherwise the probe stops with `avatar_owner_mismatch` /
`equipment_avatar_mismatch`. **Not established: whether the client accepts an
avatar with nothing equipped.** If it proceeds, the next header should be
`30/A0`.

Tests: C# `SelfTestAvatarSteps` covers:
- the three reply layouts;
- order across all stages, plus length checks;
- the body checks;
- full-chain cipher alignment from buddy to `30/A0`.

Two deliberate breakages both make it fail. Python: 34/34.

## Observed protocol map (official captures; headers only)

Lobby server `5.188.32.117:7000`. The order is the same in all three captures:

```
C 10/90 version(26)        S 10/91 (6)
C 10/84 login(91)          S 10/85 (326)        [failure form: 0x210/0x285, 520 B]
C 10/92 clock              S 10/93 (14)         (repeats periodically)
C 48/80 GG init            S 48/81 (68 or 76)   GameGuard CS-auth, server→client
C 10/D0                    S 10/D1 (8)
C 31/88 cash               S 31/89 (18)
C 30/84 ×3 property(17)    S 30/85 ×3 (3928)    inventory pages
C 30/92 gift-from          S 30/93 (3507)
C 30/90 gift-to            S 30/91 (3507)
C 10/A8 buddy(10)          S 10/A9 (3008)       ← v1.8 stopped here; v1.9 answers
[C 33/84,8A,90,8E guild…   S 33/85,8B,91,8F]    only in rf-startup
C 30/86 (10)               S 30/87 (87)         ← expected next request
C 40/A0                    S 40/A1 (10)
C 30/88 ×10..17 (10)       S 30/89 (366 each)
C 30/A0                    S 30/A1 (397/423/1255)
C 30/B4 ×5 (10)            S 30/B5 (25)
C 48/42 (116/124)          (GameGuard answer; no reply)
C 30/B2,BA,BC              S 30/B3(46), BB(14), BD(47)
C 30/CC ×5 (14)            S 30/CD (1810)
… then rf-boss-baseline continues into the room/match phase:
C 31/8A, 40/A4 ×20, 31/D6, 10/B6, 40/84 (room list, 908), 40/80 (join, 65)
  S 0x240/0x181 (520) rejects, then S 0x240/0x81 (238) accept,
C 40/88 → S 0x240/0x89 (7986), 33/80, 33/82 …
```

Full sequences: `work/reports/*-sequence.txt`.

## Hosting architecture (observed in rf-boss-baseline)

| Server | Transport | Role (working hypothesis) | Evidence |
|---|---|---|---|
| 5.188.32.117:7000 | TCP | Lobby: login, inventory, lists, rooms | RC4 `abcde` framing decodes completely |
| 5.188.32.116:33343 | TCP | Room/game session | Server first sends a Flash `<cross-domain-policy>` XML; client frames start `13 57` (0x5713). **Hypothesis: ProudNet middleware.** Not RC4 `abcde` framing. |
| 5.188.32.116:34162 | UDP | Relay / hole-punch for match traffic | Datagrams `cd ab …` wrapping `13 57 01 …` |
| 5.188.32.116:3416 | TCP | Unknown (49 B up / 280 B down; opaque) | |
| other players' IPs | UDP | Peer-to-peer attempts during the match | short bursts to two global peers at match start |

Consequences:
- Local redirection must cover **both** .117 and .116. The v1.9 harness only
  owns .117.
- Internet hosting needs TCP 7000, TCP 33343, TCP 3416 and UDP 34162 on the
  host, and probably relay support for players behind NAT.
- Clients have to reach our server instead of the 5.188.32.x addresses. How
  the client chooses those addresses (hard-coded, launcher, or patch file) is
  not yet established; checkpoint notes say no host/port was found in the
  registry. This must be solved before we can invite other players without
  route changes on their machines.

## REA analysis log

- 2026-10-20: `rea search rumblefighter.exe BUDDY --provider ghidra` →
  0 matches (Ghidra 12.1.4, x86 PE). Consistent with the packed image: the
  strings are not in the on-disk file. Next REA step: analyze the stage-1
  decompressed image (`inspect_client_stage1.py` output) with
  `--target-format raw-binary --architecture x86 --entry-point 0x819000`.
  Snapshot: `private/binaries/rumblefighter.rea-snapshot`.

## Code (work/protocol-lab)

| File | Purpose |
|---|---|
| `RFHandshakeProbe.cs`, `Test-RF-LocalHandshake.ps1`, `RunLocalHandshake.cmd`, `CleanupLocalHandshake.cmd` | Bounded real-client test (now v1.9). Admin required. |
| `lobby_wire.py`, `test_lobby_wire.py` | Buddy-list codec and tests (new) |
| `rf_sequence.py` | Time-ordered frame list from both directions; `--dump` bodies → private/ only (new) |
| `capture_endpoints.py`, `rf_flows.py`, `rf_peek.py` | Endpoint census, per-flow framing check, raw peek (private) (new) |
| `local_backend.py`, `local_store.py`, `*_wire.py` | Original Python lab server (127.0.0.1:17000), SQLite accounts |

Run tests: `python -m unittest discover -s work\protocol-lab -t work\protocol-lab`.
C# self-test: `powershell -NoProfile -Command "Add-Type -Path work\protocol-lab\RFHandshakeProbe.cs; [RFLocalHandshake.Probe]::SelfTest()"`.

## Next manual action (user)

v1.25 startup-only run (baseline profile): `work\protocol-lab\RunLocalHandshake.cmd`
as administrator; sign in; expect PLAZA session established, main menu, lobby, My Info,
Store; no equipment or room actions; Q. Equipment/room testing resumes afterwards.

The result JSON is written to `work\protocol-lab\rf-local-handshake-<date>-<id>.json`.

## Roadmap / next actions

1. Record the v1.9 result: the header after the buddy list (expected
   `0x30/0x86`, or the guild queries) and any on-screen state.
2. Replace the one-shot probe with a persistent lobby server (Python asyncio,
   reusing `protocol_probe`, `login_wire`, `lobby_wire` and the SQLite store),
   serving every observed lobby request in order. Only write fields we have
   evidence for, and mark every candidate as such.
3. Unresolved fields that block a usable character: login reply ranges
   42–96, the property-record layout, `30/86`, `30/88`, `30/A0`, `30/CC`.
   Pair each against the captures (e.g. avatar/equipment IDs).
4. GameGuard: the client runs nProtect locally. The server-side CS-auth
   (`48/80` → `48/81`, `48/42`) is currently a captured-blob replay. Find out
   whether a server that never validates `48/42` is accepted over time.
5. Room/match: identify the 33343 protocol (ProudNet hypothesis). Implement
   the room server and the UDP relay; extend redirection to .116.
6. Two local clients → LAN → a real internet host.

**v1.25 real-client result** (`rf-local-handshake-20261020-220128-b3f1b456.json`, profile
`baseline`; checkpoint `work/checkpoints/v1.25-local-startup-training`, restore with
`work\protocol-lab\RestoreCheckpoint.cmd v1.25-local-startup-training`): fully local
startup (`P2P Connected : 3`, login ok, main menu, lobby, My Info equip/unequip, Store),
client-side tutorial (Sunset Valley) played to the end ("GameFinish Query fail" logged on
return). NOT local: plaza/square button -> official `rumble-fighter.square.playredfox.net`
5.188.32.97:7000 (checked in, then FUNC_R_OS_JOIN error); launcher/GameGuard update hosts;
www.playredfox.com.

### v1.26 (built; PENDING). Snapshot `work/versions/v1.26/`
- Level: login/room-record pairs (rf_level_pairs.py): 1/13380, 4/9337, 10/65934,
  18/1.35M-2.09M, 19/2.61M, 22/8.46M. Level is a stored field (a level-1 player can hold
  more exp than a level-4 one); max captured level 22, so the level-90 exp is UNRESOLVED.
  Profile `admin`: level 90, exp 0 (experiment: shows how the client displays it).
- Currencies: Carats = login body +32 (15535 in rf-boss-baseline; Gemnet LoginRes.Carats);
  Astros = 31/89 field 2 (23/40/0); Medals = 31/89 field 3. Unlimited setting per profile
  (default 99,999,999, int32 fields).
- Purchase: 31/80 (15 bytes: 1 unread byte, catalog, item_end) -> 31/81 (instance, Carats):
  Gemnet BuyItemReq/Res layout, NOT captured. Free only with unlimited on; saved before the
  reply; ledger `<profile>.purchases.log`; observed record if catalog+item_end match, else
  Gemnet shape (+8 = 85582, item_end, zeros).
- Checks: Run-PersistenceChecks 43/43 (account 44), Python 67/67.

**v1.26 real-client result** (run `ebe7ff17`, profile `admin`; server still running at
analysis time; checkpoint `work/checkpoints/v1.26-purchases-unpack-fails`):
- Unlimited currency displayed: both balances 99999999 (screenshot 202818).
- 10 Store purchases saved (instances 1005-1014, ledger; buy flag byte = 82 each time).
- Level 90 field NOT displayed: My Info shows "Lv. 1 0/500" -> the client derives the
  displayed level from experience (exp 0), not from login +24. Level 90 needs the exp
  table (blocked).
- UNPACK: client log `dxWnd_MyCharacter.cpp(8010) Unpack start` 20:27:58.691, then
  `GServerAccess.cpp(3922) query error (return NULL)` at +30.006 s (= the client's query
  timeout) -> ServerErr FUNC_Q_UNPACK NULL -> Not Responding. Root cause: the request
  reached our lobby server and was left unanswered (no handler). Opcode per Gemnet: 31/86
  UNPACK (31/9A OPEN_BOX); the server's own record of it is written when that session ends.
- Evidence search: no capture contains 31/86, 31/87, 31/9A or 31/9B; Gemnet has no UNPACK
  handler and its OPEN_BOX uses an unpublished reward registry + placeholder fallbacks; the
  client binary is WinLicense-protected (no unpacked image; live dumping = defeating
  GameGuard anti-tamper, out of scope). Package contents (5 Seal of Zodiac - Cancer boxes)
  and box rewards exist only in client data (obfuscated tables) -> UNPACK/OPEN_BOX success
  replies BLOCKED pending a capture of an official unpack + box opening.

### v1.27 (built; PENDING). Snapshot `work/versions/v1.27/`
- 31/86 and 31/9A refused in the captured failure form (31/187 or 31/19B, 520 bytes, code
  10001 FAIL(unknown)); nothing consumed or granted. UNVERIFIED reply form for these actions.
- Live session-log line for every unanswered/refused request (opcode, length, body hex
  <= 64 bytes, owned instance/catalog it names).
- Checks: account self-test 47/47; offline suite all PASS; Python 67/67. Live loopback
  checks not rerun (the user's v1.26 server was running).
- Item generator `work\protocol-lab\RFItemGen.cmd` (local profiles only, no network code):
  list / grant / grant-family / grant-store / remove. Sources: observed capture records,
  catalog IDs the client itself sent in local Store purchases (reference record shape),
  manual IDs only with -ItemEnd -Force (unverified). Same locked atomic store as the server;
  backups before bulk changes; class item cannot be removed. Tested on a throwaway profile.
- RFItemGen fix: double-clicking RFItemGen.cmd (no arguments) failed instantly ("missing mandatory parameters: Command") and closed the window, so no grant ever reached admin.txt. Now: no arguments = interactive menu, window stays open, failures explained. Menu and CLI tested on a throwaway profile.
- Public reference import (2026-10-21): Gemnet main (`Login.cs` CreateAccount) gives 17 named
  IDs: 11 classes (M/F, Shaman, Android), 5 default Exos, fishing rod (ItemEnd 1000); 5 IDs were
  new (1000248, 1000250, 1001792, 1001793, 2040086). `AvatarDef.SlotName` names all 45 slots and
  matches the capture-derived slot/family pairs (105 hair, 106 top, 107 bottom, 108 gloves,
  109 shoes, 102 eyes, 103 nose, 104 mouth, 203 scroll, 204 ExoA/B, 301 back, 303 neck, 302 ears,
  305 glasses, 306 mask, 304 waist, 34-44 = *_BP). Gemnet has no item catalog (Prices.cs empty;
  box JSON external); gemnet-js inventory.js has none. Stored in
  private/fixtures/reference-gemnet.v1.tsv; RFItemGen source `reference` + names. 642 IDs total.

### v1.28 (built 2026-10-21; PENDING real-client test). Snapshot work/versions/v1.28/
- **Startup regression fixed.** Run f07f0a84 (profile admin, 643 items): session 2 sent
  31/8A ADD_ITEM kind 0 (body 0000bcf91e002b040000 = catalog 2,029,500, end 1067) during the
  login/server-access phase; the server left it unanswered -> client waited 30 s ->
  GServerAccess.cpp(3194) "return NULL" -> EndTask. Catalog 2,029,500 is NOT in the admin
  profile and NOT from any grant source, so the bulk grant did not introduce it; it is a
  client-initiated ADD_ITEM the server simply never answered.
- Fix: every 31/8A now gets the observed 31/18B failure (code 10001 FAIL(unknown)) - the frame
  the official server sent for ADD_ITEM in all 5 captures and the client is proven to tolerate
  and continue past (kind 1 GetLevelUpItem, kind 2 channel-100 claim). Unrecognized bodies get
  the same frame (extrapolated: same action, same tolerated failure) rather than silence. NOT
  a success reply. Logged live (add_item_unrecognized_failure) and counted
  (add_item_unrecognized_failures); the old silent add_item_unanswered path is gone.
- admin profile (643 items) verified offline: valid, unique instances, 0 dangling, paginates
  to 9 pages with no record loss. Original admin inventory preserved (backup + 5 pre-grant
  snapshots in private/accounts/backups); not modified.
- Checks: SelfTest + 48 account checks (incl. add_item_unrecognized_answered_with_failure_and_logged),
  offline suite all PASS, Python 67/67. NOT yet verified in the real client.
- Full preservation backup: C:\RumbleFighter-Backups\20261021-094318\ (4225 files, 2.3 GB,
  workspace + complete game install, SHA-256 manifest). Note: 100000_table.nsz changed to
  93963dd9... (still 2212 B) from the 155cb5f6... recorded earlier - the client updates it.

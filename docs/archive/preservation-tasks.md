# Task tracker (private build)

Statuses: **not implemented** · **experimental** (built, evidence partial or untested in-game) ·
**implemented** (built + automated tests, not yet seen working in the real client) ·
**verified in-game** (real-client run, report named) · **blocked** (missing evidence; what is missing is stated).

Updated 2026-10-20 for v1.25. Newest in-game reports: v1.23 `...205130-374519e9.json`
(works, but used the OFFICIAL plaza), v1.24 `...214640-f41b0839.json` (black screen).

## 0. PRIORITY: fully local startup (acceptance: menu, lobby, My Info, Store with no official lobby/plaza/gameplay service)
| Item | Status | Evidence / notes |
|---|---|---|
| Lobby .117 local | verified in-game | v1.18+ |
| Plaza .116 local, client reaches "P2P Connected" | experimental | v1.24: client closed after our hint (settings shifted 2 bytes); v1.25 hint byte-identical outside the key |
| Plaza stages after ConnectSuccess (pings/heartbeat) | implemented | as captured; real client not yet seen past the hint |
| Chat TCP 3416 (gchat) | blocked | opaque, server speaks first; not a startup gate in the capture; recorded only = unfinished |
| Name resolution of *.playredfox.net | not implemented | client resolves official DNS names, then uses our redirected IPs; independence needs a local resolution path (not done, no hosts changes made) |
| Launcher / GameGuard update contacts (cdn.playredfox.net, mgr.gameguard.co.kr) | not implemented | seen in capture DNS; v1.25 run audits them live |
| Baseline account emits v1.23 bytes | implemented | self-test + `private/accounts/baseline.txt` equals the v1.23 state |

| Fully local startup, menu, lobby, My Info, Store | verified in-game | v1.25 report `...220128-b3f1b456` (P2P Connected : 3) |
| Square/plaza button (5.188.32.97:7000) | not implemented | v1.25 client reached the OFFICIAL square server; needs a third local address (networking change, awaiting approval) |

## Account / currency / purchases (v1.26)
| Item | Status | Evidence / notes |
|---|---|---|
| Level 90 field | experimental | admin profile; exp threshold unresolved (max captured level 22) |
| Unlimited currency (Carats + Astros) | implemented | 44 account checks; G/R mapping to be seen in-game |
| Store purchase 31/80 -> 31/81 | experimental | Gemnet layout, no capture; free with unlimited only; ledger |
| Paid purchases (deducting prices) | blocked | no price table |
| Store purchases (free, admin) | verified in-game | v1.26 run ebe7ff17: 10 purchases saved, items shown |
| Unlimited balance display | verified in-game | both 99999999 (screenshot 202818) |
| Level 90 display | blocked | client shows Lv.1 0/500: display derives from experience; exp table unknown |
| UNPACK 31/86 (package -> boxes) | blocked | v1.26: unanswered -> FUNC_Q_UNPACK NULL; v1.27 refuses explicitly; success reply + package contents need an official capture |
| OPEN_BOX 31/9A (box -> reward) | blocked | no capture; reward tables unknown |
| Gift / period start 30/8E | not implemented | |

## Requests intentionally left unanswered (unfinished; can cause NULL/time-out dialogs)
| Request | When | Why unanswered |
|---|---|---|
| 31/8A GetLevelUpItem kind 1 | after LoginCheck | answered with the observed failure 10001 only (nothing granted) |
| 31/8A other kinds, 31/8C grade-up | rare | no captured success layout |
| 30/8E item period | some equips | 1 sample, reply meaning unknown |
| 30/80 for other players' names | rooms | no not-found reply captured |
| 30/D6 / 40/A4 for unowned or wrong-slot items | My Info | no captured failure reply |
| Room creation request(s) | Create Room | not in any capture |
| Plaza game RMIs (0x03EC join group etc.), relay, UDP hole punch | rooms | not implemented |
| TCP 3416 chat greeting | after plaza | protocol unknown |

## 1. Baseline
| Item | Status | Evidence / notes |
|---|---|---|
| Checkpoint v1.23 (code, report, fixture + client hashes) | implemented | `work/checkpoints/v1.23-store-lobby-persistent` |
| Login + startup animation | experimental | verified only with the official plaza (v1.23); v1.24 fully local: black screen |
| Main menu, lobby, empty room list | experimental | v1.23 (official plaza involved) |
| My Info display (character, inventory) | experimental | v1.22/v1.23 (official plaza involved) |
| Store browsing + temporary try-on (scrolls, Exos, clothes) | experimental | v1.23 (official plaza involved) |
| Item ownership / purchases | not implemented | no capture of a purchase (31/88 only) |

## 2. Persistent operation
| Item | Status | Evidence / notes |
|---|---|---|
| No runtime/request limits; runs until Q/Ctrl+C/window close | verified in-game | v1.23: 2 sessions, Ctrl+C, 15+ min |
| Reconnect after client exit/crash | verified in-game | v1.23 session 2 after game restart |
| Per-connection framing/cipher/state | implemented | offline reconnect test (2 sessions, 3000 polls) |
| Concurrent lobby sessions | not implemented | lobby accept loop serves one connection at a time (plaza is concurrent) |
| Client disconnect vs server stop logged separately | verified in-game | v1.23 session log |
| Frame limits / partial-frame deadline / idle never expires | implemented | lobby + plaza self-tests |

## 3. Startup, shutdown, recovery
| Item | Status | Evidence / notes |
|---|---|---|
| One launcher (`RunLocalHandshake.cmd [profile]`) with preflight + READY | implemented | port/UDP/portproxy/address conflicts reported with actions |
| Incompatible client build detection | implemented | SHA-256 of the connecting process (lobby + plaza) |
| Ctrl+C graceful stop + verified cleanup | verified in-game | v1.23 report (ctrl_c, verified_removed) |
| Window X close (console handler + watchdog) | implemented | killed-process case verified live (automated); real X click not yet clicked |
| Journal recovery after kill/power loss | implemented | automated live check C |
| Two owned addresses (.117 lobby, .116 plaza), v2 journal | implemented | automated live checks (1.24) |

## 4. Account state
| Item | Status | Evidence / notes |
|---|---|---|
| Persistent account file (identity, level, exp, balances, avatars, items, equipment) | implemented | `RFAccount.cs`, 35 account self-checks |
| Login / inventory / avatars / equipment / cash / user info from one state | implemented | baseline bytes identical to v1.23 (self-test) |
| Atomic writes, backup/restore, validation | implemented | store self-tests, `RFAdmin.ps1` |
| Survives reconnect and server restart | implemented | 2-connection scripted test reads equipment back from the file |
| Purchases / grants via game requests | blocked | no captured successful purchase or kind-1 grant reply |
| First-login / level rewards not repeated | experimental | level-1 reward still answered with the observed failure (nothing granted) |

## 5. My Info equipment
| Item | Status | Evidence / notes |
|---|---|---|
| Failing request identified | verified in-game | v1.23 session 1: 30/D6 unanswered (equip stops there) |
| 30/D6 -> 30/D7 01 (owned catalog) | implemented | 4/4 in rf-boss-baseline |
| 40/A2 select avatar, 40/A4 equip, 40/A6 unequip, saved before ack | implemented | 27+ captured acks; ownership + slot-family validation |
| Scroll / Exo (two slots) / clothing / accessory slots | implemented | slot families from 40 captured equipment replies |
| Refusal reply for invalid items | blocked | no captured failure reply; refused requests stay unanswered, state unchanged |
| 30/8E item period query (30/8F) | blocked | 1 sample; meaning of the 8-byte reply (date) not established; unanswered |
| Equipment works in gameplay | blocked | needs a playable session (section 9) |

## 6. Store and catalog
| Item | Status | Evidence / notes |
|---|---|---|
| Observed item records | implemented | 557 catalogs from 3 captures (`private/fixtures/item-records.v1.tsv`) |
| Full catalog for this build | blocked | client tables are in `res/*.nsz`; `100000_table.nsz` is obfuscated; format not yet analysed |
| Purchases with currency changes | blocked | no captured purchase exchange |
| Inventory pagination (no truncation) | implemented | 80/page, cursor rule from 3 captures; 304- and 557-item tests |

## 7. Admin / level 90
| Item | Status | Evidence / notes |
|---|---|---|
| Admin tool (show, create, grant, grant-all-observed, set-level, balances, backup/restore/reset, repair) | implemented | `RFAdmin.ps1` / `RFAdmin.cmd`, exercised on a test profile |
| Separate profiles (`baseline` regression, `loadout` equip test) | implemented | `private/accounts/` |
| Level 90 coherent state | experimental | level is login/user-info +24, exp +28 (co-occurrence in one capture); experience table not recovered |

## 8. GET_USER_INFO and rooms
| Item | Status | Evidence / notes |
|---|---|---|
| 30/80 -> 30/81 (own name) | implemented | v1.23: 30/80 unanswered -> FUNC_Q_GET_USER_INFO NULL; 4/4 captured replies, fields mapped |
| Room creation request | blocked | no capture contains room creation; next request will be recorded in the v1.24 run |
| Room join flow (40/80 -> 0x240/0x81, 40/88 -> 0x240/0x89, 33/80-83) | not implemented | captured (joins of other players' rooms) |
| Ready / match start | blocked | not in captures |

## 9-11. Gameplay, networking, multiplayer
| Item | Status | Evidence / notes |
|---|---|---|
| Plaza server identified (ProudNet core on .116:33343, connected at login) | implemented | handshake from rf-boss-baseline; 12 plaza self-checks |
| Local isolation of .116 | implemented | v1.23 and earlier reached the live official plaza (client log "P2P Connected") |
| Room P2P groups (RMI 0x03EC/0x03EB, server 0xFBF6 member join, relay 0x14/0x17) | not implemented | captured, plaintext |
| UDP relay / hole punching (34162) | not implemented | captured (0x0B/0x0E/0x0F/0x12) |
| TCP 3416 | blocked | opaque bytes; purpose unknown (recorded only) |
| Solo/training session, LAN, internet | not implemented | depends on rooms + P2P |

## 12-14. Diagnostics, automation, packaging
| Item | Status | Evidence / notes |
|---|---|---|
| Per-session JSONL (lobby sessions, plaza connections, shutdown, watchdog) | implemented | |
| Automated checks: `Run-PersistenceChecks.ps1` (42), Python 67 | implemented | `work/reports/persistence-checks/20261020-214109` |
| Packaging / LAN / internet docs | not implemented | |

## 2026-10-21 (v1.28) status update
| Item | Status | Evidence |
|---|---|---|
| Startup regression (31/8A kind 0 hang -> EndTask) | fixed, offline-verified | run f07f0a84 diagnosed; all ADD_ITEM now answered with observed 31/18B failure; 48 account checks |
| Unanswered-request logging gap for ADD_ITEM | fixed | add_item now logged live + counted (add_item_unrecognized_failures) |
| Full preservation backup (workspace + game install) | done | C:\RumbleFighter-Backups\20261021-094318 (2.3 GB, SHA-256 manifest) |
| Expanded admin profile (643 items) integrity | verified offline | valid, unique, 0 dangling, 9 pages no loss |
| Local gameplay loop (room create/solo match) | blocked - missing evidence | captures only show JOINING other players rooms (0x240/0x81 reject, 0x240/0x89 accept); no room CREATE, no solo-mode start, no map-load handshake captured |
| Sunset Valley tutorial GameFinish | needs real-client test | v1.25/f07f0a84 logged "GameFinish Query fail" on tutorial return; the finish-report opcode is not isolated yet |
| Independence (square server 5.188.32.97) | known gap | plaza/square button still reaches official 5.188.32.97:7000; not redirected (networking change, needs user OK) |

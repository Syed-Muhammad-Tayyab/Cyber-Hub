<!-- Cyber Hub API reference - Developed by Syed Muhammad Tayyab -->

# 🛡️ Cyber Hub — API reference
**Developed by Syed Muhammad Tayyab**

Security center for your Windows PC and your online accounts — antivirus engine, real-time protection, firewall,
network and Wi-Fi checks, Windows hardening, password vault, file encryption, website / code scanner, threat
intelligence, account protection, scheduler, reports and backups — in one desktop app that runs entirely on your PC.

**Status: complete — 20 / 20 parts (100%), version 1.0.0.** See [ROADMAP.md](../ROADMAP.md) for what each part does.

---

## Use it

### Option A — run from this folder (Windows)
1. Install **Python 3.10+** from python.org (tick *Add python.exe to PATH*).
2. Double-click **`start_cyberhub.bat`**. The first start sets everything up (a minute or two); later starts are quick.
3. Cyber Hub opens in its own window and puts a shield in the tray. Create your owner account — that's it.

Use **`start_cyberhub_admin.bat`** when you want to change Windows Firewall or apply machine-wide security fixes
(Windows only allows that to programs running as administrator). Everything else works without it.

### Option B — build `CyberHub.exe` and an installer
1. Double-click **`build_windows.bat`** — it installs the build tools, runs the tests, and builds `dist\CyberHub\CyberHub.exe`.
2. Optional: install [Inno Setup 6](https://jrsoftware.org/isdl.php) first and the same script also creates
   `dist\CyberHub-Setup-1.0.0.exe` — a normal Windows installer (no administrator rights needed, Start-menu and
   desktop shortcuts, optional *Start with Windows*, uninstaller that asks whether to keep your data).

### Options
| | |
|---|---|
| `CyberHub.exe --minimized` | start hidden in the tray (what *Start with Windows* uses) |
| `CyberHub.exe --browser` | use your web browser instead of the app window |
| `CyberHub.exe --server-only` | engine only — API on http://127.0.0.1:8765, docs on `/docs` |
| `python run.py` | engine only, from source (developers) |

Your data lives in `%LOCALAPPDATA%\CyberHub\` (database, logs, quarantine, reports, backups).
Tests: `python -m pytest -q` (all 20 parts; 1 test is skipped unless `yara-python` is installed).

## The app
21 pages with 60+ tabs, dark and light theme, works offline (no CDN, no framework). The sidebar groups them;
hovering a section shows its features. Every page talks to the engine through the same local API.

| Area | Pages |
|---|---|
| Overview | **Dashboard** — overall score, what to fix first (one-click fixes), protection areas, graphs, your network |
| Protection | Virus & threats (scans, history, quarantine, real-time, rules, exclusions) · Firewall · Network · Device security |
| Privacy & accounts | Password vault · Data protection (encrypt, shred, clean, find sensitive files) · Accounts & platforms |
| Tools | Website & project scanner · Threat intelligence · System monitor · Processes & startup |
| Manage | Scheduler · Notifications · Reports & backup · Activity · Settings · Account · About |

## Build your own UI instead
Replace `ui/index.html` and call the engine through `frontend-bridge/cyberhub-api.js` (`window.CyberHub.*` — every
part, including `dashboard()`, `streamNotifications()`, `reportCreate()`, `backupCreate()`, `pickPath()`).

## Part 1 endpoints
| Method | Path | Used by |
|---|---|---|
| GET | `/api/health` | "Engine online" badge (no token needed) |
| GET | `/api/bootstrap` | bridge fetches the API token (allowed origins only) |
| GET | `/api/info` | version, 20-module map, progress |
| GET | `/api/system/info` | device card: OS, CPU, RAM, disks, adapters |
| GET | `/api/system/stats` | rings & gauges: CPU, RAM, disk, net speed, processes, uptime, battery |
| WS | `/api/system/stream?token=` | live stats push every N seconds |
| GET | `/api/system/history?hours=24` | line charts (recorded every 60 s) |
| POST | `/api/system/snapshot` | record a history point now |
| GET/POST/DELETE | `/api/activity` | recent activity list |
| GET | `/api/activity/summary?days=7` | severity donut, per-day bars, per-category |
| GET/PATCH | `/api/settings`, POST `/api/settings/reset` | Settings page |

## Part 2 endpoints — Account & Login
Signed-in calls also send `X-CyberHub-Session: <session_token>` (the bridge handles this).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/account/status` | `setup_required` → show Setup or Login screen |
| POST | `/api/account/setup` | first run: create owner account + sign in |
| POST | `/api/account/login` | password **or** PIN → session token |
| POST | `/api/account/password-strength` | live strength meter (score 0–4, feedback) |
| GET / PATCH | `/api/account/me` | profile (name, email) |
| POST | `/api/account/logout`, `/lock`, `/unlock` | sign out / lock screen / unlock (PIN or password) |
| POST | `/api/account/change-password` | signs out all other sessions |
| PUT / DELETE | `/api/account/pin` | quick-unlock PIN (4–8 digits) |
| POST / GET | `/api/account/recovery-codes` | 8 one-time codes (shown once) / remaining count |
| POST | `/api/account/recover` | forgot password: recovery code → new password |
| GET / DELETE | `/api/account/sessions[/{id}]` | signed-in devices, sign one out |
| GET | `/api/account/login-history` | success/failed stats + list |
| GET / POST / DELETE | `/api/account/users` | admin: add/remove local users |
| POST | `/api/account/delete` | delete own account |

Account protections: scrypt-hashed passwords/PINs/codes · session tokens stored only as SHA-256 · 5 failed tries → 5-min lockout · auto-lock after 15 min idle · sessions expire after 8 h · all configurable in Settings. Once an account exists, changing settings or clearing the log requires sign-in.

Try it: copy `frontend-bridge/auth-example.html` + `cyberhub-api.js` into `ui/`, start the engine, open http://127.0.0.1:8765/auth-example.html

## Part 3 endpoints — Live System Monitor
All need a signed-in, unlocked session. Bridge functions in brackets.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/monitor/overview?top=5` | whole monitor page in one call: CPU, RAM, disk I/O, network, GPU, temps, health lights, top users, alert badge `[monitorOverview]` |
| GET | `/api/monitor/cpu` | total + **per-core** %, MHz, user/system/idle split, interrupts & context switches/s `[monitorCpu]` |
| GET | `/api/monitor/memory` | used / available / cached RAM + page file (swap) `[monitorMemory]` |
| GET | `/api/monitor/disks` | **read/write MB/s, IOPS, active %** per disk + space per drive `[monitorDisks]` |
| GET | `/api/monitor/network` | upload/download KB/s per adapter `[monitorNetwork]` |
| GET | `/api/monitor/gpu` | GPU usage, VRAM, temp, power (nvidia-smi → Windows GPU counters → Linux sysfs) `[gpu]` |
| GET | `/api/monitor/temperatures` | CPU / GPU / drive temps + fans `[temperatures]` |
| GET | `/api/monitor/top?by=cpu\|memory\|disk&limit=10` | top resource users `[topProcesses]` |
| GET | `/api/monitor/history?hours=24&bucket_minutes=` | averaged line-chart data incl. swap, disk I/O, GPU, temp, net MB `[monitorHistory]` |
| GET / PUT | `/api/monitor/thresholds` | alert limits `[getThresholds / setThresholds]` |
| GET | `/api/monitor/alerts?status=all\|active\|resolved\|unacknowledged` | alert list `[monitorAlerts]` |
| GET | `/api/monitor/alerts/summary?days=7` | badge count + charts `[alertsSummary]` |
| POST | `/api/monitor/alerts/check` · `/alerts/{id}/ack` · `/alerts/ack-all` | check now / acknowledge |
| DELETE | `/api/monitor/alerts` | clear resolved alerts |
| WS | `/api/monitor/stream?token=&session=&top=5` | live frames every `metrics_interval_seconds` `[streamMonitor]` |

**Alert engine** (runs every 5 s in the background): CPU 90 %, memory 90 %, disk space 90 % per drive, GPU 95 %, CPU temperature 85 °C. A value must stay over its limit for **60 s** before an alert opens (short spikes are ignored), it escalates to *high* when far over, and closes only once it drops a margin below the limit (no flapping). Every open/close lands in the activity log. All limits are editable on the Settings page or via `/api/monitor/thresholds`.

**Temperatures on Windows:** Windows hides most CPU sensors. Cyber Hub reads ACPI thermal zones by default; for real per-core CPU/GPU/SSD temperatures, run the free **LibreHardwareMonitor** in the background and Cyber Hub picks its sensors up automatically. NVIDIA GPUs report temperature via `nvidia-smi` (installed with the driver).

Try it: copy `frontend-bridge/monitor-example.html` into `ui/` too, sign in at `/auth-example.html`, then open http://127.0.0.1:8765/monitor-example.html

## Part 4 endpoints — Processes & Startup
Reading needs a signed-in session; **changing** anything needs a Cyber Hub **admin** account
(plus, for system-wide items, the engine started with *Run as administrator*). Bridge functions in brackets.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/processes?search=&sort=cpu\|memory\|disk\|name\|pid\|threads\|risk\|started&flagged_only=&signatures=` | Task-Manager list with risk flags + summary `[processes]` |
| GET | `/api/processes/tree` | parent → child tree with subtree CPU / memory totals `[processTree]` |
| GET | `/api/processes/summary` | counts for the Processes card, riskiest 5, elevation state `[processSummary]` |
| GET | `/api/processes/{pid}?hash=true` | command line, parent/children, handles, open files, connections, **signature**, SHA-256, risk `[processDetails]` |
| POST | `/api/processes/{pid}/end` `{create_time, tree, force}` | end task / end tree / force kill `[endProcess]` |
| POST | `/api/processes/{pid}/suspend` · `/resume` | freeze / unfreeze `[suspendProcess / resumeProcess]` |
| PUT | `/api/processes/{pid}/priority` `{priority}` | idle · below_normal · normal · above_normal · high `[setProcessPriority]` |
| GET | `/api/processes/actions` | who ended / suspended what, and when `[processActions]` |
| GET | `/api/startup?source=&state=all\|enabled\|disabled\|new&flagged_only=&microsoft_tasks=&manual_services=&refresh=` | everything that starts with the PC, riskiest first `[startupItems]` |
| GET | `/api/startup/summary` · `/sources` · `/{id}` | donut counts per source, NEW / flagged / unsigned counts `[startupSummary]` |
| POST | `/api/startup/{id}/disable` · `/enable` | switch an item off / on (original entry is never deleted) `[disableStartup / enableStartup]` |
| POST | `/api/startup/{id}/accept` · `/accept-all` | mark NEW items as reviewed `[acceptStartup / acceptAllStartup]` |
| GET | `/api/startup/changes` | enable/disable history incl. previous service start type `[startupChanges]` |
| POST | `/api/startup/watch/check` | rescan now for new persistence entries `[checkStartupNow]` |

**Startup sources (Windows):** Run / RunOnce registry keys (user + machine, 32 + 64-bit), user & all-users Startup folders (shortcuts resolved to their target), auto-start services, and scheduled tasks (non-Microsoft by default, `microsoft_tasks=true` for all). Disabling works exactly like Task Manager — `StartupApproved` flags for Run keys / Startup folder, `sc config start= disabled` for services (the old start type is remembered and restored on enable), `schtasks /Change /DISABLE` for tasks. On Linux it reads XDG autostart, systemd and cron `@reboot`, so the engine is testable off Windows.

**Safety rails**
- Critical Windows processes (csrss, lsass, winlogon, services, svchost in System32, Defender…), Cyber Hub itself and its launcher can't be ended or suspended — `403 Protected`.
- Essential services (Defender, Firewall, Windows Update, Event Log, RPC…) can't be disabled.
- Pass the row's `create_time` with every action: if Windows has reused that PID for another program you get `409` instead of killing the wrong thing.
- "End task" asks the program to close first; if it refuses you get `still_running` and can retry with `force: true`.
- Every action lands in `process_actions` / `startup_changes` and the activity log.

**Risk flags** (shown as a coloured pill with reasons): running from Temp / Downloads / Public, Windows system name in the wrong folder (*masquerading*), shell or script host launched by Word / Excel / PDF reader, encoded PowerShell, hidden window, missing file, unsigned or tampered signature, new since last review. Signatures use Windows Authenticode and are cached per file until it changes.

**Persistence watch:** the first scan is your trusted baseline. Every 10 min (setting `startup_watch_interval_minutes`) Cyber Hub rescans and raises a *medium* (or *high* if risky) activity alert the first time a new startup entry appears — the classic sign of malware installing itself — and notes removed entries.

Try it: copy `frontend-bridge/processes-example.html` into `ui/`, sign in, then open http://127.0.0.1:8765/processes-example.html

## Part 5 endpoints — Antivirus Scan Engine
Any signed-in user can run, pause, resume and cancel scans (like Windows Security). Changing the
signature database or exclusions and dismissing a threat needs a Cyber Hub **admin**. Bridge functions in brackets.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/scan/summary?days=14` | protection status, active threats by severity, last scan per type, scans/threats per day, signature stats, running job `[scanSummary]` |
| POST | `/api/scan/quick` · `/full` · `/custom {paths:[]}` | start a scan → `202` + job (queued if another scan is running) `[quickScan / fullScan / customScan]` |
| GET | `/api/scan/jobs?kind=` · `/jobs/active` · `/jobs/{id}` | history + live progress `[scanJobs / activeScans / scanJob]` |
| POST | `/api/scan/jobs/{id}/pause` · `/resume` · `/cancel` | job control `[pauseScan / resumeScan / cancelScan]` |
| GET | `/api/scan/jobs/{id}/detections` | threats found by one scan |
| WS | `/api/scan/stream?token=&session=` | live progress + `threat`, `job_started`, `job_paused`, `job_finished` events `[streamScans]` |
| POST | `/api/scan/file {path}` | scan one file right now `[scanFile]` |
| POST | `/api/scan/lookup {hash}` | is this MD5 / SHA-1 / SHA-256 known malware? `[lookupHash]` |
| POST | `/api/scan/self-test` | proves hash lookup, pattern match and archive scanning work (EICAR, in memory) `[scanSelfTest]` |
| GET | `/api/scan/detections?status=active\|dismissed\|resolved\|superseded\|all` | threat list `[detections]` |
| POST | `/api/scan/detections/{id}/dismiss` | false alarm / handled (to act on the file use Part 6) `[dismissDetection]` |
| GET / POST | `/api/scan/signatures` · `/signatures/stats` | browse / add a signature `[signatures / addSignature]` |
| POST | `/api/scan/signatures/import {text \| path, severity}` | bulk-load a hash list `[importSignaturesText / importSignaturesFile]` |
| PATCH / DELETE | `/api/scan/signatures/{hash}` · `DELETE /api/scan/signatures?source=` | enable/disable, delete one, delete a whole import |
| GET / PUT | `/api/scan/exclusions {paths, extensions}` | folders / file types never scanned `[getScanExclusions / setScanExclusions]` |
| GET | `/api/scan/locations` | what Quick and Full scans cover |
| DELETE | `/api/scan/cache` | forget cached hashes `[clearScanCache]` |

**How a scan works:** the engine first counts the files (so the ring can show a real %), then streams each file once to get **SHA-256 + SHA-1 + MD5**, looks them up in the local signature database and checks built-in byte patterns. **.zip / .jar / .docx / .apk** style archives are opened and every file inside is checked too (nested archives 2 levels deep, with zip-bomb and size guards; password-protected entries are listed but can't be read). Files that haven't changed since the last scan reuse their cached hashes, so a repeat scan is several times faster. Only one scan runs at a time; others queue. If the engine stops mid-scan the job shows as *interrupted*.

| Scan | Covers |
|---|---|
| **Quick** | your Temp + Windows Temp, Downloads, Desktop, Startup folders, programs & scripts in AppData / ProgramData / Public, **every running program's file** and **every startup item's program file** (from Part 4) |
| **Full** | every file on every fixed drive (skips *System Volume Information* / Windows upgrade folders) |
| **Custom** | files / folders you pick (up to 50) |

**Signature database:** ships with the EICAR test signatures. Load real malware hashes by importing a list — plain hashes, `hash,name` CSV, `sha256sum` output, or the free **MalwareBazaar** exports (download `full_sha256.zip` or the recent CSV from bazaar.abuse.ch/export and import the file path directly, zip and all). Built-in signatures can be disabled but not deleted. Part 8 adds YARA rules, heuristics and online lookups.

**Settings:** `scan_max_file_mb` (256), `scan_archives` (on), `scan_archive_max_mb` (100), `scan_hash_cache` (on), `scan_excluded_paths`, `scan_excluded_extensions`. Excluding a whole drive is refused.

**Testing detection:** click **Self-test** — it runs the EICAR test through the engine in memory. Writing a real EICAR file to disk works too, but Windows Defender will usually delete it before Cyber Hub sees it, so point a Custom scan at a folder Defender excludes, or add a hash of any harmless file as a signature and scan that file.

Try it: copy `frontend-bridge/scanner-example.html` into `ui/`, sign in, then open http://127.0.0.1:8765/scanner-example.html

## Part 6 endpoints — Quarantine & Threat History
Any signed-in user can quarantine / remove threats and delete quarantine items. **Restore, allow, dismiss,
force-quarantining OS files, emptying the vault and clearing history need an admin** (same split as Windows Security).
Bridge functions in brackets.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/threats/summary?days=30` | protection-history dashboard: status donut, active by severity, per-day detected / quarantined / removed / restored / allowed bars, top threats, top folders, handled %, quarantine stats `[threatSummary]` |
| GET | `/api/threats?status=&severity=&search=&days=` | protection history (`history` = all except duplicates; or `active` · `quarantined` · `removed` · `restored` · `allowed` · `dismissed` · `resolved`) with the actions each row allows `[threats]` |
| GET | `/api/threats/{id}` | one threat + **timeline** (detected → quarantined → restored …), quarantine item, allowed status `[threat]` |
| POST | `/api/threats/{id}/quarantine` · `/remove` | quarantine (restorable) · remove (vault copy destroyed at once) `[quarantineThreat / removeThreat]` |
| POST | `/api/threats/{id}/allow` · `/dismiss` | admin: “Allow on device” (SHA-256) · false alarm `[allowThreat / dismissThreat]` |
| POST | `/api/threats/actions {action, ids?}` | **Start actions** — one action on many threats, every id gets its own result `[threatActions]` |
| GET | `/api/threats/export.csv` | history as CSV (same filters) `[downloadThreatCsv]` |
| DELETE | `/api/threats/history?older_than_days=` | admin: forget finished entries (active / quarantined kept) `[clearThreatHistory]` |
| GET / POST / DELETE | `/api/threats/allowed[/{id}]` | allowed threats by SHA-256 or threat name, with hit counter `[allowedThreats / addAllowedHash / addAllowedThreatName / removeAllowed]` |
| GET | `/api/quarantine?status=quarantined\|restored\|deleted\|missing\|all` · `/{id}` | vault items with expiry date `[quarantine / quarantineItem]` |
| GET | `/api/quarantine/stats` | items, size, % of limit, by severity, retention, auto-mode, vault info `[quarantineStats]` |
| POST | `/api/quarantine {path}` | quarantine any file (known threats keep their name) `[quarantineFile]` |
| POST | `/api/quarantine/{id}/restore {destination?, conflict, allow}` | admin: restore to the original place or a folder; `conflict` = rename / overwrite / fail `[restoreQuarantined]` |
| DELETE | `/api/quarantine/{id}` | delete permanently (file + key destroyed) `[deleteQuarantined]` |
| POST | `/api/quarantine/{id}/verify` · `/rescan` | integrity check · still detected with today's signatures? `[verifyQuarantined / rescanQuarantined]` |
| POST | `/api/quarantine/purge {older_than_days?}` · `/vault/check` | admin: empty the vault · consistency check `[purgeQuarantine / checkVault]` |
| WS | `/api/scan/stream` | now also sends `quarantined`, `restored`, `quarantine_deleted` events |

**How quarantine works:** (1) programs running from the file are stopped — protected Windows processes never are; (2) the file is encrypted into the vault with **AES-256-GCM** in 1 MiB authenticated chunks using its **own random key**, written to a temp file, flushed and renamed; (3) the original is deleted — if Windows has it locked, removal is scheduled for the next restart (shown as *removed after restart*); (4) every active detection of that file (including ones inside it, if it's a zip) is linked to the item. The item key is encrypted with the vault master key, which on Windows is sealed with **DPAPI** to your Windows account. Changing a single byte of a vault file makes verify / restore fail; deleting an item destroys its key, so it can't be recovered even from a backup.

**Restore** writes the exact bytes back (SHA-256 checked) with the original modified time, permissions and Windows *Mark of the Web*, recreating the folder if needed. Tick **allow** to stop future scans reporting it — otherwise the next scan finds it again. OS files (System32, SysWOW64, WinSxS…), Cyber Hub's own files and its data folder can't be quarantined by accident.

**Settings:** `scan_auto_quarantine` (`off` · `high` = high + critical · `all`, acts the moment a scan finds a threat), `quarantine_kill_processes` (on), `quarantine_retention_days` (30, 0 = forever), `quarantine_max_mb` (4096 — oldest go first). Housekeeping runs hourly; the vault is checked at every start (missing files, orphans, half-finished quarantines rolled back).

Try it: copy `frontend-bridge/quarantine-example.html` into `ui/`, sign in, run a scan, then open http://127.0.0.1:8765/quarantine-example.html

## Part 7 endpoints — Real-time Protection
Any signed-in user can see the status, turn protection **on**, resume it and scan a plugged-in USB drive.
**Turning it off, pausing it, changing protected folders, trusting / forgetting drives and clearing the log need an admin.**
The same applies to the `realtime_protection`, `rtp_*`, `scan_auto_quarantine` and scan-exclusion settings via `PATCH /api/settings`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/realtime/status` | on / paused / off, every protected folder + watch status, USB drives plugged in, queue, counters, last threat `[realtimeStatus]` |
| POST | `/api/realtime/enable` · `/disable` | master switch (disable = admin) `[realtimeEnable / realtimeDisable]` |
| POST | `/api/realtime/pause {minutes}` · `/resume` | admin: off for 1–480 min, comes back on by itself `[realtimePause / realtimeResume]` |
| POST | `/api/realtime/self-test` | proves Windows is delivering file events (with latency) + scan-engine self-test `[realtimeSelfTest]` |
| GET / POST / DELETE | `/api/realtime/folders` | protected folders: defaults (Downloads, Desktop, Documents, Startup) + your own `[realtimeFolders / addProtectedFolder / removeProtectedFolder]` |
| GET | `/api/realtime/events?status=&origin=` | every file checked on arrival: result, threat, action (quarantined / alerted / failed), downloaded-from URL, ms taken `[realtimeEvents]` |
| DELETE | `/api/realtime/events` | admin: clear the list `[clearRealtimeEvents]` |
| GET | `/api/realtime/summary?days=14` | per-day files checked / threats / USB plug-ins / bursts, top threats, actions, busiest folders `[realtimeSummary]` |
| GET | `/api/realtime/usb?connected=` | every USB / removable drive seen: label, size, fs, times plugged in, trusted, warnings `[usbDevices]` |
| PATCH | `/api/realtime/usb/{id} {trusted}` | admin: trusted drives aren't auto-scanned on plug-in `[trustUsb]` |
| POST | `/api/realtime/usb/{id}/scan` | full scan of that drive (progress on `/api/scan/stream`) `[scanUsb]` |
| DELETE | `/api/realtime/usb/{id}` | admin: forget an unplugged drive `[forgetUsb]` |
| WS | `/api/realtime/stream` | live: `file_scanned`, `threat_found`, `threat_blocked`, `usb_inserted`, `usb_removed`, `burst`, `protection` `[streamRealtime]` |

**How it works:** Windows tells the engine about every new, changed or renamed file in a protected folder
(`ReadDirectoryChangesW` via *watchdog*). The file waits until it stops changing (browsers write `.crdownload` / `.part`
first — the engine catches the final rename), then the Part 5 engine checks it (hashes, patterns, inside zips). On a threat,
`rtp_action = quarantine` (default) moves it into the Part 6 vault at once; `alert` only reports it (Part 6's
`scan_auto_quarantine` policy still applies). A folder dropped or unzipped in is checked file by file. Files you restored from
quarantine in the last 15 minutes are reported, not re-quarantined — tick **allow** on restore to stop that for good.

**USB drives:** polled every second. On plug-in: alert (*first time on this PC* noted), quick root checks — **autorun.inf**
that starts a program, the **shortcut virus** pattern (hidden folders + `.lnk` look-alikes), programs in the root — then
`rtp_usb_scan` = `auto` (default: full scan unless trusted) · `notify` (suggest a scan) · `off`. While plugged in, new files on
the drive are checked like any protected folder. Unplugging cancels a running scan of it.

**Ransomware early warning:** more than `rtp_burst_threshold` (300) file changes in 10 s in one folder raises a high alert
(once per 5 min) — normal for a big copy or unzip, but also exactly what ransomware does.

**Settings:** `realtime_protection` (on), `rtp_watch_default_folders` (on), `rtp_watched_paths`, `rtp_action`
(`quarantine` · `alert`), `rtp_max_file_mb` (100), `rtp_watch_removable` (on), `rtp_usb_alerts` (on), `rtp_usb_scan`
(`auto` · `notify` · `off`), `rtp_burst_threshold` (300, 0 = off), `rtp_log_clean_files` (on), `rtp_event_retention` (5000 rows).

**Honest limit:** this is *on-write* scanning — a file is checked as soon as it has been written (usually < 2 s), not blocked
before the first open. True pre-open blocking needs a signed kernel minifilter driver; Windows Defender keeps doing that
job alongside Cyber Hub (Part 11 checks Defender is on).

Try it: copy `frontend-bridge/realtime-example.html` into `ui/`, sign in, open http://127.0.0.1:8765/realtime-example.html
and save the EICAR test file into your Downloads folder (Defender may grab it first — add a Defender exclusion for a test
folder and add that folder to Cyber Hub instead).

## Part 8 endpoints — Rules Engine, Heuristics & Hash Lookup
Every file the hash database doesn't know now gets a **second opinion** from YARA rules and the heuristic engine —
in Quick / Full / Custom scans, single-file scans, real-time protection and **inside .zip archives**.
Anyone signed in can view rules, analyse files and validate rule text. **Adding / changing / switching off rules,
API keys, caches and the `yara_*`, `heuristics_*`, `rules_*`, `cloud_*` settings need an admin.**

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/rules/status` | engine backend (libyara or YARA-lite), active rules / sets, settings, verdict cache size, detections per engine `[rulesStatus]` |
| GET | `/api/rules/summary?days=30` | chart data: detections per day by engine, top threats, by severity `[rulesSummary]` |
| POST | `/api/rules/self-test` | YARA test marker, double-extension + archive heuristics, clean file — in memory `[rulesSelfTest]` |
| GET | `/api/rules/heuristics` | every heuristic check with weight + category, sensitivity thresholds `[heuristicChecks]` |
| GET | `/api/rules/detections?method=yara\|heuristic\|cloud\|all` | detections with the reason: rule + matched strings / flags + score / cloud verdict `[ruleDetections]` |
| POST | `/api/rules/analyze {path \| content_base64+name, lookup}` | **deep-dive one file** (nothing recorded): hashes, type, entropy, every YARA match, every heuristic flag, PE sections / entropy / imports / packer `[analyzeFile / analyzeBlob]` |
| GET | `/api/rules` · `/api/rules/{id}` | rule sets (built-in pack + yours): status ok / error / unsupported, rule names, hits; one set with source `[ruleSets / ruleSet]` |
| POST | `/api/rules/validate {source}` | live editor check: valid?, error + line, rule names `[validateRules]` |
| POST | `/api/rules {name, source}` | admin: add a rule set (validated first) `[addRuleSet]` |
| POST | `/api/rules/import {path, prefix}` | admin: a `.yar` file, a folder of them or a `.zip` bundle (e.g. YARA-Forge) — one set per file, broken files reported `[importRules]` |
| PATCH / DELETE | `/api/rules/{id}` | admin: switch on / off, rename, edit; built-in sets can only be switched off `[updateRuleSet / deleteRuleSet]` |
| DELETE | `/api/rules/cache/verdicts` | admin: forget remembered verdicts `[clearVerdictCache]` |
| GET | `/api/lookup/status` | online lookup on / off, providers (key set? hint, requests today / limits), background queue `[lookupStatus]` |
| PUT | `/api/lookup/keys {virustotal, malwarebazaar}` | admin: save / remove API keys — stored **encrypted**, never returned `[setLookupKeys]` |
| POST | `/api/lookup/hash {hash, providers, force}` · `/api/lookup/file {path}` | is this hash known malware online? cached + rate-limited `[lookupHash / lookupFile]` |
| POST | `/api/lookup/test` | admin: check each saved key `[testLookupKeys]` |
| GET / DELETE | `/api/lookup/history` · `/api/lookup/cache` | past answers (filter by verdict) / clear them `[lookupHistory / clearLookupCache]` |
| POST | `/api/lookup/queue/run` | admin: process queued background lookups now `[runLookupQueue]` |

**YARA rules.** Uses real **libyara** (`yara-python`) when installed — full language incl. `pe` / `math` / `hash` modules.
If that package can't be installed, the built-in **YARA-lite** engine (pure Python) takes over: text / hex / regex strings,
`nocase wide ascii fullword`, jumps and alternatives, `at` / `in` / `#` / `@` / `!`, `N of` / `%` / `them`, `uint16/32(be)`,
rule references, private / global rules, externals — with a literal pre-filter like libyara (8 MB in < 1 s). Rules that need
modules are kept and marked *needs native YARA*. Force one with `CYBERHUB_YARA_BACKEND=native|lite`.
External variables for your rules: `filename`, `filepath`, `extension`. Rule `meta:` understood: `threat_name`,
`severity` (low / medium / high / critical), `description`.

**Built-in rule pack (22 rules)** — PowerShell download cradles, encoded PowerShell launchers, Defender tampering,
shadow-copy / backup deletion (ransomware prep), VBS / JS droppers, HTA launchers, reverse shells, LOLBin downloads
(certutil, bitsadmin, mshta, regsvr32), PHP / ASPX / JSP web shells, credential-dumping tools, LSASS dumps, coin miners,
ransom notes, auto-run Office macros, RTF Equation Editor exploits, PDF launch actions, malicious shortcuts, HTML
smuggling, plus a harmless test rule: put `CYBERHUB-RULES-ENGINE-TEST-STRING` in any file to see a detection.

**Heuristics (40+ explainable checks)** — each adds a weight to a 0–100 suspicion score; a file is reported at
**low 80 / medium 60 (default) / high 45**: double / padded extensions, right-to-left-override names, programs posing as
documents; for programs an own PE parser (packer sections UPX / MPRESS / Themida / VMProtect…, encrypted code, RWX
sections, entry point outside code, tiny import tables, process-injection / keylogger / downloader API combinations,
encrypted overlays — an embedded Authenticode certificate lowers the score, a verified signature on Windows clears it);
script obfuscation (base64 blobs, char codes, string splitting, IEX / eval, download-and-run, AV tampering, backup
deletion); Office macros (auto-run, starting programs, remote template injection); malicious `.lnk` / `.url` shortcuts;
password-protected archives hiding programs; HTML smuggling. **Tested against 48,919 clean files: 0 false alarms at medium.**

**Verdicts are remembered** per SHA-256 + file name with the rules + heuristics version — unchanged files are never
re-analysed, and changing a rule or the sensitivity re-checks everything automatically.

**Policy.** YARA hits are normal threats (Part 6 auto-quarantine, Part 7 real-time quarantine). Heuristic-only
findings are *suspicious, not proven*: they're reported but **not quarantined automatically** unless you switch on
`heuristics_auto_quarantine`; real-time protection alerts you ("review it in Protection history").

**Online lookup (opt-in).** Add a free **VirusTotal** API key and / or **MalwareBazaar** Auth-Key (abuse.ch) and switch
on `cloud_lookup_enabled`. **Only the hash is sent — never the file.** Answers are cached (`cloud_cache_days`, 7; malicious
30), VirusTotal is rate-limited to its free tier (4 / min, 500 / day). With `cloud_auto_lookup` = `executables` (default) or
`all`, clean files from scans and real-time protection are checked in the background (new arrivals first); a hash the cloud
calls malicious (≥ `cloud_vt_min_detections`, 3) becomes a detection (method `cloud`) and — with `cloud_add_to_signatures` —
a local signature, so it's caught offline from then on.

**Settings:** `yara_enabled` (on), `heuristics_enabled` (on), `heuristics_sensitivity` (`low` · `medium` · `high`),
`heuristics_auto_quarantine` (off), `rules_max_file_mb` (20 — bigger files get name / header checks), `rules_scan_archives` (on),
`cloud_lookup_enabled` (off), `cloud_auto_lookup` (`off` · `executables` · `all`), `cloud_providers`, `cloud_vt_min_detections` (3),
`cloud_vt_per_minute` (4), `cloud_vt_per_day` (500), `cloud_cache_days` (7), `cloud_add_to_signatures` (on).

Try it: copy `frontend-bridge/rules-example.html` into `ui/`, sign in, open http://127.0.0.1:8765/rules-example.html and drop
any file on the *Analyse a file* box.

## Part 9 endpoints — Firewall & Network Protection
All under `/api/firewall` (signed in). 🔒 = Cyber Hub administrator. Changes also need the engine to run elevated
(`start_cyberhub_admin.bat`) — otherwise they answer **403** with that hint and the page stays read-only.

| Method | Path | Used by |
|---|---|---|
| GET | `/status` | Firewall card: on / partial / off, block-all-incoming, each profile + the network on it, rule mix, blocks, health score, unread alerts |
| GET | `/profiles` | Domain / Private / Public cards (`active` = your network uses it) |
| PATCH | `/profiles/{domain\|private\|public\|all}` | `{enabled, default_inbound, default_outbound, block_all_inbound, notify_on_listen, log_blocked, log_allowed}` — turning protection **down** is 🔒 |
| POST | `/shields-up` | `{on}` block **all** incoming connections, even allowed apps (airport Wi-Fi mode) — off is 🔒 |
| GET | `/rules` | every rule: `search`, `direction`, `action`, `enabled`, `profile`, `origin` (cyberhub · system · policy), `flagged`, `sort` (name · risk · program) |
| GET / PATCH / DELETE | `/rules/{id}` | details · `{enabled}` (ALLOW off = anyone; BLOCK off / ALLOW on = 🔒) · delete 🔒 (Cyber Hub rules; others need `force`) |
| POST | `/block/app` | `{path, direction: in\|out\|both, minutes?, reason?}` cut a program off the network |
| POST | `/block/process` | `{pid, create_time?}` "Block network" button in the Processes list |
| POST | `/block/ip` | `{addresses: [IP \| CIDR \| a-b range], direction, minutes?}` |
| POST | `/block/port` | `{ports: "445" \| "6000-6010" \| "80,443", protocol: tcp\|udp\|both, direction}` |
| POST | `/allow/app` 🔒 | "Allow an app through firewall" (incoming, Private networks by default) |
| GET | `/blocks` | Cyber Hub blocks (`status`: current · active · missing · expired · removed), `remaining_seconds` for timed ones |
| DELETE | `/blocks/{id}` 🔒 | unblock · POST `/blocks/{id}/repair` re-creates rules someone removed · POST `/blocks/verify` |
| GET | `/analysis` | 0-100 health score (Protected · Good · Needs attention · At risk) + findings |
| POST | `/findings/{id}/fix` | one-click fix (turn on, block by default, switch risky rule off, repair block; deleting orphans is 🔒) |
| POST | `/watch` | check now for rule / profile changes made outside Cyber Hub (also runs every 5 min) |
| GET | `/events` | firewall timeline; poll with `after_id`; POST `/events/ack` · DELETE `/events` 🔒 |
| GET | `/summary` | graphs: events per day by severity + blocks created, rule mix, blocks by kind, score |
| GET | `/log` | dropped packets per hour, top blocked sources / ports, **port-scan suspects**, latest drops |
| GET / POST | `/snapshots` | list / save the whole policy (`netsh advfirewall export`) |
| POST | `/snapshots/{id}/restore` 🔒 | safety snapshot first, refuses a file changed since it was saved · DELETE 🔒 |
| POST | `/reset` 🔒 | `{confirm: true}` Windows defaults (safety snapshot first, Cyber Hub blocks end) |

**How blocks work.** Each block is one row in Cyber Hub plus 1-4 Windows Firewall rules named `CyberHub-B<id>-in/out[-tcp/udp]`
in the **Cyber Hub** group — you can see them in *Windows Defender Firewall with Advanced Security* too. Duplicates return the
existing block (`already: true`). Timed blocks end by themselves (checked every 30 s). If anything deletes a Cyber Hub rule, the
block turns **missing**, you get a high alert, and **Repair** puts it back.

**Guards.** Loopback, `0.0.0.0` and this PC's own addresses can't be blocked; networks wider than /8 and ranges over 16 M addresses
need `force`; LAN addresses (router, printer) come back with a warning. Blocking outgoing DNS / DHCP / HTTP / HTTPS, the
Windows networking programs (`svchost.exe`, `lsass.exe`, Defender…) or Cyber Hub's own engine is refused unless an admin passes
`force`. "Allow an app" refuses programs in Temp / Downloads / Public folders. Group Policy rules are read-only.

**Health check & fixes.** Firewall off for a profile (critical on Public), incoming allowed by default, *allow-everything* rules,
RDP / SMB / Telnet / VNC / database ports open to any address, programs in Temp / Downloads allowed in, rules for uninstalled
programs, notifications off, packet logging off, removed Cyber Hub blocks — each with a one-click fix.

**Change watch.** Every `firewall_watch_interval_minutes` (5) Cyber Hub compares the rules and profiles with what it saw last time.
A new **inbound allow** rule (how malware opens a backdoor) is a medium alert — high if it opens RDP / SMB etc. or points into
Temp / Downloads; a block rule switched off is medium; the firewall turned off outside Cyber Hub is **critical**. Its own changes
never alert. 50+ new rules at once (software install, policy import) become one summary alert.

**Packet log.** Turn on *Log dropped packets* (a one-click fix) and the `/log` endpoint reads the end of `pfirewall.log`
(Windows) or `ufw.log` (Linux): drops per hour, who is knocking, which ports, and any address that tried 10+ ports (port scan),
with a **Block** button per source. Reading Windows' log needs the elevated engine.

**Settings:** `firewall_watch_enabled` (on 🔒), `firewall_watch_interval_minutes` (5), `firewall_alert_new_allow_rules` (on 🔒),
`firewall_log_path` ('' = the profile's own log 🔒), `firewall_log_max_mb` (20), `firewall_snapshot_keep` (20 automatic snapshots).

**Other systems.** Linux uses **ufw** (address / port blocks, profile = `all`, no per-program rules). For UI work without touching
your real firewall, start the engine with `CYBERHUB_FIREWALL_BACKEND=memory` (a simulated Windows-like firewall).

Try it: copy `frontend-bridge/firewall-example.html` into `ui/`, run `start_cyberhub_admin.bat`, sign in, open
http://127.0.0.1:8765/firewall-example.html.

## Part 10 endpoints — Network Monitor & Wi-Fi
All under `/api/network` (signed in). 🔒 = Cyber Hub administrator. Fixes that block something go through the Part 9
firewall (same guards; the engine must be elevated to change Windows Firewall).

| Method | Path | Used by |
|---|---|---|
| GET | `/status` | Network card: connection counts, Wi-Fi (name, security rating, signal), LAN (devices, new today, router alert), 0-100 score, unread alerts, LAN scan state |
| GET | `/connections` | every connection + owning program (`pid`, `create_time`, `exe`), `direction` (incoming · outgoing), `scope` (internet · lan · local), service name, risk flags + reasons. Filters: `search`, `state`, `proto`, `scope`, `direction`, `pid`, `flagged`, `include_listening`; `resolve=true` adds host names |
| GET | `/connections/by-process` | one row per program: connections, internet hosts, listening ports, top remote ports, behaviour warnings (port-scan-like, very many hosts) |
| GET | `/listening` | open ports: program, **who can connect** (this PC only · network) and the **firewall's verdict** for that port (blocked · allowed by rule X · open · unknown) |
| GET | `/findings` | everything worth fixing across connections, ports, Wi-Fi and the LAN, with one-click fixes |
| POST | `/findings/{id}/fix` | block the remote address / the incoming port / the program (Part 9), or "It's my new router" 🔒 |
| GET | `/wifi` | current Wi-Fi + rating, nearby networks (strongest per name, open count), saved networks, Wi-Fi findings |
| GET | `/wifi/history` | networks this PC joined (name, BSSID, security, rating, first / last seen) |
| GET | `/lan` | devices on the current network (or `?network_id=` a past one): IP, MAC, vendor, name, type guess, open ports, online, flags; includes **This PC** |
| POST | `/lan/scan` | `{ports: true}` find every device on the current **private** network; GET `/lan/scan` progress · POST `/lan/scan/cancel` |
| GET / PATCH / DELETE | `/lan/devices/{id}` | details · `{label, notes}` (anyone) / `{trusted}` 🔒 · forget 🔒 |
| GET | `/lan/networks` | networks seen (Wi-Fi name or wired subnet), device counts |
| POST | `/lan/networks/{id}/home` | `{home, name?}` mark as Home (new devices = medium alerts, automatic scans allowed) — un-marking is 🔒 |
| POST | `/lan/networks/{id}/accept-gateway` 🔒 | accept a changed router hardware address |
| GET | `/oui` | MAC vendor list status · POST `/oui/import` 🔒 `{text \| path}` (IEEE oui.csv / oui.txt, Wireshark manuf) · POST `/oui/update` 🔒 (downloads the IEEE list, https only) |
| POST | `/watch` | run the background check now (also every `network_watch_interval_minutes`) |
| GET | `/events` | network timeline; poll with `after_id`; POST `/events/ack` · DELETE `/events` 🔒 |
| GET | `/summary` | graphs: connections / internet hosts / flagged over time, alerts per day + kind, top programs, top remote ports, scope + TCP-state donuts |
| WS | `/stream?token=&session=` | every 3 s: live counts, new alerts, LAN scan progress |

**Connection red flags** (each explained in plain words): outgoing to an internet port used by Metasploit (4444), backdoors
(1337 / 31337), IRC botnets (6666-6669 / 6697), Tor (9001 / 9030 / 9050 / 9150), mining pools (3333 / 5555 / 7777 / 14433 /
14444) or SOCKS tunnels (1080), plus your own `network_extra_suspicious_ports`; PowerShell / cmd / mshta / rundll32 and other
LOLBins talking to the internet; programs in Temp / Downloads / Public; Windows system names in the wrong folder; broken
signatures; **someone on the internet connected to your Remote Desktop / SMB / database**. Per program: 30+ half-open
connections at once (port scanner / worm) and more than `network_many_hosts` (150) different internet addresses. Connections to
an address you already blocked are marked `blocked_target`. Cyber Hub's own engine is never flagged.

**Open ports + firewall.** A port bound to `127.0.0.1` is "this PC only" (safe). For anything reachable from the network the
Part 9 firewall answers *would an incoming connection get through?* — using the profile of the network you are on (the most
exposed active profile decides), block-all-incoming, block rules first, then allow rules (program, protocol, port, address
scope), then the default. RDP / SMB / Telnet / VNC / databases that the firewall lets in are **medium**, **high** on Public
Wi-Fi or with the firewall off; if only the firewall keeps them closed they are **low**. Fix = block incoming on that port.

**Wi-Fi check.** WPA3 = excellent · WPA2-AES / Enterprise / WPA2+3 = good · Enhanced Open = fair · WPA2-TKIP = weak (medium) ·
WPA = weak (high) · **Open = high** · **WEP = critical**. Also: a nearby access point with the **same name but weaker / no
security** (evil twin, high), saved networks that **auto-join open hotspots** (medium) or use WEP / WPA. Joining an insecure network
raises one alert per connection. Windows reads `netsh wlan` (English output) — saved Wi-Fi **passwords are never read** (no
`key=clear`). Windows 11 24H2+ only shows Wi-Fi details to apps when *Location services* are on; the API returns that hint.
Linux uses `nmcli`.

**LAN discovery.** Without scanning, the page lists devices from the ARP table (nothing is sent). **Scan network** works only on
private home / office ranges you are connected to (10/8, 172.16/12, 192.168/16; at most 1024 addresses, otherwise the /24 around
this PC — never the internet): one empty UDP packet per address makes Windows learn who is there (ARP), then each device gets a
fixed list of 20 common ports, a NetBIOS name query and a reverse-DNS lookup. Devices get a vendor (built-in list of virtual
machines / Raspberry Pi; import the IEEE list for every vendor), a type guess (router, printer, camera, iPhone, Chromecast, NAS,
Windows PC, Raspberry Pi, virtual machine, phone with a private address…) and flags: **Telnet open (high, Mirai target)**, camera
RTSP (medium), VNC (medium), FTP / MQTT / RDP (low), router admin page HTTP-only (low). The first look and the first full scan
build a baseline quietly; after that a **new device** is an alert (medium on Home networks).

**ARP-spoofing watch.** Cyber Hub remembers your router's hardware address per network. If the router IP suddenly answers from a
different address, that is a **high** alert (someone may be intercepting your traffic) until it goes back or an admin clicks
*It's my new router*. Another IP using the router's hardware address is a medium alert.

**Settings:** `network_watch_enabled` (on 🔒), `network_watch_interval_minutes` (2), `network_alert_new_listeners` (on 🔒),
`network_alert_suspicious` (on 🔒), `network_many_hosts` (150 🔒), `network_extra_suspicious_ports` ([] 🔒),
`network_resolve_hostnames` (off), `network_sample_retention_days` (7), `lan_alert_new_devices` (on 🔒), `lan_arp_watch` (on 🔒),
`lan_auto_scan_minutes` (0 = off; Home networks only, minimum 15), `wifi_alert_insecure` (on 🔒).

**Developer mode.** `CYBERHUB_NETWORK_BACKEND=memory` simulates a home LAN (router, Raspberry Pi, a VM, a Telnet camera, a phone)
and Wi-Fi (`CYBERHUB_WIFI_BACKEND=memory` for Wi-Fi alone); connections stay real.

Try it: copy `frontend-bridge/network-example.html` into `ui/`, run `start_cyberhub_admin.bat`, sign in, open
http://127.0.0.1:8765/network-example.html.

## Part 11 endpoints — Windows Security Posture
The "is this PC set up safely?" section, organised exactly like the Windows Security app. Reading needs a signed-in
session; fixes that **raise** protection are open to anyone signed in, fixes that could **lock someone out** (Remote
Desktop off, built-in Administrator off, removing Defender exclusions), undo, ignore and force need a Cyber Hub
**admin**. Machine-wide settings need the engine started with `start_cyberhub_admin.bat`; per-user ones (file
extensions, AutoPlay, screen lock, PowerShell policy, Store SmartScreen) work without it.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/posture/status` | card: 0–100 score + grade, six section scores, counts, top 5 issues, OS, restart pending `[postureStatus]` |
| GET | `/api/posture/checks?category=&status=pass\|fail\|unknown\|ignored&refresh=` | every check, failing first `[postureChecks]` |
| GET | `/api/posture/checks/{id}` | one check: value, why it matters, evidence, fix or manual steps `[postureCheck]` |
| POST | `/api/posture/checks/{id}/fix` `{confirm, force}` | one-click fix, read back + verified; **428** = show the warning, resend with `confirm` `[fixPostureCheck]` |
| POST | `/api/posture/fix-all` `{categories, min_severity}` | fix every safe issue, report skipped ones + score before/after `[fixAllPosture]` |
| POST / DELETE | `/api/posture/checks/{id}/ignore` `{reason, days}` | accept a risk (admin) / watch it again `[ignorePostureCheck / unignorePostureCheck]` |
| GET | `/api/posture/changes` · POST `/changes/{id}/revert` | every fix with previous values · undo (admin) `[postureChanges / revertPostureChange]` |
| GET | `/api/posture/defender` | Defender versions, definition + scan age, switches, exclusions with risk notes `[defenderStatus]` |
| POST | `/api/posture/defender/update` · `/defender/scan` `{type}` | update definitions · start a Defender quick / full scan |
| GET | `/api/posture/updates` | Windows version + end-of-support date, last install, history, pause, restart `[windowsUpdates]` |
| POST / GET | `/api/posture/updates/search` | ask Windows Update which updates are missing (background) `[searchWindowsUpdates]` |
| GET | `/api/posture/accounts` | local accounts: enabled, admin, Guest / Administrator, password required, last sign-in |
| POST | `/api/posture/open/{target}` | open the right Windows Security / Settings page for a manual fix `[openWindowsSettings]` |
| POST | `/api/posture/watch` · `/rebaseline` | re-check now / new baseline (admin) |
| GET / POST / DELETE | `/api/posture/events` · `/events/ack` · `/events` | alert timeline (after_id polling), acknowledge, clear (admin) |
| GET | `/api/posture/summary?days=30` | graphs: score per day, alerts per day / kind, fixes, section scores `[postureSummary]` |

**What it checks (Windows):**
- *Virus & threat protection* — an antivirus is on (Defender or another product in Security Center), real-time / behaviour / download / script scanning, Tamper Protection, cloud protection, sample submission, PUA blocking, network protection, controlled folder access (optional), definition age, last quick scan, and **dangerous Defender exclusions** (whole drives, Temp, Downloads, AppData, user profiles, PowerShell / cmd, `*.exe`…).
- *Account protection* — UAC on / prompt level / secure desktop, Guest account, built-in Administrator, accounts without a required password, number of administrators, WDigest plain-text passwords, LSA protection, screen lock.
- *Firewall & network protection* — firewall on (read **and fixed through Part 9**), Remote Desktop and how exposed it is (Part 9's real inbound verdict), NLA, Remote Assistance, SMBv1, LLMNR.
- *App & browser control* — SmartScreen for apps / Edge / Store apps, Smart App Control, hidden file extensions, AutoPlay, PowerShell execution policy.
- *Device security* — Secure Boot, TPM (version + ready), Memory integrity, BitLocker on the system drive (weighs more on laptops; Home editions get Device encryption steps), suspended BitLocker, other internal drives.
- *Windows Update & support* — version still supported (Microsoft's end-of-updates dates per edition, e.g. 24H2 Home/Pro ended 2026-10-13), last OS update (Defender definition updates don't count), paused updates, disabled update service, update policy, restart pending.
- *Linux* (read-only advice): Secure Boot, TPM, LUKS root encryption, automatic updates, pending reboot, SSH root / password login, guest session.

**How fixes stay safe:** only allow-listed changes exist (a fixed table of registry values, Defender settings, the two
built-in accounts by SID, `wuauserv`, CurrentUser execution policy) — no API call can name an arbitrary registry path;
every value reaches PowerShell through `$env:CH_*`. Each fix records the previous values, is **read back** afterwards
(Tamper Protection or Group Policy silently refusing a change is reported, and the change is rolled back), a multi-step
fix that fails half-way is rolled back, one fix runs at a time, and any fix can be undone. Guards refuse to disable the
Administrator account you are signed in with or the only administrator, and to switch Remote Desktop off while you or
someone else is connected through it (admin `force` overrides). Policy-managed settings are shown read-only. Settings
that need firmware access or could break drivers (Secure Boot, TPM, Memory integrity, LSA protection, turning BitLocker
on, Tamper Protection) are manual steps with a button that opens the right page.

**Score:** `100 × 100 / (100 + penalty)` (critical 25, high 12, medium 6, low 2) so a neglected PC still shows progress;
any critical issue caps it at 49 (*At risk*), any high at 84. Each section gets its own score (the six tile rings).

**Watch** (every 30 min, `posture_watch_*` settings): the first run records a baseline; afterwards it alerts when a
setting gets **weaker** (pass → fail, e.g. real-time protection switched off = critical) and when a **new Defender
exclusion** appears (high — a classic malware move). Cyber Hub's own fixes and undos never alert.

**Developer mode.** `CYBERHUB_POSTURE_BACKEND=memory` simulates a slightly neglected Windows 11 25H2 laptop (an
exclusion on Downloads, Guest on, WDigest on, UAC never notifies, RDP without NLA, no BitLocker, 52-day-old updates…).

Try it: copy `frontend-bridge/posture-example.html` into `ui/`, run `start_cyberhub_admin.bat`, sign in, open
http://127.0.0.1:8765/posture-example.html.

## Part 12 endpoints — Password Vault & Auditor
Your own encrypted password manager plus a health check of every saved password. Every route needs a signed-in session;
item routes also need the vault **unlocked with the master password** (423 *"Password vault is locked"* otherwise — the
UI shows its vault unlock screen, which is separate from the app lock screen). Each Cyber Hub user has a private vault:
**an administrator can't open anyone else's.**

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/passwords/status` | card: exists / unlocked, items per type, trash, device-bound, auto-lock countdown, last audit, unread alerts `[vaultStatus]` |
| POST | `/api/passwords/setup` `{master_password, hint}` | create the vault → **recovery key, shown once** `[setupVault]` |
| POST | `/api/passwords/unlock` `{master_password}` · `{recovery_key, new_master_password}` | unlock; 401 wrong, **429 + Retry-After** after 5 tries, 503 = device key missing → use the recovery key `[unlockVault / unlockVaultWithRecovery]` |
| POST | `/api/passwords/lock` · GET `/hint` | lock now · show the hint |
| POST | `/api/passwords/master-password` · `/recovery-key` · `/vault/delete` | change master password · new recovery key · destroy the vault (sign-in password + **428** confirm) |
| GET / POST | `/api/passwords/items?q=&type=&folder=&favorite=&trash=&issue=` | list (no secrets: strength, reused, breached, issues per item) · add `{type, data}` → `{item, warnings[]}` `[vaultItems / addVaultItem]` |
| GET / PATCH / DELETE | `/api/passwords/items/{id}?reveal=` | one item (secrets masked unless `reveal=true`) · partial update · trash or `permanent=true` |
| POST / DELETE | `/api/passwords/items/{id}/restore` · `/trash` | restore from / empty the trash |
| GET | `/api/passwords/items/{id}/history` · `/totp` | last 10 passwords · current 2FA code + seconds left `[passwordHistory / vaultTotp]` |
| POST | `/api/passwords/items/{id}/copy` `{field}` · `/clipboard/clear` | copy to the clipboard, auto-wiped, kept out of Win+V history; **501** → browser clipboard `[copyVaultField]` |
| GET / POST | `/api/passwords/folders` · `/folders/rename` | folders with counts · rename / remove |
| POST | `/api/passwords/generate` | random password, EFF passphrase or PIN + entropy + strength (no unlock needed) `[generatePassword]` |
| POST | `/api/passwords/check` `{password, user_inputs, breach}` | strength meter + optional breach check, nothing stored `[checkPassword]` |
| GET | `/api/passwords/audit` | 0–100 vault health + grade, counts, strength distribution, reused groups, every issue `[vaultAudit]` |
| POST / GET | `/api/passwords/audit/breaches` | check all saved passwords against Have I Been Pwned in the background · poll `[checkBreaches]` |
| POST | `/api/passwords/import` `{content \| path, format, password, folder, delete_source}` | CSV from Chrome / Edge / Firefox / Bitwarden / LastPass / 1Password / KeePass(XC) / any url-username-password CSV, or a `.chvault` backup `[importPasswords]` |
| POST | `/api/passwords/export` `{format: chvault \| csv, master_password, export_password, confirm, path}` | encrypted backup for any PC, or plain CSV (**428** until `confirm`) `[exportPasswords]` |
| GET / POST / DELETE | `/api/passwords/events` · `/events/ack` · `/events` | your vault's alerts (after_id polling): wrong passwords, lockout, breaches found, recovery used, plain-text export… |
| GET | `/api/passwords/summary?days=30` | graphs: health per day, weak / reused / breached per day, alerts per day, items by type `[vaultSummary]` |

**How the vault is protected**
- Master password → **scrypt** (N = 2¹⁷, r = 8 ≈ 128 MB, ~0.4 s) → HKDF with a **device pepper** derived from Part 6's
  DPAPI-sealed `vault.key` → key that unwraps a random 256-bit vault key. A copy of `cyberhub.db` can't even be
  brute-forced offline without this Windows user's `vault.key`.
- Every item is **AES-256-GCM** encrypted; the authenticated data binds user + item id + type, so a row copied, swapped or
  edited in the database shows up as *damaged*, never as wrong data. **Titles, user names, URLs, notes and cards are
  encrypted too** — events and the stored audit summary hold counts, never content (a test greps the raw database file).
- **Recovery key** (160 bits, `XXXX-XXXX-…`, shown once) wraps the same vault key and is *not* device-bound — it gets you in
  on a new PC or after reinstalling Windows. Using it forces a new master password and issues a new recovery key.
- The master password must score *Strong* (zxcvbn), be 10+ characters and **differ from your Cyber Hub sign-in password**.
- Unlocked keys live only in memory, per Cyber Hub session, and are wiped after `pv_auto_lock_minutes` unused (default 5),
  when the app locks or signs out (Part 2 now notifies other modules), when the master password changes, and on exit.
- Wrong master passwords: 5 free tries, then 30 s, 60 s, 120 s… up to 30 min. Old vaults are upgraded to the current
  scrypt cost on the next unlock.

**Auditor** — per item and for the whole vault: **breached** (Have I Been Pwned, critical — caps the score at 49),
**reused** (high), **weak / fair** (zxcvbn + Pakistani cities, names, cricket and "786" so *Lahore@786* is called weak, plus
your own user name / site), old (> `pv_old_password_days`), `http://` sites, duplicate accounts, logins without a password,
expired cards.

**Breach checks use k-anonymity:** only the first 5 characters of the password's SHA-1 are sent to
`api.pwnedpasswords.com`, the answer is padded so its size reveals nothing, and the match happens on your PC.
`pv_breach_check`: `off` · `manual` (default — the button) · `auto` (new / changed passwords and a weekly re-check on unlock).

**Clipboard:** on Windows a copied password is marked so it never lands in **Win+V clipboard history** or the cloud
clipboard, and is wiped after `pv_clipboard_clear_seconds` (default 30) — only if it is still the clipboard's content.

Try it: copy `frontend-bridge/passwords-example.html` into `ui/`, sign in, open http://127.0.0.1:8765/passwords-example.html.

## Part 13 endpoints — Data Protection
Four tools that protect the files on your PC. Each one runs as a **background job** with live progress and Cancel —
the POST answers at once with the job, poll `/api/data/jobs/{id}` or listen on `/api/data/stream`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/data/status` · `/health` · `/summary?days=30` | card (features, settings, data-exposure score, running jobs) · score · graphs `[dataStatus / dataSummary]` |
| POST | `/api/data/encrypt` `{paths, mode, password, delete_original, hide_names, save_to_vault, allow_weak}` | encrypt files / folders to `.chx` `[encryptFiles]` |
| POST | `/api/data/decrypt` `{paths, password, destination, conflict, delete_encrypted}` | back to the original names (rename / overwrite / skip), decrypted files are virus-scanned `[decryptFiles]` |
| POST | `/api/data/inspect` · `/verify` `{path, password}` | what a `.chx` is (real name only with the key) · check every block without writing `[inspectEncrypted / verifyEncrypted]` |
| GET | `/api/data/encrypted` | files Cyber Hub encrypted (still on disk or not) |
| POST | `/api/data/shred/preview` · `/shred` `{paths, method, confirm}` | what would be destroyed (SSD warning, hard links, running programs) · shred (**428** until `confirm`) `[shredPreview / shredFiles]` |
| POST / GET | `/api/data/cleaner/analyze` · `/cleaner/report` | measure every privacy category `[analyzePrivacy / privacyReport]` |
| POST | `/api/data/cleaner/clean` `{categories, secure, confirm}` | clean the ticked categories (Recycle Bin / cookies: **428** until `confirm`) `[cleanPrivacy]` |
| POST / GET | `/api/data/finder/scan` `{paths, types}` · `/finder/roots` | search Documents, Desktop, Downloads (+ `dp_finder_paths`) for sensitive data `[findSensitiveFiles]` |
| GET | `/api/data/finder/findings?status=&severity=&type=&q=` · `/{id}` | findings with **masked** samples, advice and actions `[sensitiveFindings]` |
| POST | `/api/data/finder/findings/{id}/encrypt` · `/shred` · `/ignore` · `/unignore` | one-click fixes `[encryptFinding / shredFinding / ignoreFinding]` |
| GET / POST | `/api/data/jobs?kind=` · `/jobs/{id}` · `/jobs/{id}/cancel` | running + past jobs · progress · cancel (stops after the current file) `[dataJobs / waitDataJob]` |
| GET / POST / DELETE | `/api/data/events` · `/events/ack` · `/events` | alerts: sensitive files found, wrong passwords, decrypted threat, failed jobs… |
| WS | `/api/data/stream?token=&session=` | live `{jobs, events, unacknowledged}` every second `[streamData]` |

**Encryption (`.chx`)** — AES-256-GCM in 1 MiB authenticated chunks (same design as the quarantine vault: any edited,
swapped or cut block is detected). *Password mode*: scrypt (N = 2¹⁷, r = 8) → a per-file key (HKDF with a random
per-file salt), opens on any PC with Cyber Hub; the password must be 8+ characters and *Good* on the strength meter
(or `allow_weak`), and can be saved straight into your **Part 12 password vault** (`save_to_vault`, needs the vault
unlocked — checked before any file is touched). *Device mode*: no password, tied to this Windows account through Part 6's
DPAPI-sealed key — lost if Windows is reinstalled. The real file name is stored **encrypted inside** the file
(`hide_names` gives the `.chx` a random name). Every file is **decrypted again and compared (SHA-256) before the original
is shredded / deleted / kept**, so a crash or a full disk never leaves you with neither copy.

**Shredder** — `zero`, `random` (default), `dod3` (0x00, 0xFF, random), `random3`; every pass flushed to disk, the last
one read back (`dp_shred_verify`), then truncated, renamed to a random name twice and deleted. Links / junctions are
removed, never followed; files with extra hard links are skipped unless `allow_hardlinks`. *Honest limit:* on SSDs
wear-levelling can keep old copies of blocks — the preview says so and BitLocker is the real fix.

**Privacy cleaner** — Temporary files (only older than `dp_cleaner_temp_min_age_hours`, default 24 h), Recycle Bin,
thumbnail cache, recent-files list, error reports / crash dumps, DNS cache; for Chrome, Edge, Brave, Vivaldi, Opera,
Chromium and Firefox (every profile): cache, history (incl. downloads list — Firefox history is cleared inside
`places.sqlite` so **bookmarks stay**) and cookies. A browser that is open is skipped ("Close Chrome first"). Nothing
outside the listed folders is ever deleted, and Cyber Hub's own folders are excluded.

**Sensitive-file finder** — private keys / `.pfx` / PuTTY keys, plain-text **password exports** (critical), API keys
(AWS, GitHub, Slack, Stripe, Google, OpenAI, `api_key = …`), passwords written in files, **card numbers** (brand +
Luhn), **Pakistani CNICs**, IBANs (mod-97 checked), US SSNs, crypto wallets, big contact lists — in text, Office
(.docx / .xlsx / .pptx / .odt) and PDF files. Only masked samples are stored (`35•••-•••••••-1`, `•••• 1111`).
Ignored files stay ignored until they change. Encrypting / shredding a file (from anywhere) closes its finding.
**Data-exposure score** 0–100 (critical caps it at 49, high at 84) feeds Part 18.

**Plays well with the other parts** — Part 7 real-time protection is told about Cyber Hub's own writes, so encrypting a
big folder doesn't trigger the ransomware burst alert and `.chx` output isn't scanned (decrypted files still are);
Part 5 scans decrypted files; jobs never work on overlapping paths (409); interrupted jobs are cleaned up at the next
start; programs running from a file block it from being encrypted / shredded.

Try it: copy `frontend-bridge/data-example.html` into `ui/`, sign in, open http://127.0.0.1:8765/data-example.html.

## Part 14 endpoints — Website / Developer Scanner
Checks **your websites** (HTTPS, headers, cookies, leaked files, outdated software, open ports) and **your code
projects** (vulnerable npm / PyPI / Composer packages, secrets in code, risky settings). Scans are background jobs:
the POST answers at once, poll `/api/web/jobs/{id}` or listen on `/api/web/stream`, then read `/api/web/scans/{id}`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/web/status` · `/health` · `/summary?days=30` | card · Part 18 score · graphs `[webStatus / webHealth / webSummary]` |
| POST | `/api/web/scan` `{target, checks, confirm_owner, save, monitor, label}` | scan a website (`example.com`, `https://site.pk/shop`, `localhost:5173`) `[scanWebsite]` |
| POST | `/api/web/project/scan` `{path, online, secrets, save, monitor}` | scan a code folder `[scanProject]` |
| POST | `/api/web/packages/check` `{ecosystem, name, version}` | is one package version safe? `[checkPackage]` |
| GET / POST | `/api/web/jobs` · `/jobs/{id}` · `/jobs/{id}/cancel` | running + past scans · progress · cancel `[webJobs / waitWebScan]` |
| GET / DELETE | `/api/web/scans?kind=&target_id=` · `/scans/{id}` | stored reports (findings + advice, passed checks, grade per category, changes since last scan) `[webScans / webScan]` |
| GET / POST / PATCH / DELETE | `/api/web/targets` · `/targets/{id}` · `/targets/{id}/history` · `/targets/{id}/scan` | saved sites / projects, monitoring on/off, "I own this site", score history `[webTargets …]` |
| GET / POST | `/api/web/dev-servers` · `/dev-servers/{port}/block` · `/dev-servers/{port}/scan` | dev servers on this PC reachable from the network → one-click Part 9 firewall block `[devServers / blockDevServer]` |
| GET / POST / DELETE | `/api/web/vulndb` · `/vulndb/import` `{path \| download}` (admin) | offline copy of the OSV vulnerability database `[vulnDbStatus / importVulnDb]` |
| GET / POST / DELETE | `/api/web/events` · `/events/ack` · `/events` | alerts: critical problems, new issues on monitored targets, grade drops, certificates expiring, site down, dev servers exposed |
| WS | `/api/web/stream?token=&session=` | live `{jobs, events, unacknowledged}` `[streamWeb]` |

**Website checks** — *HTTPS & certificate*: trusted chain, expiry (critical when expired, high ≤ 7 days, medium ≤
`web_cert_warn_days`), wrong host name, self-signed, SHA-1 / weak keys, which TLS versions are accepted (1.0 / 1.1 =
warning, 1.3 missing = low), weak ciphers, http → https redirect. *Security headers*: HSTS, Content-Security-Policy
(`unsafe-inline`, `unsafe-eval`, wildcards), clickjacking, `nosniff`, Referrer-Policy, Permissions-Policy, version
leaks (`Server`, `X-Powered-By`), CORS (sends a made-up `Origin` and checks whether it is reflected, with credentials
= high). *Cookies*: Secure / HttpOnly / SameSite (names only — values are never stored). *Page content*: mixed
content, forms posting over HTTP, password boxes on HTTP pages, CDN scripts without `integrity`, scripts from the
hijacked polyfill.io / bootcss / staticfile CDNs (critical). *Debug pages* on the home page and on a 404: Flask /
Werkzeug debugger (critical), Django `DEBUG = True`, Laravel Whoops / Ignition, Symfony, Rails, Python / Node stack
traces, PHP warnings. *Software*: CMS / framework / server / CDN fingerprint (WordPress, Laravel, Django, Next.js,
Shopify, nginx, IIS …) and known-vulnerable versions of jQuery, jQuery UI, Bootstrap, AngularJS, Lodash, Moment,
Handlebars, Vue 2 (with CVEs and the fixed version), end-of-life PHP, Apache 2.2 and IIS.

**Active checks — only on sites you own.** *Exposed files*: `/.git/`, `.env`, config backups, SQL dumps, backup
zips, `.htpasswd`, phpinfo, Apache server-status, `web.config`, editor SFTP settings, private keys, Spring actuator,
Laravel Ignition, ELMAH, open `crossdomain.xml`, WordPress user list / XML-RPC, directory listing, `robots.txt`
hints, `security.txt`. Each file is recognised by its **content** and compared with the site's own 404 page, so sites
that answer "200 OK" for everything don't produce false alarms. *Open ports*: a fixed list of 40 well-known ports
(databases, Redis, Docker API, Node debugger, RDP, SMB, Telnet …), connect + greeting only; OpenSSH versions affected
by regreSSHion are flagged. These run automatically for this PC and your own network; for internet sites tick
**"I own / manage this site"** (`confirm_owner`) — it is remembered with the saved site. Without it they are skipped
(or **428** if you asked for them).

**Project scan** — lockfiles for npm (`package-lock.json` v1–v3, `yarn.lock` classic + berry, `pnpm-lock.yaml`),
Python (`Pipfile.lock`, `poetry.lock`, `uv.lock`, `requirements*.txt` with `-r` includes) and PHP (`composer.lock`);
without a lockfile `package.json` / `composer.json` ranges are used and marked *approximate*. Packages are checked
against **OSV** (osv.dev: GitHub advisories, PyPA, npm, Packagist and malicious-package reports) using OSV's own
version-range rules, with the fixed version to upgrade to. Severity comes from the advisory, otherwise a CVSS 3.x
score computed from the vector; dev-only packages count one step lower; **malicious packages are always critical**.
Only package **names + versions** are sent (`web_dep_online`, answers cached `web_osv_cache_days`); an admin can
import / download OSV's `all.zip` for fully offline checks. *Secrets in code* reuse **Part 13's** finder rules (AWS /
GitHub / Stripe / OpenAI keys, private keys, passwords) — values masked, `node_modules` / venvs skipped, test /
example files lowered. *Settings*: `.env` not in `.gitignore`, Laravel `APP_DEBUG=true` in production, Django
`DEBUG = True` / hard-coded `SECRET_KEY`, Flask `debug=True`, npm tokens in `.npmrc`, missing lockfiles, unpinned
requirements.

**Grades** — score 100·100/(100+penalty), any critical caps it at 49 (F), any high at 84 (B); grades A+ … F overall
and per category. Every finding has *why* and *what to do*; passed checks are listed too.

**Monitoring** — saved targets with `monitor` are re-scanned every `web_monitor_interval_hours` (default 24 h) and
alert on new problems, a worse grade, certificates expiring (once per stage) and sites going down (once a day).

**Plays well with the other parts** — *Part 10* lists the listening ports and *Part 9* gives the real firewall
verdict, so the scanner can say "your Vite / Django / Jupyter dev server — or the Node debugger (critical) — can be
opened from other devices"; the fix is a normal Part 9 port block (removable in the firewall page). *Part 13*'s
sensitive-file rules find secrets in projects. `health()` feeds Part 18, `web_events` feed Part 17.

Try it: copy `frontend-bridge/web-example.html` into `ui/`, sign in, open http://127.0.0.1:8765/web-example.html.

## Part 15 endpoints — Threat Intelligence
"Is this link / IP / domain / e-mail / file hash dangerous?" — answered **offline first** from free threat feeds,
your own block list, the antivirus signatures and a phishing analyser; optionally confirmed online. Also watches this
PC's live internet connections against the feeds every minute.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/intel/status` · `/health` · `/summary?days=30` | card · Part 18 score · graphs `[intelStatus / intelHealth / intelSummary]` |
| POST | `/api/intel/check` `{value, online, deep, full_url}` | verdict **malicious / suspicious / low_risk / clean / unknown**, 0–100 score, reasons, feed matches, phishing findings, one-click actions `[checkIndicator]` |
| POST | `/api/intel/check/bulk` `{text, online}` | every indicator in a pasted e-mail / report / chat (≤ 500) `[checkText]` |
| GET / DELETE | `/api/intel/checks` | your recent checks (query strings never stored) |
| GET | `/api/intel/iocs?q=&type=&feed=&threat=&category=` | search the local intel database (exact for indicators, text for malware families / tags) `[searchIocs]` |
| GET | `/api/intel/hunt?value=` | **was it ever on this PC?** antivirus cache + detections, quarantine, downloads (Mark of the Web), network / firewall / web events, saved sites, activity log, live connections `[huntIndicator]` |
| GET / POST / PATCH / DELETE | `/api/intel/feeds` · `/feeds/{id}` · `/feeds/refresh` · `/jobs/{id}` | feed list + status, add your own https feed (admin), switch on (anyone) / off (admin), update now (job) `[intelFeeds / refreshFeeds / waitFeedRefresh / addFeed]` |
| GET / POST | `/api/intel/blocklist` · `/blocklist/remove` (admin) · `/import` · `/export?format=csv\|txt\|stix\|json` | your own block list; import lists / CSV / hosts files / STIX 2.x; export `[addToBlocklist / importIocs / downloadIntelExport]` |
| GET / POST / DELETE | `/api/intel/allowlist` (adding = admin) | false positives that must never be flagged (covers sub-domains) `[allowIndicator]` |
| POST | `/api/intel/block-ip` `{ip, minutes}` | one-click firewall block through **Part 9** (in + out) `[blockAddress]` |
| GET / PUT | `/api/intel/providers` · `/providers/abuseipdb/key` (admin) | online services and their keys `[intelProviders / setAbuseIpdbKey]` |
| POST | `/api/intel/watch/run` | match live connections now `[runIntelWatch]` |
| GET / POST / DELETE | `/api/intel/events` · `/events/{id}/block` · `/events/ack` | alerts: programs talking to known-bad servers, files / downloads that new intel now flags, auto-blocks, feed problems `[intelEvents / blockFromAlert]` |
| WS | `/api/intel/stream?token=&session=` | live `{jobs, events, unacknowledged}` `[streamIntel]` |

**Built-in feeds** (free, reviewed 2026-11-13; refreshed every `intel_update_hours`, default 6 h, with ETag so
unchanged lists cost nothing): **Feodo Tracker** botnet C2 IPs · **URLhaus** malware download links · **ThreatFox**
IPs / domains / URLs / hashes of named malware · **Spamhaus DROP** v4 + v6 hijacked networks (JSON format) ·
**OpenPhish** live phishing pages · **Emerging Threats** compromised hosts · **Tor exit nodes** (informational, off by
default). abuse.ch now requires a free **Auth-Key** (https://auth.abuse.ch/): it is the **same key you enter for
MalwareBazaar in Part 8** (`/api/lookup/keys`) — enter it once and ThreatFox switches on, URLhaus sends it too.
Without it ThreatFox shows *needs key* (it is never even asked). A broken / empty / oversized download never wipes
the last good copy (`intel_max_feed_mb`). Custom feeds must be **https://** on a public address and can't redirect
into your network.

**How a check works** — the indicator is cleaned (`hxxps://evil[.]com`, `1.2.3[.]4`, `bob[@]x.com`, IDN → punycode)
and matched: exact values, **IP ranges** (CIDR), parent domains (`login.evil.com` → `evil.com`), malware links hosted
on the same host (not on shared hosts like Google Docs / GitHub / Dropbox, where one bad link says nothing about the
rest), e-mail domains, and for hashes Part 5 signatures + Part 8's cached cloud verdicts. The **phishing analyser**
spots brand names in the wrong place (`paypal.com.secure-login.xyz`), look-alike spellings (`paypa1`, `rnicrosoft`),
mixed-alphabet homoglyphs (Cyrillic `а` in `pаypal.com`), `@` tricks, IP-address hosts, shorteners, risky TLDs,
dynamic-DNS / free hosting, executables in links and redirect parameters — with 80+ brands incl. Pakistani banks,
wallets and government sites (HBL, Meezan, JazzCash, Easypaisa, NADRA, FBR …). **Deep check** opens the page
read-only through Part 14's `web_probe` (no scripts, no cookies, can't be redirected into your LAN): redirect chain
(every hop checked), fake login pages (brand in the title on a non-brand site, password forms posting elsewhere,
assets copied from the real brand), downloads disguised as links, certificate age, domain age (RDAP). Score =
strongest signal, +10 when independent sources agree; verdict ≥ 80 malicious, ≥ 50 suspicious, ≥ 25 low risk.

**Online (off by default, `intel_online_lookup`)** — only the indicator is sent; private / local addresses never
are; URL query strings (reset tokens!) are stripped unless `full_url`. **VirusTotal** uses Part 8's key **and its
rate limit** (one shared budget), **abuse.ch** URLhaus + ThreatFox use the same Auth-Key, **AbuseIPDB** has its own
key (1,000 checks/day free). Answers cached `intel_cache_hours`. Hashes go through Part 8's lookup (VirusTotal +
MalwareBazaar), so a malicious answer also becomes a local signature.

**Plays well with the other parts** — *Part 10*: every `intel_watch_interval_seconds` the internet connections are
matched (exact IPs, DROP ranges, malware-hosting IPs), alerts name the program + PID, once a day per address and
program. *Part 9*: one-click block from an alert or a check, or automatic with `intel_auto_block` = `c2` (exact
botnet-C2 matches) / `high` (admin setting). *Part 5*: feed hashes become antivirus signatures (`source intel:<feed>`,
removed when the feed is switched off, never touching your own or built-in signatures). *Retro-hunt*: after every
feed update (and when you add to your block list) files already hashed on this PC and files downloaded from sites
that are now listed raise an alert with a "scan it" fix. *Part 14*: deep checks reuse its safe fetcher; the hunt
searches its saved sites. `health()` feeds Part 18, `intel_events` feed Part 17.

Try it: copy `frontend-bridge/intel-example.html` into `ui/`, sign in, open http://127.0.0.1:8765/intel-example.html.

## Part 16 endpoints — Social & Platform Accounts
Keep a list of the accounts you use (Google, Facebook, Instagram, WhatsApp, LinkedIn, YouTube, GitHub, Fiverr, Upwork,
JazzCash, Easypaisa, VS Code, Chrome … **55 platforms**, or any site), see how well each one is protected, which
account can take over which, whether your e-mail addresses or the sites you use were breached, and whether a link
"from Facebook" really is from Facebook.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/platforms/status` · `/health` · `/summary?days=30` | card · Part 18 score · graphs `[platformsStatus / platformsHealth / platformsSummary]` |
| GET | `/api/platforms/catalog` · `/catalog/{key}` | every platform: official domains, 2FA + recovery options, security-page links, tips, the site's breaches `[platformCatalog]` |
| GET / POST | `/api/platforms/accounts` `{platform, label, handle, email, phone_last4, notes, importance, custom_name, custom_domain, recovery_account_id, sso_account_id, vault_item_id}` | your accounts, worst first, with an overview score `[platformAccounts / addPlatformAccount]` |
| GET / PATCH / DELETE | `/api/platforms/accounts/{id}` | checklist (who answered each item: you / vault / github), issues, recovery chain, breaches `[platformAccount]` |
| PUT · POST | `/accounts/{id}/checklist` `{items:{two_factor:"done"…}}` · `/accounts/{id}/reviewed` | tick items · "I just checked devices / apps / keys" `[setPlatformChecklist / markPlatformReviewed]` |
| GET · POST | `/accounts/{id}/vault-matches` · `/accounts/{id}/vault-link` `{item_id \| create, password}` | link to (or create) the **Part 12** vault login `[platformVaultMatches / linkPlatformVault]` |
| POST / DELETE | `/accounts/{id}/github` `{token}` · `/github/sync` | connect GitHub with a **read-only** token → real 2FA state + SSH key ages `[connectGithub / syncGithub]` |
| GET · POST | `/api/platforms/recovery-graph` · `/discover` `{sources:["vault","apps"], create}` | who can reset whom · find accounts in your vault / apps running on this PC `[platformRecoveryGraph / discoverPlatforms]` |
| POST | `/api/platforms/check-link` `{value, platform, deep}` | **"is this really from Facebook?"** official-domain check + Part 15 feeds + phishing analyser `[checkPlatformLink]` |
| GET / POST / PATCH / DELETE | `/api/platforms/emails` · `/emails/{id}?reveal=` · `/emails/suggest` · `/emails/{id}/ack` | monitored e-mail addresses + their breaches, what leaked and what to do `[platformEmails / addPlatformEmail …]` |
| POST · GET | `/api/platforms/emails/check` `{ids}` · `/jobs/{id}` | breach check now (background job) `[checkPlatformEmails / waitPlatformJob]` |
| GET · POST | `/api/platforms/breaches?q=&domain=` · `/breaches/refresh` | the public Have I Been Pwned breach list `[platformBreaches / refreshBreachList]` |
| GET / PUT | `/api/platforms/providers` · `/providers/hibp/key` (admin) | breach providers + the HIBP API key `[platformProviders / setHibpKey]` |
| GET · POST | `/api/platforms/extensions?refresh=` · `/extensions/scan` `{key}` | browser + code-editor extensions with a risk score · antivirus-scan one `[platformExtensions / scanExtension]` |
| GET / POST / DELETE | `/api/platforms/events` · `/events/ack` | alerts: e-mail breaches, breached sites you use, GitHub 2FA off / old SSH keys, weak recovery accounts, reviews due, new risky extensions `[platformEvents / ackPlatformEvents]` |
| WS | `/api/platforms/stream?token=&session=` | live `{job, events, unacknowledged}` `[streamPlatforms]` |

**Accounts & checklist** — each platform's checklist comes from what it actually offers (reviewed 2026-11-13):
2FA, an app / passkey / security key instead of SMS (SIM-swap warning), passkey, backup codes, recovery e-mail /
phone, sign-in alerts, devices, connected apps, SSH keys / tokens, privacy, mail forwarding rules (Gmail / Outlook),
and "password changed after this site's breach". **Facts beat ticks**: the unlocked **Part 12 vault** tells it whether
the password is reused / weak / breached and whether a 2FA code is saved; **GitHub's own API** says whether 2FA is on
and how old your SSH keys are; the breach list says when the site lost passwords. Review items go stale after
`platform_review_days` (180) and a reminder comes once a month. Score per account = weighted checklist, minus issues,
critical cap 49 / high cap 84 (like every other section); overall = weighted by importance.

**Recovery chain** — accounts signed up with `you@gmail.com` are linked to your Google account automatically, and
YouTube / Gmail / Meet / Chrome to the Google login (VS Code → GitHub, Teams / Outlook / Edge → Microsoft). An e-mail
account that can reset others but has no 2FA is a **critical** issue and a monthly alert — it is the key to
everything else.

**Breach monitoring** — the **public HIBP breach list** downloads in the background (no personal data is sent) and
warns you when a site you use is breached. Your **e-mail addresses** are only sent when you press *Check* (default
`platform_breach_check = manual`; `auto` re-checks every `platform_breach_interval_hours`, admin setting):
**XposedOrNot** (free, no key) or **Have I Been Pwned** (paid API key, used first when saved). Breaches of the very
site an account is on (your LinkedIn e-mail in the LinkedIn breach) are **critical** until you acknowledge them.
Breach data: Have I Been Pwned (CC BY 4.0) / XposedOrNot — show the `attribution` the API returns.

**Privacy** — handle, e-mail, phone ending (only the last 2–4 digits are accepted) and notes are sealed with
AES-256-GCM under a key derived from Part 6's DPAPI-protected `vault.key`; e-mails are de-duplicated with an HMAC,
listed masked (`sy•••@gmail.com`). Vault links store only flags (reused / weak / 2FA saved), never titles or
passwords, and reading them never keeps the vault from auto-locking. The GitHub token is encrypted the same way,
only **GET** requests are ever made, and tokens with write scopes (`repo`, `delete_repo`, `admin:*` …) are refused
unless you insist.

**Extensions** — Chrome / Edge / Brave / Vivaldi / Chromium / Firefox and VS Code / Insiders / VSCodium / Cursor /
Windsurf: each extension gets an explainable risk score (every site, cookies, traffic interception, native programs,
debugger, proxy; unpacked / side-loaded / unsigned; `.vsix` installs, "starts with every window"). New medium / high
risk extensions raise an alert; one click scans the extension's folder with the **Part 5** antivirus. Nothing is ever
changed — the response tells you where to remove it (`chrome://extensions`, …).

**Plays well with the other parts** — *Part 15*: link / sender checks run through the threat-intel feeds and phishing
analyser (and appear in its history). *Part 12*: evidence, discovery from vault logins, "create vault login".
*Part 6*: device key for sealing. *Part 5*: extension scans. *Part 2*: your Cyber Hub e-mail is suggested for
monitoring; removing a user removes their accounts. `health()` feeds Part 18, `platform_events` feed Part 17.

Try it: copy `frontend-bridge/platforms-example.html` into `ui/`, sign in, open http://127.0.0.1:8765/platforms-example.html.

## Part 17 endpoints — Scheduler & Notifications
| Method | Path | What |
|---|---|---|
| GET | `/api/notifications` | inbox (`status` open / unread / dismissed / all, `source`, `severity`, `min_severity`, `search`, `after_id`) |
| GET | `/api/notifications/summary` · `/status` | unread by severity, per source / day · toast backend, quiet hours, sources |
| POST | `/api/notifications/read` · `/unread` · `/dismiss` · `/collect` · `/test` | mark / pull now / test toast |
| DELETE | `/api/notifications` | clear (`dismissed_only`); shared alerts need an admin |
| WS | `/api/notifications/stream` | new notifications + unread count |
| GET | `/api/scheduler/status` · `/actions` · `/schedules` · `/schedules/{id}` · `/upcoming` · `/runs` | |
| POST · PATCH · DELETE | `/api/scheduler/schedules[/{id}]` | create / change / delete (admin) |
| POST | `/api/scheduler/schedules/{id}/run` | run now (admin) |

## Part 18 endpoints — Security Score & Dashboard
| Method | Path | What |
|---|---|---|
| GET | `/api/dashboard` | everything the front page shows, in one call |
| GET | `/api/score` · `/api/score/history` · `/api/score/recommendations` | score with areas + reasons · history · what to fix (each with its one-click API call) |
| WS | `/api/dashboard/stream` | score, tiles, unread count and live stats every few seconds |

## Part 19 endpoints — Reports, Export & Backup
| Method | Path | What |
|---|---|---|
| GET · POST | `/api/reports` | list · create `{type, format: pdf/html/csv/json, days}` |
| GET | `/api/reports/{id}/download` · `/preview` · `/types` · `/status` | |
| GET | `/api/reports/logs/export` | diagnostics .zip (admin) |
| GET · POST | `/api/backup` | list · create `{mode: password/device, password?, include_quarantine?, destination?}` (admin) |
| POST | `/api/backup/verify` · `/restore` | check a backup · stage a restore (`confirm: true`; applied at next start) |
| DELETE | `/api/backup/restore` | cancel a staged restore |
| GET · POST | `/api/backup/settings/export` · `/settings/import` | settings as JSON |

## Part 20 endpoints — Desktop app
| Method | Path | What |
|---|---|---|
| GET | `/api/about` | version, developer, components |
| GET | `/api/desktop/status` | window / tray / packaged, start-up entry, data folder |
| PUT | `/api/desktop/autostart` | `{enabled}` — start with Windows |
| POST | `/api/desktop/pick` · `/show` · `/activate` · `/restart` · `/quit` | native file dialog, window control |

## Security design
- Listens on **127.0.0.1 only** — never reachable from the network.
- Per-install **API token** (`X-CyberHub-Token`), compared in constant time; any other website open in your browser can't use the engine.
- Data in `%LOCALAPPDATA%\CyberHub\` (database, logs, token, quarantine, reports).
- Quarantine vault: per-item AES-256-GCM keys wrapped by a DPAPI-sealed master key (`vault.key`); the vault folder is never scanned.
- Real-time protection never watches its own data folder; lowering protection (off, pause, folders, exclusions, auto-quarantine, rules, heuristics) needs an admin.
- Online lookup is off by default and sends hashes only; API keys are AES-GCM encrypted with the vault master key and never returned by the API.
- Firewall changes pass every user value (program path, IP, port, rule id) to PowerShell through environment variables, never inside the script text; lowering firewall protection needs an admin, and Windows itself needs the engine elevated.
- The LAN scan only touches private networks you are connected to, with a fixed port list (no user-supplied targets or ports); reading Wi-Fi never reads saved passwords; network fixes reuse the Part 9 firewall guards.
- Security posture fixes only use an allow-list of settings (no arbitrary registry paths), pass values through environment variables, are verified, rolled back on failure and can be undone; risky ones need an admin and a confirmation.
- Data protection refuses Cyber Hub's own folders, operating-system / program folders, whole drives and your home folder; encrypted files are verified before originals go; the finder stores masked samples only; file passwords are never logged or stored.
- Password vault: zero-knowledge at rest (scrypt + device pepper + AES-256-GCM per item, titles included), per-user vaults, keys only in memory with auto-lock, k-anonymity breach checks, clipboard kept out of Win+V history.
- Website scanner: only http(s) addresses, never sends credentials or cookies, runs no scripts, size / redirect / request limits; DNS is resolved once and connections are pinned to that address; link-local / cloud-metadata addresses are refused and a public site can't redirect the scanner into your own network; exposed-file and port checks only run on this PC, your network, or sites you confirmed you own; reports never store page bodies or cookie values; dependency checks send only package names + versions.
- Threat intelligence: offline first; online lookups are opt-in, send only the indicator (never private / local addresses, URL query strings only on request); feed downloads use verified TLS with size caps and keep the last good copy; custom feeds must be https on a public address; the abuse.ch / AbuseIPDB keys are vault-encrypted and never returned; allow-listing and switching feeds / watching off need an admin; pages are opened read-only through the Part 14 fetcher.
- Platform accounts: handles / e-mails / phone endings / notes sealed with a device-derived key, e-mails sent to a breach provider only on request (or the admin's `auto` setting), GitHub connected read-only with an encrypted token.
- Notifications never contain secrets; toasts get their text through environment variables, never inside the script.
- Scheduled jobs that change things are created by admins only; cookie / history cleaning always needs a click.
- Reports and diagnostics contain no passwords, vault items, keys, tokens or full monitored e-mail addresses.
- Backups are encrypted and authenticated end to end (a single flipped byte is refused); the vault key inside a portable backup is wrapped under your backup password; restores keep the replaced data as a safety copy.
- The desktop app binds the engine to 127.0.0.1 only, runs as a normal user, and asks Windows for administrator rights only when you choose to.
- Versioned DB migrations: later parts upgrade your data without wiping it.

## Project layout
```
CyberHub.pyw            desktop launcher (window + tray + engine)          run.py  engine only
start_cyberhub.bat      start from source        start_cyberhub_admin.bat   same, as administrator
build_windows.bat       build CyberHub.exe (+ installer)
packaging/              CyberHub.spec (PyInstaller) · CyberHub.iss (Inno Setup) · version_info.txt
cyberhub/
  config.py   database.py   logger.py   security.py   main.py   desktop_app.py
  routers/    core · account · system · monitor · processes · scanner · quarantine · realtime · rules · firewall
              network · posture · passwords · data · web · intel · platforms · notifications · scheduler
              dashboard · reports · desktop · activity · settings
  services/   (Parts 1-16 as before) + notifications · scheduler · security_score · reports · pdf_writer
              backup · desktop
  data/       eff_large_wordlist.txt (passphrases, CC BY 3.0 US - EFF)
  rules/      built-in YARA rule pack (*.yar)
ui/                     the app's interface (index.html + assets/)
frontend-bridge/        cyberhub-api.js (for your own UI) + one example page per part
tests/                  test_part1.py ... test_part20_desktop.py
```

---
<sub>Cyber Hub · Developed by Syed Muhammad Tayyab</sub>

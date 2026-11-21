<!-- ============================================================
     Cyber Hub — README
     Developed by Syed Muhammad Tayyab
     ============================================================ -->

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:050b18,50:1d4ed8,100:22d3ee&height=190&section=header&text=Cyber%20Hub&fontSize=64&fontColor=ffffff&fontAlignY=36&desc=Developed%20by%20Syed%20Muhammad%20Tayyab&descSize=19&descAlignY=58&animation=fadeIn" alt="Cyber Hub — Developed by Syed Muhammad Tayyab" width="100%"/>

<img src="docs/assets/banner.svg" alt="Cyber Hub banner" width="100%"/>

<a href="#-features">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=21&duration=2600&pause=700&color=22D3EE&center=true&vCenter=true&width=760&lines=One+desktop+app+for+your+whole+PC's+security;Antivirus+%E2%80%A2+Real-time+%E2%80%A2+Firewall+%E2%80%A2+Wi-Fi+%E2%80%A2+Hardening;Password+vault+%E2%80%A2+Encryption+%E2%80%A2+Shredder+%E2%80%A2+Cleaner;Threat+intel+%E2%80%A2+Website+scanner+%E2%80%A2+Account+protection;Scheduler+%E2%80%A2+Reports+%E2%80%A2+Encrypted+backups;Runs+100%25+on+your+PC+%E2%80%94+no+cloud+account" alt="Typing SVG"/>
</a>

<br/>

<!-- status -->
<img src="https://img.shields.io/badge/version-1.0.0-4f8cff?style=for-the-badge&labelColor=0b1220" alt="version"/>
<img src="https://img.shields.io/badge/build-20%20%2F%2020%20parts-34d399?style=for-the-badge&labelColor=0b1220" alt="parts"/>
<img src="https://img.shields.io/badge/tests-604%20passing-22c55e?style=for-the-badge&labelColor=0b1220&logo=pytest&logoColor=white" alt="tests"/>
<img src="https://img.shields.io/badge/license-MIT-a78bfa?style=for-the-badge&labelColor=0b1220" alt="license"/>

<!-- platform -->
<img src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6?style=for-the-badge&logo=windows11&logoColor=white" alt="Windows"/>
<img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
<img src="https://img.shields.io/badge/FastAPI-engine-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/>
<img src="https://img.shields.io/badge/SQLite-local%20data-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite"/>

<!-- security -->
<img src="https://img.shields.io/badge/AES--256--GCM-encryption-0ea5e9?style=flat-square&labelColor=0b1220" alt="AES"/>
<img src="https://img.shields.io/badge/scrypt-key%20derivation-0ea5e9?style=flat-square&labelColor=0b1220" alt="scrypt"/>
<img src="https://img.shields.io/badge/DPAPI-sealed%20keys-0ea5e9?style=flat-square&labelColor=0b1220" alt="DPAPI"/>
<img src="https://img.shields.io/badge/YARA-rules-f97316?style=flat-square&labelColor=0b1220" alt="YARA"/>
<img src="https://img.shields.io/badge/listens%20on-127.0.0.1%20only-34d399?style=flat-square&labelColor=0b1220" alt="loopback"/>
<img src="https://img.shields.io/badge/online%20lookups-opt--in-34d399?style=flat-square&labelColor=0b1220" alt="opt-in"/>
<img src="https://img.shields.io/badge/UI-offline%2C%20no%20CDN-a78bfa?style=flat-square&labelColor=0b1220" alt="offline"/>

<br/><br/>

**[✨ Features](#-features)** &nbsp;•&nbsp;
**[🖼️ Gallery](#️-gallery)** &nbsp;•&nbsp;
**[🏗️ Architecture](#️-architecture)** &nbsp;•&nbsp;
**[🚀 Getting started](#-getting-started)** &nbsp;•&nbsp;
**[🔐 Security design](#-security-design)** &nbsp;•&nbsp;
**[🗺️ Roadmap](#️-roadmap)** &nbsp;•&nbsp;
**[❓ FAQ](#-faq)** &nbsp;•&nbsp;
**[👨‍💻 Developer](#-developer)**

<img src="docs/assets/divider.svg" width="100%" alt=""/>

</div>

<details>
<summary><b>📑 Table of contents</b> (click to open)</summary>

<br/>

1. [About the project](#-about-the-project)
2. [Highlights](#-highlights)
3. [Features — all 20 parts](#-features)
4. [Gallery](#️-gallery)
5. [Tech stack](#️-tech-stack)
6. [Architecture](#️-architecture)
7. [How the security score works](#-how-the-security-score-works)
8. [Project structure](#-project-structure)
9. [Colour palette](#-colour-palette)
10. [How it works — module by module](#️-how-it-works--module-by-module)
11. [Getting started](#-getting-started)
12. [Build the .exe and installer](#-build-the-exe-and-installer)
13. [Testing](#-testing)
14. [API & building your own UI](#-api--building-your-own-ui)
15. [Security design](#-security-design)
16. [Roadmap](#️-roadmap)
17. [FAQ](#-faq)
18. [Contributing](#-contributing)
19. [License & credits](#-license--credits)
20. [Developer](#-developer)

</details>

---

## 🛡️ About the project

**Cyber Hub** is a complete security center for a Windows PC and the online accounts that live on it — in **one desktop app**, styled like Windows Security, that runs **entirely on your own computer**. No cloud account, no telemetry, no CDN: the engine listens on `127.0.0.1` only and every online lookup is switched off until you turn it on.

It was built in **20 parts of 5% each**. Every part shipped working and tested, and was connected to the parts before it without breaking them — from the core engine (Part 1) to the antivirus scanner, firewall, password vault and threat intelligence, all the way to the scheduler, security score, encrypted backups and the packaged desktop app (Part 20).

> [!NOTE]
> Cyber Hub works **next to** Microsoft Defender, not instead of it. It reads Defender's state, warns you when something is off, and adds what Windows Security doesn't have: a single score, account protection, a password vault, a website scanner, threat intelligence, reports and backups.

<div align="center"><img src="docs/assets/build-progress.svg" alt="All 20 build parts complete" width="100%"/></div>

---

## 🌟 Highlights

<table>
<tr>
<td width="33%" valign="top">

### 🎯 One score
A 0–100 security score from 9 weighted areas, plus a **"What to fix first"** list. Many items have a **one-click fix**.

</td>
<td width="33%" valign="top">

### 🦠 Real antivirus engine
Quick / full / custom scans, SHA-256 signatures, **22 built-in YARA rules**, 40+ heuristics, encrypted quarantine and **real-time protection**.

</td>
<td width="33%" valign="top">

### 🔥 Firewall & network
Windows Firewall control, one-click blocks, open-port checks, Wi-Fi safety rating, **evil-twin** and **ARP-spoofing** alerts.

</td>
</tr>
<tr>
<td valign="top">

### 🔑 Zero-knowledge vault
Passwords, cards and notes with **AES-256-GCM** per item, scrypt keys, breach checks (k-anonymity), 2FA codes.

</td>
<td valign="top">

### 🌐 Accounts & threat intel
55 platforms (Google, WhatsApp, JazzCash, GitHub…), 2FA checklists, **breach monitoring**, phishing-link checks.

</td>
<td valign="top">

### 🗓️ Runs by itself
Scheduler, Windows toast notifications, weekly **PDF reports** and **encrypted backups** — protection that keeps going from the tray.

</td>
</tr>
</table>

---

## ✨ Features

<div align="center">

| # | Part | What you get |
|:-:|---|---|
| 01 | ⚙️ **Core engine** | FastAPI server on loopback, SQLite with versioned migrations, API token, live stats over WebSocket, activity log, settings |
| 02 | 👤 **Account & login** | Owner account, scrypt hashing, sessions, brute-force lockout, auto-lock, PIN unlock, recovery codes, extra users (admin / standard) |
| 03 | 📈 **System monitor** | Per-core CPU, RAM, disk I/O, network, GPU, temperatures, top programs, smart alerts with hysteresis, history |
| 04 | 🧩 **Processes & startup** | Process tree with risk flags, end / suspend, signature checks, startup items, services and tasks — with **new-item alerts** |
| 05 | 🦠 **Antivirus engine** | Quick / full / custom scans with real progress & ETA, signature DB (MalwareBazaar import), archive scanning, zip-bomb guard |
| 06 | 🔒 **Quarantine** | AES-256-GCM vault with DPAPI-sealed keys, verified restore, allow list, auto-quarantine, protection history + CSV export |
| 07 | ⚡ **Real-time protection** | Watches Downloads / Desktop / Documents / Startup, waits for downloads to finish, USB checks, **ransomware burst alert** |
| 08 | 🧬 **Rules & heuristics** | YARA (native or built-in YARA-lite), 40+ explainable heuristics, PE parser, macro / script / LNK checks, opt-in VirusTotal |
| 09 | 🔥 **Firewall** | Profiles, rules, one-click blocks (app / IP / port, timed), health score, change watch, snapshots, log reader |
| 10 | 📡 **Network & Wi-Fi** | Live connections with owning program, open ports + real firewall verdict, Wi-Fi rating, LAN device scan, new-device alerts |
| 11 | 🖥️ **Windows posture** | **47 checks** across Windows Security's six sections, verified one-click fixes with undo, update & support status |
| 12 | 🔑 **Password vault** | Zero-knowledge vault, generator, strength meter (zxcvbn), reused / weak / breached audit, TOTP, imports from 8 managers |
| 13 | 🗄️ **Data protection** | File encryption (`.chx`), secure shredder, privacy cleaner (temp, browsers), sensitive-file finder (keys, cards, CNIC, IBAN) |
| 14 | 🌍 **Website & project scanner** | TLS & certificates, headers, cookies, vulnerable JS libraries, exposed files, dependency CVEs (OSV), dev-server exposure |
| 15 | 🛰️ **Threat intelligence** | Offline feeds (abuse.ch, Spamhaus, OpenPhish…), IOC checks, phishing analyser, live connection matching, block list, hunt |
| 16 | 👥 **Accounts & platforms** | 55-platform catalog, 2FA checklists, recovery chain, HIBP breach monitoring, GitHub connector, extension audit |
| 17 | 🔔 **Scheduler & notifications** | One inbox for every alert, Windows toasts with quiet hours, 16 schedulable jobs with catch-up and battery rules |
| 18 | 🎯 **Security score & dashboard** | Weighted overall score, caps for areas at risk, one-click recommendations, score history, single-call dashboard |
| 19 | 📄 **Reports & backup** | PDF / HTML / CSV / JSON reports, encrypted `.chbackup` backups (portable or this-PC), staged restore, diagnostics |
| 20 | 🪟 **Desktop app** | Native window + tray icon, start with Windows, single instance, file pickers, `CyberHub.exe` + Windows installer |

</div>

---

## 🖼️ Gallery

<div align="center">

<img src="docs/assets/screenshots/dashboard.webp" alt="Dashboard" width="100%"/>
<sub><b>Dashboard</b> — overall score, what to fix first, protection areas, live system and network</sub>

<br/><br/>

<table>
<tr>
<td width="50%"><img src="docs/assets/screenshots/virus-threats.webp" alt="Virus & threat protection"/><p align="center"><sub><b>Virus & threat protection</b></sub></p></td>
<td width="50%"><img src="docs/assets/screenshots/firewall.webp" alt="Firewall"/><p align="center"><sub><b>Firewall</b></sub></p></td>
</tr>
<tr>
<td><img src="docs/assets/screenshots/device-security.webp" alt="Device security"/><p align="center"><sub><b>Device security — 47 Windows checks</b></sub></p></td>
<td><img src="docs/assets/screenshots/network.webp" alt="Network"/><p align="center"><sub><b>Network & Wi-Fi</b></sub></p></td>
</tr>
<tr>
<td><img src="docs/assets/screenshots/password-health.webp" alt="Password vault"/><p align="center"><sub><b>Password vault — health audit</b></sub></p></td>
<td><img src="docs/assets/screenshots/accounts.webp" alt="Accounts & platforms"/><p align="center"><sub><b>Accounts & platforms</b></sub></p></td>
</tr>
<tr>
<td><img src="docs/assets/screenshots/threat-intel.webp" alt="Threat intelligence"/><p align="center"><sub><b>Threat intelligence — phishing link check</b></sub></p></td>
<td><img src="docs/assets/screenshots/data-protection.webp" alt="Data protection"/><p align="center"><sub><b>Data protection</b></sub></p></td>
</tr>
</table>

<details>
<summary><b>📸 More screenshots</b></summary>
<br/>
<table>
<tr>
<td width="50%"><img src="docs/assets/screenshots/system-monitor.webp" alt="System monitor"/><p align="center"><sub><b>System monitor</b></sub></p></td>
<td width="50%"><img src="docs/assets/screenshots/scheduler.webp" alt="Scheduler"/><p align="center"><sub><b>Scheduler</b></sub></p></td>
</tr>
<tr>
<td><img src="docs/assets/screenshots/reports.webp" alt="Reports"/><p align="center"><sub><b>Reports & backup</b></sub></p></td>
<td><img src="docs/assets/screenshots/notifications.webp" alt="Notifications"/><p align="center"><sub><b>Notification center</b></sub></p></td>
</tr>
<tr>
<td><img src="docs/assets/screenshots/threat-history.webp" alt="Threat history"/><p align="center"><sub><b>Threat history</b></sub></p></td>
<td><img src="docs/assets/screenshots/dashboard-light.webp" alt="Light theme"/><p align="center"><sub><b>Light theme</b></sub></p></td>
</tr>
<tr>
<td><img src="docs/assets/screenshots/login.webp" alt="Sign in"/><p align="center"><sub><b>Sign-in</b></sub></p></td>
<td><img src="docs/assets/screenshots/about.webp" alt="About"/><p align="center"><sub><b>About</b></sub></p></td>
</tr>
</table>
</details>

<sub>Screenshots use the built-in simulated Windows PC that the tests run against.</sub>

</div>

---

## 🛠️ Tech stack

<div align="center">

| Layer | Technology | Used for |
|---|---|---|
| 🐍 Engine | ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) ![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white) ![Uvicorn](https://img.shields.io/badge/Uvicorn-499848?style=flat-square&logo=gunicorn&logoColor=white) ![Pydantic](https://img.shields.io/badge/Pydantic-E92063?style=flat-square&logo=pydantic&logoColor=white) | REST API + WebSockets on 127.0.0.1 |
| 🗃️ Storage | ![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white) | 20 versioned migrations, WAL, per-user data |
| 🔐 Crypto | ![cryptography](https://img.shields.io/badge/cryptography-AES--256--GCM-0ea5e9?style=flat-square) ![scrypt](https://img.shields.io/badge/scrypt-HKDF-0ea5e9?style=flat-square) ![DPAPI](https://img.shields.io/badge/Windows-DPAPI-0078D6?style=flat-square&logo=windows&logoColor=white) | Quarantine, vault, `.chx` files, backups |
| 🖥️ System | ![psutil](https://img.shields.io/badge/psutil-system%20data-6b7280?style=flat-square) ![watchdog](https://img.shields.io/badge/watchdog-file%20events-6b7280?style=flat-square) ![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat-square&logo=powershell&logoColor=white) | Monitor, real-time protection, firewall, posture |
| 🧬 Detection | ![YARA](https://img.shields.io/badge/YARA-native%20%2B%20lite-f97316?style=flat-square) ![zxcvbn](https://img.shields.io/badge/zxcvbn-strength-f97316?style=flat-square) | Rules, heuristics, password strength |
| 🎨 Interface | ![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white) ![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white) ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black) ![SVG](https://img.shields.io/badge/SVG%20charts-FFB13B?style=flat-square&logo=svg&logoColor=black) | 21 pages, no framework, works offline |
| 🪟 Desktop | ![pywebview](https://img.shields.io/badge/pywebview-WebView2-0078D6?style=flat-square) ![pystray](https://img.shields.io/badge/pystray-tray-6b7280?style=flat-square) ![PyInstaller](https://img.shields.io/badge/PyInstaller-.exe-3776AB?style=flat-square) ![Inno Setup](https://img.shields.io/badge/Inno%20Setup-installer-264de4?style=flat-square) | Window, tray, packaging |
| 🧪 Quality | ![pytest](https://img.shields.io/badge/pytest-604%20tests-0A9EDC?style=flat-square&logo=pytest&logoColor=white) ![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-CI-2088FF?style=flat-square&logo=githubactions&logoColor=white) | Tests on Windows + Ubuntu |

</div>

---

## 🏗️ Architecture

```mermaid
flowchart LR
    subgraph APP["🪟 CyberHub.exe"]
        direction TB
        W["🖼️ Window<br/>(WebView2)"]
        T["🛡️ Tray icon<br/>quick scan · pause · quit"]
        UI["🎨 UI · 21 pages<br/>HTML / CSS / JS"]
        W --- UI
    end

    subgraph ENGINE["⚙️ Engine · FastAPI on 127.0.0.1"]
        direction TB
        API["🔑 API token + session<br/>REST + WebSockets"]
        subgraph MOD["Modules (Parts 3–16)"]
            direction LR
            AV["🦠 Scan · Quarantine<br/>Real-time · YARA"]
            NET["🔥 Firewall · Network<br/>Wi-Fi · LAN"]
            DEV["🖥️ Windows posture<br/>Processes · Startup"]
            PRIV["🔑 Vault · Data<br/>Accounts"]
            INT["🛰️ Threat intel<br/>Web scanner"]
        end
        subgraph TOP["Parts 17–19"]
            direction LR
            SCH["🗓️ Scheduler"]
            NOT["🔔 Notifications"]
            SCO["🎯 Score"]
            REP["📄 Reports · Backup"]
        end
        API --> MOD
        API --> TOP
        MOD -->|events| NOT
        MOD -->|health| SCO
        SCH -->|runs jobs| MOD
    end

    DB[("🗃️ SQLite<br/>%LOCALAPPDATA%\\CyberHub")]
    WIN["🪟 Windows<br/>Defender · Firewall · Registry"]
    NETW["🌐 Opt-in online<br/>HIBP · OSV · abuse.ch · VT"]

    UI <-->|HTTP / WS| API
    T --> API
    ENGINE --- DB
    MOD <-->|PowerShell · psutil| WIN
    INT -.->|only if enabled| NETW
    PRIV -.->|k-anonymity| NETW
```

<details>
<summary><b>🔁 What happens when a file is downloaded</b> (sequence)</summary>

```mermaid
sequenceDiagram
    autonumber
    participant B as 🌐 Browser
    participant RT as ⚡ Real-time protection
    participant S as 🦠 Scan engine
    participant Q as 🔒 Quarantine vault
    participant N as 🔔 Notifications
    participant U as 👤 You
    B->>RT: invoice.pdf.exe arrives in Downloads
    RT->>RT: waits until the download is finished
    RT->>S: scan (hashes · signatures · YARA · heuristics)
    S-->>RT: Trojan found (high)
    RT->>Q: encrypt + lock away (AES-256-GCM)
    Q-->>N: "Threat quarantined"
    N->>U: Windows toast + inbox entry
    U->>Q: Restore / Delete / Allow (from the app)
```

</details>

<details>
<summary><b>🗓️ How a scheduled job runs</b></summary>

```mermaid
flowchart TD
    A["⏰ Every 15 s: anything due?"] -->|no| A
    A -->|yes| B{"Scheduler on?"}
    B -->|no| A
    B -->|yes| C{"Still running<br/>from last time?"}
    C -->|yes| S1["⏭️ Skipped (recorded)"]
    C -->|no| D{"PC was off at<br/>planned time?"}
    D -->|yes, no catch-up| S1
    D -->|yes, catch-up| E
    D -->|no| E{"Heavy job<br/>on battery?"}
    E -->|yes| P["🔌 Postponed 30 min"]
    E -->|no| R["▶️ Run: scan · check · report · backup"]
    R --> OK["✅ Result saved to history"]
    R --> F["❌ Failed → notification"]
```

</details>

<details>
<summary><b>💾 Backup & restore</b></summary>

```mermaid
flowchart LR
    DB[("Live database")] -->|SQLite online backup| SNAP["Consistent snapshot"]
    SNAP --> ZIP["zip + manifest<br/>(+ quarantine)"]
    ZIP -->|AES-256-GCM chunks| CHB["📦 .chbackup"]
    CHB -->|read back + verify| OK["✅ kept"]
    CHB -.->|restore| STAGE["Staged"]
    STAGE -->|next start| SWAP["Old data → pre-restore folder<br/>backup → live · migrations · sign-out"]
```

</details>

---

## 🎯 How the security score works

<div align="center"><img src="docs/assets/score-weights.svg" alt="Security score weights" width="100%"/></div>

- Each area reuses its **own module's score** — nothing is invented for the dashboard.
- Areas you don't use (no vault yet, no website scanned) **neither help nor hurt**.
- One area **at risk** (below 50) caps the total at **59**, and one that **needs attention** (below 70) caps it at **89**. A single critical problem can't hide behind eight good areas.
- A module that can't be read is shown as **unavailable** with the reason, never guessed.

| Score | Grade | Status |
|:-:|:-:|---|
| 95–100 | A+ | 🟢 Protected |
| 90–94 | A | 🟢 Protected |
| 70–89 | B / C | 🟡 Good |
| 50–69 | D | 🟠 Needs attention |
| 0–49 | E / F | 🔴 At risk |

---

## 📁 Project structure

```text
📦 Cyber-Hub
├── 🛡️ CyberHub.pyw                 → desktop launcher: engine + window + tray
├── ▶️ run.py                        → engine only (developers)
├── 🪟 start_cyberhub.bat            → start from source (sets everything up)
├── 🔐 start_cyberhub_admin.bat      → same, as administrator (firewall & system fixes)
├── 🏗️ build_windows.bat             → tests → CyberHub.exe → installer
├── 📋 requirements.txt · requirements-desktop.txt
├── 🗺️ ROADMAP.md                    → what each of the 20 parts delivers
├── 📂 cyberhub/
│   ├── ⚙️ config.py · database.py · security.py · logger.py · main.py · desktop_app.py
│   ├── 🌐 routers/                  → 24 API routers (one per area)
│   ├── 🧠 services/                 → 60+ modules
│   │   ├── 🦠 scanner · malware_db · quarantine · vault · realtime · rules_engine · yara_lite · heuristics
│   │   ├── 🔥 firewall · firewall_backends · network · netprobe · posture · posture_backends
│   │   ├── 🔑 password_vault · password_tools · data_protection · file_crypto · shredder · privacy_cleaner
│   │   ├── 🛰️ threat_intel · intel_feeds · phishing · web_scanner · web_probe · dep_audit
│   │   ├── 👥 platform_accounts · platform_catalog · breach_watch · extensions_audit
│   │   └── 🗓️ scheduler · notifications · security_score · reports · pdf_writer · backup · desktop
│   ├── 🧬 rules/                    → built-in YARA rule pack
│   └── 📚 data/                     → EFF wordlist for passphrases
├── 🎨 ui/                           → the app interface (no framework, offline)
│   ├── index.html
│   └── assets/ → app.css · core.js · app.js · pages-*.js · icon.png · icon.ico
├── 🌉 frontend-bridge/              → cyberhub-api.js + an example page per part
├── 📦 packaging/                    → CyberHub.spec (PyInstaller) · CyberHub.iss (Inno Setup) · version_info.txt
├── 🧪 tests/                        → test_part1.py … test_part20_desktop.py (604 tests)
├── 📖 docs/                         → API.md · assets/ (banner, diagrams, screenshots)
└── 🤖 .github/                      → CI workflow · issue & PR templates
```

---

## 🎨 Colour palette

<div align="center">

| Swatch | Name | Hex | Used for |
|:-:|---|:-:|---|
| ![#070d1a](https://img.shields.io/badge/%20-070d1a-070d1a?style=for-the-badge) | Deep navy | `#070D1A` | Background |
| ![#0b1426](https://img.shields.io/badge/%20-0b1426-0b1426?style=for-the-badge) | Night panel | `#0B1426` | Dialogs, drawers |
| ![#4f8cff](https://img.shields.io/badge/%20-4f8cff-4f8cff?style=for-the-badge) | Shield blue | `#4F8CFF` | Brand, buttons, charts |
| ![#22d3ee](https://img.shields.io/badge/%20-22d3ee-22d3ee?style=for-the-badge) | Cyan glow | `#22D3EE` | Accents, active tab |
| ![#34d399](https://img.shields.io/badge/%20-34d399-34d399?style=for-the-badge) | Protected green | `#34D399` | Good state, switches |
| ![#fbbf24](https://img.shields.io/badge/%20-fbbf24-fbbf24?style=for-the-badge) | Amber | `#FBBF24` | Medium severity |
| ![#fb923c](https://img.shields.io/badge/%20-fb923c-fb923c?style=for-the-badge) | Orange | `#FB923C` | High severity |
| ![#f87171](https://img.shields.io/badge/%20-f87171-f87171?style=for-the-badge) | Alert red | `#F87171` | Critical, at risk |
| ![#e8eefc](https://img.shields.io/badge/%20-e8eefc-e8eefc?style=for-the-badge) | Ice white | `#E8EEFC` | Text |

</div>

---

## ⚙️ How it works — module by module

<details>
<summary><b>🦠 Antivirus engine, quarantine & real-time protection</b> (Parts 5–8)</summary>

<br/>

- **One pass per file** computes SHA-256, SHA-1 and MD5, compares them with the signature DB (EICAR built-in, MalwareBazaar imports), runs byte patterns, YARA rules and 40+ heuristics, and opens archives two levels deep with a zip-bomb guard.
- A **hash cache** makes re-scans fast. Quick scans also check running programs and startup items.
- Detections go to an **encrypted vault**: each file gets its own AES-256-GCM key, wrapped by a master key that Windows DPAPI seals to your account. Restores are SHA-256 verified.
- **Real-time protection** watches your folders with `ReadDirectoryChangesW`, waits until downloads finish (`.crdownload`, `.part`), scans on arrival, checks USB drives (autorun.inf, shortcut viruses) and raises a **ransomware alert** when many files change at once.

</details>

<details>
<summary><b>🔥 Firewall, network & Wi-Fi</b> (Parts 9–10)</summary>

<br/>

- Drives Windows Defender Firewall through the official **NetSecurity PowerShell module**. Every value you type is passed through an environment variable, never pasted into the script.
- **One-click blocks** for a program, IP range or port, optionally timed. Each block is verified, and repaired if something removed it.
- Lists every connection with its program and explains why it may be risky (Tor, mining pools, Metasploit ports, programs in Temp…). Shows which open ports the firewall really lets through.
- Rates Wi-Fi from Open to WPA3, spots **evil-twin** networks, scans your LAN (private ranges only) and alerts on **new devices** or a changed router MAC (ARP spoofing).

</details>

<details>
<summary><b>🖥️ Windows security posture</b> (Part 11)</summary>

<br/>

- **47 checks** in Windows Security's six sections: Defender (real-time, tamper, cloud, PUA, exclusions, definition age), accounts (UAC, Guest, WDigest, LSA), firewall & network (RDP + NLA, SMBv1, LLMNR), app control (SmartScreen, Smart App Control), device (Secure Boot, TPM, Memory integrity, BitLocker) and updates (support end dates, paused updates).
- Fixes come from an **allow-list only**. Each fix is read back to confirm it worked, rolled back if it didn't, and can be undone later.

</details>

<details>
<summary><b>🔑 Password vault & data protection</b> (Parts 12–13)</summary>

<br/>

- Master password → **scrypt** (~128 MB) → HKDF with a device pepper → wraps a random vault key. Every item, titles included, is encrypted with AES-256-GCM. Keys live only in memory and are wiped on auto-lock.
- The audit finds **breached** (Have I Been Pwned, k-anonymity: only 5 characters of a hash leave the PC), reused, weak and old passwords. Includes 2FA codes, a generator with EFF passphrases, and imports from Chrome, Edge, Firefox, Bitwarden, LastPass, 1Password and KeePass.
- **`.chx` file encryption** (password or this-PC mode). Each file is decrypted and compared before the original is shredded.
- **Shredder** with DoD-style passes (it warns honestly about SSDs), a **privacy cleaner** for temp files and browsers, and a **sensitive-file finder** for keys, password lists, cards (Luhn), CNICs, IBANs and crypto wallets.

</details>

<details>
<summary><b>🛰️ Threat intelligence & website scanner</b> (Parts 14–15)</summary>

<br/>

- Check any IP, domain, URL, e-mail or hash, defanged forms included (`hxxp://evil[.]com`), against offline feeds: Feodo, URLhaus, ThreatFox, Spamhaus DROP, OpenPhish, ET and your own block list.
- The **phishing analyser** knows 80+ brands, including Pakistani banks, wallets and government sites. It catches typosquats, homoglyph domains and fake login pages, and can open a page read-only to look closer.
- Live connections are matched against the feeds; a hit names the program and offers a one-click firewall block.
- The **website scanner** checks TLS and certificates, security headers, cookies, mixed content, vulnerable jQuery / Bootstrap / AngularJS, exposed `.git` / `.env` / backups and debug pages. **Project scans** look up `package-lock`, `poetry.lock`, `composer.lock` and others in OSV for CVEs and find leaked secrets.

</details>

<details>
<summary><b>👥 Accounts & platforms</b> (Part 16)</summary>

<br/>

- A catalog of **55 platforms** (Google, Microsoft, Apple, Facebook, WhatsApp, Instagram, LinkedIn, TikTok, GitHub, AWS, PayPal, Payoneer, JazzCash, Easypaisa, Daraz, Binance…), each with its 2FA options, recovery options and security-page links.
- A checklist per account (2FA, passkeys, backup codes, sign-in alerts, connected apps…) where facts from the vault and GitHub beat manual ticks.
- The **recovery chain** shows which e-mail can reset which accounts and warns when that hub is weak.
- Breach monitoring (HIBP / XposedOrNot), a link & sender checker, and an audit of browser and VS Code extensions.

</details>

<details>
<summary><b>🗓️ Scheduler, notifications, score, reports & backup</b> (Parts 17–19)</summary>

<br/>

- **16 schedulable jobs** (scans, checks, feed updates, clean-ups, reports, backups). They run in local time and handle DST. Missed runs catch up once, heavy jobs wait for mains power, and nothing overlaps.
- **One notification inbox** collects alerts from every module, each exactly once. Windows toasts respect quiet hours, muted areas and a per-minute limit.
- The **score engine** and **"What to fix first"** list come with the exact API call for each one-click fix.
- **Reports** are made by a built-in PDF writer (no extra package), with "Developed by Syed Muhammad Tayyab" in every header and footer.
- **Backups** are verified after writing. They are portable with a password, and restores are staged and applied at the next start with a safety copy.

</details>

<details>
<summary><b>🪟 Desktop app</b> (Part 20)</summary>

<br/>

- The engine runs inside the app. The UI opens in a **native window** (Microsoft Edge WebView2) with real file pickers and downloads.
- The **tray icon** offers open, quick scan, pause / resume protection and quit, and shows the toasts. Closing the window keeps protection running.
- **Single instance**: opening it again just brings the window forward. *Start with Windows* uses the per-user Run key (no admin needed) and stays in step with the setting.
- If WebView2 or the tray isn't available, it falls back to your browser.

</details>

---

## 🚀 Getting started

### ✅ Requirements

| | |
|---|---|
| 🪟 OS | Windows 10 or 11 (64-bit). The engine and tests also run on Linux. |
| 🐍 Python | 3.10 or newer — tick **“Add python.exe to PATH”** in the installer |
| 🌐 WebView2 | Already part of Windows 10/11 (used for the app window) |
| 💽 Disk | ~150 MB with all packages |

### ▶️ Run it

```bash
# 1. get the code
git clone https://github.com/Syed-Muhammad-Tayyab/Cyber-Hub.git
cd Cyber-Hub
```

```text
# 2. double-click
start_cyberhub.bat
```

The first start creates a virtual environment and installs everything (a minute or two). Cyber Hub then opens in its own window, a 🛡️ appears in the tray, and you create your owner account. That's it.

> [!TIP]
> Use **`start_cyberhub_admin.bat`** when you want to change Windows Firewall or apply machine-wide fixes. Windows only allows that to programs running as administrator. Everything else works without it.

<details>
<summary><b>🐧 Manual / Linux / developers</b></summary>

```bash
python -m venv .venv
.venv\Scripts\activate            # Linux / macOS: source .venv/bin/activate
pip install -r requirements-desktop.txt
pip install yara-python           # optional: native YARA (the built-in YARA-lite works without it)

python CyberHub.pyw               # app window + tray
python CyberHub.pyw --browser     # open in your browser instead
python run.py                     # engine only → http://127.0.0.1:8765/docs
```

</details>

### 🎛️ Launch options

| Option | What it does |
|---|---|
| `--minimized` | start hidden in the tray (what *Start with Windows* uses) |
| `--browser` | use your default browser instead of the app window |
| `--server-only` | engine only — API on `http://127.0.0.1:8765`, interactive docs on `/docs` |
| `--no-tray` | no tray icon (closing the window quits) |
| `--port 9000` | another port (a free one is picked automatically if 8765 is taken) |

Your data lives in **`%LOCALAPPDATA%\CyberHub\`** (database, logs, quarantine, reports, backups).

---

## 📦 Build the .exe and installer

```text
build_windows.bat
```

1. Installs the build tools from `requirements-desktop.txt`
2. Runs the **full test suite** — the build stops if anything fails
3. Builds **`dist\CyberHub\CyberHub.exe`** with PyInstaller (one-folder build, no console, version info, icon)
4. If [Inno Setup 6](https://jrsoftware.org/isdl.php) is installed, it also creates **`dist\CyberHub-Setup-1.0.0.exe`**

| Installer feature | |
|---|---|
| 👤 Per-user install | no administrator rights needed (`%LOCALAPPDATA%\Programs\Cyber Hub`) |
| 🧷 Shortcuts | Start menu + optional desktop shortcut |
| 🚀 Start with Windows | optional — keeps protection on after every sign-in |
| 🗑️ Uninstall | closes the app and asks whether to keep your data |

---

## 🧪 Testing

```bash
python -m pytest -q
```

```text
604 passed, 2 skipped
```

| What is tested | How |
|---|---|
| Every part, 1 → 20 | `tests/test_partN_*.py` against a real engine with temp folders |
| Windows-only features | built-in simulators for the firewall, network, Wi-Fi and Windows posture |
| Online services | fake HIBP / OSV / abuse.ch / GitHub transports — tests never touch the internet |
| Crypto | tampering a single byte of a backup or `.chx` file must be refused |
| Restore on another PC | a backup restored on a fresh install reopens the vault and a quarantined file |
| UI ↔ engine | every one of the 250+ API paths the UI calls must exist in the engine |
| Desktop launcher | real engine start on a free port, single-instance check |

The two skipped tests need native `yara-python` and PowerShell, so they run on Windows. CI runs the suite on **Windows and Ubuntu** for every push (`.github/workflows/tests.yml`).

---

## 🔌 API & building your own UI

The engine exposes **400+ endpoints** with interactive docs at `http://127.0.0.1:8765/docs` while it runs. The full reference for every part is in **[docs/API.md](docs/API.md)**.

To build your own interface, include `frontend-bridge/cyberhub-api.js` and call `window.CyberHub.*`:

```html
<script src="cyberhub-api.js"></script>
<script>
  // everything the front page needs, in one call
  CyberHub.dashboard().then(d => {
    document.querySelector("#score").textContent = d.score.score;          // e.g. 87
    document.querySelector("#status").textContent = d.score.status_text;   // "Good"
  });

  // live notifications
  CyberHub.streamNotifications(m => setBadge(m.unread));

  // run the top recommendation's one-click fix
  CyberHub.recommendations().then(r => CyberHub.applyRecommendation(r.items[0]));
</script>
```

---

## 🔐 Security design

<table>
<tr><td>🏠</td><td><b>Local only</b></td><td>The engine binds to <code>127.0.0.1</code> and needs a per-install API token (compared in constant time), so other websites in your browser can't use it.</td></tr>
<tr><td>🔑</td><td><b>Keys</b></td><td>Master keys are sealed with Windows DPAPI. Vault keys exist only in memory while unlocked. API keys you add are stored encrypted and never sent back to the UI.</td></tr>
<tr><td>🧪</td><td><b>Authenticated encryption</b></td><td>AES-256-GCM in 1 MiB chunks for quarantine, <code>.chx</code> files and backups. One flipped byte is detected and refused.</td></tr>
<tr><td>🛂</td><td><b>Roles</b></td><td>Lowering protection (turning things off, exclusions, auto-block, schedules) needs a Cyber Hub administrator. Standard users can only raise it.</td></tr>
<tr><td>🧱</td><td><b>No injection</b></td><td>PowerShell scripts are fixed; your values reach them only through environment variables. Fixes come from allow-lists. CSV exports are guarded against formula injection.</td></tr>
<tr><td>🌐</td><td><b>Opt-in online</b></td><td>Every online lookup is off until you turn it on, and sends the minimum: hashes, 5-character hash prefixes, package names and versions — never files or passwords.</td></tr>
<tr><td>🚧</td><td><b>Guards</b></td><td>Cyber Hub refuses to shred or encrypt system folders, whole drives or its own files. Scans never follow links into the network. A public website can't redirect the scanner into your LAN.</td></tr>
<tr><td>📄</td><td><b>Reports</b></td><td>Reports and diagnostics never contain passwords, vault items, keys, tokens or full monitored e-mail addresses.</td></tr>
</table>

> [!IMPORTANT]
> Found a security problem in Cyber Hub itself? Please report it privately — see **[SECURITY.md](SECURITY.md)**.

---

## 🗺️ Roadmap

<details open>
<summary><b>✅ Done — all 20 parts (v1.0.0)</b></summary>

<br/>

- [x] **Part 01** — Core engine
- [x] **Part 02** — Account & login
- [x] **Part 03** — Live system monitor
- [x] **Part 04** — Processes & startup
- [x] **Part 05** — Antivirus scan engine
- [x] **Part 06** — Quarantine & threat history
- [x] **Part 07** — Real-time protection
- [x] **Part 08** — Rules engine & hash lookup
- [x] **Part 09** — Firewall & network protection
- [x] **Part 10** — Network monitor & Wi-Fi
- [x] **Part 11** — Windows security posture
- [x] **Part 12** — Password vault & auditor
- [x] **Part 13** — Data protection
- [x] **Part 14** — Website / developer scanner
- [x] **Part 15** — Threat intelligence
- [x] **Part 16** — Social & platform accounts
- [x] **Part 17** — Scheduler & notifications
- [x] **Part 18** — Security score & dashboard
- [x] **Part 19** — Reports, export & backup
- [x] **Part 20** — Desktop app & packaging

</details>

<details>
<summary><b>💡 Ideas for later</b></summary>

<br/>

- [ ] Code-signed `CyberHub.exe` (fewer SmartScreen prompts)
- [ ] Auto-update from GitHub Releases
- [ ] Urdu interface
- [ ] Browser extension for live phishing warnings
- [ ] Kernel minifilter for blocking files *before* they open (today: scan on write)

</details>

The detailed part-by-part breakdown is in **[ROADMAP.md](ROADMAP.md)**.

---

## ❓ FAQ

<details>
<summary><b>Does Cyber Hub replace Microsoft Defender?</b></summary>
<br/>
No — it works alongside it. Cyber Hub reads Defender's state and fixes its settings, and adds its own scanner, real-time watcher, YARA rules and everything else on top. Keep Defender on.
</details>

<details>
<summary><b>Does anything leave my PC?</b></summary>
<br/>
Not unless you switch it on. Online features (cloud hash lookup, breach checks, threat-feed downloads, link reputation) are opt-in and send the minimum: hashes, 5-character hash prefixes, or the single link you asked about. Everything else — your vault, files, scan results, reports — stays in <code>%LOCALAPPDATA%\CyberHub</code>.
</details>

<details>
<summary><b>Why does it sometimes ask for administrator rights?</b></summary>
<br/>
Windows only lets elevated programs change the firewall and machine-wide settings (BitLocker, UAC, SMBv1…). Cyber Hub runs as a normal user and asks only when you choose such a fix — use <code>start_cyberhub_admin.bat</code> or <i>Restart as administrator</i> on the Firewall page.
</details>

<details>
<summary><b>I forgot my password vault's master password.</b></summary>
<br/>
Use the <b>recovery key</b> shown when you created the vault. Without the master password or the recovery key, nobody — Cyber Hub included — can open the vault. That's what zero-knowledge means.
</details>

<details>
<summary><b>Can I move Cyber Hub to a new PC?</b></summary>
<br/>
Yes. Create a <b>password-protected backup</b> (Reports & backup → Backup with a password), copy the <code>.chbackup</code> file, and restore it on the new PC. Your vault, settings, history and accounts come with you.
</details>

<details>
<summary><b>Windows SmartScreen warns about CyberHub.exe.</b></summary>
<br/>
New, unsigned programs get this warning. Click <i>More info → Run anyway</i>, or run from source with <code>start_cyberhub.bat</code>. Code signing is on the roadmap.
</details>

<details>
<summary><b>Will it slow down my PC?</b></summary>
<br/>
Real-time protection only scans new or changed files in the folders it watches, and re-scans use a hash cache. Full scans and clean-ups can be scheduled for idle hours and wait automatically while a laptop is on battery.
</details>

---

## 🤝 Contributing

Contributions, bug reports and ideas are welcome.

1. 🍴 Fork the repository
2. 🌿 Create a branch — `git checkout -b feature/my-idea`
3. 🧪 Add tests and run `python -m pytest -q`
4. 💬 Commit — `git commit -m "Add my idea"`
5. 🚀 Push and open a **Pull Request**

Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** and the **[Code of Conduct](CODE_OF_CONDUCT.md)** first.

---

## 📜 License & credits

Released under the **[MIT License](LICENSE)** © 2026 **Syed Muhammad Tayyab**.

<details>
<summary><b>🙏 Built with & thanks to</b></summary>

<br/>

| Project / data | Used for | License |
|---|---|---|
| [FastAPI](https://fastapi.tiangolo.com) · [Uvicorn](https://www.uvicorn.org) · [Pydantic](https://docs.pydantic.dev) | Engine & API | MIT / BSD |
| [psutil](https://github.com/giampaolo/psutil) | System, process & network data | BSD-3 |
| [cryptography](https://cryptography.io) | AES-GCM, scrypt, HKDF, certificates | Apache-2.0 / BSD |
| [watchdog](https://github.com/gorakhargosh/watchdog) | Real-time file events | Apache-2.0 |
| [zxcvbn-python](https://github.com/dwolfhub/zxcvbn-python) | Password strength | MIT |
| [YARA](https://virustotal.github.io/yara/) / yara-python | Rule matching (optional) | BSD-3 |
| [pywebview](https://pywebview.flowrl.com) · [pystray](https://github.com/moses-palmer/pystray) · [Pillow](https://python-pillow.org) | Window, tray, icon | BSD / LGPL / HPND |
| [EFF Large Wordlist](https://www.eff.org/dice) | Passphrases | CC BY 3.0 US |
| [Have I Been Pwned](https://haveibeenpwned.com) · [XposedOrNot](https://xposedornot.com) | Breach data (opt-in) | per their terms |
| [abuse.ch](https://abuse.ch) · [Spamhaus](https://www.spamhaus.org) · [OpenPhish](https://openphish.com) | Threat feeds | per their terms |
| [OSV.dev](https://osv.dev) | Package vulnerability data | CC BY 4.0 |

</details>

---

## 👨‍💻 Developer

<div align="center">

<img src="docs/assets/logo.png" width="84" alt="Cyber Hub logo"/>

### Syed Muhammad Tayyab

**BS Computer Science (Information Security)** · FUUAST Islamabad<br/>
Red Team intern · Web & full-stack developer · 📍 Islamabad, Pakistan

<a href="https://github.com/Syed-Muhammad-Tayyab"><img src="https://img.shields.io/badge/GitHub-Syed--Muhammad--Tayyab-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/></a>

<br/><br/>

<img src="https://github-readme-stats.vercel.app/api/pin/?username=Syed-Muhammad-Tayyab&repo=Cyber-Hub&theme=tokyonight&hide_border=true&bg_color=0b1220" alt="Cyber Hub repo card"/>

<br/><br/>

⭐ **If Cyber Hub helps you or you like the project, please give it a star — it really helps!** ⭐

<br/>

<img src="docs/assets/divider.svg" width="100%" alt=""/>

<sub>🛡️ <b>Cyber Hub</b> · v1.0.0 · Made with ❤️ in Pakistan · <b>Developed by Syed Muhammad Tayyab</b></sub>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:22d3ee,50:1d4ed8,100:050b18&height=130&section=footer&text=Stay%20safe%20%E2%80%94%20Cyber%20Hub&fontSize=26&fontColor=ffffff&fontAlignY=72" alt="footer" width="100%"/>

</div>

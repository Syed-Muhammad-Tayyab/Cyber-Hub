"""
Cyber Hub Backend - User settings store
Developed by Syed Muhammad Tayyab

Key/value settings persisted as JSON in SQLite. DEFAULTS defines every
setting the UI's Settings page can show; later parts add their keys here.
"""
from __future__ import annotations

import json
from typing import Any

from ..database import Database

DEFAULTS: dict[str, Any] = {
    "theme": "dark",                       # dark | light
    "accent_color": "#3B82F6",
    "language": "en",
    "notifications_enabled": True,
    "start_with_windows": False,
    "minimize_to_tray": True,
    "metrics_interval_seconds": 2,         # live graph refresh
    "metrics_history_enabled": True,       # store snapshots for history graphs
    "metrics_retention_days": 7,
    "activity_retention_days": 90,
    # ---- Part 2: account security
    "session_timeout_minutes": 480,        # sign-in lasts 8 h
    "auto_lock_minutes": 15,               # lock after idle (0 = never)
    "max_failed_logins": 5,                # attempts before temporary lockout
    "lockout_minutes": 5,
    # ---- Part 3: live system monitor + resource alerts
    "monitor_alerts_enabled": True,
    "monitor_check_interval_seconds": 5,   # how often the alert engine samples
    "alert_cpu_percent": 90,
    "alert_memory_percent": 90,
    "alert_disk_percent": 90,              # disk space used, per drive
    "alert_gpu_percent": 95,
    "alert_temperature_c": 85,             # CPU temperature
    "alert_sustain_seconds": 60,           # must stay over the limit this long
    # ---- Part 4: processes & startup
    "startup_watch_enabled": True,         # alert when a new auto-start entry appears
    "startup_watch_interval_minutes": 10,
    "process_signature_check": True,       # verify publisher signatures (Windows)
    # ---- Part 5: antivirus scan engine
    "scan_max_file_mb": 256,               # bigger files are skipped (counted as skipped)
    "scan_archives": True,                 # look inside .zip / .jar / .docx-style archives
    "scan_archive_max_mb": 100,            # archives bigger than this are hashed but not opened
    "scan_excluded_paths": [],             # folders / files never scanned
    "scan_excluded_extensions": [],        # e.g. [".iso", ".vhdx"]
    "scan_hash_cache": True,               # reuse hashes of unchanged files (much faster re-scans)
    # ---- Part 6: quarantine & threat history
    "scan_auto_quarantine": "off",         # off | high (high + critical threats) | all - acted on as soon as found
    "quarantine_kill_processes": True,     # stop programs running the file before quarantining it
    "quarantine_retention_days": 30,       # quarantined items older than this are deleted (0 = keep forever)
    "quarantine_max_mb": 4096,             # vault size cap - oldest items are deleted first
    # ---- Part 7: real-time protection
    "realtime_protection": True,           # master switch (admin)
    "rtp_watch_default_folders": True,     # Downloads, Desktop, Documents, Startup folder(s)
    "rtp_watched_paths": [],               # extra folders the user added
    "rtp_action": "quarantine",            # quarantine | alert - what happens when a new file is a threat
    "rtp_max_file_mb": 100,                # bigger new files are not scanned on arrival (a full scan still covers them)
    "rtp_watch_removable": True,           # also watch USB / removable drives while they are plugged in
    "rtp_usb_alerts": True,                # alert when a USB drive is plugged in
    "rtp_usb_scan": "auto",                # off | notify | auto - scan a USB drive when it is plugged in (trusted drives skipped)
    "rtp_burst_threshold": 300,            # file changes in 10 s in one folder that raise a mass-change alert (0 = off)
    "rtp_log_clean_files": True,           # keep clean files in the real-time activity list too
    "rtp_event_retention": 5000,           # rows kept in the real-time activity list
    # ---- Part 8: rules engine, heuristics & online lookup
    "yara_enabled": True,                  # run YARA rules on files no hash signature knows
    "heuristics_enabled": True,            # score how suspicious a file's structure is
    "heuristics_sensitivity": "medium",    # low (score 80+) | medium (60+) | high (45+)
    "heuristics_auto_quarantine": False,   # heuristic-only findings wait for you instead of being quarantined
    "rules_max_file_mb": 20,               # bigger files get name / header checks only
    "rules_scan_archives": True,           # also run rules + heuristics on files inside .zip archives
    "cloud_lookup_enabled": False,         # ask VirusTotal / MalwareBazaar about file hashes (never the file)
    "cloud_auto_lookup": "executables",    # off | executables | all - background check of clean files
    "cloud_providers": ["virustotal", "malwarebazaar"],
    "cloud_vt_min_detections": 3,          # engines that must flag a file before it counts as malicious
    "cloud_vt_per_minute": 4,              # VirusTotal free tier: 4 / minute, 500 / day
    "cloud_vt_per_day": 500,
    "cloud_cache_days": 7,                 # re-ask about clean / unknown hashes after this many days
    "cloud_add_to_signatures": True,       # malicious in the cloud -> local signature (works offline next time)
    # ---- Part 9: firewall & network protection
    "firewall_watch_enabled": True,        # alert when another program adds an allow rule or turns the firewall off
    "firewall_watch_interval_minutes": 5,
    "firewall_alert_new_allow_rules": True,  # new inbound ALLOW rules raise an alert (other changes are logged)
    "firewall_log_path": "",               # packet-log location override ('' = the profile's own log file)
    "firewall_log_max_mb": 20,             # how much of the end of the packet log feeds the graphs
    "firewall_snapshot_keep": 20,          # automatic policy snapshots kept (manual ones are never pruned)
    # ---- Part 10: network monitor & Wi-Fi
    "network_watch_enabled": True,         # background check of ports, connections, LAN and Wi-Fi
    "network_watch_interval_minutes": 2,
    "network_alert_new_listeners": True,   # alert when a program starts accepting connections from the network
    "network_alert_suspicious": True,      # alert on red-flag connections (Tor / mining / backdoor ports, LOLBins...)
    "network_many_hosts": 150,             # distinct internet addresses one program may talk to before a warning
    "network_extra_suspicious_ports": [],  # your own red-flag remote ports, e.g. ["8888"]
    "network_resolve_hostnames": False,    # reverse-DNS remote addresses in the connection list
    "network_sample_retention_days": 7,    # traffic-shape samples kept for the graphs
    "lan_alert_new_devices": True,         # alert when a new device joins (medium on networks marked Home)
    "lan_arp_watch": True,                 # alert when the router's hardware address changes (ARP spoofing)
    "lan_auto_scan_minutes": 0,            # 0 = off; otherwise scan Home networks this often (minimum 15)
    "wifi_alert_insecure": True,           # alert when connecting to Open / WEP / WPA Wi-Fi
    # ---- Part 11: Windows security posture
    "posture_watch_enabled": True,         # re-check Defender / UAC / BitLocker / RDP ... in the background
    "posture_watch_interval_minutes": 30,
    "posture_alert_regressions": True,     # alert when a setting gets weaker or a Defender exclusion appears
    "posture_signature_max_age_days": 3,   # older virus definitions count as out of date
    "posture_update_max_age_days": 35,     # no successful Windows update for longer = warning
    "posture_scan_max_age_days": 14,       # no Defender quick scan for longer = reminder
    "posture_score_retention_days": 365,   # score history kept for the graphs
    # ---- Part 12: password vault & auditor
    "pv_auto_lock_minutes": 5,             # lock the password vault after this long unused (0 = only with the app)
    "pv_lock_with_session": True,          # lock the vault when Cyber Hub locks / signs out
    "pv_clipboard_clear_seconds": 30,      # wipe a copied password from the clipboard (0 = never)
    "pv_breach_check": "manual",           # off | manual | auto - Have I Been Pwned (k-anonymity, 5 hash chars only)
    "pv_old_password_days": 365,           # passwords unchanged for longer count as old in the audit
    "pv_trash_days": 30,                   # deleted items stay in the trash this long
    "pv_score_retention_days": 365,        # vault-health history kept for the graphs
    # ---- Part 13: data protection
    "dp_encrypt_original": "shred",        # shred | delete | keep - the original after it is encrypted (and verified)
    "dp_encrypt_hide_names": False,        # give .chx files random names (the real name is stored encrypted inside)
    "dp_decrypt_scan": True,               # scan decrypted files with the antivirus engine
    "dp_shred_method": "random",           # zero | random | dod3 | random3
    "dp_shred_verify": True,               # read the last pass back to check the drive kept it
    "dp_cleaner_temp_min_age_hours": 24,   # temp files younger than this are left alone (running installers)
    "dp_cleaner_secure": False,            # shred cleaned files instead of plain delete (slower)
    "dp_finder_default_folders": True,     # search Documents, Desktop and Downloads
    "dp_finder_paths": [],                 # extra folders for the sensitive-file finder
    "dp_finder_max_file_mb": 20,           # bigger files are skipped by the finder
    "dp_finder_types": ["private_key", "password_export", "api_key", "password", "credit_card", "cnic", "iban",
                        "ssn", "crypto_wallet", "contacts"],
    "dp_finder_alert": True,               # alert when a search finds new high / critical files
    "dp_history_days": 90,                 # job history, events and resolved findings kept this long
    # ---- Part 14: website / developer scanner
    "web_scan_timeout_seconds": 10,        # per request to the scanned site
    "web_cert_warn_days": 21,              # certificates expiring sooner are reported / alerted
    "web_check_exposed_files": True,       # look for .git, .env, backups ... (only on sites you confirmed you own)
    "web_monitor_enabled": True,           # re-scan saved sites / projects that have monitoring on
    "web_monitor_interval_hours": 24,
    "web_alert_regressions": True,         # alert when a monitored target gets new problems or a worse grade
    "web_dev_watch": True,                 # warn when a dev server on this PC can be reached from the network
    "web_dep_online": True,                # ask osv.dev about package versions (names + versions only, no code)
    "web_osv_cache_days": 1,               # reuse osv.dev answers this long
    "web_secret_scan": True,               # project scans also look for keys / passwords in the code (Part 13 rules)
    "web_history_days": 180,               # scans and events kept this long (the latest scan per target is kept)
    # ---- Part 15: threat intelligence
    "intel_auto_update": True,             # download the enabled threat feeds in the background
    "intel_update_hours": 6,               # how often each feed is refreshed (feeds may ask for less often)
    "intel_watch_connections": True,       # match this PC's internet connections (Part 10) against the feeds
    "intel_watch_interval_seconds": 60,
    "intel_auto_block": "off",             # off | c2 | high - block matching addresses in the firewall (Part 9)
    "intel_hashes_to_signatures": True,    # feed file hashes -> antivirus signatures (Part 5), caught offline
    "intel_retro_hunt": True,              # new feed data vs files already scanned / downloaded on this PC
    "intel_online_lookup": False,          # send the indicator you check to VirusTotal / abuse.ch / AbuseIPDB
    "intel_online_providers": ["virustotal", "abusech", "abuseipdb"],
    "intel_cache_hours": 24,               # reuse online answers this long
    "intel_abuseipdb_min_score": 50,       # AbuseIPDB confidence that counts as "reported for abuse"
    "intel_max_feed_mb": 64,               # biggest feed download / import accepted
    "intel_history_days": 90,              # checks and events kept this long
    # ---- Part 16: social & platform accounts
    "platform_breach_check": "manual",     # off | manual | auto - send your monitored e-mail addresses to the provider
    "platform_breach_providers": ["xposedornot", "hibp"],  # HIBP is used first when its API key is saved
    "platform_breach_interval_hours": 168, # auto mode: re-check each address this often
    "platform_catalog_auto_update": True,  # download the public HIBP breach list (no personal data sent)
    "platform_catalog_update_hours": 24,
    "platform_review_days": 180,           # account reviews (devices, apps, keys) go stale after this long
    "platform_alert_breaches": True,       # alert on new breaches of your e-mails / of sites you use
    "platform_extension_audit": True,      # watch browser + code-editor extensions for new risky ones
    "platform_extension_watch_hours": 6,
    "platform_github_sync_hours": 24,      # re-read connected GitHub accounts (2FA, SSH keys)
    "platform_history_days": 180,          # events kept this long
    # ---- Part 17: scheduler & notifications
    "notify_center_min_severity": "low",   # low | medium | high | critical - what is kept in the notification center
    "notify_toasts": True,                 # show Windows toast notifications
    "notify_toast_min_severity": "medium", # low | medium | high | critical - what pops up as a toast
    "notify_toast_max_per_minute": 4,      # more than this in a minute are kept in the center without a pop-up
    "notify_quiet_hours": False,           # no pop-ups between the two times below
    "notify_quiet_start": "22:00",
    "notify_quiet_end": "07:00",
    "notify_quiet_allow_critical": True,   # critical alerts still pop up during quiet hours
    "notify_muted_sources": [],            # sources that never pop up (still listed in the center)
    "notify_retention_days": 60,           # notifications kept this long
    "scheduler_enabled": True,             # run scheduled scans / checks / reports / backups (admin)
    "scheduler_skip_on_battery": True,     # postpone full scans and clean-ups while the laptop runs on battery
    "scheduler_history_days": 90,          # schedule run history kept this long
    # ---- Part 18: security score & dashboard
    "score_history_days": 365,             # overall-score history kept for the graph
    "score_alert_drop": 10,                # notify when the overall score falls by this many points (0 = off)
    # ---- Part 19: reports, export & backup
    "report_default_format": "pdf",        # pdf | html | csv | json
    "report_default_days": 30,             # period a report covers
    "report_keep": 50,                     # newest reports kept per user (older ones are deleted)
    "backup_dir": "",                      # where backups are written ('' = Cyber Hub's own data folder)
    "backup_keep": 10,                     # newest automatic backups kept (manual ones are never pruned)
    "backup_include_quarantine": False,    # also copy the encrypted quarantine vault into backups
}

CHOICES: dict[str, set[str]] = {
    "theme": {"dark", "light"},
    "scan_auto_quarantine": {"off", "high", "all"},
    "rtp_action": {"quarantine", "alert"},
    "rtp_usb_scan": {"off", "notify", "auto"},
    "heuristics_sensitivity": {"low", "medium", "high"},
    "cloud_auto_lookup": {"off", "executables", "all"},
    "pv_breach_check": {"off", "manual", "auto"},
    "dp_encrypt_original": {"shred", "delete", "keep"},
    "dp_shred_method": {"zero", "random", "dod3", "random3"},
    "intel_auto_block": {"off", "c2", "high"},
    "platform_breach_check": {"off", "manual", "auto"},
    "notify_center_min_severity": {"low", "medium", "high", "critical"},
    "notify_toast_min_severity": {"low", "medium", "high", "critical"},
    "report_default_format": {"pdf", "html", "csv", "json"},
}

# list settings whose items must come from a fixed set
LIST_CHOICES: dict[str, set[str]] = {
    "cloud_providers": {"virustotal", "malwarebazaar"},
    "dp_finder_types": {"private_key", "password_export", "api_key", "password", "credit_card", "cnic", "iban",
                        "ssn", "crypto_wallet", "contacts"},
    "intel_online_providers": {"virustotal", "abusech", "abuseipdb"},
    "platform_breach_providers": {"xposedornot", "hibp"},
    "notify_muted_sources": {"threat", "realtime", "firewall", "network", "device", "passwords", "data", "web",
                             "intel", "platforms", "monitor", "account", "startup", "scheduler", "reports", "system"},
}

RANGES: dict[str, tuple[int, int]] = {
    "metrics_interval_seconds": (1, 60),
    "metrics_retention_days": (1, 365),
    "activity_retention_days": (1, 3650),
    "session_timeout_minutes": (5, 7 * 24 * 60),
    "auto_lock_minutes": (0, 240),
    "max_failed_logins": (3, 20),
    "lockout_minutes": (1, 1440),
    "monitor_check_interval_seconds": (2, 300),
    "alert_cpu_percent": (50, 100),
    "alert_memory_percent": (50, 100),
    "alert_disk_percent": (50, 99),
    "alert_gpu_percent": (50, 100),
    "alert_temperature_c": (50, 110),
    "alert_sustain_seconds": (0, 3600),
    "startup_watch_interval_minutes": (1, 1440),
    "scan_max_file_mb": (1, 8192),
    "scan_archive_max_mb": (1, 2048),
    "quarantine_retention_days": (0, 3650),
    "quarantine_max_mb": (64, 102400),
    "rtp_max_file_mb": (1, 4096),
    "rtp_burst_threshold": (0, 100000),
    "rtp_event_retention": (100, 100000),
    "rules_max_file_mb": (1, 256),
    "cloud_vt_min_detections": (1, 30),
    "cloud_vt_per_minute": (1, 1000),
    "cloud_vt_per_day": (1, 1000000),
    "cloud_cache_days": (1, 365),
    "firewall_watch_interval_minutes": (1, 1440),
    "firewall_log_max_mb": (1, 512),
    "firewall_snapshot_keep": (1, 200),
    "network_watch_interval_minutes": (1, 1440),
    "network_many_hosts": (20, 5000),
    "network_sample_retention_days": (1, 365),
    "lan_auto_scan_minutes": (0, 1440),
    "posture_watch_interval_minutes": (5, 1440),
    "posture_signature_max_age_days": (1, 30),
    "posture_update_max_age_days": (7, 365),
    "posture_scan_max_age_days": (1, 365),
    "posture_score_retention_days": (7, 3650),
    "pv_auto_lock_minutes": (0, 240),
    "pv_clipboard_clear_seconds": (0, 600),
    "pv_old_password_days": (30, 3650),
    "pv_trash_days": (1, 365),
    "pv_score_retention_days": (7, 3650),
    "dp_cleaner_temp_min_age_hours": (0, 720),
    "dp_finder_max_file_mb": (1, 512),
    "dp_history_days": (7, 3650),
    "web_scan_timeout_seconds": (2, 60),
    "web_cert_warn_days": (1, 90),
    "web_monitor_interval_hours": (1, 720),
    "web_osv_cache_days": (0, 30),
    "web_history_days": (7, 3650),
    "intel_update_hours": (1, 168),
    "intel_watch_interval_seconds": (15, 3600),
    "intel_cache_hours": (1, 720),
    "intel_abuseipdb_min_score": (1, 100),
    "intel_max_feed_mb": (1, 512),
    "intel_history_days": (7, 3650),
    "platform_breach_interval_hours": (24, 2160),
    "platform_catalog_update_hours": (6, 720),
    "platform_review_days": (30, 730),
    "platform_extension_watch_hours": (1, 168),
    "platform_github_sync_hours": (1, 720),
    "platform_history_days": (7, 3650),
    "notify_toast_max_per_minute": (1, 60),
    "notify_retention_days": (1, 3650),
    "scheduler_history_days": (7, 3650),
    "score_history_days": (7, 3650),
    "score_alert_drop": (0, 100),
    "report_default_days": (1, 365),
    "report_keep": (1, 1000),
    "backup_keep": (1, 500),
}

# Turning protection down needs a Cyber Hub administrator (like Windows Security asking for admin).
ADMIN_KEYS = {"realtime_protection", "rtp_watch_default_folders", "rtp_watched_paths", "rtp_action",
              "rtp_max_file_mb", "rtp_watch_removable", "rtp_usb_scan", "scan_auto_quarantine",
              "scan_excluded_paths", "scan_excluded_extensions",
              "yara_enabled", "heuristics_enabled", "heuristics_sensitivity", "heuristics_auto_quarantine",
              "rules_max_file_mb", "rules_scan_archives", "cloud_lookup_enabled", "cloud_auto_lookup",
              "cloud_providers", "cloud_vt_min_detections", "cloud_add_to_signatures",
              "firewall_watch_enabled", "firewall_alert_new_allow_rules", "firewall_log_path",
              "network_watch_enabled", "network_alert_new_listeners", "network_alert_suspicious",
              "network_many_hosts", "network_extra_suspicious_ports", "lan_alert_new_devices", "lan_arp_watch",
              "wifi_alert_insecure",
              "posture_watch_enabled", "posture_alert_regressions", "posture_signature_max_age_days",
              "posture_update_max_age_days", "posture_scan_max_age_days",
              "pv_auto_lock_minutes", "pv_lock_with_session", "pv_clipboard_clear_seconds",
              "dp_decrypt_scan", "dp_finder_alert",
              "web_monitor_enabled", "web_alert_regressions", "web_dev_watch", "web_check_exposed_files",
              "web_secret_scan", "web_dep_online",
              "intel_auto_update", "intel_update_hours", "intel_watch_connections", "intel_auto_block",
              "intel_hashes_to_signatures", "intel_retro_hunt", "intel_online_lookup", "intel_online_providers",
              "platform_breach_check", "platform_breach_providers", "platform_catalog_auto_update",
              "platform_alert_breaches", "platform_extension_audit",
              "scheduler_enabled", "backup_dir", "backup_keep", "backup_include_quarantine"}

# 'HH:MM' settings (Part 17 quiet hours)
TIME_KEYS = {"notify_quiet_start", "notify_quiet_end"}

# list settings whose items must be port numbers (Part 10)
PORT_LIST_KEYS = {"network_extra_suspicious_ports"}

LIST_LIMITS = (500, 1024)                  # max items, max chars per item for list settings


def _valid_hhmm(v: str) -> bool:
    parts = v.split(":")
    return (len(parts) == 2 and all(p.isdigit() and len(p) == 2 for p in parts)
            and int(parts[0]) < 24 and int(parts[1]) < 60)


class SettingsStore:
    def __init__(self, db: Database):
        self.db = db

    def all(self) -> dict[str, Any]:
        out = dict(DEFAULTS)
        for row in self.db.fetchall("SELECT key, value FROM settings"):
            out[row["key"]] = json.loads(row["value"])
        return out

    def get(self, key: str) -> Any:
        row = self.db.fetchone("SELECT value FROM settings WHERE key=?", (key,))
        if row:
            return json.loads(row["value"])
        if key in DEFAULTS:
            return DEFAULTS[key]
        raise KeyError(key)

    def update(self, changes: dict[str, Any]) -> dict[str, Any]:
        unknown = [k for k in changes if k not in DEFAULTS]
        if unknown:
            raise KeyError(f"Unknown setting(s): {', '.join(unknown)}")
        for k, v in changes.items():
            expected = type(DEFAULTS[k])
            ok = isinstance(v, expected) and not (expected is int and isinstance(v, bool))
            if not ok:
                raise TypeError(f"Setting '{k}' must be {expected.__name__}")
            if expected is list:
                if len(v) > LIST_LIMITS[0] or not all(isinstance(x, str) and 0 < len(x) <= LIST_LIMITS[1] for x in v):
                    raise TypeError(f"Setting '{k}' must be a list of up to {LIST_LIMITS[0]} short strings")
            if k in PORT_LIST_KEYS and not all(x.strip().isdigit() and 1 <= int(x) <= 65535 for x in v):
                raise ValueError(f"{k} items must be port numbers 1-65535 (as text, e.g. \"8888\")")
            if k in LIST_CHOICES and not set(v) <= LIST_CHOICES[k]:
                raise ValueError(f"{k} items must be from: {', '.join(sorted(LIST_CHOICES[k]))}")
            if k in TIME_KEYS and not _valid_hhmm(v):
                raise ValueError(f"{k} must be a time like 22:00")
            if expected is str and len(v) > LIST_LIMITS[1]:
                raise ValueError(f"{k} is too long")
            if k in CHOICES and v not in CHOICES[k]:
                raise ValueError(f"{k} must be one of: {', '.join(sorted(CHOICES[k]))}")
            if k in RANGES and not RANGES[k][0] <= v <= RANGES[k][1]:
                raise ValueError(f"{k} must be between {RANGES[k][0]} and {RANGES[k][1]}")
        with self.db.tx() as c:
            for k, v in changes.items():
                c.execute(
                    "INSERT INTO settings(key, value, updated_at) VALUES (?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                    (k, json.dumps(v)),
                )
        return self.all()

    def reset(self) -> dict[str, Any]:
        self.db.execute("DELETE FROM settings")
        return self.all()

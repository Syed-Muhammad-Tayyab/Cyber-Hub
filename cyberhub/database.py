"""
Cyber Hub Backend - Database layer (SQLite)
Developed by Syed Muhammad Tayyab

One local SQLite file with versioned migrations. Every later part appends
its tables to MIGRATIONS, so existing user data is upgraded in place.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .logger import get_logger

log = get_logger("db")

# (version, description, SQL). Never edit a released migration - add a new one.
MIGRATIONS: list[tuple[int, str, str]] = [
    (
        1,
        "core: activity log + settings",
        """
        CREATE TABLE IF NOT EXISTS activity_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            category   TEXT    NOT NULL,          -- system | scan | network | account | ...
            severity   TEXT    NOT NULL DEFAULT 'info',  -- info | low | medium | high | critical
            title      TEXT    NOT NULL,
            detail     TEXT,
            source     TEXT    NOT NULL DEFAULT 'backend'
        );
        CREATE INDEX IF NOT EXISTS idx_activity_ts  ON activity_log(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_activity_cat ON activity_log(category);

        CREATE TABLE IF NOT EXISTS settings (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,             -- JSON-encoded
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        """,
    ),
    (
        2,
        "core: system metric snapshots (feeds history graphs)",
        """
        CREATE TABLE IF NOT EXISTS metric_snapshots (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            cpu       REAL NOT NULL,
            memory    REAL NOT NULL,
            disk      REAL NOT NULL,
            net_sent  INTEGER NOT NULL,
            net_recv  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_metric_ts ON metric_snapshots(ts DESC);
        """,
    ),
    (
        3,
        "part 2: accounts, sessions, login history, recovery codes",
        """
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name    TEXT NOT NULL,
            email           TEXT,
            password_hash   TEXT NOT NULL,          -- scrypt$n$r$p$salt$hash
            pin_hash        TEXT,                   -- optional quick-unlock PIN
            role            TEXT NOT NULL DEFAULT 'admin',
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until    TEXT,
            password_changed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            last_login_at   TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash   TEXT NOT NULL UNIQUE,      -- SHA-256 of the session token
            created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            expires_at   TEXT NOT NULL,
            is_locked    INTEGER NOT NULL DEFAULT 0,
            device       TEXT,
            revoked      INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

        CREATE TABLE IF NOT EXISTS login_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            username  TEXT NOT NULL,
            success   INTEGER NOT NULL,
            method    TEXT NOT NULL,                -- password | pin | recovery
            reason    TEXT,
            device    TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_login_ts ON login_history(ts DESC);

        CREATE TABLE IF NOT EXISTS recovery_codes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash  TEXT NOT NULL,
            used_at    TEXT
        );
        """,
    ),
    (
        4,
        "part 3: live monitor - extended history columns + resource alerts",
        """
        ALTER TABLE metric_snapshots ADD COLUMN swap           REAL;
        ALTER TABLE metric_snapshots ADD COLUMN disk_read_mbs  REAL;
        ALTER TABLE metric_snapshots ADD COLUMN disk_write_mbs REAL;
        ALTER TABLE metric_snapshots ADD COLUMN gpu            REAL;
        ALTER TABLE metric_snapshots ADD COLUMN cpu_temp       REAL;

        CREATE TABLE IF NOT EXISTS resource_alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            metric          TEXT NOT NULL,          -- cpu | memory | disk_space | gpu | temperature
            target          TEXT NOT NULL,          -- 'cpu', 'memory', 'C:\\', ...
            severity        TEXT NOT NULL,          -- medium | high
            status          TEXT NOT NULL DEFAULT 'active',   -- active | resolved
            threshold       REAL NOT NULL,
            value           REAL NOT NULL,          -- latest reading
            peak            REAL NOT NULL,
            message         TEXT NOT NULL,
            started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            resolved_at     TEXT,
            acknowledged_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON resource_alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_started ON resource_alerts(started_at DESC);
        """,
    ),
    (
        5,
        "part 4: processes & startup - signature cache, action log, startup tracking",
        """
        CREATE TABLE IF NOT EXISTS file_signatures (
            path          TEXT PRIMARY KEY COLLATE NOCASE,
            size          INTEGER NOT NULL,
            mtime         REAL NOT NULL,
            status        TEXT NOT NULL,          -- signed | unsigned | tampered | untrusted | unsupported | error
            publisher     TEXT,
            issuer        TEXT,
            thumbprint    TEXT,
            cert_expires  TEXT,
            is_os_binary  INTEGER NOT NULL DEFAULT 0,
            checked_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );

        CREATE TABLE IF NOT EXISTS process_actions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            username  TEXT NOT NULL,
            action    TEXT NOT NULL,              -- ended | force-killed | suspended | resumed | priority -> x
            pid       INTEGER NOT NULL,
            name      TEXT NOT NULL,
            exe       TEXT,
            result    TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_proc_actions_ts ON process_actions(ts DESC);

        CREATE TABLE IF NOT EXISTS startup_seen (
            id          TEXT PRIMARY KEY,         -- stable hash of source + location + name
            source      TEXT NOT NULL,
            name        TEXT NOT NULL,
            command     TEXT,
            first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            removed_at  TEXT,
            accepted    INTEGER NOT NULL DEFAULT 0,   -- 1 = baseline or reviewed by the user
            alerted_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS startup_changes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            item_id   TEXT NOT NULL,
            source    TEXT NOT NULL,
            name      TEXT NOT NULL,
            action    TEXT NOT NULL,              -- enable | disable
            previous  TEXT,                       -- JSON: state before the change (service start type...)
            username  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_startup_changes_item ON startup_changes(item_id);
        """,
    ),
    (
        6,
        "part 5: antivirus scan engine - signature DB, scan jobs, detections, hash cache",
        """
        CREATE TABLE IF NOT EXISTS malware_signatures (
            hash        TEXT PRIMARY KEY COLLATE NOCASE,   -- lowercase hex
            hash_type   TEXT NOT NULL,                     -- sha256 | sha1 | md5
            name        TEXT NOT NULL,                     -- threat name shown to the user
            family      TEXT,
            severity    TEXT NOT NULL DEFAULT 'high',      -- low | medium | high | critical
            source      TEXT NOT NULL DEFAULT 'user',      -- builtin | import:<file> | user
            enabled     INTEGER NOT NULL DEFAULT 1,
            added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_sig_source ON malware_signatures(source);

        CREATE TABLE IF NOT EXISTS scan_jobs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            kind            TEXT NOT NULL,                 -- quick | full | custom
            status          TEXT NOT NULL,                 -- queued | running | paused | completed | cancelled | failed | interrupted
            targets         TEXT NOT NULL,                 -- JSON list
            options         TEXT NOT NULL DEFAULT '{}',    -- JSON
            started_by      TEXT,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            started_at      TEXT,
            finished_at     TEXT,
            files_total     INTEGER NOT NULL DEFAULT 0,
            files_scanned   INTEGER NOT NULL DEFAULT 0,
            files_skipped   INTEGER NOT NULL DEFAULT 0,
            archive_entries INTEGER NOT NULL DEFAULT 0,
            bytes_scanned   INTEGER NOT NULL DEFAULT 0,
            threats_found   INTEGER NOT NULL DEFAULT 0,
            errors          INTEGER NOT NULL DEFAULT 0,
            duration_seconds REAL NOT NULL DEFAULT 0,
            message         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at DESC);

        CREATE TABLE IF NOT EXISTS scan_detections (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id         INTEGER REFERENCES scan_jobs(id) ON DELETE SET NULL,
            detected_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            path           TEXT NOT NULL,
            archive_member TEXT,                           -- file inside a .zip, if any
            size           INTEGER,
            sha256         TEXT,
            md5            TEXT,
            threat_name    TEXT NOT NULL,
            severity       TEXT NOT NULL,
            method         TEXT NOT NULL,                  -- hash | pattern (+ Part 8: yara | heuristic | cloud)
            status         TEXT NOT NULL DEFAULT 'active', -- active | dismissed | resolved | superseded (+ Part 6 states)
            status_changed_at TEXT,
            status_by      TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_det_job ON scan_detections(job_id);
        CREATE INDEX IF NOT EXISTS idx_det_status ON scan_detections(status);
        CREATE INDEX IF NOT EXISTS idx_det_path ON scan_detections(path);

        CREATE TABLE IF NOT EXISTS file_hash_cache (
            path      TEXT PRIMARY KEY,
            size      INTEGER NOT NULL,
            mtime     REAL NOT NULL,
            sha256    TEXT NOT NULL,
            sha1      TEXT NOT NULL,
            md5       TEXT NOT NULL,
            hashed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        """,
    ),
    (
        7,
        "part 6: quarantine vault, allowed threats, threat history events",
        """
        ALTER TABLE scan_detections ADD COLUMN quarantine_id TEXT;
        CREATE INDEX IF NOT EXISTS idx_det_sha ON scan_detections(sha256);

        CREATE TABLE IF NOT EXISTS quarantine_items (
            id              TEXT PRIMARY KEY,                -- random 32-hex id, also the vault file name
            status          TEXT NOT NULL DEFAULT 'quarantined', -- quarantined | restored | deleted | missing
            original_path   TEXT NOT NULL,
            file_name       TEXT NOT NULL,
            size            INTEGER NOT NULL,
            sha256          TEXT NOT NULL,
            md5             TEXT NOT NULL,
            mtime           REAL,
            atime           REAL,
            mode            INTEGER,
            zone_identifier TEXT,                            -- Windows 'Mark of the Web' (downloaded-from info)
            threat_name     TEXT NOT NULL,
            severity        TEXT NOT NULL,
            detection_id    INTEGER REFERENCES scan_detections(id) ON DELETE SET NULL,
            source          TEXT NOT NULL DEFAULT 'manual',  -- manual | detection | auto | realtime
            original_state  TEXT NOT NULL DEFAULT 'removed', -- removed | pending_reboot
            stored_size     INTEGER NOT NULL DEFAULT 0,      -- encrypted file size on disk
            wrapped_key     TEXT,                            -- per-item AES key, encrypted with the vault key (NULL once deleted)
            note            TEXT,
            quarantined_by  TEXT NOT NULL,
            quarantined_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            status_changed_at TEXT,
            status_by       TEXT,
            restored_path   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_q_status ON quarantine_items(status);
        CREATE INDEX IF NOT EXISTS idx_q_at ON quarantine_items(quarantined_at DESC);

        CREATE TABLE IF NOT EXISTS allowed_threats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            kind        TEXT NOT NULL,                       -- sha256 | threat_name
            value       TEXT NOT NULL COLLATE NOCASE,
            threat_name TEXT,
            note        TEXT,
            added_by    TEXT NOT NULL,
            added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            hits        INTEGER NOT NULL DEFAULT 0,          -- times a scan skipped a match because of this entry
            last_hit_at TEXT,
            UNIQUE(kind, value)
        );

        CREATE TABLE IF NOT EXISTS threat_events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            detection_id  INTEGER,
            quarantine_id TEXT,
            action        TEXT NOT NULL,   -- detected | quarantined | restored | removed | purged | allowed | unallowed | dismissed | resolved | superseded
            username      TEXT,
            detail        TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_tev_det ON threat_events(detection_id);
        CREATE INDEX IF NOT EXISTS idx_tev_q ON threat_events(quarantine_id);
        CREATE INDEX IF NOT EXISTS idx_tev_ts ON threat_events(ts DESC);

        -- history for detections recorded by Part 5
        INSERT INTO threat_events(ts, detection_id, action, detail)
            SELECT detected_at, id, 'detected', 'found by ' || method || ' match' FROM scan_detections;
        INSERT INTO threat_events(ts, detection_id, action, username)
            SELECT status_changed_at, id, status, status_by FROM scan_detections
            WHERE status != 'active' AND status_changed_at IS NOT NULL;
        """,
    ),
    (
        8,
        "part 7: real-time protection - file events, USB devices, daily counters",
        """
        CREATE TABLE IF NOT EXISTS realtime_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            path            TEXT NOT NULL,
            event           TEXT NOT NULL,              -- created | modified | moved | usb_scan
            origin          TEXT NOT NULL,              -- folder | usb
            watch_root      TEXT,
            status          TEXT NOT NULL,              -- clean | infected | skipped | error
            reason          TEXT,
            threat_name     TEXT,
            severity        TEXT,
            detection_id    INTEGER,
            quarantine_id   TEXT,
            action          TEXT,                       -- quarantined | alerted | allowed | failed | none
            size            INTEGER,
            sha256          TEXT,
            downloaded_from TEXT,
            duration_ms     INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_rte_ts ON realtime_events(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_rte_status ON realtime_events(status);

        CREATE TABLE IF NOT EXISTS usb_devices (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            device_key    TEXT NOT NULL UNIQUE,          -- volume serial / fs UUID, or label+size+fs
            label         TEXT,
            serial        TEXT,
            model         TEXT,
            bus           TEXT,
            fstype        TEXT,
            total_bytes   INTEGER,
            first_seen    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            last_seen     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            last_mount    TEXT,
            insert_count  INTEGER NOT NULL DEFAULT 0,
            connected     INTEGER NOT NULL DEFAULT 0,
            trusted       INTEGER NOT NULL DEFAULT 0,
            warnings      TEXT,                           -- JSON list from the last insertion check
            last_scan_job INTEGER
        );

        CREATE TABLE IF NOT EXISTS realtime_daily (
            day           TEXT PRIMARY KEY,               -- YYYY-MM-DD (UTC)
            files_scanned INTEGER NOT NULL DEFAULT 0,
            threats       INTEGER NOT NULL DEFAULT 0,
            skipped       INTEGER NOT NULL DEFAULT 0,
            usb_inserts   INTEGER NOT NULL DEFAULT 0,
            bursts        INTEGER NOT NULL DEFAULT 0
        );
        """,
    ),    (
        9,
        "part 8: YARA rule sets, rule/heuristic verdict cache, online hash reputation",
        """
        ALTER TABLE scan_detections ADD COLUMN details TEXT;      -- JSON: YARA rule / heuristic flags / cloud verdict
        CREATE INDEX IF NOT EXISTS idx_det_method ON scan_detections(method);

        CREATE TABLE IF NOT EXISTS yara_rule_sets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
            origin      TEXT NOT NULL DEFAULT 'user',          -- builtin | user | import
            source      TEXT NOT NULL,
            sha256      TEXT NOT NULL,
            enabled     INTEGER NOT NULL DEFAULT 1,
            status      TEXT,                                  -- ok | error | unsupported (needs native YARA)
            error       TEXT,
            rule_count  INTEGER NOT NULL DEFAULT 0,
            rule_names  TEXT,                                  -- JSON list
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            created_by  TEXT,
            updated_at  TEXT,
            updated_by  TEXT
        );

        CREATE TABLE IF NOT EXISTS rule_verdict_cache (
            sha256      TEXT NOT NULL,
            name_key    TEXT NOT NULL,                         -- lower-case file name (name tricks are part of the verdict)
            version     TEXT NOT NULL,                         -- rules version | heuristics version + sensitivity
            result      TEXT NOT NULL,                         -- JSON list of verdicts ([] = clean)
            checked_at  TEXT NOT NULL,
            PRIMARY KEY (sha256, name_key)
        );

        CREATE TABLE IF NOT EXISTS hash_reputation (
            hash         TEXT NOT NULL,
            provider     TEXT NOT NULL,                        -- virustotal | malwarebazaar
            verdict      TEXT NOT NULL,                        -- malicious | suspicious | clean | unknown
            malicious    INTEGER,
            total        INTEGER,
            threat_label TEXT,
            sha256       TEXT,
            permalink    TEXT,
            checked_at   TEXT NOT NULL,
            raw          TEXT,
            PRIMARY KEY (hash, provider)
        );
        CREATE INDEX IF NOT EXISTS idx_rep_verdict ON hash_reputation(verdict);

        CREATE TABLE IF NOT EXISTS cloud_api_keys (
            provider    TEXT PRIMARY KEY,
            wrapped     TEXT NOT NULL,                         -- AES-GCM with the vault master key
            hint        TEXT,
            updated_at  TEXT,
            updated_by  TEXT
        );

        CREATE TABLE IF NOT EXISTS cloud_usage (
            day         TEXT NOT NULL,
            provider    TEXT NOT NULL,
            requests    INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (day, provider)
        );
        """,
    ),
    (
        10,
        "part 9: firewall blocks, firewall events, rule-watch baseline, policy snapshots",
        """
        CREATE TABLE IF NOT EXISTS firewall_blocks (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            kind          TEXT NOT NULL,                 -- app | ip | port | allow_app
            target        TEXT NOT NULL,                 -- program path | address list | port list
            target_key    TEXT NOT NULL,                 -- normalised target for duplicate checks
            label         TEXT,
            direction     TEXT NOT NULL,                 -- in | out | both
            protocol      TEXT NOT NULL DEFAULT 'any',   -- any | tcp | udp | both
            profiles      TEXT,                          -- JSON list
            rule_ids      TEXT NOT NULL DEFAULT '[]',    -- JSON list of OS rule ids
            specs         TEXT NOT NULL DEFAULT '[]',    -- JSON rule specs (used to repair a removed block)
            reason        TEXT,
            sha256        TEXT,
            status        TEXT NOT NULL DEFAULT 'active', -- pending | active | missing | expired | removed
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            created_by    TEXT,
            expires_at    TEXT,                          -- NULL = until removed
            ended_at      TEXT,
            ended_by      TEXT,
            last_verified TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_fwb_status ON firewall_blocks(status);
        CREATE INDEX IF NOT EXISTS idx_fwb_key ON firewall_blocks(kind, target_key);

        CREATE TABLE IF NOT EXISTS firewall_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            kind         TEXT NOT NULL,      -- block_created | rule_added | profile_changed | firewall_off | ...
            severity     TEXT NOT NULL DEFAULT 'info',
            title        TEXT NOT NULL,
            detail       TEXT,
            rule_id      TEXT,
            block_id     INTEGER,
            username     TEXT,
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_fwe_ts ON firewall_events(ts DESC);

        CREATE TABLE IF NOT EXISTS firewall_rule_seen (
            rule_id     TEXT PRIMARY KEY,
            name        TEXT,
            direction   TEXT,
            action      TEXT,
            enabled     INTEGER,
            fingerprint TEXT NOT NULL,
            first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            present     INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS firewall_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL                          -- JSON
        );

        CREATE TABLE IF NOT EXISTS firewall_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            file        TEXT NOT NULL,
            backend     TEXT NOT NULL,
            note        TEXT,
            size        INTEGER,
            sha256      TEXT,
            rules       INTEGER,
            auto        INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            created_by  TEXT
        );
        """,
    ),
    (
        11,
        "part 10: network events, traffic samples, listener baseline, LAN networks + devices, MAC vendors, Wi-Fi history",
        """
        CREATE TABLE IF NOT EXISTS network_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            kind         TEXT NOT NULL,      -- new_listener | suspicious_connection | new_device | gateway_changed | ...
            severity     TEXT NOT NULL DEFAULT 'info',
            title        TEXT NOT NULL,
            detail       TEXT,
            ref          TEXT,               -- finding / alert key
            username     TEXT,
            data         TEXT,               -- JSON
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_nete_ts ON network_events(ts DESC);

        CREATE TABLE IF NOT EXISTS network_samples (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            established  INTEGER NOT NULL DEFAULT 0,
            listening    INTEGER NOT NULL DEFAULT 0,
            internet     INTEGER NOT NULL DEFAULT 0,
            lan          INTEGER NOT NULL DEFAULT 0,
            local        INTEGER NOT NULL DEFAULT 0,
            udp          INTEGER NOT NULL DEFAULT 0,
            syn_sent     INTEGER NOT NULL DEFAULT 0,
            processes    INTEGER NOT NULL DEFAULT 0,
            remote_hosts INTEGER NOT NULL DEFAULT 0,
            flagged      INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_nets_ts ON network_samples(ts);

        CREATE TABLE IF NOT EXISTS network_listeners_seen (
            key         TEXT PRIMARY KEY,    -- proto|port|program
            proto       TEXT NOT NULL,
            port        INTEGER NOT NULL,
            program     TEXT,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            present     INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS network_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL                -- JSON
        );

        CREATE TABLE IF NOT EXISTS lan_networks (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            key               TEXT NOT NULL UNIQUE,   -- sha1(ssid or 'wired' | subnet)
            name              TEXT NOT NULL,
            kind              TEXT NOT NULL,          -- wifi | wired
            ssid              TEXT,
            subnet            TEXT NOT NULL,
            gateway_ip        TEXT,
            gateway_mac       TEXT,                   -- known-good router hardware address
            gateway_alert_mac TEXT,                   -- a different address seen (ARP spoofing alert)
            gateway_alert_at  TEXT,
            interface         TEXT,
            home              INTEGER NOT NULL DEFAULT 0,
            baseline_at       TEXT,
            last_scan         TEXT,
            first_seen        TEXT NOT NULL,
            last_seen         TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lan_devices (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id     INTEGER NOT NULL REFERENCES lan_networks(id) ON DELETE CASCADE,
            mac            TEXT NOT NULL,
            ip             TEXT NOT NULL,
            hostname       TEXT,
            nb_name        TEXT,
            vendor         TEXT,
            device_type    TEXT,
            open_ports     TEXT,                    -- JSON list (NULL = never port-scanned)
            randomized_mac INTEGER NOT NULL DEFAULT 0,
            label          TEXT,
            notes          TEXT,
            trusted        INTEGER NOT NULL DEFAULT 0,
            source         TEXT,                    -- passive | scan
            first_seen     TEXT NOT NULL,
            last_seen      TEXT NOT NULL,
            UNIQUE(network_id, mac)
        );

        CREATE TABLE IF NOT EXISTS oui_vendors (
            prefix TEXT PRIMARY KEY,               -- AABBCC
            vendor TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS wifi_connections (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid       TEXT,
            bssid      TEXT,
            auth       TEXT,
            cipher     TEXT,
            rating     TEXT,
            signal     INTEGER,
            channel    INTEGER,
            band       TEXT,
            interface  TEXT,
            first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            last_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        """,
    ),
    (
        12,
        "part 11: security posture - events, check states (watch baseline), applied fixes + undo, ignored checks, "
        "score history",
        """
        CREATE TABLE IF NOT EXISTS posture_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            kind         TEXT NOT NULL,      -- regression | resolved | exclusion_added | fix_applied | ...
            severity     TEXT NOT NULL DEFAULT 'info',
            title        TEXT NOT NULL,
            detail       TEXT,
            check_id     TEXT,
            username     TEXT,
            data         TEXT,               -- JSON
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_poste_ts ON posture_events(ts DESC);

        CREATE TABLE IF NOT EXISTS posture_check_state (
            check_id     TEXT PRIMARY KEY,
            status       TEXT NOT NULL,      -- pass | fail | unknown
            severity     TEXT NOT NULL,
            title        TEXT NOT NULL,
            value        TEXT,
            since        TEXT NOT NULL,      -- when it last changed status
            last_checked TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posture_changes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            check_id        TEXT NOT NULL,
            title           TEXT NOT NULL,
            label           TEXT NOT NULL,
            ops             TEXT NOT NULL,   -- JSON list of allow-listed changes that were made
            before          TEXT NOT NULL,   -- JSON list of the previous values (for undo)
            username        TEXT,
            status          TEXT NOT NULL,   -- applied | not_applied | failed | reverted
            reboot_required INTEGER NOT NULL DEFAULT 0,
            message         TEXT,
            reverted_at     TEXT,
            reverted_by     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_postc_ts ON posture_changes(ts DESC);

        CREATE TABLE IF NOT EXISTS posture_ignored (
            check_id   TEXT PRIMARY KEY,
            reason     TEXT,
            username   TEXT,
            until      TEXT,                 -- NULL = until switched back on
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );

        CREATE TABLE IF NOT EXISTS posture_scores (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            score      INTEGER NOT NULL,
            grade      TEXT NOT NULL,
            passed     INTEGER NOT NULL DEFAULT 0,
            failed     INTEGER NOT NULL DEFAULT 0,
            unknown    INTEGER NOT NULL DEFAULT 0,
            categories TEXT                  -- JSON {category: score}
        );
        CREATE INDEX IF NOT EXISTS idx_posts_ts ON posture_scores(ts);

        CREATE TABLE IF NOT EXISTS posture_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL              -- JSON
        );
        """,
    ),
    (
        13,
        "part 12: password vault & auditor",
        """
        -- One vault per Cyber Hub user. Nothing here is readable without the master password
        -- (or the recovery key): titles, user names, URLs, notes and passwords live only inside the
        -- AES-256-GCM blobs. Deleting the Cyber Hub user deletes the vault (ON DELETE CASCADE).
        CREATE TABLE IF NOT EXISTS pv_vaults (
            user_id           INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            kdf               TEXT NOT NULL,     -- JSON {name: scrypt, n, r, p}
            salt              TEXT NOT NULL,     -- base64, master-password KDF salt
            wrapped_pw        TEXT NOT NULL,     -- vault key wrapped by the master-password key
            recovery_salt     TEXT NOT NULL,
            wrapped_recovery  TEXT NOT NULL,     -- vault key wrapped by the recovery key
            device_bound      INTEGER NOT NULL DEFAULT 0,  -- master-password key also needs this PC's vault.key
            hint              TEXT,
            created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            master_changed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            recovery_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            failed_unlocks    INTEGER NOT NULL DEFAULT 0,
            locked_until      TEXT,
            last_unlock_at    TEXT,
            last_audit        TEXT               -- JSON: score + counts only (never titles / passwords)
        );

        CREATE TABLE IF NOT EXISTS pv_items (
            id          TEXT PRIMARY KEY,         -- 32 hex
            user_id     INTEGER NOT NULL REFERENCES pv_vaults(user_id) ON DELETE CASCADE,
            type        TEXT NOT NULL,            -- login | card | note | identity
            blob        TEXT NOT NULL,            -- base64(nonce | AES-GCM(json payload)), AAD binds user + id + type
            rev         INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            deleted_at  TEXT                      -- in the trash since
        );
        CREATE INDEX IF NOT EXISTS idx_pvi_user ON pv_items(user_id, deleted_at);

        CREATE TABLE IF NOT EXISTS pv_breach (
            item_id    TEXT PRIMARY KEY REFERENCES pv_items(id) ON DELETE CASCADE,
            fp         TEXT NOT NULL,             -- keyed HMAC of the password checked (changes -> result stale)
            count      INTEGER NOT NULL,          -- times seen in breaches (0 = not found)
            checked_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pv_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
            kind         TEXT NOT NULL,           -- vault_created | unlocked | unlock_failed | lockout | breach_found ...
            severity     TEXT NOT NULL DEFAULT 'info',
            title        TEXT NOT NULL,
            detail       TEXT,
            item_id      TEXT,                    -- never the item's title: the UI resolves it while unlocked
            data         TEXT,                    -- JSON
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_pve_user ON pv_events(user_id, id DESC);

        CREATE TABLE IF NOT EXISTS pv_scores (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            score    INTEGER,
            total    INTEGER NOT NULL DEFAULT 0,
            weak     INTEGER NOT NULL DEFAULT 0,
            reused   INTEGER NOT NULL DEFAULT 0,
            breached INTEGER NOT NULL DEFAULT 0,
            old      INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_pvs_user ON pv_scores(user_id, ts);
        """,
    ),
    (
        14,
        "part 13: data protection (encryption, shredder, privacy cleaner, sensitive-file finder)",
        """
        -- Background jobs (encrypt / decrypt / shred / clean / cleaner_analyze / finder) with their results.
        -- temp = the half-written file of the job in progress, removed at the next start after a crash.
        CREATE TABLE IF NOT EXISTS dp_jobs (
            id          TEXT PRIMARY KEY,
            kind        TEXT NOT NULL,
            user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
            username    TEXT,
            status      TEXT NOT NULL,            -- running | done | failed | cancelled | interrupted
            created_at  TEXT NOT NULL,
            finished_at TEXT,
            params      TEXT,                     -- JSON (never passwords)
            progress    TEXT,                     -- JSON
            result      TEXT,                     -- JSON
            error       TEXT,
            temp        TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_dpj_created ON dp_jobs(created_at DESC);

        -- Files Cyber Hub encrypted (.chx). source_path is NULL when the name was hidden.
        CREATE TABLE IF NOT EXISTS dp_encrypted (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
            path         TEXT NOT NULL,
            source_path  TEXT,
            mode         TEXT NOT NULL,           -- password | device
            size         INTEGER,
            hidden_name  INTEGER NOT NULL DEFAULT 0,
            job_id       TEXT,
            status       TEXT NOT NULL DEFAULT 'encrypted',   -- encrypted | decrypted
            created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            decrypted_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_dpe_path ON dp_encrypted(path);

        -- Sensitive-file finder results: masked samples only, never the full card / CNIC / key.
        CREATE TABLE IF NOT EXISTS dp_findings (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id           INTEGER REFERENCES users(id) ON DELETE CASCADE,
            path              TEXT NOT NULL,
            name              TEXT NOT NULL,
            size              INTEGER,
            mtime             REAL,
            severity          TEXT NOT NULL,
            points            INTEGER NOT NULL DEFAULT 0,
            types             TEXT NOT NULL,      -- JSON {type: {count, samples[masked], severity, kinds}}
            status            TEXT NOT NULL DEFAULT 'open',   -- open | ignored | encrypted | shredded | resolved
            note              TEXT,
            first_seen        TEXT NOT NULL,
            last_seen         TEXT NOT NULL,
            status_changed_at TEXT,
            UNIQUE(user_id, path)
        );
        CREATE INDEX IF NOT EXISTS idx_dpf_user ON dp_findings(user_id, status);

        CREATE TABLE IF NOT EXISTS dp_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
            kind         TEXT NOT NULL,
            severity     TEXT NOT NULL DEFAULT 'info',
            title        TEXT NOT NULL,
            detail       TEXT,
            data         TEXT,
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_dpev_user ON dp_events(user_id, id DESC);

        CREATE TABLE IF NOT EXISTS dp_daily (
            day             TEXT PRIMARY KEY,
            encrypted_files INTEGER NOT NULL DEFAULT 0,
            decrypted_files INTEGER NOT NULL DEFAULT 0,
            shredded_files  INTEGER NOT NULL DEFAULT 0,
            shredded_bytes  INTEGER NOT NULL DEFAULT 0,
            cleaned_files   INTEGER NOT NULL DEFAULT 0,
            cleaned_bytes   INTEGER NOT NULL DEFAULT 0,
            findings_new    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS dp_scores (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id  INTEGER REFERENCES users(id) ON DELETE CASCADE,
            score    INTEGER,
            critical INTEGER NOT NULL DEFAULT 0,
            high     INTEGER NOT NULL DEFAULT 0,
            medium   INTEGER NOT NULL DEFAULT 0,
            low      INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_dps_user ON dp_scores(user_id, ts);

        CREATE TABLE IF NOT EXISTS dp_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL              -- JSON
        );
        """,
    ),
    (
        15,
        "part 14: website / developer scanner (targets, scans, vulnerability database, events)",
        """
        -- Saved websites / project folders (monitor = re-scan on a schedule and alert on changes).
        CREATE TABLE IF NOT EXISTS web_targets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
            kind            TEXT NOT NULL,            -- site | project
            target          TEXT NOT NULL,            -- normalized URL or folder path
            label           TEXT,
            owner_confirmed INTEGER NOT NULL DEFAULT 0,  -- "I own / manage this site" -> active checks allowed
            monitor         INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            last_scan_id    TEXT,
            last_scan_at    TEXT,
            last_score      INTEGER,
            last_grade      TEXT,
            last_error      TEXT,
            cert_not_after  TEXT,
            UNIQUE(user_id, kind, target)
        );

        -- Every scan (also the job record: running / done / failed / cancelled / interrupted).
        CREATE TABLE IF NOT EXISTS web_scans (
            id          TEXT PRIMARY KEY,
            user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
            username    TEXT,
            target_id   INTEGER REFERENCES web_targets(id) ON DELETE SET NULL,
            kind        TEXT NOT NULL,            -- site | project | vulndb
            target      TEXT NOT NULL,
            trigger     TEXT NOT NULL DEFAULT 'manual',   -- manual | monitor
            status      TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            finished_at TEXT,
            params      TEXT,                     -- JSON
            progress    TEXT,                     -- JSON
            result      TEXT,                     -- JSON (findings, facts - never page bodies or cookie values)
            score       INTEGER,
            grade       TEXT,
            critical    INTEGER NOT NULL DEFAULT 0,
            high        INTEGER NOT NULL DEFAULT 0,
            medium      INTEGER NOT NULL DEFAULT 0,
            low         INTEGER NOT NULL DEFAULT 0,
            error       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_ws_user ON web_scans(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ws_target ON web_scans(target_id, created_at DESC);

        -- OSV vulnerability records (from osv.dev lookups or an imported offline copy).
        CREATE TABLE IF NOT EXISTS web_vulns (
            id         TEXT PRIMARY KEY,           -- GHSA-... / PYSEC-... / MAL-... / CVE-...
            summary    TEXT,
            severity   TEXT NOT NULL,
            cvss       REAL,
            aliases    TEXT,                       -- JSON
            published  TEXT,
            modified   TEXT,
            data       TEXT NOT NULL,              -- JSON: compact record incl. affected ranges
            source     TEXT NOT NULL,              -- online | import
            fetched_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS web_vuln_pkgs (
            ecosystem TEXT NOT NULL,
            name      TEXT NOT NULL,               -- normalized package name
            vuln_id   TEXT NOT NULL REFERENCES web_vulns(id) ON DELETE CASCADE,
            PRIMARY KEY (ecosystem, name, vuln_id)
        );
        CREATE INDEX IF NOT EXISTS idx_wvp_vuln ON web_vuln_pkgs(vuln_id);

        -- osv.dev answers per package version (vulnerability ids), reused for web_osv_cache_days.
        CREATE TABLE IF NOT EXISTS web_osv_cache (
            key        TEXT PRIMARY KEY,           -- ecosystem|name|version
            vuln_ids   TEXT NOT NULL,              -- JSON list
            fetched_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS web_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,   -- NULL = this PC (dev servers)
            target_id    INTEGER REFERENCES web_targets(id) ON DELETE SET NULL,
            kind         TEXT NOT NULL,
            severity     TEXT NOT NULL DEFAULT 'info',
            title        TEXT NOT NULL,
            detail       TEXT,
            data         TEXT,
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_we_user ON web_events(user_id, id);

        CREATE TABLE IF NOT EXISTS web_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL              -- JSON
        );
        """,
    ),
    (
        16,
        "part 15: threat intelligence - feeds, IOCs, allow list, lookups cache, checks, events",
        """
        -- Threat feeds: built-in catalog rows (builtin=1) + custom feeds + 'local' = your own block list.
        CREATE TABLE IF NOT EXISTS intel_feeds (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            key           TEXT NOT NULL UNIQUE,
            name          TEXT NOT NULL,
            provider      TEXT,
            url           TEXT,                     -- NULL for 'local' and imported lists
            format        TEXT NOT NULL DEFAULT 'auto',
            column_spec   TEXT,                     -- csv column (name or index) for custom CSV feeds
            category      TEXT NOT NULL DEFAULT 'custom',
            severity      TEXT NOT NULL DEFAULT 'high',
            builtin       INTEGER NOT NULL DEFAULT 0,
            enabled       INTEGER NOT NULL DEFAULT 1,
            refresh_hours INTEGER,                  -- NULL = intel_update_hours
            status        TEXT NOT NULL DEFAULT 'never',  -- never | ok | error | needs_key | disabled | manual
            last_fetch_at TEXT,
            last_ok_at    TEXT,
            last_error    TEXT,
            etag          TEXT,
            last_modified TEXT,
            sha256        TEXT,
            ioc_count     INTEGER NOT NULL DEFAULT 0,
            skipped       INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            created_by    TEXT
        );

        CREATE TABLE IF NOT EXISTS intel_iocs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_id     INTEGER NOT NULL REFERENCES intel_feeds(id) ON DELETE CASCADE,
            type        TEXT NOT NULL,              -- ip | cidr | domain | url | email | md5 | sha1 | sha256
            value       TEXT NOT NULL,              -- normalised (lower-case host, punycode, canonical IP / CIDR)
            host        TEXT,                       -- url IOCs: their host (for "same site" matches)
            port        INTEGER,
            ver         INTEGER,                    -- cidr: 4 | 6
            net_lo      TEXT,                       -- cidr: first address, 32 hex chars
            net_hi      TEXT,                       -- cidr: last address
            threat      TEXT,                       -- malware family / list reference
            category    TEXT,                       -- NULL = feed category
            severity    TEXT,                       -- NULL = feed severity
            confidence  INTEGER,
            tags        TEXT,
            first_seen  TEXT,
            ref         TEXT,
            note        TEXT,                       -- your block list: why you added it
            added_by    TEXT,
            added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(feed_id, type, value)
        );
        CREATE INDEX IF NOT EXISTS idx_ioc_value ON intel_iocs(type, value);
        CREATE INDEX IF NOT EXISTS idx_ioc_host  ON intel_iocs(host) WHERE host IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_ioc_feed  ON intel_iocs(feed_id);
        CREATE INDEX IF NOT EXISTS idx_ioc_threat ON intel_iocs(threat) WHERE threat IS NOT NULL;

        -- Never flag these (false positives) - admin only.
        CREATE TABLE IF NOT EXISTS intel_allow (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            type       TEXT NOT NULL,
            value      TEXT NOT NULL,
            note       TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            created_by TEXT,
            UNIQUE(type, value)
        );

        -- Online reputation answers (VirusTotal, abuse.ch, AbuseIPDB, RDAP) reused for intel_cache_hours.
        CREATE TABLE IF NOT EXISTS intel_lookups (
            key        TEXT PRIMARY KEY,            -- provider|type|value
            provider   TEXT NOT NULL,
            verdict    TEXT NOT NULL,
            result     TEXT NOT NULL,               -- JSON
            fetched_at TEXT NOT NULL
        );

        -- Your "check this link / IP / hash" history (query strings are never stored).
        CREATE TABLE IF NOT EXISTS intel_checks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
            type       TEXT NOT NULL,
            value      TEXT NOT NULL,
            verdict    TEXT NOT NULL,
            score      INTEGER NOT NULL,
            summary    TEXT                         -- JSON: top reasons, sources
        );
        CREATE INDEX IF NOT EXISTS idx_ichk_user ON intel_checks(user_id, id);

        CREATE TABLE IF NOT EXISTS intel_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,   -- NULL = this PC (everyone sees it)
            kind         TEXT NOT NULL,             -- connection_match | retro_file | retro_download | feed_error ...
            severity     TEXT NOT NULL DEFAULT 'info',
            title        TEXT NOT NULL,
            detail       TEXT,
            ref          TEXT,                      -- dedupe key
            data         TEXT,                      -- JSON
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_ie_ts ON intel_events(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_ie_ref ON intel_events(ref);

        CREATE TABLE IF NOT EXISTS intel_api_keys (
            provider    TEXT PRIMARY KEY,            -- abuseipdb (VirusTotal + abuse.ch keys live in Part 8)
            wrapped     TEXT NOT NULL,
            hint        TEXT,
            updated_at  TEXT NOT NULL,
            updated_by  TEXT
        );

        CREATE TABLE IF NOT EXISTS intel_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL              -- JSON
        );
        """,
    ),
    (
        17,
        "part 16: social & platform accounts, checklist, e-mail breach monitor, breach catalog, connections",
        """
        -- monitored e-mail addresses (per Cyber Hub user). The address itself is sealed (AES-GCM, device key);
        -- fp = HMAC of the address for de-duplication, masked = 'sy•••@gmail.com' for lists.
        CREATE TABLE IF NOT EXISTS platform_emails (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            fp              TEXT NOT NULL,
            secret          TEXT NOT NULL,
            masked          TEXT NOT NULL,
            domain          TEXT NOT NULL,
            monitor         INTEGER NOT NULL DEFAULT 1,
            source          TEXT NOT NULL DEFAULT 'manual',   -- manual | account
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            last_checked_at TEXT,
            last_provider   TEXT,
            last_error      TEXT,
            UNIQUE(user_id, fp)
        );

        -- the accounts a user has on each platform. handle / e-mail / phone ending / notes live in `secret`.
        CREATE TABLE IF NOT EXISTS platform_accounts (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            platform            TEXT NOT NULL,                 -- catalog key or 'custom'
            custom_name         TEXT,
            custom_domain       TEXT,
            label               TEXT,
            importance          TEXT,                          -- NULL = the platform's default
            secret              TEXT NOT NULL,
            email_id            INTEGER REFERENCES platform_emails(id) ON DELETE SET NULL,
            recovery_account_id INTEGER REFERENCES platform_accounts(id) ON DELETE SET NULL,
            sso_account_id      INTEGER REFERENCES platform_accounts(id) ON DELETE SET NULL,
            vault_item_id       TEXT,                          -- Part 12 login item (random id, no content)
            vault_snapshot      TEXT,                          -- JSON flags only: reused / weak / has_totp ...
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL,
            last_reviewed_at    TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_pa_user ON platform_accounts(user_id);

        CREATE TABLE IF NOT EXISTS platform_checks (
            account_id INTEGER NOT NULL REFERENCES platform_accounts(id) ON DELETE CASCADE,
            item       TEXT NOT NULL,
            status     TEXT NOT NULL,                          -- done | not_done | not_applicable
            source     TEXT NOT NULL DEFAULT 'you',
            note       TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(account_id, item)
        );

        CREATE TABLE IF NOT EXISTS platform_email_breaches (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id      INTEGER NOT NULL REFERENCES platform_emails(id) ON DELETE CASCADE,
            name          TEXT NOT NULL,                       -- breach name (HIBP catalog name when known)
            provider      TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            acknowledged  INTEGER NOT NULL DEFAULT 0,
            UNIQUE(email_id, name)
        );

        -- public Have I Been Pwned breach list (no personal data)
        CREATE TABLE IF NOT EXISTS platform_breach_catalog (
            name          TEXT PRIMARY KEY,
            title         TEXT,
            domain        TEXT,
            breach_date   TEXT,
            added_date    TEXT,
            pwn_count     INTEGER NOT NULL DEFAULT 0,
            data_classes  TEXT,                                -- JSON list
            description   TEXT,
            flags         TEXT,                                -- JSON: verified, sensitive, spam_list, stealer_log ...
            first_seen_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_pbc_domain ON platform_breach_catalog(domain);

        -- read-only connections (GitHub token, wrapped by the Part 6 vault key)
        CREATE TABLE IF NOT EXISTS platform_connections (
            account_id   INTEGER PRIMARY KEY REFERENCES platform_accounts(id) ON DELETE CASCADE,
            provider     TEXT NOT NULL,
            wrapped      TEXT NOT NULL,
            hint         TEXT,
            scopes       TEXT,
            created_at   TEXT NOT NULL,
            last_sync_at TEXT,
            last_result  TEXT,
            last_error   TEXT
        );

        CREATE TABLE IF NOT EXISTS platform_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,   -- NULL = this PC (extensions, catalog)
            account_id   INTEGER REFERENCES platform_accounts(id) ON DELETE SET NULL,
            kind         TEXT NOT NULL,
            severity     TEXT NOT NULL DEFAULT 'info',
            title        TEXT NOT NULL,
            detail       TEXT,
            ref          TEXT,
            data         TEXT,
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_pe_ts ON platform_events(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_pe_ref ON platform_events(ref);

        CREATE TABLE IF NOT EXISTS platform_scores (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            score    INTEGER,
            accounts INTEGER NOT NULL,
            two_fa   INTEGER,
            details  TEXT
        );

        CREATE TABLE IF NOT EXISTS platform_api_keys (
            provider    TEXT PRIMARY KEY,                     -- hibp
            wrapped     TEXT NOT NULL,
            hint        TEXT,
            updated_at  TEXT NOT NULL,
            updated_by  TEXT
        );

        CREATE TABLE IF NOT EXISTS platform_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """,
    ),
    (
        18,
        "part 17: scheduler (schedules, run history) + notification center",
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,   -- NULL = this PC (everyone sees it)
            source       TEXT NOT NULL,          -- threat | realtime | firewall | network | device | passwords | data | web | intel | platforms | monitor | account | startup | scheduler | reports | system
            kind         TEXT,                   -- the module's own event kind
            severity     TEXT NOT NULL DEFAULT 'info',
            title        TEXT NOT NULL,
            detail       TEXT,
            link         TEXT,                   -- UI page that explains / fixes it
            source_table TEXT,                   -- where it came from (NULL = raised directly)
            source_id    INTEGER,
            read_at      TEXT,
            dismissed_at TEXT,
            toast        TEXT NOT NULL DEFAULT 'none'   -- none | shown | quiet | muted | rate | off | failed
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_src ON notifications(source_table, source_id)
            WHERE source_table IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, id DESC);
        CREATE INDEX IF NOT EXISTS idx_notif_unread ON notifications(read_at) WHERE read_at IS NULL;

        CREATE TABLE IF NOT EXISTS notify_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS schedules (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            action        TEXT NOT NULL,          -- scan_quick | scan_full | posture_check | security_report | backup | ...
            params        TEXT NOT NULL DEFAULT '{}',   -- JSON
            kind          TEXT NOT NULL,          -- interval | daily | weekly | monthly | once
            every_minutes INTEGER,                -- interval
            at_time       TEXT,                   -- 'HH:MM' local time (daily / weekly / monthly)
            weekdays      TEXT,                   -- weekly: '0,2,4' (Monday = 0)
            month_day     INTEGER,                -- monthly: 1-31 (clamped to the month's last day)
            run_at        TEXT,                   -- once: UTC time
            enabled       INTEGER NOT NULL DEFAULT 1,
            catch_up      INTEGER NOT NULL DEFAULT 1,   -- run after start-up if the PC was off at the planned time
            builtin       TEXT UNIQUE,            -- key of a schedule Cyber Hub created itself
            user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,   -- runs as this user (NULL = the owner)
            created_by    TEXT NOT NULL DEFAULT 'system',
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            next_run_at   TEXT,
            last_run_at   TEXT,
            last_status   TEXT,
            last_detail   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sched_due ON schedules(enabled, next_run_at);

        CREATE TABLE IF NOT EXISTS schedule_runs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            schedule_id  INTEGER REFERENCES schedules(id) ON DELETE CASCADE,
            name         TEXT NOT NULL,
            action       TEXT NOT NULL,
            trigger      TEXT NOT NULL DEFAULT 'schedule',   -- schedule | catch_up | manual
            status       TEXT NOT NULL DEFAULT 'running',    -- running | ok | failed | skipped | interrupted
            planned_at   TEXT,
            started_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            finished_at  TEXT,
            detail       TEXT,
            result       TEXT,                   -- JSON
            started_by   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sched_runs ON schedule_runs(schedule_id, id DESC);
        """,
    ),
    (
        19,
        "part 18: overall security score history",
        """
        CREATE TABLE IF NOT EXISTS security_scores (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
            score      INTEGER NOT NULL,
            grade      TEXT NOT NULL,
            status     TEXT NOT NULL,
            issues     INTEGER NOT NULL DEFAULT 0,
            critical   INTEGER NOT NULL DEFAULT 0,
            high       INTEGER NOT NULL DEFAULT 0,
            categories TEXT NOT NULL DEFAULT '{}'    -- JSON {category id: score}
        );
        CREATE INDEX IF NOT EXISTS idx_secscore ON security_scores(user_id, id DESC);
        """,
    ),
    (
        20,
        "part 19: generated reports, backups",
        """
        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
            type        TEXT NOT NULL,          -- summary | threats | device | network | accounts | activity | full
            format      TEXT NOT NULL,          -- pdf | html | csv | json
            title       TEXT NOT NULL,
            file_name   TEXT NOT NULL,
            size        INTEGER NOT NULL DEFAULT 0,
            sha256      TEXT,
            days        INTEGER NOT NULL DEFAULT 30,
            score       INTEGER,
            source      TEXT NOT NULL DEFAULT 'manual',   -- manual | schedule
            created_by  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id, id DESC);

        CREATE TABLE IF NOT EXISTS backups (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            ts             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            file_path      TEXT NOT NULL,
            file_name      TEXT NOT NULL,
            size           INTEGER NOT NULL DEFAULT 0,
            sha256         TEXT,
            mode           TEXT NOT NULL,       -- password (any PC) | device (this Windows account only)
            quarantine     INTEGER NOT NULL DEFAULT 0,
            schema_version INTEGER NOT NULL,
            app_version    TEXT NOT NULL,
            source         TEXT NOT NULL DEFAULT 'manual',   -- manual | schedule
            note           TEXT,
            created_by     TEXT NOT NULL,
            verified_at    TEXT
        );
        """,
    ),
]


class Database:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")

    # ---------------------------------------------------------------- migrate
    def migrate(self) -> int:
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, "
                "description TEXT, applied_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))"
            )
            current = self._conn.execute("SELECT COALESCE(MAX(version),0) FROM schema_version").fetchone()[0]
            for version, desc, sql in MIGRATIONS:
                if version > current:
                    log.info("Applying migration %s: %s", version, desc)
                    self._conn.executescript("BEGIN;" + sql + "COMMIT;")
                    self._conn.execute(
                        "INSERT INTO schema_version(version, description) VALUES (?,?)", (version, desc)
                    )
                    current = version
            return current

    # ---------------------------------------------------------------- helpers
    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN;")
            try:
                yield self._conn
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def fetchall(self, sql: str, params: tuple | dict = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def fetchone(self, sql: str, params: tuple | dict = ()) -> dict | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def schema_version(self) -> int:
        return self.fetchone("SELECT COALESCE(MAX(version),0) AS v FROM schema_version")["v"]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

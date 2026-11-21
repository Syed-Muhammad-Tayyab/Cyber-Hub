"""
Cyber Hub Backend - Application factory
Developed by Syed Muhammad Tayyab

Builds the FastAPI app, wires DB + services into app.state, registers
routers and starts background workers. Each future part adds its router
in register_routers().
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import APP_NAME, APP_VERSION, Settings, get_settings
from .database import Database
from .logger import get_logger, setup_logging
from .routers import (account, activity, core, dashboard, data, desktop, firewall, intel, monitor, network,
                      notifications, passwords, platforms, posture, processes, quarantine, realtime, reports, rules,
                      scanner, scheduler, settings, system, web)
from .security import SESSION_HEADER, TOKEN_HEADER, load_or_create_token
from .services import alerts, metrics_recorder, password_tools, startup
from .services.accounts import AccountService
from .services.allowlist import AllowList
from .services.backup import BackupService, apply_pending_restore, finish_restore
from .services.desktop import SHELL_HOOKS, DesktopService
from .services.activity import ActivityService
from .services.cloud_lookup import CloudLookup
from .services.data_protection import DataProtectionService, data_protection_loop
from .services.firewall import FirewallService, firewall_loop
from .services.heuristics import HeuristicEngine
from .services.malware_db import MalwareDB
from .services.network import NetworkService, network_loop
from .services.notifications import NotificationCenter, notification_loop
from .services.password_vault import PasswordVaultService, password_vault_loop
from .services.platform_accounts import PlatformService, platform_loop
from .services.posture import PostureService, posture_loop
from .services.processes import ProcessService
from .services.quarantine import QuarantineService, ThreatHistory
from .services.realtime import RealtimeService
from .services.reports import ReportService
from .services.rules_engine import Inspector, RulesEngine
from .services.scanner import ScanManager
from .services.scheduler import SchedulerService, scheduler_loop
from .services.security_score import ScoreService, score_loop
from .services.signatures import SignatureService
from .services.settings_store import SettingsStore
from .services.vault import Vault
from .services.threat_intel import ThreatIntelService, intel_loop
from .services.web_scanner import WebScannerService, web_loop


async def quarantine_housekeeping(q: QuarantineService, every_seconds: int = 3600) -> None:
    """Part 6: hourly - delete items past their retention period and keep the vault under its size limit."""
    while True:
        await asyncio.sleep(every_seconds)
        try:
            await asyncio.to_thread(q.enforce_limits)
        except Exception as e:                                                                   # pragma: no cover
            get_logger("quarantine").warning("Housekeeping failed: %s", e)


def register_routers(app: FastAPI) -> None:
    for r in (core.router, account.router, system.router, monitor.router, monitor.stream_router,
              processes.router, processes.startup_router, scanner.router, scanner.stream_router,
              quarantine.router, quarantine.threats_router, realtime.router, realtime.stream_router,
              rules.router, rules.lookup_router, firewall.router, network.router, network.stream_router,
              posture.router, passwords.router, data.router, data.stream_router, web.router, web.stream_router,
              intel.router, intel.stream_router, platforms.router, platforms.stream_router,
              notifications.router, notifications.stream_router, scheduler.router,          # Part 17
              dashboard.router, dashboard.stream_router,                                    # Part 18
              reports.router, reports.backup_router,                                        # Part 19
              desktop.about_router, desktop.router,                                         # Part 20
              activity.router, settings.router):
        app.include_router(r)


def create_app(cfg: Settings | None = None, start_workers: bool = True) -> FastAPI:
    cfg = cfg or get_settings()
    cfg.ensure_dirs()
    log = setup_logging(cfg.log_dir)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        restored = apply_pending_restore(cfg.data_dir)            # Part 19: a staged backup restore, if any
        db = Database(cfg.db_path)
        version = db.migrate()
        app.state.db = db
        app.state.settings = cfg
        app.state.api_token = load_or_create_token(cfg.token_path)
        app.state.activity = ActivityService(db)
        if restored:
            finish_restore(db, app.state.activity, cfg.data_dir)
            log.info("Backup %s restored (previous data kept in %s)", restored.get("backup_file"),
                     restored.get("safety_copy"))
        app.state.settings_store = SettingsStore(db)
        app.state.accounts = AccountService(db, app.state.settings_store, app.state.activity)
        app.state.alerts = alerts.AlertEngine(db, app.state.settings_store, app.state.activity)   # Part 3
        app.state.signatures = SignatureService(db)                                                # Part 4
        app.state.processes = ProcessService(db, app.state.signatures, app.state.activity)
        app.state.startup = startup.StartupService(db, app.state.signatures, app.state.activity,
                                                   app.state.settings_store)
        app.state.malware_db = MalwareDB(db)                                                       # Part 5
        app.state.scanner = ScanManager(db, app.state.malware_db, app.state.settings_store, app.state.activity,
                                        app.state.startup, cfg.data_dir)
        app.state.vault = Vault(cfg.data_dir)                                                     # Part 6
        app.state.allowlist = AllowList(db)
        app.state.quarantine = QuarantineService(db, app.state.vault, app.state.allowlist, app.state.settings_store,
                                                 app.state.activity, app.state.scanner, app.state.processes,
                                                 cfg.data_dir)
        app.state.threat_history = ThreatHistory(db, app.state.quarantine, app.state.allowlist)
        app.state.scanner.allowlist = app.state.allowlist
        app.state.scanner.on_detections = app.state.quarantine.auto_action
        app.state.rules = RulesEngine(db, app.state.activity)                                     # Part 8
        app.state.inspector = Inspector(db, app.state.settings_store, app.state.rules, HeuristicEngine(),
                                        app.state.signatures)
        app.state.cloud = CloudLookup(db, app.state.settings_store, app.state.activity, app.state.vault,
                                      app.state.malware_db)
        app.state.cloud.scanner, app.state.cloud.quarantine = app.state.scanner, app.state.quarantine
        app.state.scanner.inspector = app.state.inspector
        app.state.scanner.cloud = app.state.cloud
        app.state.realtime = RealtimeService(db, app.state.settings_store, app.state.activity,      # Part 7
                                             app.state.scanner, app.state.quarantine, cfg.data_dir)
        app.state.firewall = FirewallService(db, app.state.settings_store, app.state.activity,        # Part 9
                                             app.state.processes, cfg.data_dir)
        app.state.network = NetworkService(db, app.state.settings_store, app.state.activity,          # Part 10
                                           app.state.processes, app.state.firewall)
        app.state.posture = PostureService(db, app.state.settings_store, app.state.activity,          # Part 11
                                           app.state.firewall, cfg.data_dir)
        app.state.passwords = PasswordVaultService(db, app.state.settings_store, app.state.activity,  # Part 12
                                                   app.state.accounts, app.state.vault)
        app.state.data_protection = DataProtectionService(                                         # Part 13
            db, app.state.settings_store, app.state.activity, app.state.vault, cfg.data_dir,
            processes=app.state.processes, scanner=app.state.scanner, realtime=app.state.realtime,
            passwords=app.state.passwords)
        app.state.web = WebScannerService(db, app.state.settings_store, app.state.activity,               # Part 14
                                          network=app.state.network, firewall=app.state.firewall,
                                          data_dir=cfg.data_dir)
        app.state.intel = ThreatIntelService(db, app.state.settings_store, app.state.activity,             # Part 15
                                             vault=app.state.vault, cloud=app.state.cloud,
                                             malware_db=app.state.malware_db, network=app.state.network,
                                             firewall=app.state.firewall)
        app.state.platforms = PlatformService(db, app.state.settings_store, app.state.activity,            # Part 16
                                              vault=app.state.vault, passwords=app.state.passwords,
                                              intel=app.state.intel, scanner=app.state.scanner)
        st = app.state
        icon = cfg.ui_dir / "assets" / "icon.ico"
        st.notifications = NotificationCenter(db, st.settings_store, st.activity,                          # Part 17
                                              icon=str(icon) if icon.is_file() else None)
        if "toast" in SHELL_HOOKS:                                  # Part 20: the tray icon shows toasts itself
            st.notifications.on_toast = SHELL_HOOKS["toast"]
        st.backup = BackupService(db, st.settings_store, st.activity, cfg.data_dir, st.vault,              # Part 19
                                  notifications=st.notifications, strength=password_tools.strength)
        st.score = ScoreService(db, st.settings_store, st.activity, scanner=st.scanner,                    # Part 18
                                threat_history=st.threat_history, realtime=st.realtime, quarantine=st.quarantine,
                                rules=st.rules, firewall=st.firewall, network=st.network, posture=st.posture,
                                passwords=st.passwords, data_protection=st.data_protection, web=st.web,
                                intel=st.intel, platforms=st.platforms, accounts=st.accounts,
                                notifications=st.notifications, vault=st.vault)
        st.reports = ReportService(db, st.settings_store, st.activity, cfg.data_dir, score=st.score,       # Part 19
                                   scanner=st.scanner, threat_history=st.threat_history, quarantine=st.quarantine,
                                   realtime=st.realtime, firewall=st.firewall, network=st.network,
                                   posture=st.posture, passwords=st.passwords, data_protection=st.data_protection,
                                   web=st.web, intel=st.intel, platforms=st.platforms,
                                   notifications=st.notifications, log_dir=cfg.log_dir)
        st.scheduler = SchedulerService(db, st.settings_store, st.activity, notifications=st.notifications,  # Part 17
                                        accounts=st.accounts, scanner=st.scanner, posture=st.posture,
                                        firewall=st.firewall, network=st.network, intel=st.intel, web=st.web,
                                        platforms=st.platforms, data_protection=st.data_protection,
                                        reports=st.reports, backup=st.backup)
        st.score.scheduler = st.scheduler
        st.reports.scheduler = st.scheduler
        st.desktop = DesktopService(st.settings_store, st.activity, cfg.data_dir)                          # Part 20
        st.desktop.sync_autostart()
        try:
            app.state.quarantine.check_vault()
            app.state.quarantine.enforce_limits()
        except Exception as e:                                                                   # pragma: no cover
            log.warning("Quarantine vault check failed: %s", e)
        app.state.started_at = datetime.now(timezone.utc)
        app.state.activity.record("system", "Cyber Hub engine started",
                                  f"v{APP_VERSION}, schema v{version}, {app.state.rules.rule_count} YARA rules "
                                  f"({app.state.rules.backend}), firewall: {app.state.firewall.backend.label}, "
                                  f"network: {app.state.network.probe.label} / {app.state.network.probe.wifi.label}, "
                                  f"posture: {app.state.posture.backend.label}, "
                                  f"clipboard: {app.state.passwords.clipboard.backend.name}, "
                                  f"data protection: device key {'ok' if app.state.vault.available else 'missing'}, "
                                  f"web scanner: {app.state.web.vulndb_status()['records']} stored advisories, "
                                  f"threat intel: {app.state.intel.health()['iocs']} indicators, "
                                  f"platforms: {app.state.platforms.catalog_status()['breaches']} known breaches, "
                                  f"scheduler: {app.state.scheduler.status()['active']} active job(s), "
                                  f"toasts: {app.state.notifications.toaster.name}")
        log.info("%s backend v%s ready on http://%s:%s (data: %s)", APP_NAME, APP_VERSION, cfg.host, cfg.port, cfg.data_dir)

        tasks = []
        if start_workers:
            tasks.append(asyncio.create_task(metrics_recorder.recorder_loop(db, app.state.settings_store)))
            tasks.append(asyncio.create_task(alerts.alert_loop(app.state.alerts, app.state.settings_store)))
            tasks.append(asyncio.create_task(startup.watch_loop(app.state.startup, app.state.settings_store)))
            tasks.append(asyncio.create_task(quarantine_housekeeping(app.state.quarantine)))
            app.state.realtime.start()                              # Part 7: folder watcher + USB monitor threads
            app.state.cloud.start()                                 # Part 8: background hash lookups
            tasks.append(asyncio.create_task(firewall_loop(app.state.firewall, app.state.settings_store)))  # Part 9
            tasks.append(asyncio.create_task(network_loop(app.state.network, app.state.settings_store)))    # Part 10
            tasks.append(asyncio.create_task(posture_loop(app.state.posture, app.state.settings_store)))    # Part 11
            tasks.append(asyncio.create_task(password_vault_loop(app.state.passwords)))                     # Part 12
            tasks.append(asyncio.create_task(data_protection_loop(app.state.data_protection)))              # Part 13
            tasks.append(asyncio.create_task(web_loop(app.state.web, app.state.settings_store)))            # Part 14
            tasks.append(asyncio.create_task(intel_loop(app.state.intel, app.state.settings_store)))        # Part 15
            tasks.append(asyncio.create_task(platform_loop(app.state.platforms, app.state.settings_store)))  # Part 16
            tasks.append(asyncio.create_task(notification_loop(app.state.notifications, app.state.settings_store)))  # Part 17
            tasks.append(asyncio.create_task(scheduler_loop(app.state.scheduler)))                          # Part 17
            tasks.append(asyncio.create_task(score_loop(app.state.score)))                                  # Part 18
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.to_thread(app.state.scheduler.shutdown)   # Part 17: let a running scheduled job stop
            await asyncio.to_thread(app.state.notifications.shutdown)
            await asyncio.to_thread(app.state.platforms.shutdown)   # Part 16: stop a running e-mail breach check
            await asyncio.to_thread(app.state.intel.shutdown)       # Part 15: let a feed download stop cleanly
            await asyncio.to_thread(app.state.web.shutdown)         # Part 14: stop running site / project scans
            await asyncio.to_thread(app.state.data_protection.shutdown)  # Part 13: stop jobs after their current file
            await asyncio.to_thread(app.state.realtime.shutdown)    # stop watchers first (they feed the scanner)
            await asyncio.to_thread(app.state.cloud.shutdown)
            await asyncio.to_thread(app.state.network.shutdown)     # Part 10: stop a running LAN scan
            await asyncio.to_thread(app.state.posture.shutdown)     # Part 11: let an update search finish quietly
            await asyncio.to_thread(app.state.passwords.shutdown)   # Part 12: drop vault keys, wipe our clipboard copy
            await asyncio.to_thread(app.state.scanner.shutdown)     # stop scan threads before the DB closes
            app.state.activity.record("system", "Cyber Hub engine stopped")
            db.close()
            log.info("Backend stopped")

    app = FastAPI(
        title=f"{APP_NAME} Backend",
        version=APP_VERSION,
        description="Local security engine for the Cyber Hub desktop app. Developed by Syed Muhammad Tayyab.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.allowed_origins,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=[TOKEN_HEADER, SESSION_HEADER, "Content-Type"],
        expose_headers=["Content-Disposition"],
    )
    register_routers(app)
    # Serve the Cyber Hub UI (index.html + assets) from ./ui if present -> same origin, no CORS.
    if cfg.ui_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(cfg.ui_dir), html=True), name="ui")
    return app

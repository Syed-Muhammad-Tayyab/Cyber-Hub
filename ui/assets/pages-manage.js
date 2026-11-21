/* Cyber Hub UI - Scheduler, Notifications, Reports & backup, Activity, Settings, Account, About (Parts 1, 2, 17-20)
   Developed by Syed Muhammad Tayyab */
"use strict";

/* ================================================================== Scheduler */
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
async function scheduleDialog(actions, existing) {
  const e = existing || {};
  const avail = actions.filter(a => a.available);
  const v = await formDialog(existing ? "Change schedule" : "New schedule", [
    { name: "name", label: "Name", value: e.name || "", required: true, placeholder: "e.g. Evening quick scan" },
    { name: "action", label: "What to run", type: "select", value: e.action || "scan_quick", options: avail.map(a => [a.id, `${a.group}: ${a.label}`]) },
    { name: "kind", label: "How often", type: "select", value: e.kind || "daily", options: [["daily", "Every day"], ["weekly", "On chosen weekdays"], ["monthly", "Once a month"], ["interval", "Every N hours"], ["once", "Just once"]] },
    { name: "at_time", label: "Time (daily / weekly / monthly)", type: "time", value: e.at_time || "13:00" },
    { name: "weekdays", label: "Weekdays (weekly) - e.g. Mon, Wed, Fri", value: (e.weekdays || [0]).map(d => DAYS[d]).join(", ") },
    { name: "month_day", label: "Day of the month (monthly)", type: "number", value: e.month_day || 1, min: 1, max: 31 },
    { name: "hours", label: "Every how many hours (interval)", type: "number", value: e.every_minutes ? Math.round(e.every_minutes / 60) : 6, min: 1, max: 720 },
    { name: "run_at", label: "Date and time (just once)", type: "datetime", value: "" },
    { name: "paths", label: "Folders (custom scan only, one per line)", type: "textarea", value: ((e.params || {}).paths || []).join("\n") },
    { name: "catch_up", label: "If the PC was off at that time, run it after start-up", type: "checkbox", value: e.catch_up !== false },
  ], { submit: existing ? "Save" : "Create", wide: true, onSubmit: f => {
    const body = { name: f.name, action: f.action, kind: f.kind, catch_up: f.catch_up };
    if (["daily", "weekly", "monthly"].includes(f.kind)) body.at_time = f.at_time;
    if (f.kind === "weekly") { body.weekdays = f.weekdays.split(/[\s,]+/).map(x => DAYS.findIndex(d => d.toLowerCase() === x.slice(0, 3).toLowerCase())).filter(i => i >= 0); if (!body.weekdays.length) throw new Error("Type at least one weekday, e.g. Mon"); }
    if (f.kind === "monthly") body.month_day = f.month_day;
    if (f.kind === "interval") body.every_minutes = Math.round((f.hours || 1) * 60);
    if (f.kind === "once") { if (!f.run_at) throw new Error("Choose the date and time"); body.run_at = new Date(f.run_at).toISOString(); }
    if (f.action === "scan_custom") body.params = { paths: lines(f.paths) };
    else if (existing && existing.action === f.action) body.params = existing.params; else body.params = {};
    return existing ? PATCH(`/api/scheduler/schedules/${existing.id}`, body) : POST("/api/scheduler/schedules", body);
  } });
  return v;
}
page("scheduler", { title: "Scheduler", icon: "clock", sub: "Scans, checks, reports and backups that run by themselves",
  subs: [["schedules", "Schedules"], ["history", "Run history"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);
    const st = await GET("/api/scheduler/status");
    if (!st.enabled) body.appendChild(banner("medium", "The scheduler is switched off", "Nothing runs automatically.", isAdmin() ? btn("Turn on", () => PATCH("/api/settings", { scheduler_enabled: true }), { kind: "primary" }) : null));

    if (t.current === "schedules") {
      const [lst, acts, up] = await Promise.all([GET("/api/scheduler/schedules"), GET("/api/scheduler/actions"), GET("/api/scheduler/upcoming?hours=168&limit=8")]);
      const r7 = st.runs_7_days || {};
      body.appendChild(h("div", { class: "grid g4" }, statCard(`${st.active} / ${st.schedules}`, "Schedules switched on"), statCard(st.next ? ago(st.next.at) : "-", "Next run", st.next ? st.next.name : "Nothing planned"),
        statCard(num(r7.ok || 0), "Runs finished (7 days)", r7.failed ? `${r7.failed} failed` : r7.skipped ? `${r7.skipped} skipped` : "", r7.failed ? "var(--medium)" : null), statCard(st.on_battery ? "On battery" : "Plugged in", "Power", st.skip_on_battery ? "Heavy jobs wait for mains power" : "")));
      body.appendChild(tableCard("Schedules", [{ t: "On", v: s => toggle(s.enabled, on => PATCH(`/api/scheduler/schedules/${s.id}`, { enabled: on }), !isAdmin() || !s.available) },
        { t: "Name", v: s => h("div", null, h("b", null, s.name), h("div", { class: "dim small" }, `${s.group} · ${s.action_label}`)) }, { t: "When", v: s => s.when }, { t: "Next run", v: s => s.running ? badge("running now", "low") : s.enabled && s.next_run_at ? h("span", { title: dt(s.next_run_at) }, ago(s.next_run_at)) : "-" },
        { t: "Last result", v: s => s.last_status ? h("div", null, badge(s.last_status, s.last_status === "ok" ? "ok" : s.last_status === "failed" ? "high" : "info"), h("div", { class: "muted small wrap" }, s.last_detail || "")) : h("span", { class: "dim" }, "never ran") },
        { t: "", v: s => isAdmin() ? h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, btn("Run now", () => POST(`/api/scheduler/schedules/${s.id}/run`), { sm: true, kind: "primary", icon: "play", ok: "Started" }),
          btn("Edit", async () => { const v = await scheduleDialog(acts.items, s); return v ? undefined : "norefresh"; }, { sm: true }), btn("Delete", () => DEL(`/api/scheduler/schedules/${s.id}`), { sm: true, kind: "danger", confirm: `Delete the schedule "${s.name}"?` })) : "" }],
        lst.items, { height: "none", actions: isAdmin() ? [btn("New schedule", async () => { const v = await scheduleDialog(acts.items, null); return v ? undefined : "norefresh"; }, { sm: true, kind: "primary", icon: "plus" })] : null }));
      body.appendChild(card("Coming up this week", up.items.length ? h("div", { class: "list" }, up.items.map(u => h("div", { class: "item" }, h("span", { class: "c-low" }, icon("clock")), h("div", { class: "grow" }, h("div", { class: "t" }, u.name), h("div", { class: "d" }, u.action_label)), h("div", { class: "muted small right" }, dt(u.at), h("div", null, ago(u.at)))))) : empty("Nothing is planned for the next 7 days.")));
      if (lst.items.some(s => s.running)) every(2500, () => refresh());
    }

    if (t.current === "history") {
      const r = await GET("/api/scheduler/runs?limit=150");
      body.appendChild(card("Runs per day (30 days)", bars(daySeries(st.by_day, 30, d => ({ value: d.runs - (d.failed || 0), value2: d.failed || 0 })), { color: "var(--ok)", color2: "var(--critical)" })));
      body.appendChild(tableCard("Run history", [{ t: "Started", v: x => dt(x.started_at) }, { t: "Job", v: x => h("b", null, x.name) }, { t: "Why", v: x => ({ schedule: "On schedule", catch_up: "Caught up", manual: "Run by hand" })[x.trigger] || x.trigger },
        { t: "Result", v: x => badge(x.status, x.status === "ok" ? "ok" : x.status === "failed" ? "high" : x.status === "running" ? "low" : "info") }, { t: "Details", v: x => h("span", { class: "muted small wrap" }, x.detail || "") }, { t: "Took", v: x => x.duration_seconds !== null ? dur(x.duration_seconds) : "", cls: "num" }], r.items, { total: r.total, empty: "Nothing has run yet." }));
    }
    return root;
  } });

/* ================================================================== Notifications */
page("notifications", { title: "Notifications", icon: "bell", sub: "Everything Cyber Hub wanted you to know",
  subs: [["inbox", "Inbox"], ["settings", "Pop-up settings"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "inbox") {
      const filt = sessionStorage.getItem("nt_status") || "open", src = sessionStorage.getItem("nt_src") || "";
      const [lst, sm, st] = await Promise.all([GET("/api/notifications" + qs({ status: filt, source: src, limit: 200 })), GET("/api/notifications/summary?days=14"), GET("/api/notifications/status")]);
      setBell(lst.unread);
      body.appendChild(h("div", { class: "grid g-main" }, card("Last 14 days", bars(daySeries(sm.by_day, 14, d => ({ value: d.n - d.serious, value2: d.serious })), { color: "var(--accent)", color2: "var(--high)" })),
        card("Unread", sevDonut(sm.unread_by_severity, 120))));
      body.appendChild(tableCard("Notifications", [{ t: "", v: n => h("i", { class: "dot c-" + n.severity, title: n.severity }) }, { t: "When", v: n => h("span", { title: dt(n.ts) }, ago(n.ts)) },
        { t: "What", v: n => h("div", { style: { opacity: n.read ? 0.65 : 1 } }, h("div", { class: "bold" }, n.title), n.detail ? h("div", { class: "muted small wrap" }, n.detail) : null) }, { t: "From", v: n => n.source_name },
        { t: "", v: n => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, CH.pages[n.link] ? btn("Open", async () => { await POST("/api/notifications/read", { ids: [n.id] }); go(n.link); return "norefresh"; }, { sm: true, kind: "primary" }) : null,
          n.read ? null : btn("Read", () => POST("/api/notifications/read", { ids: [n.id] }), { sm: true }), n.dismissed ? null : btn("Dismiss", () => POST("/api/notifications/dismiss", { ids: [n.id] }), { sm: true, kind: "ghost" })) }],
        lst.items, { total: lst.total, empty: filt === "unread" ? "No unread notifications." : "Nothing here.", height: "none", actions: [
          h("select", { class: "input", style: { width: "130px" }, onchange: e => { sessionStorage.setItem("nt_status", e.target.value); refresh(); } }, [["open", "Open"], ["unread", "Unread"], ["dismissed", "Dismissed"], ["all", "All"]].map(o => h("option", { value: o[0], selected: o[0] === filt }, o[1]))),
          h("select", { class: "input", style: { width: "180px" }, onchange: e => { sessionStorage.setItem("nt_src", e.target.value); refresh(); } }, [h("option", { value: "" }, "From everything")].concat(st.sources.map(s => h("option", { value: s.id, selected: s.id === src }, s.name)))),
          btn("Mark all read", () => POST("/api/notifications/read", {}), { sm: true }), btn("Dismiss all", () => POST("/api/notifications/dismiss", {}), { sm: true, confirm: "Dismiss every open notification?" })] }));
    }

    if (t.current === "settings") {
      const st = await GET("/api/notifications/status"), s = st.settings;
      const set = (k, v) => PATCH("/api/settings", { [k]: v });
      const sevSel = key => h("select", { class: "input", onchange: e => run(null, () => set(key, e.target.value), { ok: "Saved" }) }, st.severities.map(x => h("option", { value: x, selected: s[key] === x }, cap(x) + " and above")));
      const timeIn = key => h("input", { class: "input", type: "time", value: s[key], style: { width: "120px" }, onchange: e => run(null, () => set(key, e.target.value), { ok: "Saved" }) });
      body.appendChild(card("Windows pop-up notifications", h("div", null,
        st.toasts.available ? null : banner("medium", "Pop-ups aren't available here", st.toasts.reason || ""),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Show pop-ups"), h("div", { class: "d" }, "A toast in the corner of the screen when something important happens. Everything is always kept in the inbox.")), h("div", { class: "ctl" }, toggle(s.notify_toasts && s.notifications_enabled, on => PATCH("/api/settings", { notify_toasts: on, notifications_enabled: on || s.notifications_enabled })))),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Pop up for"), h("div", { class: "d" }, "Less important things stay silent in the inbox")), h("div", { class: "ctl" }, sevSel("notify_toast_min_severity"))),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Keep in the inbox"), h("div", { class: "d" }, "What is worth recording at all")), h("div", { class: "ctl" }, sevSel("notify_center_min_severity"))),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Quiet hours"), h("div", { class: "d" }, st.quiet_now ? "Quiet right now" : "No pop-ups between these times")), h("div", { class: "ctl row", style: { flexWrap: "nowrap" } }, timeIn("notify_quiet_start"), h("span", { class: "muted" }, "to"), timeIn("notify_quiet_end"), toggle(s.notify_quiet_hours, on => set("notify_quiet_hours", on)))),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Critical alerts ignore quiet hours")), h("div", { class: "ctl" }, toggle(s.notify_quiet_allow_critical, on => set("notify_quiet_allow_critical", on)))),
        h("div", { style: { marginTop: "12px" } }, btn("Send a test notification", () => POST("/api/notifications/test"), { ok: r => r.shown ? "Sent - look at the corner of your screen" : "Windows did not show it: " + (r.reason || "unknown reason") })))));
      const muted = new Set(s.notify_muted_sources);
      body.appendChild(card("Pop-ups per area", h("div", { class: "grid g3", style: { gap: "0 26px" } }, st.sources.map(x => h("div", { class: "setting" }, h("div", { class: "t", style: { fontWeight: 500 } }, x.name), h("div", { class: "ctl", style: { minWidth: 0 } },
        toggle(!muted.has(x.id), on => { on ? muted.delete(x.id) : muted.add(x.id); return set("notify_muted_sources", [...muted]); })))))));
    }
    return root;
  } });

/* ================================================================== Reports & backup */
page("reports", { title: "Reports & backup", icon: "file", sub: "Security reports, backups and diagnostics",
  subs: [["reports", "Reports"], ["backup", "Backup & restore"], ["export", "Settings & logs"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "reports") {
      const [st, lst] = await Promise.all([GET("/api/reports/status"), GET("/api/reports?limit=100")]);
      const type = h("select", { class: "input" }, st.types.map(x => h("option", { value: x.id }, x.name))), fmt = h("select", { class: "input", style: { width: "110px" } }, st.formats.map(x => h("option", { value: x, selected: x === st.settings.report_default_format }, x.toUpperCase())));
      const days = h("select", { class: "input", style: { width: "150px" } }, [[7, "Last 7 days"], [30, "Last 30 days"], [90, "Last 90 days"], [365, "Last year"]].map(o => h("option", { value: o[0], selected: o[0] === st.settings.report_default_days }, o[1])));
      const desc = h("div", { class: "muted small", style: { marginTop: "8px" } }, st.types[0].description);
      type.onchange = () => { desc.textContent = st.types.find(x => x.id === type.value).description; };
      body.appendChild(card("Create a report", h("div", null, h("div", { class: "row" }, type, days, fmt, btn("Create", async () => { const r = await POST("/api/reports", { type: type.value, format: fmt.value, days: Number(days.value) }); toast(`${r.file_name} created (${r.size_text})`, "ok"); await download(`/api/reports/${r.id}/download`, r.file_name); }, { kind: "primary", icon: "file" })), desc)));
      body.appendChild(tableCard("My reports", [{ t: "Created", v: r => dt(r.ts) }, { t: "Report", v: r => h("b", null, r.title) }, { t: "Covers", v: r => `${r.days} day(s)` }, { t: "Score", v: r => r.score !== null ? h("b", { style: { color: scoreColor(r.score) } }, r.score) : "", cls: "num" },
        { t: "File", v: r => h("span", { class: "muted small" }, `${r.extension.toUpperCase()} · ${r.size_text}`) }, { t: "By", v: r => r.source === "schedule" ? "Scheduler" : r.created_by },
        { t: "", v: r => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, r.exists ? btn("Download", () => { download(`/api/reports/${r.id}/download`, r.file_name); return "norefresh"; }, { sm: true, kind: "primary", icon: "download", refresh: false }) : h("span", { class: "dim small" }, "file missing"),
          btn("Delete", () => DEL(`/api/reports/${r.id}`), { sm: true, kind: "danger" })) }], lst.items, { total: lst.total, empty: "No reports yet. A weekly summary is created automatically every Monday." }));
      body.appendChild(h("div", { class: "dim small" }, "Saved in: ", lst.folder));
    }

    if (t.current === "backup") {
      if (!isAdmin()) { body.appendChild(empty("Backups can be made and restored by a Cyber Hub administrator.")); return root; }
      const [st, lst] = await Promise.all([GET("/api/backup/status"), GET("/api/backup")]);
      if (lst.pending_restore) body.appendChild(banner("medium", "A restore is waiting", `${lst.pending_restore.backup_file} will replace the current data the next time Cyber Hub starts.`, h("div", { class: "row tight" },
        CH.desktop && CH.desktop.can_restart ? btn("Restart now", () => POST("/api/desktop/restart"), { kind: "primary", refresh: false, ok: "Restarting…" }) : h("span", { class: "muted small" }, "Close and open Cyber Hub to finish."), btn("Cancel restore", () => DEL("/api/backup/restore"), { ok: "Restore cancelled" }))));
      body.appendChild(h("div", { class: "grid g4" }, statCard(num(st.backups), "Backups", st.size_text), statCard(st.last ? ago(st.last.ts) : "Never", "Last backup", null, st.days_since_last === null || st.days_since_last > 30 ? "var(--medium)" : "var(--ok)"), statCard(st.device_key_available ? "Ready" : "Problem", "This PC's key", "for automatic backups"), statCard(st.settings.backup_keep, "Automatic backups kept")));
      const restore = async ref => { let pw = null;
        for (let i = 0; i < 3; i++) {
          try { const v = await POST("/api/backup/verify", Object.assign({}, ref, { password: pw }));
            if (!v.restorable) throw new Error(v.reason || "This backup can't be restored here");
            if (!(await confirmBox(`Restore the backup from ${dt(v.created_at)}?\n\nAccounts in it: ${v.users.join(", ")}\nMade on: ${v.computer || "?"} with Cyber Hub ${v.app_version}\n\nALL current Cyber Hub data (settings, history, vaults) is replaced when Cyber Hub restarts. Your current data is kept as a safety copy.`, "Restore", true))) return "norefresh";
            const r = await POST("/api/backup/restore", Object.assign({}, ref, { password: pw, confirm: true })); toast(r.message, "ok", 9000); return; }
          catch (e) { if (e.status !== 428 && e.status !== 403) throw e; if (e.status === 403 && pw === null) throw e;
            const f = await formDialog("Backup password", [{ name: "password", label: e.status === 403 ? "Wrong password - try again" : "Password of this backup", type: "password", required: true }], { submit: "Continue" }); if (!f) return "norefresh"; pw = f.password; }
        } };
      body.appendChild(card("Back up now", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "A backup holds your settings, history, schedules, password vault and platform accounts in one encrypted file."), h("div", { class: "row" },
        btn("Backup with a password…", async () => { const v = await formDialog("Password-protected backup", [{ name: "password", label: "Backup password", type: "password", required: true, hint: "Needed to restore - on this or any other PC. Cyber Hub can't recover it." }, { name: "again", label: "Repeat it", type: "password", required: true },
          { name: "destination", label: "Save in folder (optional - e.g. a USB drive)", type: "path" }, { name: "include_quarantine", label: "Include quarantined files", type: "checkbox", value: false }, { name: "note", label: "Note (optional)" }],
          { submit: "Create backup", onSubmit: f => { if (f.password !== f.again) throw new Error("The two passwords are not the same"); return POST("/api/backup", { mode: "password", password: f.password, destination: f.destination || null, include_quarantine: f.include_quarantine, note: f.note || null }); } }); if (v) toast(`Backup saved: ${v.file_path}`, "ok", 8000); return v ? undefined : "norefresh"; }, { kind: "primary", icon: "lock" }),
        btn("Quick backup (this PC only)", () => POST("/api/backup", { mode: "device" }), { icon: "bolt", ok: r => `Backup saved: ${r.file_name}` }),
        btn("Restore from a file…", async () => { const f = await formDialog("Restore from a backup file", [{ name: "path", label: ".chbackup file", type: "path", pick: "file", required: true }], { submit: "Continue" }); if (!f) return "norefresh"; return restore({ path: f.path }); }, { icon: "refresh" })))));
      body.appendChild(tableCard("Backups", [{ t: "Made", v: b => dt(b.ts) }, { t: "File", v: b => h("div", null, h("b", null, b.file_name), b.note ? h("div", { class: "muted small" }, b.note) : null) }, { t: "Works on", v: b => b.portable ? badge("any PC", "ok") : badge("this PC only", "low") },
        { t: "Size", v: b => b.size_text, cls: "num" }, { t: "By", v: b => b.source === "schedule" ? "Scheduler" : b.created_by },
        { t: "", v: b => b.exists ? h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, btn("Restore", () => restore({ id: b.id }), { sm: true, kind: "primary" }), btn("Download", () => { download(`/api/backup/${b.id}/download`, b.file_name); return "norefresh"; }, { sm: true, icon: "download", refresh: false }),
          btn("Delete", () => DEL(`/api/backup/${b.id}`), { sm: true, kind: "danger", confirm: "Delete this backup file?" })) : h("div", { class: "row tight" }, h("span", { class: "dim small" }, "file missing"), btn("Forget", () => DEL(`/api/backup/${b.id}`), { sm: true })) }], lst.items, { empty: "No backups yet." }));
      body.appendChild(h("div", { class: "dim small" }, "Saved in: ", lst.folder, " · Turn on the weekly backup under Scheduler."));
    }

    if (t.current === "export") {
      body.appendChild(h("div", { class: "grid g2" },
        card("Settings", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "Copy your preferences to another PC. The file holds no passwords or keys."), h("div", { class: "row" },
          btn("Export settings", async () => { const s = await GET("/api/backup/settings/export"); const a = h("a", { href: URL.createObjectURL(new Blob([JSON.stringify(s, null, 1)], { type: "application/json" })), download: "CyberHub_settings.json" }); document.body.appendChild(a); a.click(); a.remove(); return "norefresh"; }, { icon: "download" }),
          btn("Import settings…", async () => { const v = await formDialog("Import settings", [{ name: "json", label: "Paste the contents of a CyberHub_settings.json file", type: "textarea", required: true }], { submit: "Import", wide: true, onSubmit: f => { let p; try { p = JSON.parse(f.json); } catch (e) { throw new Error("That is not valid settings text"); } return POST("/api/backup/settings/import", { payload: p, only_changed: true }); } });
            if (v) { toast(`${v.applied_count} setting(s) changed, ${v.skipped.length} skipped`, "ok"); CH.settings = await GET("/api/settings"); applyTheme(CH.settings.theme); } return v ? undefined : "norefresh"; }, {})))),
        card("Diagnostics", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "One .zip with the engine's log files, the activity log and version details - for troubleshooting. No passwords, keys or vault contents."),
          isAdmin() ? btn("Export logs", () => { download("/api/reports/logs/export?days=7", "CyberHub_diagnostics.zip"); return "norefresh"; }, { icon: "download", refresh: false }) : h("span", { class: "muted" }, "Administrator only")))));
    }
    return root;
  } });

/* ================================================================== Activity */
page("activity", { title: "Activity log", icon: "list", sub: "Everything Cyber Hub did or noticed",
  async render() {
    const cat = sessionStorage.getItem("act_cat") || "", sev = sessionStorage.getItem("act_sev") || "";
    const [lst, sm] = await Promise.all([GET("/api/activity" + qs({ limit: 300, category: cat, severity: sev })), GET("/api/activity/summary?days=14")]);
    return h("div", { class: "stack" }, h("div", { class: "grid g-main" }, card("Events per day", bars(daySeries(sm.by_day, 14, d => d.n), {})), card("By importance", sevDonut(sm.by_severity, 120))),
      tableCard("Activity", [{ t: "When", v: a => h("span", { class: "nowrap" }, dt(a.ts)) }, { t: "", v: a => h("i", { class: "dot c-" + a.severity, title: a.severity }) }, { t: "Area", v: a => cap(a.category) },
        { t: "Event", v: a => h("div", null, h("div", { class: "bold" }, a.title), a.detail ? h("div", { class: "muted small wrap" }, a.detail) : null) }], lst.items, { total: lst.total, height: "none", actions: [
        h("select", { class: "input", style: { width: "160px" }, onchange: e => { sessionStorage.setItem("act_cat", e.target.value); refresh(); } }, [h("option", { value: "" }, "All areas")].concat(sm.by_category.map(c => h("option", { value: c.category, selected: c.category === cat }, `${cap(c.category)} (${c.n})`)))),
        h("select", { class: "input", style: { width: "150px" } , onchange: e => { sessionStorage.setItem("act_sev", e.target.value); refresh(); } }, [["", "Any importance"]].concat(SEV.map(s => [s, cap(s)])).map(o => h("option", { value: o[0], selected: o[0] === sev }, o[1])))] }));
  } });

/* ================================================================== Settings */
const SETTINGS_UI = [
  ["Appearance & start-up", [
    ["theme", "Theme", "Dark, light or the same as Windows", [["dark", "Dark"], ["light", "Light"], ["system", "Same as Windows"]]],
    ["start_with_windows", "Start with Windows", "Cyber Hub starts in the tray when you sign in, so protection is always on", "autostart"],
    ["minimize_to_tray", "Keep running when the window is closed", "Closing the window hides Cyber Hub in the tray; protection continues"],
    ["auto_lock_minutes", "Lock Cyber Hub after (minutes without use)", "0 = never lock", "number"],
  ]],
  ["Protection", [
    ["scan_auto_quarantine", "Quarantine threats automatically", "What scans do when they find something", [["off", "Ask me"], ["high", "Serious threats"], ["all", "Every threat"]]],
    ["rtp_action", "When real-time protection finds a threat", "", [["quarantine", "Quarantine it"], ["alert", "Only tell me"]]],
    ["rtp_usb_scan", "When a USB drive is plugged in", "", [["auto", "Scan it"], ["notify", "Tell me"], ["off", "Do nothing"]]],
    ["yara_enabled", "Rule-based detection (YARA)", "Catches malware families, not just exact known files"],
    ["heuristics_enabled", "Heuristic detection", "Flags suspicious-looking files nobody has seen before"],
    ["heuristics_sensitivity", "Heuristic sensitivity", "Higher finds more, with more false alarms", [["low", "Low"], ["medium", "Medium"], ["high", "High"]]],
  ]],
  ["Online checks (off by default - nothing leaves this PC unless you turn these on)", [
    ["cloud_lookup_enabled", "Ask VirusTotal / MalwareBazaar about unknown programs", "Only file hashes are sent, never files"],
    ["intel_online_lookup", "Ask online services when I check a link or address", "Uses the keys saved under Threat intel"],
    ["platform_breach_check", "Check my e-mail addresses for data breaches", "", [["off", "Off"], ["manual", "When I press Check"], ["auto", "Automatically"]]],
    ["pv_breach_check", "Check saved passwords for breaches", "Only 5 characters of a hash are sent", [["off", "Off"], ["manual", "When I press Check"], ["auto", "Automatically"]]],
  ]],
  ["Automation", [
    ["scheduler_enabled", "Run scheduled jobs", "Scans, reports and backups from the Scheduler page"],
    ["scheduler_skip_on_battery", "Postpone heavy jobs on battery", "Full scans and clean-ups wait until the laptop is plugged in"],
    ["intel_auto_update", "Keep threat feeds up to date", ""],
    ["score_alert_drop", "Tell me when the security score drops by (points)", "0 = never", "number"],
  ]],
];
function settingControl(key, value, kind) {
  const save = v => PATCH("/api/settings", { [key]: v }).then(s => { CH.settings = s; if (key === "theme") applyTheme(v); });
  if (kind === "autostart") { const a = (CH.desktop || {}).autostart || {}; return toggle(a.enabled, on => PUT("/api/desktop/autostart", { enabled: on }).then(async () => { CH.desktop = await GET("/api/desktop/status"); }), a.supported === false); }
  if (Array.isArray(kind)) return h("select", { class: "input", onchange: e => run(null, () => save(e.target.value), { ok: "Saved" }) }, kind.map(o => h("option", { value: o[0], selected: o[0] === value }, o[1])));
  if (typeof value === "boolean") return toggle(value, on => save(on));
  if (typeof value === "number") return h("input", { class: "input", type: "number", value, style: { width: "110px" }, onchange: e => run(null, () => save(Number(e.target.value)), { ok: "Saved" }) });
  if (Array.isArray(value)) return btn(`${value.length} item(s) - edit`, async () => { const v = await formDialog(cap(key), [{ name: "v", label: "One per line", type: "textarea", value: value.join("\n") }], { onSubmit: f => save(lines(f.v)) }); return v ? undefined : "norefresh"; }, { sm: true });
  return h("input", { class: "input", value: value === null || value === undefined ? "" : value, onchange: e => run(null, () => save(e.target.value), { ok: "Saved" }) });
}
page("settings", { title: "Settings", icon: "gear", sub: "How Cyber Hub behaves",
  subs: [["main", "Main settings"], ["all", "All settings"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);
    const s = await GET("/api/settings");
    CH.settings = s; CH.desktop = await GET("/api/desktop/status").catch(() => CH.desktop);
    if (!isAdmin()) body.appendChild(banner("medium", "Some settings need an administrator", "Settings that lower protection can only be changed by a Cyber Hub administrator."));
    if (t.current === "main") {
      SETTINGS_UI.forEach(([title, items]) => body.appendChild(card(title, h("div", null, items.filter(i => i[0] in s || i[3] === "autostart").map(([key, label, d, kind]) =>
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, label), d ? h("div", { class: "d" }, d) : null), h("div", { class: "ctl" }, settingControl(key, s[key], kind))))))));
      body.appendChild(h("div", { class: "muted small" }, "More: pop-ups are under Notifications, alert limits under System monitor, firewall under Firewall. Every single setting is on the 'All settings' tab."));
    } else {
      const q = (sessionStorage.getItem("set_q") || "").toLowerCase();
      const keys = Object.keys(s).filter(k => !q || k.includes(q)).sort();
      body.appendChild(card("All settings", h("div", null, keys.map(k => h("div", { class: "setting" }, h("div", null, h("div", { class: "t mono", style: { fontWeight: 500 } }, k)), h("div", { class: "ctl" }, settingControl(k, s[k], null))))),
        { actions: [h("input", { class: "input search", placeholder: "Filter…", value: q, onkeydown: e => { if (e.key === "Enter") { sessionStorage.setItem("set_q", e.target.value); refresh(); } } }),
          isAdmin() ? btn("Reset everything", () => POST("/api/settings/reset").then(async () => { CH.settings = await GET("/api/settings"); applyTheme(CH.settings.theme); }), { sm: true, kind: "danger", confirm: "Put every setting back to its default?", ok: "Settings reset" }) : null] }));
    }
    return root;
  } });

/* ================================================================== Account */
page("account", { title: "Your account", nav: "Account", icon: "user", sub: "Sign-in, PIN, recovery codes and users of this PC",
  async render() {
    const [me, sess, hist, rc] = await Promise.all([GET("/api/account/me"), GET("/api/account/sessions"), GET("/api/account/login-history?limit=30"), GET("/api/account/recovery-codes").catch(() => ({ remaining: 0 }))]);
    const u = me.user; CH.user = u;
    const root = h("div", { class: "stack" });
    root.appendChild(h("div", { class: "grid g2" },
      card("Profile", h("div", null, h("div", { class: "row", style: { marginBottom: "14px" } }, h("span", { class: "avatar", style: { width: "52px", height: "52px", fontSize: "22px" } }, (u.display_name || u.username).charAt(0).toUpperCase()),
        h("div", null, h("h2", null, u.display_name || u.username), h("div", { class: "muted" }, `@${u.username} · ${u.role === "admin" ? "Administrator" : "Standard user"}`))),
        kv([["E-mail", u.email], ["Account created", dt(u.created_at)], ["Password changed", ago(u.password_changed_at)]]),
        h("div", { class: "row", style: { marginTop: "14px" } },
          btn("Edit profile", async () => { const v = await formDialog("Edit profile", [{ name: "display_name", label: "Display name", value: u.display_name || "" }, { name: "email", label: "E-mail (optional)", value: u.email || "" }], { onSubmit: f => PATCH("/api/account/me", { display_name: f.display_name, email: f.email || null }) }); if (v) $("#user-name").textContent = v.display_name || (v.user || {}).display_name || u.username; return v ? undefined : "norefresh"; }, {}),
          btn("Sign out", async () => { try { await POST("/api/account/logout", {}); } catch (e) { /* */ } signOutLocal(); showAuth("login"); return "norefresh"; }, { kind: "danger", refresh: false })))),
      card("Sign-in security", h("div", null,
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Password"), h("div", { class: "d" }, "Changed " + ago(u.password_changed_at))), h("div", { class: "ctl" }, btn("Change", async () => { const v = await formDialog("Change password", [{ name: "cur", label: "Current password", type: "password", required: true }, { name: "new", label: "New password", type: "password", required: true }, { name: "again", label: "Repeat new password", type: "password", required: true }],
          { onSubmit: f => { if (f.new !== f.again) throw new Error("The two new passwords are not the same"); return POST("/api/account/change-password", { current_password: f.cur, new_password: f.new }); } }); if (v) toast("Password changed. Other windows were signed out.", "ok"); return v ? undefined : "norefresh"; }, { sm: true }))),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Quick-unlock PIN"), h("div", { class: "d" }, u.has_pin ? "A PIN unlocks Cyber Hub after it locked itself" : "Unlock with 4-8 digits instead of the whole password")), h("div", { class: "ctl row", style: { flexWrap: "nowrap" } },
          btn(u.has_pin ? "Change" : "Set PIN", async () => { const v = await formDialog("Quick-unlock PIN", [{ name: "password", label: "Your password", type: "password", required: true }, { name: "pin", label: "New PIN (4-8 digits)", type: "password", required: true }], { onSubmit: f => PUT("/api/account/pin", { password: f.password, pin: f.pin }) }); return v ? undefined : "norefresh"; }, { sm: true }),
          u.has_pin ? btn("Remove", () => DEL("/api/account/pin"), { sm: true, kind: "danger" }) : null)),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Recovery codes"), h("div", { class: "d" }, rc.remaining ? `${rc.remaining} unused code(s) left` : "None yet - without them a forgotten password can't be reset")), h("div", { class: "ctl" },
          btn(rc.remaining ? "New codes" : "Create codes", async () => { const v = await formDialog("Recovery codes", [{ name: "password", label: "Your password", type: "password", required: true }], { intro: rc.remaining ? "The old codes stop working." : "", submit: "Create", onSubmit: f => POST("/api/account/recovery-codes", { password: f.password }) }); if (v) showRecoveryCodes(v.codes || v.recovery_codes || []); return v ? undefined : "norefresh"; }, { sm: true, kind: rc.remaining ? "" : "primary" })))))));
    root.appendChild(h("div", { class: "grid g2" },
      tableCard("Where you're signed in", [{ t: "Started", v: s => dt(s.created_at) }, { t: "Last used", v: s => ago(s.last_seen_at) }, { t: "From", v: s => h("span", { class: "muted small" }, (s.device || "").slice(0, 40)) },
        { t: "", v: s => s.current ? badge("this window", "ok") : btn("Sign out", () => DEL(`/api/account/sessions/${s.id}`), { sm: true, kind: "danger" }) }], sess, { height: "260px" }),
      tableCard(`Sign-in history  ·  ${hist.stats.failed} failed in ${hist.stats.days} days`, [{ t: "When", v: x => dt(x.ts) }, { t: "User", v: x => x.username }, { t: "Result", v: x => x.success ? badge("ok", "ok") : h("span", { title: x.reason || "" }, badge("failed", "high")) }, { t: "How", v: x => cap(x.method) }], hist.items, { count: false, height: "260px" })));
    if (isAdmin()) {
      const users = await GET("/api/account/users");
      root.appendChild(tableCard("People who can use Cyber Hub on this PC", [{ t: "Name", v: x => h("div", null, h("b", null, x.display_name || x.username), h("div", { class: "dim small" }, "@" + x.username)) }, { t: "Role", v: x => x.role === "admin" ? badge("administrator", "medium") : badge("standard", "info") },
        { t: "Last sign-in", v: x => x.last_login_at ? ago(x.last_login_at) : "never" }, { t: "", v: x => x.id === u.id ? "" : btn("Remove", () => DEL(`/api/account/users/${x.id}`), { sm: true, kind: "danger", confirm: `Remove ${x.username}? Their vault and personal data in Cyber Hub are deleted.` }) }], users,
        { actions: [btn("Add person", async () => { const v = await formDialog("Add a person", [{ name: "username", label: "User name", required: true }, { name: "display_name", label: "Display name" }, { name: "password", label: "Password", type: "password", required: true }, { name: "role", label: "Role", type: "select", value: "standard", options: [["standard", "Standard - can't lower protection"], ["admin", "Administrator"]] }], { submit: "Add", onSubmit: f => POST("/api/account/users", f) }); return v ? undefined : "norefresh"; }, { sm: true, icon: "plus" })] }));
    }
    return root;
  } });

/* ================================================================== About */
page("about", { title: "About Cyber Hub", nav: "About", icon: "info", sub: "",
  async render() {
    const [a, d] = await Promise.all([GET("/api/about"), GET("/api/desktop/status").catch(() => ({}))]);
    const c = a.components || {};
    const mods = (CH.info && CH.info.modules) || [];
    return h("div", { class: "stack" },
      h("section", { class: "card", style: { textAlign: "center", padding: "30px 18px" } }, h("div", { class: "auth-logo", style: { width: "84px", height: "84px" } }), h("h1", { style: { fontSize: "30px", marginTop: "6px" } }, a.app),
        h("div", { class: "muted" }, a.tagline), h("div", { style: { margin: "14px 0 4px", fontSize: "16px" } }, "Developed by ", h("b", null, a.developer)), h("div", { class: "muted small" }, a.location),
        h("div", { class: "row", style: { justifyContent: "center", marginTop: "14px" } }, badge("Version " + a.version, "ok"), badge(`${a.build_part} of ${a.total_parts} parts - complete`, "low"),
          h("a", { class: "btn sm", href: a.github, target: "_blank", rel: "noopener" }, "GitHub: Syed-Muhammad-Tayyab")), h("div", { class: "dim small", style: { marginTop: "14px" } }, a.copyright)),
      h("div", { class: "grid g2" },
        card("This installation", kv([["Version", a.version], ["Running as", d.packaged ? "Installed app" : "From source (Python " + a.python + ")"], ["Window", ({ pywebview: "Cyber Hub window", browser: "Web browser", none: "Web browser (engine only)" })[d.shell] || d.shell], ["Tray icon", d.tray ? "Yes" : "No"],
          ["Administrator rights", d.elevated ? "Yes" : "No - some fixes will ask"], ["Starts with Windows", (d.autostart || {}).enabled ? "Yes" : "No"], ["System", a.platform], ["Data folder", h("code", { class: "wrap" }, d.data_folder || "-")]])),
        card("Engines", kv([["Database version", c.schema_version], ["Rule engine", `${c.yara_engine || "-"} · ${c.yara_rules || 0} rules`], ["Known-bad signatures", num(c.signatures)], ["Firewall", c.firewall], ["Network", c.network], ["Windows checks", c.posture], ["Pop-ups", c.toasts]]))),
      card("What's inside", h("div", { class: "grid g4", style: { gap: "8px 18px" } }, mods.map(m => h("div", { class: "row", style: { flexWrap: "nowrap", alignItems: "flex-start" } }, h("span", { class: "c-ok", style: { width: "16px", flex: "none", marginTop: "2px" } }, icon("check")),
        h("div", null, h("div", { class: "bold small" }, `${m.part}. ${m.name || cap(m.id)}`)))))),
      CH.desktop && CH.desktop.can_quit && isAdmin() ? card("Close Cyber Hub", h("div", { class: "spread" }, h("div", { class: "muted" }, "Closing the window keeps protection running in the tray. This stops Cyber Hub completely."),
        btn("Quit Cyber Hub", () => POST("/api/desktop/quit"), { kind: "danger", confirm: "Stop Cyber Hub completely? Real-time protection and scheduled jobs stop until you open it again.", confirmLabel: "Quit", refresh: false }))) : null);
  } });

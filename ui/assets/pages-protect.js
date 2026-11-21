/* Cyber Hub UI - Dashboard + Virus & threat protection (Parts 5-8, 18)
   Developed by Syed Muhammad Tayyab */
"use strict";

/* Run a recommendation's one-click fix (the exact API call comes from /api/score). */
async function runRecommendation(rec) {
  const a = rec.action;
  if (!a) { go(rec.link); return "norefresh"; }
  try { return await api(a.method, a.path, a.body === null ? {} : a.body); }
  catch (e) {
    if (e.status === 428) {                       // the fix has side effects: ask, then confirm
      if (!(await confirmBox(e.message, "Yes, apply the fix"))) return "norefresh";
      return await api(a.method, a.path, Object.assign({}, a.body || {}, { confirm: true }));
    }
    throw e;
  }
}
function recList(recs, max = 8) {
  if (!recs.length) return empty("Nothing needs fixing. Well done.");
  return h("div", { class: "list recs" }, recs.slice(0, max).map(r => h("div", { class: "item" },
    h("span", { style: { marginTop: "2px" } }, badge(r.severity)),
    h("div", { class: "grow" }, h("div", { class: "t" }, r.title), r.detail ? h("div", { class: "d" }, r.detail) : null),
    r.action ? btn(r.action.label, () => runRecommendation(r), { sm: true, kind: "primary", ok: "Done", title: r.action.admin && !isAdmin() ? "Needs an administrator" : null })
             : btn("Open", () => { go(r.link); return "norefresh"; }, { sm: true }))));
}
/* The little network picture on the dashboard: internet -> router -> this PC + other devices */
function topologyArt(net, fw, rt) {
  const lan = (net && net.lan) || {}, wifi = (net && net.wifi) || {};
  const others = Math.max(0, (lan.devices || lan.online || 0) - 1), okFw = fw && fw.profiles && fw.profiles.every(p => p.enabled);
  const s = svg("svg", { class: "device-art", viewBox: "0 0 520 210" });
  const node = (x, y, label, sub, col, draw) => {
    const g = svg("g", { transform: `translate(${x},${y})` });
    g.appendChild(svg("circle", { r: 34, fill: "var(--panel2)", stroke: col, "stroke-width": 1.6 }));
    g.appendChild(svg("path", { d: draw, fill: "none", stroke: col, "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round" }));
    g.appendChild(svg("text", { y: 52, "text-anchor": "middle", style: "fill:var(--text);font-size:12px;font-weight:600" }, label));
    if (sub) g.appendChild(svg("text", { y: 66, "text-anchor": "middle", style: "font-size:10.5px" }, sub));
    return g;
  };
  const link = (x1, y1, x2, y2, col, dash) => svg("line", { x1, y1, x2, y2, stroke: col, "stroke-width": 1.6, "stroke-dasharray": dash || null, opacity: 0.8 });
  const ok = "var(--ok)", warn = "var(--medium)", acc = "var(--accent2)";
  s.appendChild(link(94, 80, 196, 80, acc, "4 5")); s.appendChild(link(264, 80, 366, 80, okFw ? ok : warn));
  s.appendChild(link(250, 106, 300, 150, "var(--line2)"));
  s.appendChild(node(60, 80, "Internet", "", acc, "M-16 6a9 9 0 0 1 3-17 12 12 0 0 1 23 3 8 8 0 0 1 2 15z"));
  s.appendChild(node(230, 80, wifi.connected ? (wifi.ssid || "Wi-Fi") : "Router", wifi.connected ? String(wifi.auth || "").toUpperCase() : (lan.gateway && lan.gateway.ip) || "", wifi.rating === "insecure" ? "var(--critical)" : acc,
    "M-16 4h32v10h-32zM-9 9h.01M-3 9h.01M8 4v-14M-12 -4a14 14 0 0 1 0-0M2 -8a8 8 0 0 1 12 0"));
  s.appendChild(node(400, 80, "This PC", rt && rt.protected ? "Protected" : "Check protection", rt && rt.protected ? ok : warn,
    "M-15 -12h30v19h-30zM-21 12h42M-5 -3l4 4 7-8"));
  const g = svg("g", { transform: "translate(318,165)" });
  g.appendChild(svg("rect", { x: -18, y: -15, width: 36, height: 30, rx: 8, fill: "var(--panel2)", stroke: "var(--line2)" }));
  g.appendChild(svg("text", { y: 5, "text-anchor": "middle", style: "fill:var(--text);font-size:13px;font-weight:700" }, others));
  g.appendChild(svg("text", { x: 26, y: 4, style: "font-size:11px" }, "other device(s) on your network"));
  s.appendChild(g);
  return s;
}

page("dashboard", { title: "Dashboard", icon: "home", sub: "Your security at a glance",
  async render() {
    const d = await GET("/api/dashboard?days=14");
    const s = d.score && !d.score.error ? d.score : null;
    if (s) paintScoreBadges(s);
    const th = d.threats || {}, sc = d.scans || {}, rt = d.realtime || {}, sys = d.system || {}, net = d.network || {};
    const stats = sys.stats || {}, fw = net.firewall || {}, nw = net.network || {};
    const root = h("div", { class: "stack" });

    if (s && s.counts.critical) root.appendChild(banner("critical", s.headline, s.recommendations[0] ? s.recommendations[0].title : "", btn("Show me", () => { go(s.recommendations[0].link); return "norefresh"; }, { kind: "primary" })));
    // ---- score + what to fix
    const hero = h("section", { class: "card", style: { display: "grid", alignContent: "center" } }, h("div", { class: "hero" },
      s ? ring(s.score, 190, { label: "Grade " + s.grade }) : ring(null, 190),
      h("div", null, h("div", { class: "muted small" }, "Overall security score"),
        h("h2", { style: { fontSize: "26px", margin: "2px 0 6px", color: s ? scoreColor(s.score) : null } }, s ? s.status_text : "Not available"),
        h("div", { style: { marginBottom: "10px" } }, s ? s.headline : (d.score && d.score.error) || ""),
        s && s.caps.length ? h("div", { class: "muted small", style: { marginBottom: "10px" } }, `Limited to ${s.caps[0].limit} because ${s.caps[0].reason}. Without that it would be ${s.raw_score}.`) : null,
        h("div", { class: "row" }, btn("Quick scan", () => POST("/api/scan/quick"), { kind: "primary", icon: "play", ok: "Quick scan started" }),
          btn("Refresh score", async () => { await GET("/api/score?refresh=true"); }, { icon: "refresh" }),
          btn("Create report", () => { go("reports"); return "norefresh"; }, { icon: "file" })),
        d.score && d.score.change && d.score.change.delta ? h("div", { class: "small", style: { marginTop: "10px", color: d.score.change.delta > 0 ? "var(--ok)" : "var(--critical)" } },
          `${d.score.change.delta > 0 ? "▲ +" : "▼ "}${d.score.change.delta} since ${ago(d.score.change.since)}`) : null)));
    const fix = card("What to fix first", s ? recList(s.recommendations.filter(r => r.severity !== "info" && !r.id.endsWith(":setup")), 12) : empty("-"),
      { actions: s && s.recommendations_total > 6 ? [h("span", { class: "muted small" }, `${s.recommendations_total} in total`)] : null });
    root.appendChild(h("div", { class: "grid g-main" }, hero, fix));

    // ---- protection areas
    if (d.tiles && !d.tiles.error) root.appendChild(h("div", { class: "grid g-auto" }, d.tiles.map(t => h("section", { class: "card click", onclick: () => go(t.link), title: t.note || "" },
      h("div", { class: "tile" }, ring(t.score, 62),
        h("div", { class: "meta" }, h("div", { class: "name" }, t.name),
          h("div", { class: "small", style: { color: t.score === null ? "var(--dim)" : scoreColor(t.score) } }, t.status_text),
          h("div", { class: "dim small" }, t.score === null ? "Click to set up" : t.issues ? `${t.issues} thing(s) to check` : "No issues")))))));

    // ---- key numbers
    root.appendChild(h("div", { class: "grid g4" },
      statCard(num(th.active || 0), "Active threats", th.quarantined ? `${th.quarantined} in quarantine` : "Nothing waiting", th.active ? "var(--critical)" : "var(--ok)"),
      statCard(rt.enabled ? (rt.snoozed_until ? "Paused" : "On") : "Off", "Real-time protection", rt.watching !== undefined ? `${rt.watching} folder(s) watched` : "", rt.enabled && !rt.snoozed_until ? "var(--ok)" : "var(--critical)"),
      statCard(sc.last_scan ? ago(sc.last_scan.finished_at || sc.last_scan.created_at) : "Never", "Last scan", sc.last_scan ? `${cap(sc.last_scan.kind)} · ${num(sc.last_scan.files_scanned)} files` : "Run a quick scan"),
      statCard(fw.error ? "?" : (fw.profiles || []).every(p => p.enabled) ? "On" : "Check", "Firewall", fw.grade || fw.error || "", (fw.profiles || []).every(p => p.enabled) ? "var(--ok)" : "var(--medium)")));

    // ---- graphs
    const hist = (d.score_history && d.score_history.by_day) || [];
    const sysHist = sys.history || [];
    const live = h("div");
    const drawLive = arr => { clear(live).appendChild(line([{ name: "CPU %", color: "var(--accent)", values: arr.map(x => x.cpu) }, { name: "Memory %", color: "var(--accent2)", values: arr.map(x => x.memory) }], { max: 100, height: 150, legend: true })); };
    const liveArr = sysHist.map(x => ({ cpu: x.cpu, memory: x.memory })).slice(-40);
    if (stats.cpu_percent !== undefined) liveArr.push({ cpu: stats.cpu_percent, memory: stats.memory_percent });
    drawLive(liveArr);
    const liveNums = h("div", { class: "row", style: { gap: "22px", marginBottom: "8px" } });
    const paintNums = st => clear(liveNums).append(stat((st.cpu_percent || 0).toFixed(0) + "%", "CPU"), stat((st.memory_percent || 0).toFixed(0) + "%", "Memory"), stat((st.disk_percent || 0).toFixed(0) + "%", "Disk used"), stat(num(st.process_count), "Programs running"));
    paintNums(stats);
    every(3000, async () => { try { const st = await GET("/api/system/stats", { quiet: true }); liveArr.push({ cpu: st.cpu_percent, memory: st.memory_percent }); if (liveArr.length > 60) liveArr.shift(); drawLive(liveArr); paintNums(st); } catch (e) { /* */ } });
    root.appendChild(h("div", { class: "grid g2" },
      card("Threats found per day", bars(daySeries(th.by_day, 14, x => x.detected || 0), { color: "var(--high)" }),
        { actions: [h("span", { class: "muted small" }, th.handled_percent !== undefined ? `${th.handled_percent}% handled` : "")] }),
      card("Security score", hist.length > 1 ? line([{ name: "Score", color: "var(--ok)", values: hist.map(x => x.score) }], { max: 100, height: 168 })
        : h("div", { class: "empty" }, "The graph fills in as days pass. Today: ", h("b", null, s ? s.score : "-")))));
    root.appendChild(h("div", { class: "grid g2" },
      card("This computer", h("div", null, liveNums, live), { actions: [h("span", { class: "muted small" }, (sys.device && sys.device.hostname) || "")] }),
      card("Your network", h("div", null, topologyArt(nw, fw, rt),
        h("div", { class: "row", style: { justifyContent: "space-between", marginTop: "6px" } },
          h("span", { class: "muted small" }, nw.connections ? `${num(nw.connections.total)} connections · ${num(nw.connections.flagged || 0)} flagged` : ""),
          btn("Open network", () => { go("network"); return "norefresh"; }, { sm: true }))))));

    // ---- recent things
    const no = d.notifications || {}, sch = d.schedule || {}, act = d.activity || {};
    root.appendChild(h("div", { class: "grid g3" },
      card("Latest alerts", (no.latest || []).length ? h("div", { class: "list" }, no.latest.slice(0, 5).map(n => h("div", { class: "item", style: { cursor: "pointer" }, onclick: () => go(CH.pages[n.link] ? n.link : "notifications") },
        h("i", { class: "dot c-" + n.severity, style: { marginTop: "7px" } }), h("div", null, h("div", { class: "t" }, n.title), h("div", { class: "d" }, n.source_name, " · ", ago(n.ts)))))) : empty("No alerts"),
        { actions: [btn("All", () => { go("notifications"); return "norefresh"; }, { sm: true, kind: "ghost" })] }),
      card("Coming up", (sch.upcoming || []).length ? h("div", { class: "list" }, sch.upcoming.map(u => h("div", { class: "item" }, h("span", { class: "c-low" }, icon("clock")), h("div", null, h("div", { class: "t" }, u.name), h("div", { class: "d" }, dt(u.at), " · ", ago(u.at)))))) : empty("Nothing is scheduled"),
        { actions: [btn("Scheduler", () => { go("scheduler"); return "norefresh"; }, { sm: true, kind: "ghost" })] }),
      card("Recent activity", (act.latest || []).length ? h("div", { class: "list" }, act.latest.slice(0, 5).map(a => h("div", { class: "item" }, h("i", { class: "dot c-" + a.severity, style: { marginTop: "7px" } }),
        h("div", null, h("div", { class: "t" }, a.title), h("div", { class: "d" }, cap(a.category), " · ", ago(a.ts)))))) : empty("Nothing yet"),
        { actions: [btn("All", () => { go("activity"); return "norefresh"; }, { sm: true, kind: "ghost" })] })));
    every(30000, () => refresh());
    return root;
  } });

/* ================================================================== Virus & threat protection */
function threatActions(t) {
  const acts = t.actions || [];
  const out = [];
  if (acts.includes("quarantine")) out.push(btn("Quarantine", () => POST(`/api/threats/${t.id}/quarantine`), { sm: true, kind: "primary", ok: "Moved to quarantine" }));
  if (acts.includes("remove")) out.push(btn("Remove", () => POST(`/api/threats/${t.id}/remove`), { sm: true, kind: "danger", confirm: `Delete this file permanently?\n${t.path}`, ok: "Removed" }));
  if (acts.includes("allow") && isAdmin()) out.push(btn("Allow", () => POST(`/api/threats/${t.id}/allow`), { sm: true, confirm: "Allow this item? Cyber Hub will stop reporting it.", ok: "Allowed" }));
  return h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, out);
}
function scanJobCard(j) {
  const running = ["running", "queued", "paused"].includes(j.status);
  return h("section", { class: "card" }, h("div", { class: "spread" },
    h("div", null, h("div", { class: "bold" }, cap(j.kind), " scan ", badge(j.status, j.status === "completed" ? "ok" : j.status === "running" ? "low" : "medium")),
      h("div", { class: "muted small" }, `${num(j.files_scanned)} of ${num(j.files_total)} files · ${j.threats_found} threat(s)`, j.eta_seconds ? ` · about ${dur(j.eta_seconds)} left` : "", j.current_file ? ` · ${j.current_file}` : "")),
    running ? h("div", { class: "row tight" },
      j.status === "paused" ? btn("Resume", () => POST(`/api/scan/jobs/${j.id}/resume`), { sm: true }) : btn("Pause", () => POST(`/api/scan/jobs/${j.id}/pause`), { sm: true }),
      btn("Cancel", () => POST(`/api/scan/jobs/${j.id}/cancel`), { sm: true, kind: "danger" })) : null),
    h("div", { style: { marginTop: "10px" } }, progress(j.percent)));
}

page("protection", { title: "Virus & threat protection", nav: "Virus & threats", icon: "shield", sub: "Scans, threats, quarantine and real-time protection",
  subs: [["overview", "Overview & scans"], ["threats", "Threat history"], ["quarantine", "Quarantine"], ["realtime", "Real-time protection"], ["rules", "Rules & signatures"], ["options", "Exclusions & cloud lookup"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar);
    const body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "overview") {
      const [sm, active, jobs, rt] = await Promise.all([GET("/api/scan/summary?days=14"), GET("/api/scan/jobs/active"), GET("/api/scan/jobs?limit=12"), GET("/api/realtime/status")]);
      if (sm.active_threats) body.appendChild(banner("critical", sm.status_text, "Quarantine keeps the file locked away so it can't run.",
        btn("Quarantine all", () => POST("/api/threats/actions", { action: "quarantine" }), { kind: "primary", ok: r => `${r.succeeded} item(s) quarantined` })));
      else body.appendChild(banner(rt.protected ? "ok" : "medium", rt.protected ? "No current threats" : "Real-time protection is not running", sm.status_text));
      body.appendChild(h("div", { class: "grid g4" },
        statCard(num(sm.active_threats), "Active threats", null, sm.active_threats ? "var(--critical)" : "var(--ok)"),
        statCard(sm.last_scan ? ago(sm.last_scan.finished_at || sm.last_scan.created_at) : "Never", "Last scan", sm.last_scan ? `${cap(sm.last_scan.kind)} · ${dur(sm.last_scan.duration_seconds)}` : ""),
        statCard(num(sm.totals ? sm.totals.files : 0), "Files scanned (14 days)", `${sm.totals ? sm.totals.scans : 0} scan(s)`),
        statCard(num(sm.signatures ? sm.signatures.enabled : 0), "Known-bad signatures", sm.signatures && sm.signatures.patterns ? `${sm.signatures.patterns} pattern(s)` : "")));
      body.appendChild(card("Scan now", h("div", { class: "row" },
        btn("Quick scan", () => POST("/api/scan/quick"), { kind: "primary", icon: "bolt", ok: "Quick scan started" }),
        btn("Full scan", () => POST("/api/scan/full"), { icon: "data", ok: "Full scan started", confirm: "A full scan checks every file on this PC and can take hours. Start it now?", confirmLabel: "Start full scan" }),
        btn("Scan a folder…", async () => { const v = await formDialog("Custom scan", [{ name: "paths", label: "Folders or files to scan (one per line)", type: "textarea", required: true, placeholder: "C:\\Users\\You\\Downloads" }], { submit: "Start scan", onSubmit: f => POST("/api/scan/custom", { paths: lines(f.paths) }) }); return v ? undefined : "norefresh"; }, { icon: "folder" }),
        btn("Check one file…", async () => { const v = await formDialog("Check a file", [{ name: "path", label: "Full path of the file", type: "path", pick: "file", required: true }], { submit: "Scan", onSubmit: f => POST("/api/scan/file", { path: f.path }) });
          if (v) detailDialog("Result", kv([["File", v.path], ["Verdict", v.status === "clean" ? badge("Clean", "ok") : badge(v.status === "infected" ? "Threat found" : cap(v.status), v.status === "infected" ? "critical" : "medium")], ["Threat", (v.detections || []).map(x => x.threat_name).join(", ") || v.reason], ["Size", bytes(v.size)], ["SHA-256", h("code", { class: "wrap" }, v.sha256 || "-")]])); return "norefresh"; }, { icon: "file" }),
        btn("Test detection", () => POST("/api/scan/self-test"), { ok: r => r.passed ? "Detection works: all " + Object.keys(r.checks || {}).length + " engine checks passed" : "Self-test did not pass - check the engine", refresh: false }))));
      const act = (active.items || []);
      act.forEach(j => body.appendChild(scanJobCard(j)));
      if (act.length) every(1500, () => refresh());
      body.appendChild(h("div", { class: "grid g2" },
        card("Files scanned per day", bars(daySeries(sm.by_day, 14, x => x.files || 0), {})),
        card("Detections by type", Object.keys(sm.detections_by_method || {}).length ? donut(Object.entries(sm.detections_by_method).map(([k, v], i) => ({ label: cap(k), value: v, color: ["var(--accent)", "var(--accent2)", "var(--medium)", "var(--high)", "var(--critical)"][i % 5] })))
          : empty("No detections yet"))));
      body.appendChild(tableCard("Recent scans", [
        { t: "Started", v: j => dt(j.started_at || j.created_at) }, { t: "Type", v: j => cap(j.kind) },
        { t: "Result", v: j => badge(j.status, j.status === "completed" ? "ok" : j.status === "failed" ? "critical" : "medium") },
        { t: "Files", v: j => num(j.files_scanned), cls: "num" }, { t: "Threats", v: j => j.threats_found ? h("b", { class: "c-critical" }, j.threats_found) : "0", cls: "num" },
        { t: "Time", v: j => dur(j.duration_seconds), cls: "num" }, { t: "By", v: j => j.started_by }], jobs.items, { empty: "No scans yet - run a quick scan" }));
    }

    if (t.current === "threats") {
      const [sm, lst] = await Promise.all([GET("/api/threats/summary?days=30"), GET("/api/threats" + qs({ status: "all", limit: 200 }))]);
      body.appendChild(h("div", { class: "grid g2" },
        card("Last 30 days", bars(daySeries(sm.by_day, 30, x => x.detected || 0), { color: "var(--high)" })),
        card("What happened to them", donut([["Active", sm.by_status.active, "var(--critical)"], ["Quarantined", sm.by_status.quarantined, "var(--accent)"], ["Removed", sm.by_status.removed, "var(--ok)"],
          ["Allowed", sm.by_status.allowed, "var(--medium)"], ["Restored", sm.by_status.restored, "var(--accent2)"], ["Dismissed", (sm.by_status.dismissed || 0) + (sm.by_status.resolved || 0), "var(--dim)"]].map(([label, value, color]) => ({ label, value, color })), 130, sm.handled_percent + "%"))));
      body.appendChild(tableCard("Protection history", [
        { t: "Found", v: x => dt(x.detected_at) }, { t: "Threat", v: x => h("b", null, x.threat_name) }, { t: "Severity", v: x => badge(x.severity) },
        { t: "Status", v: x => badge(x.status, x.status === "active" ? "critical" : x.status === "quarantined" ? "low" : "ok") }, { t: "How", v: x => cap(x.method) },
        { t: "File", v: x => pathCell(x.path + (x.archive_member ? " > " + x.archive_member : "")) }, { t: "", v: x => threatActions(x) }], lst.items,
        { total: lst.total, empty: "No threats have been found. That's the goal.", actions: [btn("Export CSV", () => { download("/api/threats/export.csv?status=all", "threats.csv"); return "norefresh"; }, { sm: true, icon: "download", refresh: false })] }));
      const allowed = await GET("/api/threats/allowed");
      body.appendChild(tableCard("Allowed threats", [{ t: "Added", v: a => dt(a.created_at) }, { t: "What", v: a => a.threat_name || h("code", null, (a.sha256 || "").slice(0, 24) + "…") }, { t: "Note", v: a => a.note },
        { t: "Seen", v: a => num(a.hits), cls: "num" }, { t: "", v: a => isAdmin() ? btn("Stop allowing", () => DEL(`/api/threats/allowed/${a.id}`), { sm: true, kind: "danger" }) : "" }], allowed.items, { empty: "Nothing is allowed. Allowed items are never reported again." }));
    }

    if (t.current === "quarantine") {
      const [st, lst] = await Promise.all([GET("/api/quarantine/stats"), GET("/api/quarantine" + qs({ status: "quarantined", limit: 200 }))]);
      body.appendChild(h("div", { class: "grid g4" }, statCard(num(st.items), "Files in quarantine"), statCard(bytes(st.stored_bytes), "Space used", `${st.used_percent}% of ${bytes(st.limit_bytes)}`),
        statCard(st.retention_days ? st.retention_days + " days" : "Forever", "Kept for"), statCard(st.vault && st.vault.available ? "Locked" : "Problem", "Vault (AES-256)", st.vault ? cap(st.vault.key_protection) + " key" : "", st.vault && st.vault.available ? "var(--ok)" : "var(--critical)")));
      body.appendChild(tableCard("Quarantined files", [
        { t: "Since", v: q => dt(q.quarantined_at) }, { t: "Threat", v: q => h("b", null, q.threat_name) }, { t: "Severity", v: q => badge(q.severity) }, { t: "Size", v: q => bytes(q.size), cls: "num" },
        { t: "Came from", v: q => pathCell(q.original_path) }, { t: "Deleted on", v: q => q.expires_at ? day(q.expires_at) : "-" },
        { t: "", v: q => h("div", { class: "row tight", style: { flexWrap: "nowrap" } },
          btn("Restore", () => POST(`/api/quarantine/${q.id}/restore`, {}), { sm: true, confirm: `Put this file back?\n${q.original_path}\n\nOnly do this if you are sure it is safe.`, confirmLabel: "Restore", ok: "Restored" }),
          btn("Delete", () => DEL(`/api/quarantine/${q.id}`), { sm: true, kind: "danger", confirm: "Delete this file for good? It can't be brought back.", ok: "Deleted" })) }], lst.items,
        { total: lst.total, empty: "The quarantine is empty.", actions: [
          btn("Quarantine a file…", async () => { const v = await formDialog("Quarantine a file", [{ name: "path", label: "Full path of the file", type: "path", pick: "file", required: true }, { name: "note", label: "Note (optional)" }], { submit: "Quarantine", onSubmit: f => POST("/api/quarantine", { path: f.path, note: f.note || null }) }); return v ? undefined : "norefresh"; }, { sm: true, icon: "plus" }),
          btn("Check vault", () => POST("/api/quarantine/vault/check"), { sm: true, ok: r => r.missing_items ? `${r.missing_items} quarantined file(s) are missing from the vault` : "Vault checked - every file is in place" })] }));
    }

    if (t.current === "realtime") {
      const [rt, ev, usb, sm] = await Promise.all([GET("/api/realtime/status"), GET("/api/realtime/events?limit=60"), GET("/api/realtime/usb"), GET("/api/realtime/summary?days=14").catch(() => ({}))]);
      body.appendChild(card("Real-time protection", h("div", null,
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Check new files as they arrive"), h("div", { class: "d" }, rt.snoozed_until ? `Paused until ${dt(rt.snoozed_until)}` : rt.error ? rt.error : `Watching ${rt.watching} folder(s) with the ${rt.engine} engine`)),
          h("div", { class: "ctl" }, toggle(rt.enabled, on => POST(on ? "/api/realtime/enable" : "/api/realtime/disable")))),
        h("div", { class: "row", style: { marginTop: "12px" } },
          rt.snoozed_until ? btn("Resume now", () => POST("/api/realtime/resume"), { kind: "primary" }) : btn("Pause 15 minutes", () => POST("/api/realtime/pause", { minutes: 15 }), {}),
          btn("Test it", () => POST("/api/realtime/self-test"), { ok: r => r.ok ? "Works: new files are noticed and the scan engine passed its checks" : "Real-time protection did not pass its test - check the folders below" }),
          h("span", { class: "muted small" }, `${num(rt.counters.files_scanned)} files checked · ${num(rt.counters.threats)} threat(s) stopped since start`)))));
      body.appendChild(tableCard("Watched folders", [{ t: "Folder", v: f => pathCell(f.path) }, { t: "Kind", v: f => cap(f.kind) }, { t: "Status", v: f => badge(f.status, f.status === "watching" ? "ok" : "medium") },
        { t: "", v: f => f.kind === "custom" ? btn("Remove", () => DEL("/api/realtime/folders" + qs({ path: f.path })), { sm: true, kind: "danger" }) : "" }], rt.folders,
        { actions: [btn("Add folder…", async () => { const v = await formDialog("Watch another folder", [{ name: "path", label: "Folder", type: "path", required: true }], { submit: "Add", onSubmit: f => POST("/api/realtime/folders", { path: f.path }) }); return v ? undefined : "norefresh"; }, { sm: true, icon: "plus" })] }));
      body.appendChild(tableCard("USB drives", [{ t: "Drive", v: u => h("b", null, u.label || u.name || u.mount || u.id) }, { t: "Last seen", v: u => ago(u.last_seen || u.last_seen_at) }, { t: "Connected", v: u => onoff(u.connected, "Yes", "No") },
        { t: "Trusted", v: u => toggle(u.trusted, on => PATCH(`/api/realtime/usb/${u.id}`, { trusted: on })) }, { t: "", v: u => u.connected ? btn("Scan", () => POST(`/api/realtime/usb/${u.id}/scan`), { sm: true, ok: "Drive scan started" }) : "" }],
        usb.devices, { empty: "No USB drive has been plugged in yet. New drives are checked automatically." }));
      body.appendChild(tableCard("What real-time protection saw", [{ t: "When", v: e => dt(e.ts || e.detected_at) }, { t: "Result", v: e => badge(e.status, e.status === "clean" ? "ok" : e.status === "infected" ? "critical" : "info") },
        { t: "File", v: e => pathCell(e.path) }, { t: "Action", v: e => cap(e.action || "-") }], ev.items, { total: ev.total, empty: "No files have arrived in the watched folders yet." }));
    }

    if (t.current === "rules") {
      const [st, sets, sig] = await Promise.all([GET("/api/rules/status"), GET("/api/rules"), GET("/api/scan/signatures/stats")]);
      body.appendChild(h("div", { class: "grid g4" }, statCard(num(st.active_rules), "Active YARA rules", `${st.active_sets} rule set(s)`), statCard(cap(st.settings.heuristics_sensitivity), "Heuristic sensitivity", st.settings.heuristics_enabled ? "On" : "Off"),
        statCard(num(sig.enabled), "File signatures", Object.entries(sig.by_source || {}).map(([k, v]) => `${k}: ${v}`).join(" · ")), statCard(st.backend.name === "lite" ? "Built-in" : "Native", "Rule engine", st.backend.label)));
      body.appendChild(tableCard("Rule sets", [{ t: "Name", v: s => h("b", null, s.name) }, { t: "From", v: s => cap(s.origin) }, { t: "Rules", v: s => s.rule_count, cls: "num" }, { t: "Hits", v: s => num(s.detections), cls: "num" },
        { t: "Status", v: s => s.status === "ok" ? badge("OK", "ok") : h("span", { title: s.error || "" }, badge(s.status, "medium")) },
        { t: "On", v: s => toggle(s.enabled, on => PATCH(`/api/rules/${s.id}`, { enabled: on }), !isAdmin()) },
        { t: "", v: s => s.origin !== "builtin" && isAdmin() ? btn("Delete", () => DEL(`/api/rules/${s.id}`), { sm: true, kind: "danger", confirm: `Delete rule set ${s.name}?` }) : "" }], sets.items,
        { actions: [btn("Add rules…", async () => { const v = await formDialog("Add YARA rules", [{ name: "name", label: "Name", required: true, placeholder: "my-rules" }, { name: "source", label: "Rules", type: "textarea", required: true, placeholder: "rule Example { strings: $a = \"bad\" condition: $a }" }], { submit: "Add", wide: true, onSubmit: f => POST("/api/rules", { name: f.name, source: f.source }) }); return v ? undefined : "norefresh"; }, { sm: true, icon: "plus" }),
          btn("Import file…", async () => { const v = await formDialog("Import rules", [{ name: "path", label: ".yar file, folder or .zip", type: "path", pick: "file", required: true }], { submit: "Import", onSubmit: f => POST("/api/rules/import", { path: f.path }) }); return v ? undefined : "norefresh"; }, { sm: true }),
          btn("Self-test", () => POST("/api/rules/self-test"), { sm: true, ok: r => r.passed ? "Rules and heuristics work" : "Self-test did not pass" })] }));
      body.appendChild(card("File signatures", h("div", { class: "row" },
        btn("Add a hash…", async () => { const v = await formDialog("Add a known-bad file", [{ name: "hash", label: "SHA-256, SHA-1 or MD5", required: true }, { name: "name", label: "Threat name", required: true, value: "Malware.Custom" }, { name: "severity", label: "Severity", type: "select", value: "high", options: ["low", "medium", "high", "critical"].map(x => [x, cap(x)]) }], { submit: "Add", onSubmit: f => POST("/api/scan/signatures", f) }); return v ? undefined : "norefresh"; }, { icon: "plus" }),
        btn("Import a hash list…", async () => { const v = await formDialog("Import hashes", [{ name: "path", label: "File (.txt / .csv / .zip, e.g. from MalwareBazaar)", type: "path", pick: "file" }, { name: "text", label: "…or paste hashes here", type: "textarea" }], { submit: "Import", onSubmit: f => POST("/api/scan/signatures/import", { path: f.path || null, text: f.text || null }) }); if (v) toast(`${num(v.added !== undefined ? v.added : v.imported || 0)} signature(s) added`, "ok"); return v ? undefined : "norefresh"; }, {}),
        btn("Analyse a file…", async () => { const v = await formDialog("Analyse a file", [{ name: "path", label: "Full path of the file", type: "path", pick: "file", required: true }], { submit: "Analyse", onSubmit: f => POST("/api/rules/analyze", { path: f.path }) });
          if (v) detailDialog("Analysis", (() => { const why = [].concat(((v.yara || {}).matches || []).map(m => "Rule: " + (m.rule || m.name || m)), ((v.heuristics || {}).flags || []).map(f => (f.title || f.id || f) + (f.detail ? " - " + f.detail : "")), v.signature_match ? ["Known-bad file: " + (v.signature_match.name || "signature match")] : []);
            return h("div", null, kv([["Verdict", v.malicious ? badge(v.verdict && v.verdict.threat_name ? v.verdict.threat_name : "Suspicious", "high") : badge("Nothing found", "ok")], ["File type", cap(v.file_type)], ["Heuristic score", `${(v.heuristics || {}).score || 0} (alerts from ${(v.heuristics || {}).threshold || "-"})`], ["Entropy", v.entropy], ["SHA-256", h("code", { class: "wrap" }, v.sha256 || "-")]]),
              h("h3", { style: { margin: "14px 0 6px" } }, "Reasons"), why.length ? h("ul", null, why.map(r => h("li", null, r))) : h("p", { class: "muted" }, "Nothing suspicious was found.")); })()); return "norefresh"; }, { icon: "search" }))));
    }

    if (t.current === "options") {
      const [ex, lk] = await Promise.all([GET("/api/scan/exclusions"), GET("/api/lookup/status")]);
      body.appendChild(card("Exclusions", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "Files and folders listed here are never scanned. Keep this list short - malware loves excluded folders."),
        kv([["Folders / files", ex.paths.length ? h("div", null, ex.paths.map(p => h("div", { class: "mono" }, p))) : "None"], ["File types", ex.extensions.length ? ex.extensions.join(", ") : "None"]]),
        h("div", { style: { marginTop: "12px" } }, btn("Change…", async () => { const v = await formDialog("Exclusions", [{ name: "paths", label: "Folders or files (one per line)", type: "textarea", value: ex.paths.join("\n") }, { name: "extensions", label: "File types (e.g. .iso .vhd)", value: ex.extensions.join(" ") }],
          { onSubmit: f => PUT("/api/scan/exclusions", { paths: lines(f.paths), extensions: f.extensions.split(/[\s,]+/).filter(Boolean) }) }); return v ? undefined : "norefresh"; }, {})))));
      body.appendChild(card("Cloud file check (optional)", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, lk.privacy),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Ask online services about unknown programs"), h("div", { class: "d" }, lk.ready ? "Ready" : "Add a free API key below to use it")),
          h("div", { class: "ctl" }, toggle(lk.enabled, on => PATCH("/api/settings", { cloud_lookup_enabled: on }), !isAdmin()))),
        Object.values(lk.providers).map(p => h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, p.label), h("div", { class: "d" }, p.key_set ? `Key saved (${p.key_hint || "hidden"}) · ${p.requests_today} of ${p.daily_limit} checks used today` : "No key yet - get a free one at " + p.get_key_at)),
          h("div", { class: "ctl" }, isAdmin() ? btn(p.key_set ? "Change key" : "Add key", async () => { const v = await formDialog(p.label + " API key", [{ name: "key", label: "API key", type: "password", required: true }], { onSubmit: f => PUT("/api/lookup/keys", { [p.provider]: f.key }) }); return v ? undefined : "norefresh"; }, { sm: true }) : null))))));
    }
    return root;
  } });

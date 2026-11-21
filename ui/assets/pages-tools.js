/* Cyber Hub UI - Website scanner, Threat intelligence, System monitor, Processes & startup (Parts 3, 4, 14, 15)
   Developed by Syed Muhammad Tayyab */
"use strict";

/* ================================================================== Website / developer scanner */
async function waitWebJob(job, label) {
  toast(label + " started", "info", 2500);
  for (let i = 0; i < 400; i++) {
    await new Promise(r => setTimeout(r, 900));
    const j = await GET(`/api/web/jobs/${job.id}`, { quiet: true });
    if (!["queued", "running"].includes(j.status)) { toast(j.status === "done" ? `${label} finished` : `${label}: ${j.status}${j.error ? " - " + j.error : ""}`, j.status === "done" ? "ok" : "error"); return j; }
  }
}
async function scanDialog(id) {
  const s = await GET(`/api/web/scans/${id}`), r = s.result || {}, sc = r.score || {};
  const findings = (r.findings || []).slice().sort((a, b) => SEV.indexOf(b.severity) - SEV.indexOf(a.severity));
  detailDialog(s.target, h("div", null,
    h("div", { class: "row", style: { marginBottom: "12px" } }, ring(s.score, 76), h("div", null, h("div", { class: "bold", style: { fontSize: "16px" } }, "Grade ", s.grade || "-"), h("div", { class: "muted small" }, `${cap(s.kind)} scan · ${dt(s.finished_at || s.created_at)}`),
      h("div", { class: "row tight", style: { marginTop: "4px" } }, ["critical", "high", "medium", "low"].filter(x => s[x]).map(x => badge(`${s[x]} ${x}`, x))))),
    s.error ? banner("critical", "The scan could not finish", s.error) : null,
    r.lookup && r.lookup.online && !r.lookup.ok ? banner("medium", "Package vulnerabilities could not be checked online", r.lookup.error) : null,
    r.changes && (r.changes.new || []).length ? banner("medium", `${r.changes.new.length} new problem(s) since the last scan`, "") : null,
    sc.categories ? h("div", { style: { margin: "6px 0 12px" } }, Object.entries(sc.categories).map(([k, v]) => hbar(cap(k), typeof v === "object" ? v.score : v, 100))) : null,
    h("h3", { style: { margin: "12px 0 4px" } }, `Problems (${findings.length})`),
    findings.length ? h("div", { class: "list" }, findings.map(f => h("div", { class: "item" }, h("span", { style: { marginTop: "2px" } }, badge(f.severity)), h("div", null, h("div", { class: "t" }, f.title), h("div", { class: "d" }, f.detail), f.advice ? h("div", { class: "small c-low" }, "Fix: ", f.advice) : null, f.evidence ? h("div", { class: "dim small mono wrap" }, typeof f.evidence === "string" ? f.evidence : JSON.stringify(f.evidence).slice(0, 300)) : null))))
      : h("p", { class: "muted" }, "No problems were found."),
    (r.packages || []).length ? h("div", null, h("h3", { style: { margin: "14px 0 4px" } }, "Vulnerable packages"), table([{ t: "Package", v: p => h("b", null, p.name) }, { t: "Version", v: p => p.version }, { t: "Level", v: p => badge(p.severity || "medium") }, { t: "Fixed in", v: p => p.fixed || p.fixed_version || (p.fix || {}).version }, { t: "Advisories", v: p => (p.vulns || p.ids || []).map(x => x.id || x).slice(0, 3).join(", ") }], r.packages, {})) : null,
    (r.passed || []).length ? h("div", null, h("h3", { style: { margin: "14px 0 4px" } }, "Passed"), h("div", { class: "muted small" }, r.passed.map(p => p.title).join(" · "))) : null));
}
page("web", { title: "Website & project scanner", nav: "Website scanner", icon: "globe", sub: "Check your sites and code projects for security problems",
  subs: [["scan", "Scan & results"], ["targets", "Saved & monitored"], ["dev", "Dev servers"], ["alerts", "Alerts"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "scan") {
      const [hl, scans, jobs] = await Promise.all([GET("/api/web/health"), GET("/api/web/scans?limit=40"), GET("/api/web/jobs?limit=5")]);
      const url = h("input", { class: "input", placeholder: "example.com or https://my-site.com" });
      const scanSite = async () => { const body1 = { target: url.value.trim(), save: true };
        let job; try { job = await POST("/api/web/scan", body1); } catch (e) { if (e.status !== 428) throw e; if (!(await confirmBox(e.message, "It's my site - run all checks"))) return "norefresh"; job = await POST("/api/web/scan", Object.assign(body1, { confirm_owner: true })); }
        const j = await waitWebJob(job, "Website scan"); if (j && j.scan_id) scanDialog(j.scan_id); else { const l = await GET("/api/web/scans?limit=1"); if (l.items[0]) scanDialog(l.items[0].id); } };
      url.addEventListener("keydown", e => { if (e.key === "Enter") run(null, scanSite); });
      body.appendChild(h("div", { class: "grid g2" },
        card("Scan a website", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "HTTPS and certificate, security headers, cookies, outdated libraries and exposed files. Only safe, read-only requests are sent."),
          h("div", { class: "row", style: { flexWrap: "nowrap" } }, url, btn("Scan", scanSite, { kind: "primary", icon: "search" })))),
        card("Scan a code project", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "Vulnerable packages (npm, pip, composer), keys left in files and risky settings like DEBUG=True."),
          btn("Choose a project folder…", async () => { const v = await formDialog("Scan a project", [{ name: "path", label: "Project folder", type: "path", required: true }], { submit: "Scan", onSubmit: f => POST("/api/web/project/scan", { path: f.path, save: true }) });
            if (!v) return "norefresh"; await waitWebJob(v, "Project scan"); const l = await GET("/api/web/scans?limit=1"); if (l.items[0]) scanDialog(l.items[0].id); }, { icon: "folder" })))));
      if ((jobs.running || []).length) { body.appendChild(card("Running now", h("div", null, jobs.running.map(j => h("div", { style: { marginBottom: "10px" } }, h("div", { class: "spread" }, h("b", null, j.target), h("span", { class: "muted small" }, (j.progress || {}).phase || "")), progress((j.progress || {}).percent))))));
        every(1500, () => refresh()); }
      if (hl.score !== null) body.appendChild(h("div", { class: "grid g4" }, statCard(hl.score, "Overall score", "Grade " + hl.grade, scoreColor(hl.score)), statCard(num(hl.sites) + " / " + num(hl.projects), "Sites / projects"), statCard(num(hl.open.critical + hl.open.high), "Serious problems", null, hl.open.critical + hl.open.high ? "var(--critical)" : "var(--ok)"), statCard(num(hl.vulnerable_packages), "Vulnerable packages")));
      body.appendChild(tableCard("Scan results", [{ t: "When", v: s => dt(s.finished_at || s.created_at) }, { t: "Target", v: s => h("b", { class: "wrap" }, s.target) }, { t: "Kind", v: s => cap(s.kind) },
        { t: "Grade", v: s => s.status === "done" ? h("b", { style: { color: scoreColor(s.score) } }, `${s.grade} (${s.score})`) : badge(s.status, "medium") },
        { t: "Problems", v: s => h("span", { class: "row tight" }, ["critical", "high", "medium", "low"].filter(x => s[x]).map(x => badge(`${s[x]} ${x}`, x))) },
        { t: "", v: s => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, btn("Open", async () => { await scanDialog(s.id); return "norefresh"; }, { sm: true, kind: "primary" }), btn("Delete", () => DEL(`/api/web/scans/${s.id}`), { sm: true, kind: "danger" })) }],
        scans.items, { total: scans.total, onRow: s => run(null, async () => { await scanDialog(s.id); return "norefresh"; }), empty: "No scans yet. Scan a website or a project folder above." }));
    }

    if (t.current === "targets") {
      const tg = await GET("/api/web/targets");
      body.appendChild(tableCard("Saved sites and projects", [{ t: "Target", v: x => h("div", null, h("b", { class: "wrap" }, x.label || x.target), x.label ? h("div", { class: "dim small" }, x.target) : null) }, { t: "Kind", v: x => cap(x.kind) },
        { t: "Last grade", v: x => x.last_grade ? h("b", { style: { color: scoreColor(x.last_score) } }, `${x.last_grade} (${x.last_score})`) : "-" }, { t: "Last scan", v: x => ago(x.last_scan_at) },
        { t: "Certificate", v: x => x.cert_days_left !== null && x.cert_days_left !== undefined ? h("span", { class: x.cert_days_left < 14 ? "c-critical" : "" }, x.cert_days_left + " days left") : "" },
        { t: "Watch", v: x => toggle(x.monitor, on => PATCH(`/api/web/targets/${x.id}`, { monitor: on })) },
        { t: "", v: x => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, btn("Scan now", async () => { await waitWebJob(await POST(`/api/web/targets/${x.id}/scan`), "Scan"); }, { sm: true }), btn("Remove", () => DEL(`/api/web/targets/${x.id}`), { sm: true, kind: "danger", confirm: "Remove this target? Its scan history stays." })) }],
        tg.items, { empty: "Scanned sites and projects are saved here. Turn on Watch to re-scan them every day and get alerts when something gets worse." }));
    }

    if (t.current === "dev") {
      const d = await GET("/api/web/dev-servers");
      body.appendChild(banner(d.counts.reachable ? "critical" : "ok", d.counts.reachable ? `${d.counts.reachable} development server(s) can be reached from your network` : "No development server is exposed", "Dev servers (Vite, Django, Jupyter, Node debugger…) often have no password. They should only listen on this PC."));
      body.appendChild(tableCard("Development servers on this PC", [{ t: "Port", v: x => h("b", null, x.port) }, { t: "What", v: x => x.kind_label || x.kind || x.service || x.process }, { t: "Program", v: x => x.process },
        { t: "Reachable from", v: x => x.reachable ? badge("the network", "critical") : x.exposed ? badge("blocked by firewall", "ok") : badge("this PC only", "ok") }, { t: "Level", v: x => x.severity && x.severity !== "info" ? badge(x.severity) : "" },
        { t: "", v: x => x.exposed || x.reachable ? btn("Block in firewall", () => POST(`/api/web/dev-servers/${x.port}/block`), { sm: true, kind: "primary", ok: "Port blocked for incoming connections" }) : "" }], d.items, { empty: "No development server is running right now." }));
    }

    if (t.current === "alerts") { const ev = await GET("/api/web/events?limit=100"); body.appendChild(eventsCard("Website & project alerts", "/api/web", ev.items)); }
    return root;
  } });

/* ================================================================== Threat intelligence */
const VERDICT = { malicious: "critical", suspicious: "high", low_risk: "medium", clean: "ok", unknown: "info" };
function intelResult(r) {
  const ind = r.indicator || {}, ph = r.phishing || {};
  const acts = [];
  if (ind.type === "ip" && isAdmin()) acts.push(btn("Block in firewall", () => POST("/api/intel/block-ip", { ip: ind.value }), { sm: true, kind: "danger", ok: "Address blocked", refresh: false }));
  if (r.verdict !== "clean") acts.push(btn("Add to my block list", () => POST("/api/intel/blocklist", { values: [ind.value] }), { sm: true, ok: "Added to your block list", refresh: false }));
  return h("div", { class: "stack", style: { marginTop: "14px" } },
    banner(VERDICT[r.verdict] === "ok" ? "ok" : VERDICT[r.verdict] === "critical" || VERDICT[r.verdict] === "high" ? "critical" : "medium", `${cap(r.verdict)} (${r.score}/100)`, r.summary, h("div", { class: "row tight" }, acts)),
    kv([["Checked", h("code", { class: "wrap" }, ind.defanged || ind.value)], ["Kind", cap(ind.type)], ["On threat lists", (r.matches || []).length ? r.matches.map(m => m.feed_name || m.feed || m.threat).join(", ") : "No"], ph.level ? ["Phishing signs", `${cap(ph.level)} (${ph.score})`] : null, r.online_used ? ["Online services", Object.keys(r.online || {}).join(", ")] : null]),
    (r.reasons || []).length ? h("ul", { class: "muted", style: { margin: 0 } }, r.reasons.map(x => h("li", null, x))) : null);
}
page("intel", { title: "Threat intelligence", nav: "Threat intel", icon: "radar", sub: "Check links, addresses and files against known threats",
  subs: [["check", "Check something"], ["feeds", "Threat feeds"], ["blocklist", "My block list"], ["alerts", "Alerts"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "check") {
      const [hl, hist] = await Promise.all([GET("/api/intel/health"), GET("/api/intel/checks?limit=30")]);
      const input = h("input", { class: "input", placeholder: "A link, website, IP address, e-mail address or file hash" }), deep = h("input", { type: "checkbox" }), out = h("div");
      const check = async () => { clear(out).appendChild(intelResult(await POST("/api/intel/check", { value: input.value.trim(), deep: deep.checked }))); return "norefresh"; };
      input.addEventListener("keydown", e => { if (e.key === "Enter") run(null, check); });
      body.appendChild(card("Is it safe?", h("div", null, h("div", { class: "row", style: { flexWrap: "nowrap" } }, input, btn("Check", check, { kind: "primary", icon: "search" })),
        h("label", { class: "check", style: { marginTop: "10px" } }, deep, h("span", null, "Also open the page safely and look for a fake login form ", h("span", { class: "muted small" }, "(read-only; nothing is clicked or typed)"))), out)));
      body.appendChild(h("div", { class: "grid g4" }, statCard(num(hl.iocs), "Known-bad indicators"), statCard(`${hl.feeds_ok} / ${hl.feeds_enabled}`, "Feeds up to date", hl.last_update ? "Updated " + ago(hl.last_update) : "Never updated", hl.feeds_stale.length ? "var(--medium)" : null),
        statCard(num(Object.values(hl.open_alerts).reduce((a, b) => a + b, 0)), "Open alerts"), statCard(hl.watch_connections ? "On" : "Off", "Connection matching", "Live connections vs. threat lists", hl.watch_connections ? "var(--ok)" : "var(--medium)")));
      body.appendChild(card("Check many at once", h("div", null, btn("Paste a list or a suspicious e-mail…", async () => { const v = await formDialog("Check many", [{ name: "text", label: "Paste text - every link, address and hash in it is checked", type: "textarea", required: true }], { submit: "Check", wide: true, onSubmit: f => POST("/api/intel/check/bulk", { text: f.text }) });
        if (v) detailDialog(`Checked ${(v.items || v.results || []).length} item(s)`, table([{ t: "Verdict", v: x => badge(x.verdict, VERDICT[x.verdict]) }, { t: "Score", v: x => x.score, cls: "num" }, { t: "Indicator", v: x => h("code", { class: "wrap" }, (x.indicator || {}).defanged || x.defanged || x.value) }, { t: "Why", v: x => h("span", { class: "muted small" }, x.summary) }], v.items || v.results || [], {})); return "norefresh"; }, {}))));
      body.appendChild(tableCard("Recent checks", [{ t: "When", v: c => ago(c.ts) }, { t: "Verdict", v: c => badge(c.verdict, VERDICT[c.verdict]) }, { t: "Score", v: c => c.score, cls: "num" }, { t: "Checked", v: c => h("code", { class: "wrap" }, c.defanged || c.value) }, { t: "Kind", v: c => cap(c.type) }], hist.items, { empty: "Nothing checked yet." }));
    }

    if (t.current === "feeds") {
      const f = await GET("/api/intel/feeds");
      body.appendChild(tableCard(`Threat feeds  ·  ${num(f.total_iocs)} indicators`, [{ t: "On", v: x => x.local ? "" : toggle(x.enabled, on => PATCH(`/api/intel/feeds/${x.id}`, { enabled: on }), !isAdmin()) }, { t: "Feed", v: x => h("div", null, h("b", null, x.name), h("div", { class: "dim small" }, x.provider, x.category_label ? " · " + x.category_label : "")) },
        { t: "Indicators", v: x => num(x.ioc_count), cls: "num" }, { t: "Updated", v: x => x.last_ok_at ? ago(x.last_ok_at) : x.local ? "-" : "Never" },
        { t: "State", v: x => x.last_error ? h("span", { title: x.last_error }, badge("error", "high")) : x.key_required && !x.key_ready ? badge("needs key", "medium") : x.stale ? badge("out of date", "medium") : badge(x.status || "ok", "ok") },
        { t: "", v: x => !x.builtin && isAdmin() ? btn("Delete", () => DEL(`/api/intel/feeds/${x.id}`), { sm: true, kind: "danger", confirm: `Delete feed ${x.name}?` }) : "" }], f.items,
        { count: false, actions: [btn("Update now", () => POST("/api/intel/feeds/refresh", { force: true }), { sm: true, kind: "primary", icon: "refresh", ok: "Feeds are updating in the background" }),
          isAdmin() ? btn("Add feed…", async () => { const v = await formDialog("Add a threat feed", [{ name: "name", label: "Name", required: true }, { name: "url", label: "Address (https://…)", required: true }, { name: "severity", label: "Severity of matches", type: "select", value: "high", options: ["low", "medium", "high", "critical"].map(x => [x, cap(x)]) }], { submit: "Add", onSubmit: fm => POST("/api/intel/feeds", fm) }); return v ? undefined : "norefresh"; }, { sm: true, icon: "plus" }) : null] }));
      if (!f.abusech_key) body.appendChild(banner("medium", "Some feeds need a free abuse.ch key", "URLhaus and ThreatFox ask for a free Auth-Key. Add it under Virus & threats → Exclusions & cloud lookup (MalwareBazaar key).", btn("Open", () => { go("protection", "options"); return "norefresh"; }, { sm: true })));
    }

    if (t.current === "blocklist") {
      const [bl, al] = await Promise.all([GET("/api/intel/blocklist?limit=300"), GET("/api/intel/allowlist")]);
      body.appendChild(tableCard("My block list", [{ t: "Added", v: x => ago(x.created_at || x.first_seen || x.ts) }, { t: "Indicator", v: x => h("code", { class: "wrap" }, x.value) }, { t: "Kind", v: x => cap(x.type) }, { t: "Level", v: x => badge(x.severity) }, { t: "Note", v: x => x.note || x.threat },
        { t: "", v: x => isAdmin() ? btn("Remove", () => POST("/api/intel/blocklist/remove", { ids: [x.id] }), { sm: true, kind: "danger" }) : "" }], bl.items,
        { total: bl.total, empty: "Your own list of bad addresses, sites and file hashes. Anything here is treated as malicious everywhere in Cyber Hub.",
          actions: [btn("Add…", async () => { const v = await formDialog("Add to block list", [{ name: "text", label: "Addresses, sites, links or hashes (one per line)", type: "textarea", required: true }, { name: "note", label: "Note (optional)" }], { submit: "Add", onSubmit: f => POST("/api/intel/blocklist", { text: f.text, note: f.note || null }) }); return v ? undefined : "norefresh"; }, { sm: true, kind: "primary", icon: "plus" }),
            btn("Export", () => { download("/api/intel/export?format=csv&what=blocklist", "blocklist.csv"); return "norefresh"; }, { sm: true, icon: "download", refresh: false })] }));
      body.appendChild(tableCard("Always trusted", [{ t: "Value", v: x => h("code", null, x.value) }, { t: "Note", v: x => x.note }, { t: "Added", v: x => ago(x.created_at) }, { t: "", v: x => isAdmin() ? btn("Remove", () => DEL(`/api/intel/allowlist/${x.id}`), { sm: true, kind: "danger" }) : "" }], al.items || [],
        { empty: "Sites and addresses that should never be flagged.", actions: isAdmin() ? [btn("Add…", async () => { const v = await formDialog("Always trust", [{ name: "value", label: "Site or address", required: true }, { name: "note", label: "Note (optional)" }], { submit: "Add", onSubmit: f => POST("/api/intel/allowlist", { value: f.value, note: f.note || null }) }); return v ? undefined : "norefresh"; }, { sm: true, icon: "plus" })] : null }));
    }

    if (t.current === "alerts") {
      const ev = await GET("/api/intel/events?limit=100");
      body.appendChild(tableCard("Threat-intelligence alerts", [{ t: "When", v: e => dt(e.ts) }, { t: "Severity", v: e => badge(e.severity) }, { t: "What happened", v: e => h("div", null, h("div", { class: "bold" }, e.title), e.detail ? h("div", { class: "muted small wrap" }, e.detail) : null) },
        { t: "", v: e => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, e.can_block || (e.data && e.data.ip) ? btn("Block address", () => POST(`/api/intel/events/${e.id}/block`), { sm: true, kind: "danger", ok: "Blocked in the firewall" }) : null,
          e.acknowledged || e.acknowledged_at ? h("span", { class: "dim small" }, "seen") : btn("OK", () => POST("/api/intel/events/ack", { ids: [e.id] }), { sm: true })) }], ev.items,
        { empty: "No alerts. Connections are compared with the threat lists every minute.", actions: [btn("Check connections now", () => POST("/api/intel/watch/run"), { sm: true, ok: "Connections checked" })] }));
    }
    return root;
  } });

/* ================================================================== System monitor */
page("monitor", { title: "System monitor", icon: "pulse", sub: "Live CPU, memory, disk, network and alerts",
  subs: [["live", "Live"], ["history", "History"], ["alerts", "Alerts & limits"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "live") {
      const o = await GET("/api/monitor/overview?top=8");
      const buf = { cpu: [], mem: [], up: [], down: [] };
      const charts = h("div", { class: "grid g2" }), tiles = h("div", { class: "grid g4" }), cores = h("div"), top = h("div"), disks = h("div");
      const paint = m => {
        buf.cpu.push(m.cpu.percent); buf.mem.push(m.memory.percent); buf.up.push(m.network.upload_kbps); buf.down.push(m.network.download_kbps);
        Object.values(buf).forEach(a => { if (a.length > 60) a.shift(); });
        const temp = m.temperatures || {}, gpu = m.gpu || {};
        clear(tiles).append(statCard(m.cpu.percent.toFixed(0) + "%", "CPU", `${m.cpu.logical_cores} cores · ${(m.cpu.frequency_mhz / 1000 || 0).toFixed(1)} GHz`, m.cpu.percent > 90 ? "var(--critical)" : null),
          statCard(m.memory.percent.toFixed(0) + "%", "Memory", `${m.memory.used_gb} of ${m.memory.total_gb} GB`, m.memory.percent > 90 ? "var(--critical)" : null),
          statCard(`${m.disk_io.read_mb_s.toFixed(1)} / ${m.disk_io.write_mb_s.toFixed(1)}`, "Disk read / write (MB/s)"),
          statCard(temp.available && temp.cpu_celsius ? Math.round(temp.cpu_celsius) + " °C" : gpu.available ? (gpu.max_usage_percent || 0) + "%" : `${m.network.download_kbps.toFixed(0)} kb/s`, temp.available && temp.cpu_celsius ? "CPU temperature" : gpu.available ? "GPU" : "Download"));
        clear(charts).append(card("CPU and memory", line([{ name: "CPU %", color: "var(--accent)", values: buf.cpu }, { name: "Memory %", color: "var(--accent2)", values: buf.mem }], { max: 100, legend: true })),
          card("Network (kb/s)", line([{ name: "Download", color: "var(--ok)", values: buf.down }, { name: "Upload", color: "var(--medium)", values: buf.up }], { legend: true })));
        clear(cores).appendChild(h("div", null, m.cpu.per_core.map((v, i) => hbar("Core " + (i + 1), v, 100, v.toFixed(0) + "%", "var(--accent)"))));
        clear(disks).appendChild(h("div", null, (m.disk_io.partitions || []).map(p => hbar(p.mount, p.percent, 100, `${p.free_gb} GB free`, p.percent > 90 ? "var(--critical)" : "var(--accent2)"))));
        if (m.top) clear(top).appendChild(table([{ t: "Program", v: p => h("b", null, p.name) }, { t: "CPU", v: p => p.cpu_percent.toFixed(1) + "%", cls: "num" }, { t: "Memory", v: p => p.memory_mb.toFixed(0) + " MB", cls: "num" }, { t: "PID", v: p => p.pid, cls: "num" }], (m.top.items || m.top.cpu || m.top).slice ? (m.top.items || m.top.cpu || m.top) : [], {}));
      };
      body.append(tiles, charts, h("div", { class: "grid g3" }, card("Processor cores", cores), card("Drives", disks), card("Busiest programs", top, { actions: [btn("All", () => { go("processes"); return "norefresh"; }, { sm: true, kind: "ghost" })] })));
      if (!o.top) try { o.top = await GET("/api/monitor/top?limit=8"); } catch (e) { /* */ }
      paint(o);
      every(2000, async () => { try { const m = await GET("/api/monitor/overview?top=8", { quiet: true }); if (!m.top) m.top = o.top; paint(m); } catch (e) { /* */ } });
    }

    if (t.current === "history") {
      const hours = Number(sessionStorage.getItem("mon_hours") || 24);
      const hi = await GET("/api/monitor/history?hours=" + hours);
      const p = hi.points || [];
      body.appendChild(h("div", { class: "row" }, h("span", { class: "muted" }, "Show the last"), h("select", { class: "input", style: { width: "140px" }, onchange: e => { sessionStorage.setItem("mon_hours", e.target.value); refresh(); } }, [[6, "6 hours"], [24, "24 hours"], [72, "3 days"], [168, "7 days"]].map(o => h("option", { value: o[0], selected: o[0] === hours }, o[1])))));
      body.appendChild(card("CPU (average and peak)", line([{ name: "Average %", color: "var(--accent)", values: p.map(x => x.cpu) }, { name: "Peak %", color: "var(--high)", values: p.map(x => x.cpu_peak) }], { max: 100, legend: true })));
      body.appendChild(h("div", { class: "grid g2" }, card("Memory %", line([{ name: "Memory", color: "var(--accent2)", values: p.map(x => x.memory) }], { max: 100 })),
        card("Network (MB per interval)", line([{ name: "Received", color: "var(--ok)", values: p.map(x => x.net_recv_mb) }, { name: "Sent", color: "var(--medium)", values: p.map(x => x.net_sent_mb) }], { legend: true }))));
    }

    if (t.current === "alerts") {
      const [al, th] = await Promise.all([GET("/api/monitor/alerts?limit=100"), GET("/api/monitor/thresholds")]);
      body.appendChild(tableCard("Resource alerts", [{ t: "Started", v: a => dt(a.started_at) }, { t: "Level", v: a => badge(a.severity) }, { t: "What", v: a => h("span", { class: "wrap" }, a.message) }, { t: "Peak", v: a => a.peak, cls: "num" }, { t: "State", v: a => badge(a.status, a.status === "active" ? "medium" : "ok") },
        { t: "", v: a => a.acknowledged_at ? h("span", { class: "dim small" }, "seen") : btn("OK", () => POST(`/api/monitor/alerts/${a.id}/ack`), { sm: true }) }], al.items, { empty: "No resource alerts.", actions: [btn("Mark all seen", () => POST("/api/monitor/alerts/ack-all"), { sm: true })] }));
      const num1 = (key, label, unit) => h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, label)), h("div", { class: "ctl row", style: { flexWrap: "nowrap" } }, h("input", { class: "input", type: "number", style: { width: "90px" }, value: th[key], onchange: e => run(null, () => PUT("/api/monitor/thresholds", { [key]: Number(e.target.value) }), { ok: "Saved" }) }), h("span", { class: "muted" }, unit)));
      body.appendChild(card("Alert when…", h("div", null, h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Resource alerts"), h("div", { class: "d" }, `Only when the limit is passed for ${th.alert_sustain_seconds} seconds in a row`)), h("div", { class: "ctl" }, toggle(th.monitor_alerts_enabled, on => PUT("/api/monitor/thresholds", { monitor_alerts_enabled: on })))),
        num1("alert_cpu_percent", "CPU is above", "%"), num1("alert_memory_percent", "Memory is above", "%"), num1("alert_disk_percent", "A drive is fuller than", "%"), num1("alert_temperature_c", "CPU is hotter than", "°C"))));
    }
    return root;
  } });

/* ================================================================== Processes & startup */
async function processDialog(p) {
  const d = await GET(`/api/processes/${p.pid}`);
  const x = d.process || d;
  detailDialog(`${x.name} (PID ${x.pid})`, h("div", null, kv([["Program", h("code", { class: "wrap" }, x.exe || "-")], ["Command", h("code", { class: "wrap" }, x.cmdline || "-")], ["User", x.user], ["Started", dt(x.started_at)], ["Parent", x.parent_name ? `${x.parent_name} (${x.ppid})` : x.ppid],
    ["CPU / memory", `${(x.cpu_percent || 0).toFixed(1)}% / ${(x.memory_mb || 0).toFixed(0)} MB`], ["Threads", x.threads], ["Signature", x.signature ? (x.signature.status || x.signature.state || "") + (x.signature.signer ? " - " + x.signature.signer : "") : "Not checked"],
    x.sha256 ? ["SHA-256", h("code", { class: "wrap" }, x.sha256)] : null, ["Risk", x.risk_level && x.risk_level !== "none" ? badge(x.risk_level) : "None"]]),
    (x.reasons || []).length ? h("ul", { class: "muted" }, x.reasons.map(r => h("li", null, r))) : null,
    (x.connections || []).length ? h("div", null, h("h3", { style: { margin: "12px 0 4px" } }, "Connections"), table([{ t: "Remote", v: c => h("code", null, `${c.remote_ip || c.raddr || "*"}:${c.remote_port || ""}`) }, { t: "State", v: c => c.status }], x.connections.slice(0, 30), {})) : null),
    x.protected ? [] : [btn("Suspend", () => POST(`/api/processes/${x.pid}/suspend`, { create_time: x.create_time }), { ok: "Suspended" }), btn("End program", () => POST(`/api/processes/${x.pid}/end`, { create_time: x.create_time }), { kind: "danger", confirm: `End ${x.name}? Unsaved work in it is lost.`, ok: "Ended" })]);
}
page("processes", { title: "Processes & startup", icon: "cpu", sub: "What is running and what starts with Windows",
  subs: [["running", "Running programs"], ["startup", "Startup items"], ["changes", "Startup changes"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "running") {
      const q = sessionStorage.getItem("proc_q") || "", flagged = sessionStorage.getItem("proc_flag") === "1", sort = sessionStorage.getItem("proc_sort") || "cpu";
      const r = await GET("/api/processes" + qs({ search: q, sort, order: "desc", limit: 300, flagged_only: flagged ? true : null }));
      const s = r.summary;
      body.appendChild(h("div", { class: "grid g4" }, statCard(num(s.processes), "Programs running", `${num(s.threads)} threads`), statCard(num(s.flagged), "Flagged", "worth a look", s.flagged ? "var(--high)" : "var(--ok)"), statCard(num(s.signatures.unsigned), "Unsigned"), statCard(num(s.suspended), "Suspended")));
      body.appendChild(tableCard("Running programs", [{ t: "Name", v: p => h("div", null, h("b", null, p.name), h("div", { class: "path", style: { maxWidth: "300px" } }, p.exe || "")) }, { t: "PID", v: p => p.pid, cls: "num" }, { t: "User", v: p => p.user },
        { t: "CPU", v: p => (p.cpu_percent || 0).toFixed(1) + "%", cls: "num" }, { t: "Memory", v: p => (p.memory_mb || 0).toFixed(0) + " MB", cls: "num" },
        { t: "Risk", v: p => p.risk_level && p.risk_level !== "none" ? h("span", { title: (p.reasons || []).join("\n") }, badge(p.risk_level)) : "" },
        { t: "", v: p => p.protected ? h("span", { class: "dim small", title: p.protected_reason || "" }, "protected") : btn("End", () => POST(`/api/processes/${p.pid}/end`, { create_time: p.create_time }), { sm: true, kind: "danger", confirm: `End ${p.name}? Unsaved work in it is lost.`, ok: "Program ended" }) }],
        r.items, { total: r.total, onRow: p => run(null, async () => { await processDialog(p); return "norefresh"; }),
          actions: [h("input", { class: "input search", placeholder: "Search…", value: q, onkeydown: e => { if (e.key === "Enter") { sessionStorage.setItem("proc_q", e.target.value); refresh(); } } }),
            h("select", { class: "input", style: { width: "130px" }, onchange: e => { sessionStorage.setItem("proc_sort", e.target.value); refresh(); } }, [["cpu", "By CPU"], ["memory", "By memory"], ["name", "By name"], ["risk", "By risk"]].map(o => h("option", { value: o[0], selected: o[0] === sort }, o[1]))),
            h("label", { class: "check", style: { margin: 0 } }, h("input", { type: "checkbox", checked: flagged, onchange: e => { sessionStorage.setItem("proc_flag", e.target.checked ? "1" : ""); refresh(); } }), "Only flagged")] }));
    }

    if (t.current === "startup") {
      const r = await GET("/api/startup");
      const s = r.summary;
      body.appendChild(h("div", { class: "grid g4" }, statCard(num(s.enabled), "Start with the PC", `${num(s.disabled)} switched off`), statCard(num(s.new), "New since last check", null, s.new ? "var(--medium)" : "var(--ok)"), statCard(num(s.flagged), "Flagged", null, s.flagged ? "var(--high)" : "var(--ok)"), statCard(num(s.unsigned), "Unsigned")));
      body.appendChild(tableCard("Startup items", [{ t: "On", v: i => toggle(i.enabled, on => POST(`/api/startup/${i.id}/${on ? "enable" : "disable"}`), !i.can_toggle) },
        { t: "Name", v: i => h("div", null, h("b", null, i.name), i.is_new ? h("span", null, " ", badge("new", "medium")) : null, h("div", { class: "path" }, i.command || i.path || "")) }, { t: "Where", v: i => i.source_label || i.location }, { t: "Publisher", v: i => i.publisher || "" },
        { t: "Risk", v: i => i.risk_level && i.risk_level !== "none" ? h("span", { title: (i.reasons || []).join("\n") }, badge(i.risk_level)) : "" },
        { t: "", v: i => i.is_new ? btn("I know it", () => POST(`/api/startup/${i.id}/accept`), { sm: true }) : !i.can_toggle && i.protected_reason ? h("span", { class: "dim small", title: i.protected_reason }, "system") : "" }],
        r.items, { total: r.total, actions: [btn("Check for new items", () => POST("/api/startup/watch/check"), { sm: true, icon: "refresh", ok: "Checked" }), s.new ? btn("I know them all", () => POST("/api/startup/accept-all"), { sm: true }) : null] }));
    }

    if (t.current === "changes") {
      const c = await GET("/api/startup/changes?limit=100");
      body.appendChild(tableCard("Startup changes", [{ t: "When", v: x => dt(x.ts || x.created_at) }, { t: "Change", v: x => cap(x.change || x.action || x.kind) }, { t: "Item", v: x => h("b", null, x.name || x.item_name) }, { t: "Where", v: x => x.source_label || x.source || x.location }, { t: "By", v: x => x.username || x.by || "" }], c.items, { empty: "Nothing has been added to or removed from startup since Cyber Hub began watching." }));
    }
    return root;
  } });

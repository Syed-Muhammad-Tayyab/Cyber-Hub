/* Cyber Hub UI - Firewall, Network, Device security (Parts 9-11)
   Developed by Syed Muhammad Tayyab */
"use strict";

/* A fix that may answer 428 ("this has side effects - confirm") */
async function fixWithConfirm(path, body) {
  try { return await POST(path, body || {}); }
  catch (e) {
    if (e.status !== 428) throw e;
    if (!(await confirmBox(e.message, "Yes, do it"))) return "norefresh";
    return await POST(path, Object.assign({}, body || {}, { confirm: true }));
  }
}
function findingsCard(title, findings, fixPath) {
  const real = (findings || []).slice().sort((a, b) => SEV.indexOf(b.severity) - SEV.indexOf(a.severity));
  return card(title, real.length ? h("div", { class: "list" }, real.map(f => h("div", { class: "item" }, h("span", { style: { marginTop: "2px" } }, badge(f.severity)),
    h("div", { class: "grow" }, h("div", { class: "t" }, f.title), f.detail ? h("div", { class: "d" }, f.detail) : null),
    f.fix ? btn(f.fix_label || "Fix", () => fixWithConfirm(fixPath(f)), { sm: true, kind: "primary", ok: "Fixed" }) : null))) : empty("No problems found"));
}
function eventsCard(title, base, items) {
  return tableCard(title, [{ t: "When", v: e => dt(e.ts) }, { t: "Severity", v: e => badge(e.severity) }, { t: "What happened", v: e => h("div", null, h("div", { class: "bold" }, e.title), e.detail ? h("div", { class: "muted small wrap" }, e.detail) : null) },
    { t: "", v: e => e.acknowledged || e.acknowledged_at ? h("span", { class: "dim small" }, "seen") : btn("OK", () => POST(base + "/events/ack", { ids: [e.id] }), { sm: true }) }], items,
    { empty: "No alerts. Cyber Hub keeps watching in the background.", actions: items && items.length ? [btn("Mark all seen", () => POST(base + "/events/ack", {}), { sm: true })] : null });
}
const minutesOptions = [["", "Until I remove it"], ["60", "1 hour"], ["1440", "1 day"], ["10080", "1 week"]];
const mins = v => (v ? Number(v) : null);

/* ================================================================== Firewall */
page("firewall", { title: "Firewall", icon: "fire", sub: "Windows Defender Firewall, blocks and rules",
  subs: [["overview", "Status & health"], ["blocks", "Blocks & allowed apps"], ["rules", "All rules"], ["alerts", "Alerts"], ["backup", "Snapshots & reset"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);
    const st = await GET("/api/firewall/status");
    if (!st.backend.available) { body.appendChild(banner("medium", "The firewall can't be read on this system", st.backend.reason || st.error || "")); return root; }
    if (!st.can_modify) body.appendChild(banner("medium", "Read-only right now", "Changing the firewall needs Cyber Hub to run as administrator.",
      CH.desktop && CH.desktop.can_restart && isAdmin() ? btn("Restart as administrator", () => POST("/api/desktop/restart?elevated=true"), { refresh: false, ok: "Restarting…" }) : null));

    if (t.current === "overview") {
      const [an, sm] = await Promise.all([GET("/api/firewall/analysis"), GET("/api/firewall/summary?days=14")]);
      body.appendChild(h("div", { class: "grid g-main" },
        h("section", { class: "card" }, h("div", { class: "hero" }, ring(an.score, 150, { label: an.grade }),
          h("div", null, h("h2", { style: { marginBottom: "6px" } }, "Firewall is ", h("span", { style: { color: st.state === "on" ? "var(--ok)" : "var(--critical)" } }, cap(st.state))),
            h("div", { class: "muted" }, (st.networks || []).map(n => `${n.name} (${cap(n.profile)} network)`).join(" · ") || "No network connected"),
            h("div", { class: "row", style: { marginTop: "14px" } },
              h("span", null, "Block all incoming connections"), toggle(st.shields_up, on => POST("/api/firewall/shields-up", { on })),
              h("span", { class: "muted small" }, "Use on public Wi-Fi: nothing can connect to this PC."))))),
        card("Rules", donut([{ label: "Incoming allowed", value: st.rules.inbound_allow, color: "var(--medium)" }, { label: "Incoming blocked", value: st.rules.inbound_block, color: "var(--ok)" },
          { label: "Outgoing allowed", value: st.rules.outbound_allow, color: "var(--accent)" }, { label: "Outgoing blocked", value: st.rules.outbound_block, color: "var(--accent2)" }, { label: "Switched off", value: st.rules.disabled, color: "var(--dim)" }], 120, num(st.rules.total)))));
      body.appendChild(h("div", { class: "grid g3" }, st.profiles.map(p => card(cap(p.name) + " network" + (p.active ? "  (in use)" : ""), h("div", null,
        h("div", { class: "setting" }, h("div", { class: "t" }, "Firewall"), h("div", { class: "ctl" }, toggle(p.enabled, on => on ? PATCH(`/api/firewall/profiles/${p.name}`, { enabled: true })
          : confirmBox(`Turn the firewall off for ${p.name} networks? This PC will accept connections from anyone on that network.`, "Turn off", true).then(ok => ok ? PATCH(`/api/firewall/profiles/${p.name}`, { enabled: false }) : "norefresh")))),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Incoming"), h("div", { class: "d" }, "Connections started by others")), h("div", { class: "ctl" }, badge(p.default_inbound, p.default_inbound === "block" ? "ok" : "high"))),
        h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, "Log blocked connections")), h("div", { class: "ctl" }, toggle(p.log_blocked, on => PATCH(`/api/firewall/profiles/${p.name}`, { log_blocked: on })))))))));
      body.appendChild(h("div", { class: "grid g2" }, findingsCard("Firewall health", an.findings, f => `/api/firewall/findings/${encodeURIComponent(f.id)}/fix`),
        card("Alerts and new blocks (14 days)", bars(sm.per_day.map(d => ({ label: d.day.slice(5), value: d.blocks_created, value2: d.medium + d.high + d.critical })), { color: "var(--accent)", color2: "var(--high)" }))));
    }

    if (t.current === "blocks") {
      const bl = await GET("/api/firewall/blocks?limit=200");
      const dirOpts = [["both", "Both directions"], ["out", "Outgoing only"], ["in", "Incoming only"]];
      body.appendChild(card("Block or allow", h("div", { class: "row" },
        btn("Block a program…", async () => { const v = await formDialog("Block a program", [{ name: "path", label: "Program (.exe)", type: "path", pick: "file", required: true }, { name: "direction", label: "Direction", type: "select", options: dirOpts, value: "both" }, { name: "minutes", label: "For how long", type: "select", options: minutesOptions }, { name: "reason", label: "Note (optional)" }],
          { submit: "Block", onSubmit: f => POST("/api/firewall/block/app", { path: f.path, direction: f.direction, minutes: mins(f.minutes), reason: f.reason || null }) }); return v ? undefined : "norefresh"; }, { icon: "x" }),
        btn("Block an address…", async () => { const v = await formDialog("Block IP addresses", [{ name: "addresses", label: "Addresses, ranges or networks (one per line)", type: "textarea", required: true, placeholder: "203.0.113.7\n198.51.100.0/24" }, { name: "direction", label: "Direction", type: "select", options: dirOpts, value: "both" }, { name: "minutes", label: "For how long", type: "select", options: minutesOptions }],
          { submit: "Block", onSubmit: f => POST("/api/firewall/block/ip", { addresses: lines(f.addresses), direction: f.direction, minutes: mins(f.minutes) }) }); return v ? undefined : "norefresh"; }, { icon: "x" }),
        btn("Block a port…", async () => { const v = await formDialog("Block a port", [{ name: "ports", label: "Port(s), e.g. 3389 or 5000-5010", required: true }, { name: "protocol", label: "Protocol", type: "select", options: [["tcp", "TCP"], ["udp", "UDP"], ["both", "Both"]], value: "tcp" }, { name: "direction", label: "Direction", type: "select", options: [["in", "Incoming"], ["out", "Outgoing"], ["both", "Both"]], value: "in" }],
          { submit: "Block", onSubmit: f => POST("/api/firewall/block/port", { ports: f.ports, protocol: f.protocol, direction: f.direction }) }); return v ? undefined : "norefresh"; }, { icon: "x" }),
        btn("Allow an app through…", async () => { const v = await formDialog("Allow an app", [{ name: "path", label: "Program (.exe)", type: "path", pick: "file", required: true }], { submit: "Allow", intro: "The app may accept connections on Private networks.", onSubmit: f => POST("/api/firewall/allow/app", { path: f.path }) }); return v ? undefined : "norefresh"; }, { icon: "check" }))));
      body.appendChild(tableCard("Cyber Hub blocks", [{ t: "Since", v: b => dt(b.created_at) }, { t: "Kind", v: b => cap(b.kind) }, { t: "Target", v: b => h("b", { class: "wrap" }, b.label || b.target || b.program || (b.addresses || []).join(", ") || b.ports || "-") },
        { t: "Direction", v: b => cap(b.direction) }, { t: "Ends", v: b => b.expires_at ? ago(b.expires_at) : "Never" }, { t: "Status", v: b => badge(b.status, b.status === "active" ? "ok" : "medium") },
        { t: "", v: b => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, b.status === "missing" ? btn("Repair", () => POST(`/api/firewall/blocks/${b.id}/repair`), { sm: true }) : null, btn("Remove", () => DEL(`/api/firewall/blocks/${b.id}`), { sm: true, kind: "danger", ok: "Block removed" })) }],
        bl.items, { total: bl.total, empty: "Nothing is blocked by Cyber Hub yet.", actions: [btn("Verify", () => POST("/api/firewall/blocks/verify"), { sm: true, ok: "Blocks verified against the firewall" })] }));
    }

    if (t.current === "rules") {
      const flagged = sessionStorage.getItem("fw_flagged") === "1";
      const r = await GET("/api/firewall/rules" + qs({ limit: 300, flagged: flagged ? true : null }));
      body.appendChild(tableCard("Firewall rules", [{ t: "On", v: x => toggle(x.enabled, on => PATCH(`/api/firewall/rules/${encodeURIComponent(x.id)}`, { enabled: on }), !x.editable) },
        { t: "Name", v: x => h("div", null, h("b", null, x.name), x.group ? h("div", { class: "dim small" }, x.group) : null) }, { t: "Direction", v: x => x.direction === "in" ? "Incoming" : "Outgoing" },
        { t: "Action", v: x => badge(x.action, x.action === "block" ? "ok" : "medium") }, { t: "Program", v: x => pathCell(x.program || x.service || "Any") },
        { t: "Ports", v: x => `${String(x.protocol || "any").toUpperCase()} ${x.local_ports || "any"}` }, { t: "Networks", v: x => (x.profiles || []).map(cap).join(", ") },
        { t: "Risk", v: x => (x.flags || []).length ? h("span", { title: x.flags.map(f => f.title || f.id || f).join("\n") }, badge(x.risk || "check", x.risk || "medium")) : "" }],
        r.items, { total: r.total, actions: [h("label", { class: "check", style: { margin: 0 } }, h("input", { type: "checkbox", checked: flagged, onchange: e => { sessionStorage.setItem("fw_flagged", e.target.checked ? "1" : ""); refresh(); } }), "Only risky rules")] }));
    }

    if (t.current === "alerts") {
      const ev = await GET("/api/firewall/events?limit=100");
      body.appendChild(eventsCard("Firewall alerts", "/api/firewall", ev.items));
      const lg = await GET("/api/firewall/log?hours=24").catch(() => null);
      if (lg && lg.available !== false && (lg.top_sources || lg.top_ports)) body.appendChild(h("div", { class: "grid g2" },
        card("Most blocked addresses (24 h)", table([{ t: "Address", v: x => h("code", null, x.ip || x.address || x.source) }, { t: "Dropped", v: x => num(x.n || x.count), cls: "num" }], lg.top_sources || [], { empty: "No dropped connections logged" })),
        card("Most hit ports (24 h)", table([{ t: "Port", v: x => x.port }, { t: "Dropped", v: x => num(x.n || x.count), cls: "num" }], lg.top_ports || [], { empty: "No dropped connections logged" }))));
    }

    if (t.current === "backup") {
      const sn = await GET("/api/firewall/snapshots");
      body.appendChild(tableCard("Firewall snapshots", [{ t: "Taken", v: s => dt(s.created_at || s.ts) }, { t: "Note", v: s => s.note || s.reason }, { t: "Rules", v: s => num(s.rules || s.rule_count), cls: "num" }, { t: "By", v: s => s.created_by },
        { t: "", v: s => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, btn("Restore", () => POST(`/api/firewall/snapshots/${s.id}/restore`), { sm: true, confirm: "Replace the current firewall rules with this snapshot? A safety snapshot of the current rules is taken first.", ok: "Firewall restored" }),
          btn("Delete", () => DEL(`/api/firewall/snapshots/${s.id}`), { sm: true, kind: "danger" })) }], sn.snapshots,
        { empty: "No snapshots yet. Take one before changing many rules.", actions: [btn("Take snapshot", async () => { const v = await formDialog("Firewall snapshot", [{ name: "note", label: "Note (optional)" }], { submit: "Save snapshot", onSubmit: f => POST("/api/firewall/snapshots", { note: f.note || null }) }); return v ? undefined : "norefresh"; }, { sm: true, icon: "plus" })] }));
      if (isAdmin()) body.appendChild(card("Reset", h("div", { class: "spread" }, h("div", { class: "muted" }, "Put Windows Firewall back to its default rules. Cyber Hub blocks are removed too."),
        btn("Reset firewall", () => POST("/api/firewall/reset", { confirm: true }), { kind: "danger", confirm: "Reset the firewall to Windows defaults? Custom rules will be lost (a snapshot is taken first).", confirmLabel: "Reset", ok: "Firewall reset to defaults" }))));
    }
    return root;
  } });

/* ================================================================== Network */
page("network", { title: "Network", icon: "wifi", sub: "Connections, open ports, Wi-Fi and devices on your network",
  subs: [["overview", "Overview"], ["connections", "Connections"], ["ports", "Open ports"], ["wifi", "Wi-Fi"], ["devices", "Devices on my network"], ["alerts", "Alerts"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "overview") {
      const [st, fd, sm] = await Promise.all([GET("/api/network/status"), GET("/api/network/findings"), GET("/api/network/summary?hours=6").catch(() => ({}))]);
      const c = st.connections, w = st.wifi || {}, lan = st.lan || {};
      body.appendChild(h("div", { class: "grid g-main" },
        h("section", { class: "card" }, h("div", { class: "hero" }, ring(fd.score, 150, { label: fd.grade }),
          h("div", { class: "grid g2", style: { gap: "14px 26px" } }, stat(num(c.total), "Connections", `${c.internet} to the internet`), stat(num(c.flagged), "Flagged", "worth a look", c.flagged ? "var(--high)" : "var(--ok)"),
            stat(num(c.processes), "Programs online"), stat(num(lan.devices || 0), "Devices on network", lan.new_24h ? `${lan.new_24h} new today` : "")))),
        card("Wi-Fi", w.connected ? h("div", null, h("div", { class: "row" }, h("h2", null, w.ssid), badge(String(w.auth || "?").toUpperCase(), w.rating === "good" || w.rating === "excellent" ? "ok" : w.rating === "insecure" ? "critical" : "medium")),
          h("div", { class: "muted", style: { margin: "6px 0 10px" } }, `Signal ${w.signal}% · ${w.nearby} network(s) nearby`), hbar("Signal", w.signal, 100, w.signal + "%", "var(--accent2)")) : empty(w.available === false ? "No Wi-Fi adapter" : "Not connected to Wi-Fi (cable or offline)"))));
      const samples = sm.samples || sm.traffic || [];
      body.appendChild(h("div", { class: "grid g2" }, findingsCard("Network health", fd.findings, f => `/api/network/findings/${encodeURIComponent(f.id)}/fix`),
        card("Traffic (last hours)", samples.length > 1 ? line([{ name: "Download", color: "var(--accent2)", values: samples.map(x => x.recv_kbps || x.download_kbps || x.recv || 0) }, { name: "Upload", color: "var(--accent)", values: samples.map(x => x.sent_kbps || x.upload_kbps || x.sent || 0) }], { legend: true, height: 160 })
          : empty("Traffic samples appear after a few minutes"))));
    }

    if (t.current === "connections") {
      const only = sessionStorage.getItem("net_flagged") === "1";
      const [r, by] = await Promise.all([GET("/api/network/connections" + qs({ limit: 300, flagged: only ? true : null, scope: sessionStorage.getItem("net_scope") || null })), GET("/api/network/connections/by-process").catch(() => ({ items: [] }))]);
      body.appendChild(card("Programs using the network", table([{ t: "Program", v: p => h("b", null, p.process || p.name || "System") }, { t: "Connections", v: p => num(p.connections || p.total), cls: "num" }, { t: "Internet", v: p => num(p.internet), cls: "num" },
        { t: "Remote hosts", v: p => num(p.remote_hosts), cls: "num" }, { t: "Risk", v: p => (p.risk_level && p.risk_level !== "none") ? badge(p.risk_level) : h("span", { class: "dim" }, "none") },
        { t: "", v: p => p.exe && !p.protected && !p.cyberhub ? btn("Block", () => POST("/api/firewall/block/app", { path: p.exe, direction: "out" }), { sm: true, kind: "danger", confirm: `Stop ${p.process} from using the internet?`, ok: "Blocked in the firewall" }) : "" }], by.items || by.processes || [], { height: "260px", empty: "No program is online right now" })));
      body.appendChild(tableCard("Connections", [{ t: "Program", v: x => h("b", null, x.process || "-") }, { t: "Direction", v: x => cap(x.direction) }, { t: "Remote", v: x => h("code", null, `${x.remote_ip || "*"}:${x.remote_port || "*"}`) },
        { t: "Service", v: x => x.service || "" }, { t: "Where", v: x => cap(x.scope) }, { t: "State", v: x => String(x.status || "").toLowerCase() },
        { t: "Risk", v: x => x.risk_level && x.risk_level !== "none" ? h("span", { title: (x.reasons || []).join("\n") }, badge(x.risk_level)) : "" },
        { t: "", v: x => x.scope === "internet" && x.remote_ip && !x.blocked_by ? btn("Block address", () => POST("/api/firewall/block/ip", { addresses: [x.remote_ip] }), { sm: true, confirm: `Block ${x.remote_ip} in the firewall?`, ok: "Address blocked" }) : x.blocked_by ? badge("blocked", "ok") : "" }],
        r.items, { total: r.total, actions: [h("select", { class: "input", style: { width: "150px" }, onchange: e => { sessionStorage.setItem("net_scope", e.target.value); refresh(); } }, [["", "Everywhere"], ["internet", "Internet"], ["lan", "My network"], ["local", "This PC"]].map(o => h("option", { value: o[0], selected: (sessionStorage.getItem("net_scope") || "") === o[0] }, o[1]))),
          h("label", { class: "check", style: { margin: 0 } }, h("input", { type: "checkbox", checked: only, onchange: e => { sessionStorage.setItem("net_flagged", e.target.checked ? "1" : ""); refresh(); } }), "Only flagged")] }));
      every(10000, () => refresh());
    }

    if (t.current === "ports") {
      const r = await GET("/api/network/listening");
      body.appendChild(h("div", { class: "grid g4" }, statCard(num(r.counts.total), "Programs waiting for connections"), statCard(num(r.counts.exposed), "Listening on the network"),
        statCard(num(r.counts.reachable), "Reachable through the firewall", null, r.counts.reachable ? "var(--medium)" : "var(--ok)"), statCard(num(r.counts.risky), "Risky services", null, r.counts.risky ? "var(--critical)" : "var(--ok)")));
      body.appendChild(tableCard("Open ports", [{ t: "Port", v: x => h("b", null, `${x.port}/${x.proto}`) }, { t: "Program", v: x => x.process || "-" }, { t: "Service", v: x => x.service || x.risky_service || "" },
        { t: "Listens on", v: x => x.exposure === "all" || x.exposure === "network" ? "The network" : "This PC only" },
        { t: "Firewall", v: x => { const f = x.firewall || {}; const v = f.verdict || f.result || (f.allowed ? "allowed" : "blocked"); return badge(v, /allow|reach/.test(v) ? "medium" : "ok"); } },
        { t: "Why", v: x => h("span", { class: "muted small" }, (x.reasons || []).join("; ")) }, { t: "Level", v: x => x.severity !== "info" ? badge(x.severity) : "" },
        { t: "", v: x => (x.exposure === "all" || x.exposure === "network") && !x.cyberhub ? btn("Block port", () => POST("/api/firewall/block/port", { ports: String(x.port), protocol: x.proto, direction: "in" }), { sm: true, ok: "Port blocked for incoming connections" }) : "" }], r.items));
    }

    if (t.current === "wifi") {
      const [w, hist] = await Promise.all([GET("/api/network/wifi"), GET("/api/network/wifi/history?limit=30").catch(() => ({ items: [] }))]);
      if (!w.available) body.appendChild(banner("medium", "Wi-Fi can't be read", w.error || "No Wi-Fi adapter was found."));
      const cur = w.current;
      if (cur) body.appendChild(card("Connected network", h("div", { class: "grid g2" },
        kv([["Name", h("b", null, cur.ssid)], ["Security", `${cur.auth_raw || cur.auth} (${cur.cipher_raw || cur.cipher || "-"})`], ["Rating", badge((cur.assessment || {}).rating || "-", ["good", "excellent"].includes((cur.assessment || {}).rating) ? "ok" : "medium")], ["Signal", cur.signal + "%"]]),
        kv([["Standard", cur.radio], ["Band / channel", `${cur.band || "-"} / ${cur.channel || "-"}`], ["Speed", cur.rx_mbps ? `${cur.rx_mbps} Mbps` : "-"], ["Router (BSSID)", h("code", null, cur.bssid || "-")]])),
        { actions: (cur.assessment || {}).advice ? [h("span", { class: "muted small" }, cur.assessment.advice)] : null }));
      const nearby = w.nearby || w.networks || [];
      body.appendChild(tableCard("Networks nearby", [{ t: "Name", v: n => h("b", null, n.ssid || "(hidden)") }, { t: "Security", v: n => badge(String(n.auth || "?").toUpperCase(), n.rating === "insecure" || n.auth === "open" ? "critical" : n.rating === "weak" ? "medium" : "ok") },
        { t: "Signal", v: n => (n.signal || 0) + "%", cls: "num" }, { t: "Channel", v: n => n.channel, cls: "num" }, { t: "Note", v: n => h("span", { class: "muted small" }, n.note || (n.evil_twin ? "Possible fake copy of your network" : "")) }], nearby, { empty: "No other networks in range (or Windows location permission is off)." }));
      const saved = w.saved || w.profiles || [];
      if (saved.length) body.appendChild(tableCard("Saved networks", [{ t: "Name", v: n => h("b", null, n.ssid || n.name) }, { t: "Security", v: n => String(n.auth || "-").toUpperCase() }, { t: "Joins by itself", v: n => onoff(n.auto_connect !== false && n.auto !== false, "Yes", "No") },
        { t: "Risk", v: n => n.risky || n.severity && n.severity !== "info" ? badge(n.severity || "medium") : "" }], saved));
      body.appendChild(tableCard("Connection history", [{ t: "When", v: x => dt(x.connected_at || x.ts || x.first_seen) }, { t: "Network", v: x => x.ssid }, { t: "Security", v: x => String(x.auth || "-").toUpperCase() }, { t: "Rating", v: x => cap(x.rating || "") }], hist.items || hist.history || [], { empty: "No history yet" }));
    }

    if (t.current === "devices") {
      const l = await GET("/api/network/lan");
      const net = l.network || {}, sc = l.scan || {};
      if (!l.network) { body.appendChild(empty("This PC is not connected to a local network.")); return root; }
      if (net.gateway_alert_mac) body.appendChild(banner("critical", "Your router's hardware address changed", "This can mean someone is intercepting the network (ARP spoofing) - or that the router was replaced.",
        isAdmin() ? btn("It's my new router", () => POST(`/api/network/lan/networks/${net.id}/accept-gateway`), { ok: "Accepted" }) : null));
      body.appendChild(h("div", { class: "grid g4" }, statCard(num(l.counts.total), "Devices", `${l.counts.online} online`), statCard(num(l.counts.new_24h), "New in 24 hours"), statCard(num(l.counts.untrusted), "Not marked as mine", null, l.counts.untrusted ? "var(--medium)" : "var(--ok)"), statCard(num(l.counts.risky), "Risky devices", null, l.counts.risky ? "var(--critical)" : "var(--ok)")));
      body.appendChild(card(`${net.name || "Network"}  ·  ${net.subnet || ""}`, h("div", { class: "spread" },
        h("div", { class: "row" }, h("span", null, "This is my home network"), toggle(net.home, on => POST(`/api/network/lan/networks/${net.id}/home`, { home: on })), h("span", { class: "muted small" }, "On home networks new devices raise an alert.")),
        sc.state === "running" ? h("div", { class: "row" }, h("span", { class: "muted" }, `Scanning… ${sc.percent || 0}%`), btn("Stop", () => POST("/api/network/lan/scan/cancel"), { sm: true })) : btn("Scan for devices", () => POST("/api/network/lan/scan", {}), { kind: "primary", icon: "radar", ok: "Scan started" }))));
      if (sc.state === "running") every(2000, () => refresh());
      body.appendChild(tableCard("Devices", [{ t: "Device", v: d => h("div", null, h("b", null, d.label || d.hostname || d.nb_name || "Unknown device"), h("div", { class: "dim small" }, d.device_type || "")) }, { t: "Address", v: d => h("code", null, d.ip) },
        { t: "Maker", v: d => d.vendor || (d.randomized_mac ? "Private address" : "") }, { t: "Online", v: d => onoff(d.online, "Yes", "No") },
        { t: "Flags", v: d => (d.flags || []).length ? h("span", { title: d.flags.map(f => f.title || f).join("\n") }, badge(d.severity === "info" ? "note" : d.severity, d.severity)) : "" },
        { t: "Mine", v: d => d.this_pc ? badge("This PC", "ok") : d.id ? toggle(d.trusted, on => PATCH(`/api/network/lan/devices/${d.id}`, { trusted: on })) : "" },
        { t: "", v: d => d.id && !d.this_pc ? btn("Rename", async () => { const v = await formDialog("Name this device", [{ name: "label", label: "Name", value: d.label || "" }], { onSubmit: f => PATCH(`/api/network/lan/devices/${d.id}`, { label: f.label }) }); return v ? undefined : "norefresh"; }, { sm: true }) : "" }], l.devices));
    }

    if (t.current === "alerts") {
      const ev = await GET("/api/network/events?limit=100");
      body.appendChild(eventsCard("Network alerts", "/api/network", ev.items));
    }
    return root;
  } });

/* ================================================================== Device security (Windows posture) */
function checkDialog(c) {
  const steps = c.manual && (c.manual.steps || c.manual.text);
  detailDialog(c.title, h("div", null, kv([["Result", badge(c.status === "pass" ? "Passed" : c.status === "fail" ? "Needs fixing" : cap(c.status), c.status === "pass" ? "ok" : c.status === "fail" ? c.severity : "info")], ["Now", c.value], ["Section", c.category_name], c.managed ? ["Managed", "Set by your organisation - can't be changed here"] : null]),
    c.why ? h("div", null, h("h3", { style: { margin: "16px 0 4px" } }, "Why it matters"), h("p", { class: "muted", style: { margin: 0 } }, c.why)) : null,
    c.detail ? h("div", null, h("h3", { style: { margin: "16px 0 4px" } }, "Details"), h("p", { class: "muted wrap", style: { margin: 0 } }, c.detail)) : null,
    steps ? h("div", null, h("h3", { style: { margin: "16px 0 4px" } }, "How to fix it yourself"), Array.isArray(steps) ? h("ol", { class: "muted" }, steps.map(s => h("li", null, s))) : h("p", { class: "muted" }, steps)) : null));
}
page("device", { title: "Device security", icon: "laptop", sub: "Windows security settings, updates and accounts",
  subs: [["checks", "Security checks"], ["defender", "Microsoft Defender"], ["updates", "Windows Update"], ["accounts", "Local accounts"], ["history", "Changes & alerts"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "checks") {
      const a = await GET("/api/posture/checks");
      const failed = a.checks.filter(c => c.status === "fail" && !c.ignored).sort((x, y) => SEV.indexOf(y.severity) - SEV.indexOf(x.severity));
      const rest = a.checks.filter(c => !(c.status === "fail" && !c.ignored));
      body.appendChild(h("div", { class: "grid g-main" },
        h("section", { class: "card" }, h("div", { class: "hero" }, ring(a.score, 160, { label: a.grade }),
          h("div", null, h("h2", null, `${a.totals.passed} of ${a.totals.checks} checks passed`), h("div", { class: "muted", style: { margin: "4px 0 12px" } }, `${a.totals.failed} to fix · ${a.totals.fixable} can be fixed with one click` + (a.elevated ? "" : " · some need administrator rights")),
            h("div", { class: "row" }, btn("Fix all safe issues", () => fixWithConfirm("/api/posture/fix-all", {}), { kind: "primary", icon: "bolt", ok: r => r && r.fixed !== undefined ? `${Array.isArray(r.fixed) ? r.fixed.length : r.fixed} setting(s) fixed` : "Done" }),
              btn("Check again", () => GET("/api/posture/checks?refresh=true"), { icon: "refresh" }))))),
        card("By area", h("div", null, a.categories.map(c => hbar(c.name, c.score, 100, `${c.passed}/${c.total}`))))));
      body.appendChild(tableCard("To fix", [{ t: "Level", v: c => badge(c.severity) }, { t: "Setting", v: c => h("div", null, h("b", null, c.title), h("div", { class: "dim small" }, c.category_name)) }, { t: "Now", v: c => h("span", { class: "wrap" }, c.value) },
        { t: "Why it matters", v: c => h("span", { class: "muted small" }, c.why) },
        { t: "", v: c => h("div", { class: "row tight", style: { flexWrap: "nowrap" } },
          c.fix && !c.fix.blocked ? btn(c.fix.label || "Fix", () => fixWithConfirm(`/api/posture/checks/${c.id}/fix`, {}), { sm: true, kind: "primary", ok: "Fixed" })
            : c.manual && c.manual.open ? btn("Open settings", () => POST(`/api/posture/open/${c.manual.open}`), { sm: true, refresh: false }) : null,
          btn("Details", () => { checkDialog(c); return "norefresh"; }, { sm: true }),
          isAdmin() ? btn("Ignore", () => POST(`/api/posture/checks/${c.id}/ignore`, {}), { sm: true, kind: "ghost", confirm: "Ignore this check? It stops counting against your score.", ok: "Ignored" }) : null) }], failed, { empty: "Every check passed.", height: "none" }));
      body.appendChild(tableCard("Passed and other checks", [{ t: "Result", v: c => c.ignored ? badge("ignored", "off") : badge(c.status === "pass" ? "passed" : c.status, c.status === "pass" ? "ok" : "info") }, { t: "Setting", v: c => h("b", null, c.title) }, { t: "Area", v: c => c.category_name }, { t: "Now", v: c => c.value },
        { t: "", v: c => c.ignored && isAdmin() ? btn("Stop ignoring", () => DEL(`/api/posture/checks/${c.id}/ignore`), { sm: true }) : btn("Details", () => { checkDialog(c); return "norefresh"; }, { sm: true, kind: "ghost" }) }], rest, { height: "360px" }));
    }

    if (t.current === "defender") {
      const d = await GET("/api/posture/defender");
      const df = d.defender || {}, pr = d.preferences || {};
      const yn = v => v === null || v === undefined ? badge("unknown", "info") : onoff(!!v);
      body.appendChild(h("div", { class: "grid g2" },
        card("Microsoft Defender Antivirus", kv([["Antivirus", yn(df.antivirus)], ["Real-time protection", yn(df.realtime)], ["Behaviour monitoring", yn(df.behavior)], ["Scan downloads", yn(df.ioav)], ["Tamper Protection", yn(df.tamper)],
          ["Definitions", `${df.signature_version || "-"} (${df.signature_age_days !== null && df.signature_age_days !== undefined ? df.signature_age_days + " day(s) old" : "age unknown"})`], ["Last quick scan", df.quick_scan_age_days !== null && df.quick_scan_age_days !== undefined ? df.quick_scan_age_days + " day(s) ago" : "never"], ["Engine", df.engine_version]]),
          { actions: [btn("Update definitions", () => POST("/api/posture/defender/update"), { sm: true, ok: "Definition update started" }), btn("Defender quick scan", () => POST("/api/posture/defender/scan", {}), { sm: true, ok: "Defender scan started" })] }),
        card("Protection options", kv([["Cloud protection", yn(pr.maps)], ["Send samples", yn(pr.samples)], ["Block unwanted apps", yn(pr.pua)], ["Network protection", yn(pr.network_protection)], ["Ransomware folder protection", yn(pr.cfa)]]))));
      const ex = d.exclusions || {};
      const exRows = [].concat((ex.paths || []).map(p => ["Folder / file", p]), (ex.extensions || []).map(p => ["File type", p]), (ex.processes || []).map(p => ["Program", p]));
      body.appendChild(tableCard("Defender exclusions", [{ t: "Kind", v: r => r[0] }, { t: "Excluded", v: r => h("code", { class: "wrap" }, typeof r[1] === "string" ? r[1] : r[1].value || r[1].path) }], exRows, { empty: "No exclusions - good." }));
    }

    if (t.current === "updates") {
      const u = await GET("/api/posture/updates");
      const up = u.update || {}, sup = u.support || {}, srch = u.search || {};
      body.appendChild(h("div", { class: "grid g4" }, statCard(up.last_install ? ago(up.last_install) : "Unknown", "Last update installed"), statCard(up.pending_reboot ? "Needed" : "No", "Restart to finish updates", null, up.pending_reboot ? "var(--medium)" : "var(--ok)"),
        statCard(sup.days_left !== undefined && sup.days_left !== null ? sup.days_left + " days" : "-", "Windows version supported for", sup.version || "", sup.days_left < 60 ? "var(--critical)" : null), statCard(up.paused_until ? "Paused" : "On", "Automatic updates", up.paused_until ? "until " + day(up.paused_until) : "", up.paused_until ? "var(--medium)" : "var(--ok)")));
      body.appendChild(card("Windows Update", h("div", { class: "spread" }, h("div", { class: "muted" }, srch.state === "running" ? "Looking for updates…" : srch.missing !== undefined ? `${srch.missing || (srch.updates || []).length} update(s) waiting` : "Ask Windows whether updates are waiting."),
        h("div", { class: "row" }, btn("Check for updates", () => POST("/api/posture/updates/search"), { kind: "primary", ok: "Looking for updates in the background" }), btn("Open Windows Update", () => POST("/api/posture/open/windows_update"), { refresh: false })))));
      body.appendChild(tableCard("Recently installed", [{ t: "Installed", v: x => dt(x.date || x.installed_at) }, { t: "Update", v: x => x.title || x.kb }, { t: "Result", v: x => cap(x.result || "") }], up.history || [], { empty: "No update history could be read." }));
    }

    if (t.current === "accounts") {
      const a = await GET("/api/posture/accounts");
      body.appendChild(tableCard("Windows accounts on this PC", [{ t: "Account", v: u => h("b", null, u.name) }, { t: "Enabled", v: u => onoff(u.enabled, "Yes", "No") }, { t: "Administrator", v: u => u.admin || u.is_admin ? badge("admin", "medium") : "" },
        { t: "Password required", v: u => u.password_required === false ? badge("No", "high") : "Yes" }, { t: "Last sign-in", v: u => u.last_logon ? ago(u.last_logon) : "-" }], a.users || [], { empty: a.error || "Accounts could not be read." }));
    }

    if (t.current === "history") {
      const [ch, ev, sm] = await Promise.all([GET("/api/posture/changes?limit=50"), GET("/api/posture/events?limit=80"), GET("/api/posture/summary?days=30").catch(() => ({}))]);
      const hist = sm.history || sm.scores || [];
      if (hist.length > 1) body.appendChild(card("Device security score", line([{ name: "Score", color: "var(--ok)", values: hist.map(x => x.score) }], { max: 100 })));
      body.appendChild(tableCard("Changes made by Cyber Hub", [{ t: "When", v: c => dt(c.ts || c.created_at) }, { t: "Setting", v: c => h("b", null, c.title || c.check_id) }, { t: "Change", v: c => h("span", { class: "muted small wrap" }, `${c.old_value !== undefined ? c.old_value : c.before || "?"} → ${c.new_value !== undefined ? c.new_value : c.after || "?"}`) }, { t: "By", v: c => c.username || c.by },
        { t: "", v: c => isAdmin() && !c.reverted_at && c.can_revert !== false ? btn("Undo", () => POST(`/api/posture/changes/${c.id}/revert`), { sm: true, confirm: "Put this setting back to its previous value?", ok: "Reverted" }) : c.reverted_at ? h("span", { class: "dim small" }, "undone") : "" }], ch.items, { empty: "Cyber Hub has not changed any Windows setting yet." }));
      body.appendChild(eventsCard("Device security alerts", "/api/posture", ev.items));
    }
    return root;
  } });

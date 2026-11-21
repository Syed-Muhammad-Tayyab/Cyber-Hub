/* Cyber Hub UI core - Developed by Syed Muhammad Tayyab
   Small helpers shared by every page: API client, DOM builder, charts (inline SVG), tables, dialogs, router.
   No framework, no build step, no CDN - the desktop app works without internet.
   Data from the engine is always put into the page as text nodes (never as HTML). */
"use strict";

const CH = { token: null, session: sessionStorage.getItem("ch_session"), user: null, info: null, desktop: null,
             settings: null, pages: {}, cleanup: [], route: { page: "dashboard", sub: null }, score: null };

/* ------------------------------------------------------------------ API */
class ApiError extends Error {
  constructor(status, message, body) { super(message); this.status = status; this.body = body; }
}
async function api(method, path, body, opts = {}) {
  const headers = { "X-CyberHub-Token": CH.token || "" };
  if (CH.session) headers["X-CyberHub-Session"] = CH.session;
  if (body !== undefined && body !== null) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(path, { method, headers, body: body !== undefined && body !== null ? JSON.stringify(body) : undefined });
  } catch (e) { throw new ApiError(0, "The Cyber Hub engine is not answering. Is it still running?"); }
  if (opts.raw) { if (!res.ok) throw new ApiError(res.status, await errorText(res)); return res; }
  if (res.status === 204) return null;
  let data = null;
  try { data = await res.json(); } catch (e) { /* not JSON */ }
  if (res.ok) return data;
  const msg = detailText(data) || res.statusText || ("Error " + res.status);
  if (res.status === 401 && !opts.quiet && CH.user) { CH.user = null; showAuth("login", "Your session ended - please sign in again."); }
  if (res.status === 423 && !opts.quiet && /Session is locked/i.test(msg)) showAuth("lock");
  throw new ApiError(res.status, msg, data);
}
function detailText(data) {
  if (!data) return "";
  const d = data.detail !== undefined ? data.detail : data.message;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(x => (x.loc ? x.loc.slice(1).join(".") + ": " : "") + (x.msg || "")).join("; ");
  if (d && typeof d === "object") return d.message || JSON.stringify(d);
  return "";
}
async function errorText(res) { try { return detailText(await res.json()) || res.statusText; } catch (e) { return res.statusText; } }
const GET = (p, o) => api("GET", p, undefined, o), POST = (p, b, o) => api("POST", p, b === undefined ? {} : b, o),
      PATCH = (p, b) => api("PATCH", p, b), PUT = (p, b) => api("PUT", p, b), DEL = (p, b) => api("DELETE", p, b);
function qs(params) {
  const u = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") u.set(k, v); });
  const s = u.toString();
  return s ? "?" + s : "";
}
async function download(path, fallbackName) {
  const res = await api("GET", path, undefined, { raw: true });
  const cd = res.headers.get("Content-Disposition") || "";
  const m = /filename="?([^";]+)"?/.exec(cd);
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = m ? m[1] : (fallbackName || "download");
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 30000);
}
function openSocket(path, onMessage) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  let ws, closed = false;
  try {
    ws = new WebSocket(`${proto}://${location.host}${path}${path.includes("?") ? "&" : "?"}token=${encodeURIComponent(CH.token)}&session=${encodeURIComponent(CH.session || "")}`);
    ws.onmessage = ev => { try { onMessage(JSON.parse(ev.data)); } catch (e) { /* ignore */ } };
  } catch (e) { /* sockets are a bonus; pages also poll */ }
  return () => { closed = true; try { ws && ws.close(); } catch (e) { /* */ } return closed; };
}

/* ------------------------------------------------------------------ DOM */
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  if (props) for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k in el && k !== "list" && k !== "form") { try { el[k] = v; } catch (e) { el.setAttribute(k, v); } }
    else el.setAttribute(k, v === true ? "" : v);
  }
  add(el, kids);
  return el;
}
function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
const $ = (sel, root) => (root || document).querySelector(sel);
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
function svg(tag, attrs, ...kids) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, v);
  for (const k of kids.flat()) if (k) el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
  return el;
}

/* ------------------------------------------------------------------ icons (stroke paths, 24x24) */
const ICONS = {
  menu: "M4 7h16M4 12h16M4 17h16", home: "M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
  shield: "M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z", check: "M5 12.5l4.5 4.5L19 7.5",
  fire: "M12 3c1 3.5 5 5 5 10a5 5 0 0 1-10 0c0-2 1-3 2-4 .5 1.5 1.5 2 2 2 0-3 0-5 1-8z",
  wifi: "M2.5 9a14 14 0 0 1 19 0M6 12.5a9 9 0 0 1 12 0M9.2 16a4.5 4.5 0 0 1 5.6 0M12 19.5h.01",
  laptop: "M5 5h14a1 1 0 0 1 1 1v9H4V6a1 1 0 0 1 1-1zM2 18h20", key: "M14.5 9.5a4 4 0 1 1-3.9 5H8v2.5H5.5V19H3v-2.6l6.1-6.1a4 4 0 0 1 5.4-.8zM16 8.5h.01",
  lock: "M6 10V8a6 6 0 0 1 12 0v2M5 10h14v10H5z", users: "M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM2.5 20a6.5 6.5 0 0 1 13 0M16 4.3a3.5 3.5 0 0 1 0 6.4M18 14.3a6.5 6.5 0 0 1 3.5 5.7",
  globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z",
  radar: "M12 12l6-6M12 21a9 9 0 1 1 6.4-2.700M12 16a4 4 0 1 1 2.8-1.2", pulse: "M3 12h4l2.5-6 4 12 2.5-6h5",
  cpu: "M8 8h8v8H8zM5 5h14v14H5zM9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3.5 2", bell: "M6 16V11a6 6 0 0 1 12 0v5l2 2H4zM10 20a2 2 0 0 0 4 0",
  file: "M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6", list: "M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01",
  gear: "M12 15.200a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.400zM19.4 13a7.5 7.5 0 0 0 0-2l2-1.5-2-3.5-2.4 1a7.5 7.5 0 0 0-1.7-1L15 3.500h-4l-.300 2.500a7.5 7.5 0 0 0-1.7 1l-2.4-1-2 3.5 2 1.500a7.5 7.5 0 0 0 0 2l-2 1.5 2 3.5 2.4-1a7.5 7.5 0 0 0 1.7 1l.300 2.500h4l.300-2.500a7.5 7.5 0 0 0 1.7-1l2.4 1 2-3.500z",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4.5 20.500a7.5 7.5 0 0 1 15 0", info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v6M12 7.500h.01",
  refresh: "M20 11a8 8 0 0 0-14.5-4L4 8.500M4 4.500v4h4M4 13a8 8 0 0 0 14.5 4l1.5-1.500M20 19.500v-4h-4",
  play: "M7 4.500v15l12-7.500z", x: "M6 6l12 12M18 6L6 18", plus: "M12 5v14M5 12h14", download: "M12 4v11M7.5 11l4.5 4.5 4.5-4.500M5 19.500h14",
  trash: "M5 7h14M10 7V4.500h4V7M7 7l1 13h8l1-13", eye: "M2.5 12s3.5-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.5 6.5-9.5 6.500S2.5 12 2.5 12zM12 14.500a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z",
  copy: "M9 9h10v11H9zM5 15V4h10", search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM20 20l-4-4", folder: "M3 6h6l2 2.500h10V19H3z",
  alert: "M12 4l9.5 16h-19zM12 10v4.500M12 17.500h.01", bolt: "M13 3L5 13.500h6l-1 7.5 8-10.500h-6z", data: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6",
};
function icon(name) {
  const d = ICONS[name] || ICONS.info;
  return svg("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round" },
    svg("path", { d }));
}

/* ------------------------------------------------------------------ formatting */
function parseTs(ts) { if (!ts) return null; const d = new Date(typeof ts === "number" ? ts * 1000 : ts); return isNaN(d) ? null : d; }
function ago(ts) {
  const d = parseTs(ts); if (!d) return "-";
  let s = (Date.now() - d.getTime()) / 1000;
  const fut = s < 0; s = Math.abs(s);
  const t = s < 50 ? "moments" : s < 3600 ? Math.round(s / 60) + " min" : s < 86400 ? Math.round(s / 3600) + " h" : s < 86400 * 60 ? Math.round(s / 86400) + " d" : Math.round(s / 86400 / 30) + " mo";
  return s < 50 ? (fut ? "in a moment" : "just now") : fut ? "in " + t : t + " ago";
}
function dt(ts) { const d = parseTs(ts); return d ? d.toLocaleString(undefined, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "-"; }
function day(ts) { const d = parseTs(ts); return d ? d.toLocaleDateString(undefined, { day: "2-digit", month: "short" }) : "-"; }
function bytes(n) { n = Number(n) || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return (i ? n.toFixed(1) : n.toFixed(0)) + " " + u[i]; }
function num(n) { return n === null || n === undefined ? "-" : Number(n).toLocaleString(); }
function dur(s) { s = Math.round(Number(s) || 0); return s < 60 ? s + " s" : s < 3600 ? Math.floor(s / 60) + " min " + (s % 60) + " s" : Math.floor(s / 3600) + " h " + Math.floor(s % 3600 / 60) + " min"; }
function cap(s) { s = String(s === null || s === undefined ? "" : s).replace(/_/g, " "); return s.charAt(0).toUpperCase() + s.slice(1); }
function scoreColor(s) { return s === null || s === undefined ? "var(--dim)" : s >= 90 ? "var(--ok)" : s >= 70 ? "#a3e635" : s >= 50 ? "var(--medium)" : "var(--critical)"; }
const SEV = ["info", "low", "medium", "high", "critical"];
const SEV_COLOR = { critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", info: "var(--info)", ok: "var(--ok)" };

/* ------------------------------------------------------------------ small components */
function badge(text, kind) { const k = kind || String(text).toLowerCase(); return h("span", { class: "badge " + (SEV_COLOR[k] ? k : kind || "info") }, cap(text)); }
function onoff(on, onText = "On", offText = "Off") { return h("span", { class: "badge " + (on ? "ok" : "off") }, h("i", { class: "dot" }), on ? onText : offText); }
function btn(label, onClick, opts = {}) {
  const b = h("button", { class: "btn " + (opts.kind || "") + (opts.sm ? " sm" : ""), title: opts.title || null, type: "button" }, opts.icon ? icon(opts.icon) : null, label);
  if (onClick) b.addEventListener("click", ev => { ev.stopPropagation(); run(b, onClick, opts); });
  return b;
}
async function run(button, fn, opts = {}) {
  if (button && button.classList.contains("busy")) return;
  if (opts.confirm && !(await confirmBox(opts.confirm, opts.confirmLabel || "Yes, continue", opts.kind === "danger"))) return;
  if (button) { button.classList.add("busy"); button.disabled = true; }
  try {
    const r = await fn();
    if (opts.ok) toast(typeof opts.ok === "function" ? opts.ok(r) : opts.ok, "ok");
    if (opts.refresh !== false && r !== "norefresh") refresh();
    return r;
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || (e.status === 423 && /Session is locked/i.test(e.message)))) return;
    toast(e.message || String(e), "error");
  } finally { if (button) { button.classList.remove("busy"); button.disabled = false; } }
}
function card(title, body, opts = {}) {
  return h("section", { class: "card " + (opts.class || "") },
    title || opts.actions ? h("div", { class: "card-head" }, h("h3", null, title || ""), opts.actions ? h("div", { class: "row tight" }, opts.actions) : null) : null, body);
}
function stat(value, label, sub, color) { return h("div", { class: "stat" }, h("div", { class: "v", style: color ? { color } : null }, value), h("div", { class: "l" }, label), sub ? h("div", { class: "s" }, sub) : null); }
function statCard(value, label, sub, color) { return h("section", { class: "card" }, stat(value, label, sub, color)); }
function kv(pairs) { const dl = h("dl", { class: "kv" }); pairs.filter(Boolean).forEach(([k, v]) => add(dl, [h("dt", null, k), h("dd", null, v === null || v === undefined || v === "" ? "-" : v)])); return dl; }
function empty(text, action) { return h("div", { class: "empty" }, text, action ? h("div", { style: { marginTop: "12px" } }, action) : null); }
function banner(kind, title, text, action) { return h("div", { class: "banner " + kind }, h("div", { class: "grow" }, h("div", { class: "bold" }, title), text ? h("div", { class: "muted small" }, text) : null), action || null); }
function toggle(on, onChange, disabled) {
  const b = h("button", { class: "switch" + (on ? " on" : ""), type: "button", role: "switch", "aria-checked": String(!!on), disabled: !!disabled });
  b.addEventListener("click", () => run(null, () => onChange(!b.classList.contains("on"))));
  return b;
}
/* table({cols:[{t:'Title', v: row => node|string, cls:'num'}], rows, empty, max}) */
function table(cols, rows, opts = {}) {
  if (!rows || !rows.length) return empty(opts.empty || "Nothing here yet");
  const body = h("tbody");
  rows.slice(0, opts.max || 500).forEach(r => {
    const tr = h("tr", opts.onRow ? { style: { cursor: "pointer" }, onclick: () => opts.onRow(r) } : null);
    cols.forEach(c => { let v; try { v = c.v(r); } catch (e) { v = "-"; } add(tr, [h("td", { class: c.cls || null, title: c.title ? c.title(r) : null }, v === null || v === undefined || v === "" ? "-" : v)]); });
    body.appendChild(tr);
  });
  return h("div", { class: "tbl-wrap", style: opts.height ? { maxHeight: opts.height } : null },
    h("table", { class: "tbl" }, h("thead", null, h("tr", null, cols.map(c => h("th", { class: c.cls === "num" ? "num" : null }, c.t)))), body));
}
function tableCard(title, cols, rows, opts = {}) {
  return h("section", { class: "card pad0" }, h("div", { class: "card-head" }, h("h3", null, title, opts.count !== false && rows ? h("span", { class: "muted", style: { fontWeight: 400 } }, "  " + num(opts.total !== undefined ? opts.total : rows.length)) : null),
    opts.actions ? h("div", { class: "row tight" }, opts.actions) : null), table(cols, rows, opts));
}
function pathCell(p) { return h("div", { class: "path", title: p || "" }, p || "-"); }
function tabs(defs) {
  const cur = defs.find(d => d.id === CH.route.sub) || defs[0];
  const bar = h("div", { class: "tabs" }, defs.map(d => h("div", { class: "tab" + (d === cur ? " active" : ""), onclick: () => go(CH.route.page, d.id) }, d.label)));
  return { bar, current: cur.id };
}

/* ------------------------------------------------------------------ charts */
function ring(score, size = 150, opts = {}) {
  const r = size / 2 - size * 0.075, c = 2 * Math.PI * r, v = score === null || score === undefined ? 0 : Math.max(0, Math.min(100, score));
  const col = opts.color || scoreColor(score), sw = size * 0.085;
  return h("div", { class: "ring", style: { width: size + "px", height: size + "px" } },
    svg("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}` },
      svg("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "var(--line)", "stroke-width": sw }),
      svg("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: col, "stroke-width": sw, "stroke-linecap": "round", "stroke-dasharray": `${c * v / 100} ${c}`, style: `filter:drop-shadow(0 0 ${size * 0.05}px ${col})` })),
    h("div", { class: "ring-in" }, h("span", { class: "n", style: { fontSize: size * 0.3 + "px", color: col } }, score === null || score === undefined ? "–" : score),
      opts.label ? h("span", { class: "g" }, opts.label) : null));
}
function donut(parts, size = 130, centerText) {
  const total = parts.reduce((a, p) => a + (p.value || 0), 0), r = size / 2 - 12, c = 2 * Math.PI * r;
  const g = svg("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}`, style: "transform:rotate(-90deg)" },
    svg("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "var(--line)", "stroke-width": 14 }));
  let off = 0;
  parts.forEach(p => { if (!p.value || !total) return; const len = c * p.value / total;
    g.appendChild(svg("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: p.color, "stroke-width": 14, "stroke-dasharray": `${Math.max(len - 1.5, 0.5)} ${c}`, "stroke-dashoffset": -off })); off += len; });
  return h("div", { class: "row", style: { flexWrap: "nowrap", gap: "16px" } },
    h("div", { class: "ring", style: { width: size + "px", height: size + "px", flex: "none" } }, g, h("div", { class: "ring-in" }, h("span", { class: "n", style: { fontSize: "24px" } }, centerText !== undefined ? centerText : num(total)))),
    h("div", { class: "legend", style: { flexDirection: "column" } }, parts.map(p => h("span", null, h("i", { class: "dot", style: { color: p.color } }), `${p.label} `, h("b", { style: { color: "var(--text)" } }, num(p.value))))));
}
/* Per-day rows from the engine only list days that had something; fill the gaps so graphs show the whole period. */
function daySeries(rows, days, pick) {
  const by = {}; (rows || []).forEach(r => { by[r.day] = r; });
  const out = [], now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i)).toISOString().slice(0, 10);
    const v = by[d] ? pick(by[d]) : 0;
    out.push(Object.assign({ label: d.slice(5) }, typeof v === "object" ? v : { value: v }));
  }
  return out;
}
/* bars([{label, value, value2?}], {color, color2, height}) - columns over time */
function bars(points, opts = {}) {
  const W = 600, H = opts.height || 150, pad = 18;
  const g = svg("svg", { class: "chart", viewBox: `0 0 ${W} ${H + 18}`, preserveAspectRatio: "none", style: `height:${H + 18}px` });
  if (!points || !points.length) return h("div", { class: "empty", style: { padding: "34px 0" } }, opts.empty || "No data for this period yet");
  const max = Math.max(1, ...points.map(p => (p.value || 0) + (p.value2 || 0))), n = points.length, gap = n > 40 ? 1 : 4, bw = (W - gap * (n - 1)) / n;
  for (let i = 1; i <= 3; i++) g.appendChild(svg("line", { x1: 0, x2: W, y1: pad + (H - pad) * i / 4 - (H - pad) / 4 + 0.5, y2: pad + (H - pad) * i / 4 - (H - pad) / 4 + 0.5, stroke: "var(--line)", "stroke-dasharray": "3 5" }));
  points.forEach((p, i) => {
    const x = i * (bw + gap), h1 = (H - pad) * (p.value || 0) / max, h2 = (H - pad) * (p.value2 || 0) / max;
    const t = svg("title", null, `${p.label}: ${num(p.value)}${p.value2 !== undefined ? " / " + num(p.value2) : ""}`);
    g.appendChild(svg("rect", { x, y: H - h1, width: bw, height: Math.max(h1, p.value ? 2 : 0), rx: Math.min(4, bw / 2), fill: opts.color || "var(--accent)" }, t));
    if (h2) g.appendChild(svg("rect", { x, y: H - h1 - h2, width: bw, height: h2, rx: Math.min(4, bw / 2), fill: opts.color2 || "var(--critical)" }));
    if (n <= 16 || i % Math.ceil(n / 8) === 0) g.appendChild(svg("text", { x: x + bw / 2, y: H + 13, "text-anchor": "middle" }, p.label));
  });
  return g;
}
/* line([{name,color,values:[..]}], {max, height, unit}) */
function line(series, opts = {}) {
  const W = 600, H = opts.height || 140;
  const g = svg("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", style: `height:${H}px` });
  const all = series.flatMap(s => s.values.filter(v => v !== null && v !== undefined));
  if (all.length < 2) return h("div", { class: "empty", style: { padding: "34px 0" } }, "Collecting data…");
  const max = opts.max || Math.max(1, ...all) * 1.15;
  for (let i = 0; i <= 4; i++) g.appendChild(svg("line", { x1: 0, x2: W, y1: H * i / 4, y2: H * i / 4, stroke: "var(--line)", "stroke-dasharray": "3 5" }));
  series.forEach((s, si) => {
    const n = s.values.length; if (n < 2) return;
    const pts = s.values.map((v, i) => [i * W / (n - 1), H - (H - 6) * (v || 0) / max - 3]);
    const d = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    if (si === 0 || opts.fillAll) g.appendChild(svg("path", { d: `${d} L${W} ${H} L0 ${H} Z`, fill: s.color, opacity: 0.12 }));
    g.appendChild(svg("path", { d, fill: "none", stroke: s.color, "stroke-width": 2, "vector-effect": "non-scaling-stroke", "stroke-linejoin": "round" }));
  });
  return h("div", null, g, series.length > 1 || opts.legend ? h("div", { class: "legend", style: { marginTop: "8px" } }, series.map(s => h("span", null, h("i", { class: "dot", style: { color: s.color } }), s.name))) : null);
}
function hbar(label, value, max = 100, shown, color) {
  const pct = value === null || value === undefined ? 0 : Math.max(0, Math.min(100, value * 100 / (max || 1)));
  return h("div", { class: "hbar" }, h("span", { class: "muted", style: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }, title: label }, label),
    h("div", { class: "track" }, h("i", { style: { width: pct + "%", background: color || (max === 100 ? scoreColor(value) : "var(--accent)") } })),
    h("b", { class: "right" }, shown !== undefined ? shown : value === null || value === undefined ? "–" : value));
}
function progress(pct) { return h("div", { class: "progress" }, h("i", { style: { width: Math.max(0, Math.min(100, pct || 0)) + "%" } })); }
function sevDonut(counts, size) {
  return donut(["critical", "high", "medium", "low"].map(s => ({ label: cap(s), value: (counts || {})[s] || 0, color: SEV_COLOR[s] })), size);
}

/* ------------------------------------------------------------------ dialogs */
function toast(text, kind = "info", ms = 4500) {
  const t = h("div", { class: "toast " + kind }, text);
  $("#toast-root").appendChild(t);
  setTimeout(() => t.remove(), kind === "error" ? 7000 : ms);
}
function modal(title, body, buttons = [], opts = {}) {
  const root = $("#modal-root");
  const close = () => { back.remove(); document.removeEventListener("keydown", onKey); if (opts.onClose) opts.onClose(); };
  const onKey = e => { if (e.key === "Escape") close(); };
  const foot = h("div", { class: "modal-foot" });
  const back = h("div", { class: "modal-back", onmousedown: e => { if (e.target === back && !opts.sticky) close(); } },
    h("div", { class: "modal" + (opts.wide ? " wide" : "") }, h("div", { class: "modal-head" }, h("h2", null, title), h("button", { class: "icon-btn", onclick: close, title: "Close" }, icon("x"))),
      h("div", { class: "modal-body" }, body), buttons.length ? foot : null));
  buttons.forEach(b => foot.appendChild(b));
  root.appendChild(back);
  document.addEventListener("keydown", onKey);
  const first = back.querySelector("input,select,textarea");
  if (first) setTimeout(() => first.focus(), 30);
  return { close, el: back };
}
function confirmBox(text, okLabel = "Yes, continue", danger = false) {
  return new Promise(resolve => {
    let done = false;
    const m = modal("Please confirm", h("p", { style: { margin: "4px 0 8px", whiteSpace: "pre-wrap" } }, text),
      [h("button", { class: "btn", onclick: () => m.close() }, "Cancel"),
       h("button", { class: "btn " + (danger ? "danger" : "primary"), onclick: () => { done = true; m.close(); resolve(true); } }, okLabel)],
      { onClose: () => { if (!done) resolve(false); } });
  });
}
/* formDialog(title, fields, {submit, intro, onSubmit(values) -> may throw}) -> resolves values or null
   field: {name, label, type: text|password|number|select|checkbox|textarea|time|path|datetime, value, options:[[v,label]], hint, required, pick:'file'|'folder'} */
function formDialog(title, fields, opts = {}) {
  return new Promise(resolve => {
    const inputs = {}; let done = false;
    const form = h("form", { onsubmit: ev => { ev.preventDefault(); submit(); } }, opts.intro ? h("p", { class: "muted", style: { marginTop: 0 } }, opts.intro) : null);
    fields.forEach(f => {
      let inp;
      if (f.type === "select") inp = h("select", { class: "input" }, (f.options || []).map(o => h("option", { value: o[0], selected: String(o[0]) === String(f.value) }, o[1])));
      else if (f.type === "textarea") inp = h("textarea", { class: "input", placeholder: f.placeholder || "", value: f.value || "" });
      else if (f.type === "checkbox") inp = h("input", { type: "checkbox", checked: !!f.value });
      else inp = h("input", { class: "input", type: f.type === "path" ? "text" : f.type === "datetime" ? "datetime-local" : (f.type || "text"), value: f.value === undefined || f.value === null ? "" : f.value,
        placeholder: f.placeholder || "", min: f.min, max: f.max, autocomplete: f.type === "password" ? "new-password" : "off", spellcheck: false });
      inputs[f.name] = inp;
      if (f.type === "checkbox") { form.appendChild(h("label", { class: "check" }, inp, h("span", null, f.label, f.hint ? h("div", { class: "hint dim small" }, f.hint) : null))); return; }
      const rowEl = f.type === "path" && CH.desktop && CH.desktop.can_pick_files
        ? h("div", { class: "row", style: { flexWrap: "nowrap" } }, inp, h("button", { class: "btn", type: "button", onclick: async () => {
            try { const r = await POST("/api/desktop/pick", { kind: f.pick || "folder", title: f.label }); if (r.paths && r.paths.length) inp.value = r.paths[0]; } catch (e) { toast(e.message, "error"); } } }, "Browse…"))
        : inp;
      form.appendChild(h("div", { class: "field" }, h("label", null, f.label), rowEl, f.hint ? h("div", { class: "hint" }, f.hint) : null));
      if (f.onInput) inp.addEventListener("input", () => f.onInput(inp.value, form));
    });
    form.appendChild(h("button", { type: "submit", hidden: true }));
    const okBtn = h("button", { class: "btn " + (opts.danger ? "danger" : "primary"), onclick: () => submit() }, opts.submit || "Save");
    async function submit() {
      const v = {};
      for (const f of fields) {
        const inp = inputs[f.name];
        v[f.name] = f.type === "checkbox" ? inp.checked : f.type === "number" ? (inp.value === "" ? null : Number(inp.value)) : inp.value;
        if (f.required && (v[f.name] === "" || v[f.name] === null)) { toast(`${f.label} is needed`, "warn"); inp.focus(); return; }
      }
      if (opts.onSubmit) {
        okBtn.classList.add("busy"); okBtn.disabled = true;
        try { const r = await opts.onSubmit(v); done = true; m.close(); resolve(r === undefined ? v : r); }
        catch (e) { toast(e.message || String(e), "error"); }
        finally { okBtn.classList.remove("busy"); okBtn.disabled = false; }
        return;
      }
      done = true; m.close(); resolve(v);
    }
    const m = modal(title, form, [h("button", { class: "btn", onclick: () => m.close() }, "Cancel"), okBtn], { onClose: () => { if (!done) resolve(null); }, wide: opts.wide });
  });
}
function detailDialog(title, body, buttons) { return modal(title, body, buttons || [], { wide: true }); }
function lines(text) { return String(text || "").split(/\r?\n/).map(s => s.trim()).filter(Boolean); }
async function copyText(text) { try { await navigator.clipboard.writeText(text); toast("Copied", "ok", 1500); } catch (e) { toast("Could not copy - select the text and press Ctrl+C", "warn"); } }

/* ------------------------------------------------------------------ pages + router */
function page(id, def) { CH.pages[id] = Object.assign({ id }, def); }
function go(pageId, sub) { location.hash = "#/" + pageId + (sub ? "/" + sub : ""); }
function every(ms, fn) { const t = setInterval(() => { if (!document.hidden) fn(); }, ms); CH.cleanup.push(() => clearInterval(t)); }
function onLeave(fn) { CH.cleanup.push(fn); }
function isAdmin() { return CH.user && CH.user.role === "admin"; }
let renderSeq = 0;
async function render() {
  if (!CH.user) return;
  const m = /^#\/([\w-]+)(?:\/([\w-]+))?/.exec(location.hash) || [];
  const id = CH.pages[m[1]] ? m[1] : "dashboard";
  CH.route = { page: id, sub: m[2] || null };
  CH.cleanup.splice(0).forEach(fn => { try { fn(); } catch (e) { /* */ } });
  const def = CH.pages[id], view = $("#view"), seq = ++renderSeq;
  $("#page-title").textContent = def.title; $("#page-sub").textContent = def.sub || "";
  document.title = def.title + " - Cyber Hub";
  document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.page === id));
  if (!view.dataset.page || view.dataset.page !== id + "/" + (m[2] || "")) { clear(view).appendChild(h("div", { class: "stack" }, h("div", { class: "skeleton" }), h("div", { class: "skeleton", style: { height: "220px" } }))); }
  view.dataset.page = id + "/" + (m[2] || "");
  try {
    const content = await def.render();
    if (seq !== renderSeq) return;
    const top = view.scrollTop;
    clear(view).appendChild(content);
    view.scrollTop = top;
  } catch (e) {
    if (seq !== renderSeq) return;
    if (e instanceof ApiError && (e.status === 401 || (e.status === 423 && /Session is locked/i.test(e.message)))) return;
    clear(view).appendChild(card("This page could not be loaded", h("div", null, h("p", { class: "muted" }, e.message || String(e)), btn("Try again", () => {}, { icon: "refresh" }))));
    console.error(e);
  }
}
function refresh() { return render(); }
window.addEventListener("hashchange", render);

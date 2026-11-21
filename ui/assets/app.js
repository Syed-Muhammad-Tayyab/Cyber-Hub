/* Cyber Hub UI - start-up, sign-in screens, menu, notifications bell
   Developed by Syed Muhammad Tayyab */
"use strict";

const NAV = [
  ["Overview", ["dashboard"]],
  ["Protection", ["protection", "firewall", "network", "device"]],
  ["Privacy & accounts", ["passwords", "data", "platforms"]],
  ["Tools", ["web", "intel", "monitor", "processes"]],
  ["Manage", ["scheduler", "notifications", "reports", "activity", "settings", "account", "about"]],
];
const NAV_SCORE = { protection: "protection", firewall: "firewall", network: "network", device: "device", passwords: "passwords",
                    data: "data", platforms: "accounts", web: "web", intel: "intel" };

/* ------------------------------------------------------------------ sign-in screens */
function authCard(title, sub, ...content) {
  return h("div", { class: "auth-card" }, h("div", { class: "auth-logo" }), h("h1", null, title), h("div", { class: "sub" }, sub), content,
    h("div", { class: "auth-foot" }, "Cyber Hub", CH.info ? " v" + CH.info.version : "", " · Developed by Syed Muhammad Tayyab"));
}
function field(label, input, hint) { return h("div", { class: "field" }, h("label", null, label), input, hint ? h("div", { class: "hint" }, hint) : null); }
function strengthMeter(input, userInput) {
  const bar = h("i"), text = h("div", { class: "hint" }, "Use 10+ characters - a few random words work well.");
  let timer;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!input.value) { bar.style.width = "0"; return; }
      try {
        const s = await POST("/api/account/password-strength", { password: input.value, username: userInput ? userInput.value : null }, { quiet: true });
        const sc = s.score !== undefined ? s.score : 0;
        bar.style.width = (sc + 1) * 20 + "%";
        bar.style.background = ["var(--critical)", "var(--high)", "var(--medium)", "#a3e635", "var(--ok)"][Math.min(sc, 4)];
        text.textContent = (s.label || "") + (s.feedback && s.feedback.length ? " - " + s.feedback[0] : "");
      } catch (e) { /* meter is optional */ }
    }, 220);
  });
  return h("div", null, h("div", { class: "pwbar" }, bar), text);
}
async function showAuth(mode, note) {
  const root = $("#auth");
  $("#shell").hidden = true; $("#boot").hidden = true; root.hidden = false;
  CH.cleanup.splice(0).forEach(fn => { try { fn(); } catch (e) { /* */ } });
  clear(root);
  const msg = h("div", { class: "small", style: { color: "var(--medium)", minHeight: "20px", margin: "2px 0 8px" } }, note || "");
  const fail = e => { msg.style.color = "var(--critical)"; msg.textContent = e.message || String(e); };
  const submitBtn = label => h("button", { class: "btn primary", type: "submit", style: { width: "100%", justifyContent: "center", padding: "10px" } }, label);
  const guard = fn => async ev => { ev.preventDefault(); const b = ev.target.querySelector("button[type=submit]"); b.classList.add("busy"); b.disabled = true; try { await fn(); } catch (e) { fail(e); } finally { b.classList.remove("busy"); b.disabled = false; } };

  if (mode === "setup") {
    const user = h("input", { class: "input", autocomplete: "username", spellcheck: false, placeholder: "e.g. syed" }), name = h("input", { class: "input", placeholder: "Your name" });
    const pw = h("input", { class: "input", type: "password", autocomplete: "new-password" }), pw2 = h("input", { class: "input", type: "password", autocomplete: "new-password" });
    root.appendChild(authCard("Welcome to Cyber Hub", "Create the owner account for this PC",
      h("form", { onsubmit: guard(async () => {
        if (pw.value !== pw2.value) throw new Error("The two passwords are not the same");
        const r = await POST("/api/account/setup", { username: user.value.trim(), display_name: name.value.trim(), password: pw.value }, { quiet: true });
        await signedIn(r.session_token);
        if (r.recovery_codes && r.recovery_codes.length) showRecoveryCodes(r.recovery_codes);
      }) }, field("User name", user), field("Display name", name), field("Password", pw), strengthMeter(pw, user),
        h("div", { style: { height: "10px" } }), field("Repeat password", pw2), msg, submitBtn("Create account")),
      h("p", { class: "dim small center", style: { marginBottom: 0 } }, "Everything stays on this computer. There is no cloud account.")));
    user.focus();
  } else if (mode === "lock") {
    const secret = h("input", { class: "input", type: "password", autocomplete: "current-password", placeholder: CH.user && CH.user.has_pin ? "PIN or password" : "Password" });
    root.appendChild(authCard("Cyber Hub is locked", CH.user ? "Signed in as " + (CH.user.display_name || CH.user.username) : "Enter your password to continue",
      h("form", { onsubmit: guard(async () => {
        const v = secret.value, isPin = /^\d{4,8}$/.test(v) && CH.user && CH.user.has_pin;
        await POST("/api/account/unlock", isPin ? { pin: v } : { password: v }, { quiet: true });
        await enterApp();
      }) }, field(CH.user && CH.user.has_pin ? "PIN or password" : "Password", secret), msg, submitBtn("Unlock")),
      h("div", { class: "auth-links" }, h("a", { href: "#", onclick: async ev => { ev.preventDefault(); try { await POST("/api/account/logout", {}, { quiet: true }); } catch (e) { /* */ } signOutLocal(); showAuth("login"); } }, "Sign in as someone else"), h("span")),
      h("p", { class: "dim small center", style: { marginBottom: 0 } }, "Protection keeps running while Cyber Hub is locked.")));
    secret.focus();
  } else if (mode === "recover") {
    const user = h("input", { class: "input", spellcheck: false }), code = h("input", { class: "input mono", spellcheck: false, placeholder: "XXXX-XXXX-XXXX" });
    const pw = h("input", { class: "input", type: "password", autocomplete: "new-password" });
    root.appendChild(authCard("Reset your password", "Use one of the recovery codes you saved",
      h("form", { onsubmit: guard(async () => {
        const r = await POST("/api/account/recover", { username: user.value.trim(), recovery_code: code.value.trim(), new_password: pw.value }, { quiet: true });
        await signedIn(r.session_token);
        toast("Password changed. That recovery code can't be used again.", "ok");
      }) }, field("User name", user), field("Recovery code", code), field("New password", pw), strengthMeter(pw, user), msg, submitBtn("Reset password")),
      h("div", { class: "auth-links" }, h("a", { href: "#", onclick: ev => { ev.preventDefault(); showAuth("login"); } }, "Back to sign in"), h("span"))));
    user.focus();
  } else {
    const user = h("input", { class: "input", autocomplete: "username", spellcheck: false, value: localStorage.getItem("ch_last_user") || "" });
    const pw = h("input", { class: "input", type: "password", autocomplete: "current-password" });
    root.appendChild(authCard("Cyber Hub", "Sign in to your security center",
      h("form", { onsubmit: guard(async () => {
        const r = await POST("/api/account/login", { username: user.value.trim(), password: pw.value }, { quiet: true });
        localStorage.setItem("ch_last_user", user.value.trim());
        await signedIn(r.session_token);
      }) }, field("User name", user), field("Password", pw), msg, submitBtn("Sign in")),
      h("div", { class: "auth-links" }, h("a", { href: "#", onclick: ev => { ev.preventDefault(); showAuth("recover"); } }, "Forgot your password?"), h("span"))));
    (user.value ? pw : user).focus();
  }
}
function showRecoveryCodes(codes) {
  modal("Save your recovery codes", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "If you forget your password, one of these codes lets you set a new one. Each works once. They are shown only now - print them or write them down."),
    h("div", { class: "card mono", style: { columns: 2, lineHeight: 2, fontSize: "14px" } }, codes.map(c => h("div", null, c)))),
    [btn("Copy all", () => { copyText(codes.join("\n")); return "norefresh"; }, { icon: "copy" })], { sticky: true });
}
function signOutLocal() { CH.session = null; CH.user = null; sessionStorage.removeItem("ch_session"); }
async function signedIn(token) { CH.session = token; sessionStorage.setItem("ch_session", token); await enterApp(); }

/* ------------------------------------------------------------------ the app frame */
function buildNav() {
  const nav = clear($("#nav"));
  NAV.forEach(([group, ids]) => {
    nav.appendChild(h("div", { class: "nav-group" }, group));
    ids.forEach(id => {
      const p = CH.pages[id]; if (!p) return;
      const item = h("div", { class: "nav-item", dataset: { page: id }, title: p.title, onclick: () => go(id) }, icon(p.icon), h("span", { class: "nav-label" }, p.nav || p.title),
        NAV_SCORE[id] ? h("span", { class: "nav-badge", dataset: { cat: NAV_SCORE[id] } }) : null);
      if (p.subs && p.subs.length) {       // hovering a section shows its features
        let fly, timer;
        const hide = () => { timer = setTimeout(() => { if (fly) { fly.remove(); fly = null; } }, 140); };
        item.addEventListener("mouseenter", () => {
          clearTimeout(timer); if (fly) return;
          const r = item.getBoundingClientRect();
          fly = h("div", { class: "flyout", style: { left: r.right + 8 + "px", top: Math.min(r.top - 6, innerHeight - 40 - p.subs.length * 32) + "px" }, onmouseenter: () => clearTimeout(timer), onmouseleave: hide },
            h("h4", null, p.title), p.subs.map(([sid, label]) => h("a", { href: `#/${id}/${sid}`, onclick: () => { fly && fly.remove(); fly = null; } }, label)));
          document.body.appendChild(fly);
        });
        item.addEventListener("mouseleave", hide);
      }
      nav.appendChild(item);
    });
  });
}
function paintScoreBadges(score) {
  if (!score) return;
  CH.score = score;
  document.querySelectorAll(".nav-badge").forEach(b => {
    const c = score.categories.find(x => x.id === b.dataset.cat);
    b.className = "nav-badge " + (c && c.score !== null ? c.status : "");
    b.title = c ? `${c.status_text}${c.score !== null ? " - " + c.score + "/100" : ""}` : "";
  });
}
async function loadScore() { try { paintScoreBadges(await GET("/api/score", { quiet: true })); } catch (e) { /* shown on the dashboard */ } }
function setBell(n) { const c = $("#bell-count"); c.hidden = !n; c.textContent = n > 99 ? "99+" : n; }
function applyTheme(theme) {
  const t = theme === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : theme || "dark";
  document.documentElement.dataset.theme = t;
}
async function openBell() {
  const body = h("div", { class: "drawer-body" }, h("div", { class: "skeleton" }));
  const close = () => { drawer.remove(); document.removeEventListener("mousedown", outside); };
  const outside = e => { if (!drawer.contains(e.target) && !e.target.closest("#btn-bell")) close(); };
  const drawer = h("aside", { class: "drawer" }, h("div", { class: "modal-head" }, h("h2", null, "Notifications"),
    h("div", { class: "row tight" }, btn("Mark all read", async () => { await POST("/api/notifications/read", {}); await fill(); return "norefresh"; }, { sm: true }),
      h("button", { class: "icon-btn", onclick: close }, icon("x")))), body,
    h("div", { class: "modal-foot" }, h("button", { class: "btn", onclick: () => { close(); go("notifications"); } }, "Open notification center")));
  async function fill() {
    const r = await GET("/api/notifications" + qs({ status: "open", limit: 30 }));
    setBell(r.unread);
    clear(body).appendChild(r.items.length ? h("div", { class: "list" }, r.items.map(n => h("div", { class: "item", style: { cursor: "pointer", opacity: n.read ? 0.62 : 1 },
      onclick: async () => { try { await POST("/api/notifications/read", { ids: [n.id] }); } catch (e) { /* */ } close(); go(n.link && CH.pages[n.link] ? n.link : "notifications"); } },
      h("i", { class: "dot c-" + n.severity, style: { marginTop: "7px" } }), h("div", { class: "grow" }, h("div", { class: "t" }, n.title), n.detail ? h("div", { class: "d" }, n.detail) : null,
        h("div", { class: "dim small" }, n.source_name, " · ", ago(n.ts)))))) : empty("You're all caught up"));
  }
  document.body.appendChild(drawer);
  setTimeout(() => document.addEventListener("mousedown", outside), 0);
  try { await fill(); } catch (e) { clear(body).appendChild(empty(e.message)); }
}
let liveStop = null;
function startLive() {
  if (liveStop) liveStop();
  let lastId = null;
  const stopWs = openSocket("/api/notifications/stream", m => {
    if (m.type !== "notifications") return;
    setBell(m.unread);
    if (lastId !== null) m.items.filter(n => SEV.indexOf(n.severity) >= 3).slice(-2).forEach(n => toast(n.title, n.severity === "critical" ? "error" : "warn", 7000));
    lastId = m.items.length ? m.items[m.items.length - 1].id : (lastId === null ? 0 : lastId);
  });
  const poll = setInterval(async () => { if (document.hidden || !CH.user) return; try { const s = await GET("/api/notifications/summary?days=1", { quiet: true }); setBell(s.unread); } catch (e) { /* */ } }, 20000);
  const scoreT = setInterval(() => { if (!document.hidden && CH.user) loadScore(); }, 60000);
  liveStop = () => { stopWs(); clearInterval(poll); clearInterval(scoreT); liveStop = null; };
}
async function enterApp() {
  const me = await GET("/api/account/me", { quiet: true });
  if (me.session && me.session.is_locked) { CH.user = me.user; return showAuth("lock"); }
  CH.user = me.user;
  const [settings, desktop] = await Promise.all([GET("/api/settings").catch(() => ({})), GET("/api/desktop/status").catch(() => null)]);
  CH.settings = settings; CH.desktop = desktop;
  applyTheme(settings.theme);
  $("#auth").hidden = true; $("#boot").hidden = true; $("#shell").hidden = false;
  $("#user-name").textContent = CH.user.display_name || CH.user.username;
  $("#user-initial").textContent = (CH.user.display_name || CH.user.username || "?").trim().charAt(0).toUpperCase();
  $("#foot-version").textContent = CH.info ? "v" + CH.info.version : "";
  buildNav();
  startLive();
  loadScore();
  if (!location.hash) location.hash = "#/dashboard"; else render();
}
async function boot() {
  $("#burger").appendChild(icon("menu")); $("#btn-refresh").appendChild(icon("refresh")); $("#btn-bell").insertBefore(icon("bell"), $("#bell-count")); $("#btn-lock").appendChild(icon("lock"));
  $("#burger").onclick = () => { const c = $("#shell").classList.toggle("collapsed"); localStorage.setItem("ch_collapsed", c ? "1" : ""); };
  if (localStorage.getItem("ch_collapsed")) $("#shell").classList.add("collapsed");
  $("#btn-refresh").onclick = () => refresh();
  $("#btn-bell").onclick = () => openBell();
  $("#btn-user").onclick = () => go("account");
  $("#btn-lock").onclick = async () => { try { await POST("/api/account/lock", {}, { quiet: true }); } catch (e) { /* */ } showAuth("lock"); };
  for (let i = 0; i < 60; i++) {                       // the engine may still be starting
    try { const b = await (await fetch("/api/bootstrap")).json(); if (b.token) { CH.token = b.token; break; } } catch (e) { /* retry */ }
    await new Promise(r => setTimeout(r, 500));
  }
  if (!CH.token) { $(".boot-text").textContent = "The Cyber Hub engine did not start. Close this window and open Cyber Hub again."; return; }
  try { CH.info = await GET("/api/info", { quiet: true }); } catch (e) { /* */ }
  let status = {};
  try { status = await GET("/api/account/status", { quiet: true }); } catch (e) { /* */ }
  if (status.setup_required) return showAuth("setup");
  if (CH.session) { try { return await enterApp(); } catch (e) { signOutLocal(); } }
  showAuth("login");
}
boot();

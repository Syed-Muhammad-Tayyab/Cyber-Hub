/* Cyber Hub UI - Password vault, Data protection, Accounts & platforms (Parts 12, 13, 16)
   Developed by Syed Muhammad Tayyab */
"use strict";

/* ================================================================== Password vault */
function showOnce(title, secret, text) {
  modal(title, h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, text), h("div", { class: "card secret center", style: { fontSize: "16px", userSelect: "all" } }, secret)),
    [btn("Copy", () => { copyText(secret); return "norefresh"; }, { icon: "copy" })], { sticky: true });
}
async function vaultItemDialog(item) {
  const isNew = !item;
  let d = {};
  if (!isNew) d = (await GET(`/api/passwords/items/${item.id}?reveal=true`)).item.data || {};
  const type = isNew ? "login" : item.type;
  const fields = [{ name: "title", label: "Name", value: d.title || "", required: true, placeholder: "e.g. GitHub" }];
  if (isNew) fields.unshift({ name: "type", label: "Kind", type: "select", value: "login", options: [["login", "Login"], ["note", "Secure note"], ["card", "Payment card"], ["identity", "Identity"]] });
  if (type === "login") fields.push({ name: "username", label: "User name / e-mail", value: d.username || "" }, { name: "password", label: "Password", value: d.password || "", hint: "Leave empty and tick the box below to get a strong generated password." },
    { name: "generate", label: "Generate a strong password for me", type: "checkbox", value: false }, { name: "url", label: "Website", value: (d.urls || [])[0] || "", placeholder: "https://" },
    { name: "totp", label: "2FA secret (optional)", value: d.totp || "", hint: "The setup key or otpauth:// link a site shows when you turn on an authenticator app." });
  fields.push({ name: "folder", label: "Folder", value: d.folder || "" }, { name: "notes", label: "Notes", type: "textarea", value: d.notes || "" });
  return formDialog(isNew ? "Add to vault" : "Edit " + (d.title || ""), fields, { submit: isNew ? "Add" : "Save", onSubmit: async f => {
    const kind = isNew ? f.type : type;
    const data = { title: f.title, folder: f.folder || "", notes: f.notes || "" };
    if (kind === "login") {
      let pw = f.password;
      if (f.generate) pw = (await POST("/api/passwords/generate", {})).password;
      Object.assign(data, { username: f.username || "", password: pw || "", urls: f.url ? [f.url] : [], totp: f.totp || "" });
    }
    const r = isNew ? await POST("/api/passwords/items", { type: kind, data }) : await PATCH(`/api/passwords/items/${item.id}`, data);
    (r.warnings || []).forEach(w => toast(w, "warn"));
    return r;
  } });
}
async function vaultView(item) {
  const full = (await GET(`/api/passwords/items/${item.id}?reveal=true`)).item, d = full.data || {};
  const secretRow = (label, value, field) => value ? [label, h("div", { class: "row", style: { flexWrap: "nowrap" } }, h("span", { class: "secret wrap", title: "Hidden" }, "•".repeat(Math.min(String(value).length, 14))),
    btn("Show", () => { showOnce(label, value, "Visible until you close this box."); return "norefresh"; }, { sm: true, icon: "eye" }),
    btn("Copy", async () => { try { await POST(`/api/passwords/items/${item.id}/copy`, { field }); toast("Copied - the clipboard is cleared automatically", "ok"); } catch (e) { if (e.status === 501) await copyText(value); else throw e; } return "norefresh"; }, { sm: true, icon: "copy" })) ] : null;
  const body = h("div", null, kv([["Kind", cap(full.type)], d.username ? ["User name", h("span", { class: "row", style: { flexWrap: "nowrap" } }, d.username, btn("Copy", () => { copyText(d.username); return "norefresh"; }, { sm: true }))] : null,
    secretRow("Password", d.password, "password"), (d.urls || []).length ? ["Website", d.urls.join(", ")] : null, full.type === "login" ? ["Strength", badge(full.strength_label || "-", full.strength >= 3 ? "ok" : full.strength === 2 ? "medium" : "high")] : null,
    full.password_changed_at ? ["Password changed", ago(full.password_changed_at)] : null, d.folder ? ["Folder", d.folder] : null, d.notes ? ["Notes", h("span", { style: { whiteSpace: "pre-wrap" } }, d.notes)] : null, ["Updated", dt(full.updated_at)]]),
    (full.issues || []).length ? h("div", { style: { marginTop: "14px" } }, full.issues.map(i => h("div", { class: "row", style: { marginBottom: "4px" } }, badge(i.severity), cap(i.kind), i.detail ? h("span", { class: "muted" }, i.detail) : null))) : null);
  const totpBox = h("div");
  if (full.has_totp) {
    const paint = async () => { try { const tt = await GET(`/api/passwords/items/${item.id}/totp`, { quiet: true }); clear(totpBox).appendChild(h("div", { class: "card", style: { marginTop: "14px" } }, h("div", { class: "spread" }, h("div", null, h("div", { class: "muted small" }, "2FA code"), h("div", { class: "secret", style: { fontSize: "24px" } }, tt.code)), h("span", { class: "muted" }, `${tt.seconds_left || tt.remaining || ""} s`)))); } catch (e) { /* locked */ } };
    paint(); const timer = setInterval(paint, 5000);
    body.appendChild(totpBox);
    const m = detailDialog(d.title || "Item", body, []);
    const ob = new MutationObserver(() => { if (!document.body.contains(m.el)) { clearInterval(timer); ob.disconnect(); } }); ob.observe($("#modal-root"), { childList: true });
    return;
  }
  detailDialog(d.title || "Item", body, []);
}

page("passwords", { title: "Password vault", nav: "Passwords", icon: "key", sub: "Encrypted on this PC with your master password",
  subs: [["items", "My passwords"], ["health", "Password health"], ["generator", "Generator"], ["tools", "Import, export & settings"]],
  async render() {
    const st = await GET("/api/passwords/status");
    const root = h("div", { class: "stack" });
    if (!st.exists) {
      root.appendChild(card("Create your password vault", h("div", null,
        h("p", { class: "muted", style: { marginTop: 0 } }, "The vault stores passwords, cards and notes encrypted with a master password that only you know. Cyber Hub cannot read or reset it."),
        btn("Create vault", async () => { const v = await formDialog("Create your vault", [{ name: "master", label: "Master password", type: "password", required: true, hint: "At least 10 characters and different from your Cyber Hub sign-in password. Four random words work well." },
          { name: "again", label: "Repeat it", type: "password", required: true }, { name: "hint", label: "Hint (optional, never the password itself)" }],
          { submit: "Create vault", onSubmit: async f => { if (f.master !== f.again) throw new Error("The two passwords are not the same"); return POST("/api/passwords/setup", { master_password: f.master, hint: f.hint || null }); } });
          if (v && v.recovery_key) showOnce("Your vault recovery key", v.recovery_key, "If you ever forget the master password, this key is the only way back in. It is shown only now - write it down and keep it somewhere safe."); return v ? undefined : "norefresh"; }, { kind: "primary", icon: "plus" }))));
      return root;
    }
    if (!st.unlocked) {
      const pw = h("input", { class: "input", type: "password", placeholder: "Master password", style: { maxWidth: "320px" } });
      const unlock = () => run(null, async () => { await POST("/api/passwords/unlock", { master_password: pw.value }, { quiet: true }); toast("Vault unlocked", "ok"); });
      pw.addEventListener("keydown", e => { if (e.key === "Enter") unlock(); });
      root.appendChild(card("The vault is locked", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, st.locked_until ? `Too many wrong tries - wait until ${dt(st.locked_until)}.` : "Enter your master password to open it. It locks itself again after " + st.auto_lock_minutes + " minutes without use."),
        h("div", { class: "row" }, pw, h("button", { class: "btn primary", onclick: unlock }, "Unlock"),
          btn("Forgot it?", async () => { const hint = await GET("/api/passwords/hint").catch(() => ({})); const v = await formDialog("Open the vault with your recovery key", [{ name: "key", label: "Recovery key", required: true, placeholder: "XXXX-XXXX-…" }, { name: "new", label: "New master password", type: "password", required: true }],
            { intro: hint.hint ? "Your hint: " + hint.hint : "No hint was saved.", submit: "Reset master password", onSubmit: f => POST("/api/passwords/unlock", { recovery_key: f.key, new_master_password: f.new }) });
            if (v && v.recovery_key) showOnce("Your new recovery key", v.recovery_key, "The old key no longer works. Write this one down."); return v ? undefined : "norefresh"; }, { kind: "ghost" })))));
      setTimeout(() => pw.focus(), 50);
      return root;
    }
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    root.appendChild(h("div", { class: "spread" }, t.bar, btn("Lock vault", () => POST("/api/passwords/lock"), { icon: "lock", sm: true, ok: "Vault locked" })));
    root.firstChild.firstChild.style.marginBottom = "0"; root.firstChild.firstChild.style.flex = "1";

    if (t.current === "items") {
      const q = sessionStorage.getItem("pv_q") || "";
      const lst = await GET("/api/passwords/items" + qs({ q }));
      const search = h("input", { class: "input search", placeholder: "Search…", value: q, onkeydown: e => { if (e.key === "Enter") { sessionStorage.setItem("pv_q", e.target.value); refresh(); } } });
      root.appendChild(tableCard("Saved items", [{ t: "Name", v: i => h("div", null, h("b", null, i.title), h("div", { class: "dim small" }, i.host || cap(i.type))) }, { t: "User name", v: i => i.username },
        { t: "Strength", v: i => i.type === "login" && i.has_password ? badge(i.strength_label, i.strength >= 3 ? "ok" : i.strength === 2 ? "medium" : "high") : "" },
        { t: "Problems", v: i => (i.issues || []).length ? h("span", { class: "row tight" }, i.issues.map(x => badge(x.kind, x.severity))) : h("span", { class: "dim" }, "none") },
        { t: "2FA", v: i => i.has_totp ? badge("code", "ok") : "" }, { t: "Changed", v: i => i.password_changed_at ? ago(i.password_changed_at) : ago(i.updated_at) },
        { t: "", v: i => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, i.type === "login" && i.has_password ? btn("Copy password", async () => { try { await POST(`/api/passwords/items/${i.id}/copy`, { field: "password" }); toast("Password copied - the clipboard clears itself", "ok"); } catch (e) { if (e.status !== 501) throw e; const f = (await GET(`/api/passwords/items/${i.id}?reveal=true`)).item; await copyText(f.data.password); } return "norefresh"; }, { sm: true, icon: "copy" }) : null,
          btn("Edit", async () => { const v = await vaultItemDialog(i); return v ? undefined : "norefresh"; }, { sm: true }), btn("Delete", () => DEL(`/api/passwords/items/${i.id}`), { sm: true, kind: "danger", confirm: `Move "${i.title}" to the trash?`, ok: "Moved to trash" })) }],
        lst.items, { total: lst.total, onRow: i => run(null, async () => { await vaultView(i); return "norefresh"; }), empty: q ? "Nothing matches your search." : "Your vault is empty. Add your first login.",
          actions: [search, btn("Add", async () => { const v = await vaultItemDialog(null); return v ? undefined : "norefresh"; }, { kind: "primary", sm: true, icon: "plus" })] }));
      if (st.trash) { const tr = await GET("/api/passwords/items?trash=true"); root.appendChild(tableCard("Trash", [{ t: "Name", v: i => i.title }, { t: "Deleted", v: i => ago(i.deleted_at) },
        { t: "", v: i => h("div", { class: "row tight" }, btn("Restore", () => POST(`/api/passwords/items/${i.id}/restore`), { sm: true }), btn("Delete forever", () => DEL(`/api/passwords/items/${i.id}?permanent=true`), { sm: true, kind: "danger", confirm: "Delete this item for good?" })) }], tr.items,
        { actions: [btn("Empty trash", () => DEL("/api/passwords/trash"), { sm: true, kind: "danger", confirm: "Delete everything in the trash for good?" })] })); }
    }

    if (t.current === "health") {
      const a = await GET("/api/passwords/audit");
      const c = a.counts;
      root.appendChild(h("div", { class: "grid g-main" },
        h("section", { class: "card" }, h("div", { class: "hero" }, ring(a.score, 150, { label: a.grade }), h("div", null, h("h2", null, `${a.logins} login(s) checked`),
          h("div", { class: "muted", style: { margin: "4px 0 12px" } }, a.breach_checked_at ? "Checked against known breaches " + ago(a.breach_checked_at) : "Not yet checked against known data breaches"),
          btn("Check for breached passwords", () => POST("/api/passwords/audit/breaches", {}), { kind: "primary", icon: "search", ok: "Checking in the background - only 5 characters of a hash are sent, never a password" })))),
        card("Problems", donut([{ label: "In breaches", value: c.breached, color: "var(--critical)" }, { label: "Reused", value: c.reused, color: "var(--high)" }, { label: "Weak", value: c.weak, color: "var(--medium)" }, { label: "Old", value: c.old, color: "var(--low)" }, { label: "Plain http://", value: c.insecure_url, color: "var(--dim)" }], 120))));
      root.appendChild(tableCard("What to change", [{ t: "Level", v: i => badge(i.severity) }, { t: "Item", v: i => h("b", null, i.title) }, { t: "Problem", v: i => cap(i.kind) }, { t: "Detail", v: i => h("span", { class: "muted" }, i.detail) },
        { t: "", v: i => btn("Change", async () => { const v = await vaultItemDialog({ id: i.item_id, type: i.type }); return v ? undefined : "norefresh"; }, { sm: true }) }], a.issues, { empty: "No problems found in your saved passwords." }));
    }

    if (t.current === "generator") {
      const out = h("div", { class: "card secret center", style: { fontSize: "20px", userSelect: "all", minHeight: "64px", wordBreak: "break-all" } }, "…"), info = h("div", { class: "muted center small", style: { marginTop: "8px" } });
      const mode = h("select", { class: "input" }, [["password", "Random password"], ["passphrase", "Passphrase (random words)"], ["pin", "PIN (digits)"]].map(o => h("option", { value: o[0] }, o[1])));
      const len = h("input", { class: "input", type: "number", min: 4, max: 128, value: 20 }), words = h("input", { class: "input", type: "number", min: 3, max: 12, value: 5 });
      const sym = h("input", { type: "checkbox", checked: true }), amb = h("input", { type: "checkbox", checked: true });
      let current = "";
      const gen = async () => { const m = mode.value; const r = await POST("/api/passwords/generate", m === "passphrase" ? { mode: m, words: Number(words.value) } : m === "pin" ? { mode: m, length: Math.min(Number(len.value), 12) } : { mode: m, length: Number(len.value), symbols: sym.checked, avoid_ambiguous: amb.checked });
        current = r.password || r.passphrase || r.pin || ""; out.textContent = current; info.textContent = `${(r.strength || {}).label || ""} · ${Math.round(r.entropy_bits)} bits of randomness`; return "norefresh"; };
      mode.onchange = () => run(null, gen);
      root.appendChild(h("div", { class: "grid g2" }, card("Generator", h("div", null, out, info, h("div", { class: "row", style: { justifyContent: "center", marginTop: "14px" } }, btn("New one", gen, { kind: "primary", icon: "refresh" }), btn("Copy", () => { copyText(current); return "norefresh"; }, { icon: "copy" })))),
        card("Options", h("div", null, field("Kind", mode), field("Length (characters)", len), field("Words (passphrase)", words), h("label", { class: "check" }, sym, "Include symbols"), h("label", { class: "check" }, amb, "Avoid look-alike characters (0/O, 1/l)")))));
      run(null, gen);
      const pwIn = h("input", { class: "input", type: "password", placeholder: "Type a password to test it (it is not stored)" }), res = h("div", { style: { marginTop: "10px" } });
      root.appendChild(card("How strong is a password?", h("div", null, h("div", { class: "row", style: { flexWrap: "nowrap" } }, pwIn, btn("Check", async () => { const r = await POST("/api/passwords/check", { password: pwIn.value }); const s = r.strength || r;
        clear(res).appendChild(kv([["Strength", badge(s.label || "-", s.score >= 3 ? "ok" : s.score === 2 ? "medium" : "high")], ["Guessable in", ((s.crack_times || {}).offline_slow || {}).display || "-"], ["Advice", (s.suggestions || s.feedback || []).join(" ") || s.warning || "-"]])); return "norefresh"; }, {})), res)));
    }

    if (t.current === "tools") {
      root.appendChild(h("div", { class: "grid g2" },
        card("Import", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "Bring passwords from Chrome, Edge, Firefox, Bitwarden, LastPass, 1Password or KeePass (their CSV export)."),
          btn("Import a file…", async () => { const v = await formDialog("Import passwords", [{ name: "path", label: "Export file (.csv)", type: "path", pick: "file", required: true }, { name: "delete_source", label: "Securely delete the export file afterwards (recommended)", type: "checkbox", value: true }],
            { submit: "Import", onSubmit: f => POST("/api/passwords/import", { path: f.path, delete_source: f.delete_source }) }); if (v) toast(`${v.imported !== undefined ? v.imported : v.added || 0} item(s) imported, ${v.skipped || v.duplicates || 0} skipped`, "ok"); return v ? undefined : "norefresh"; }, { icon: "download" }))),
        card("Export / backup", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "An encrypted .chvault file can be opened on any PC with the backup password you choose."),
          btn("Export encrypted backup…", async () => { const v = await formDialog("Export the vault", [{ name: "path", label: "Save as", type: "path", pick: "save", required: true, placeholder: "C:\\Users\\You\\Documents\\vault.chvault" }, { name: "master", label: "Master password", type: "password", required: true }, { name: "export_password", label: "Backup password (for the file)", type: "password", required: true }],
            { submit: "Export", onSubmit: f => POST("/api/passwords/export", { format: "chvault", master_password: f.master, export_password: f.export_password, path: f.path, confirm: true }) }); if (v) toast("Vault exported", "ok"); return "norefresh"; }, { icon: "file" })))));
      root.appendChild(card("Master password & recovery", h("div", { class: "row" },
        btn("Change master password…", async () => { const v = await formDialog("Change master password", [{ name: "cur", label: "Current master password", type: "password", required: true }, { name: "new", label: "New master password", type: "password", required: true }, { name: "hint", label: "Hint (optional)" }], { onSubmit: f => POST("/api/passwords/master-password", { current_master_password: f.cur, new_master_password: f.new, hint: f.hint || null }) }); if (v) toast("Master password changed", "ok"); return "norefresh"; }, {}),
        btn("New recovery key…", async () => { const v = await formDialog("Create a new recovery key", [{ name: "master", label: "Master password", type: "password", required: true }], { submit: "Create", onSubmit: f => POST("/api/passwords/recovery-key", { master_password: f.master }) }); if (v && v.recovery_key) showOnce("Your new recovery key", v.recovery_key, "The old key no longer works."); return "norefresh"; }, {}))));
      root.appendChild(card("Vault facts", kv([["Items", `${st.total} (${Object.entries(st.counts || {}).map(([k, v]) => `${v} ${k}`).join(", ")})`], ["Encryption", "AES-256-GCM per item, key from " + ((st.kdf || {}).name || "scrypt")], ["Locks itself after", st.auto_lock_minutes + " min"], ["Created", dt(st.created_at)], ["Master password changed", ago(st.master_changed_at)]])));
    }
    return root;
  } });

/* ================================================================== Data protection */
async function waitDataJob(job, label) {
  toast(label + " started", "info", 2500);
  for (let i = 0; i < 600; i++) {
    await new Promise(r => setTimeout(r, 700));
    const j = await GET(`/api/data/jobs/${job.id}`, { quiet: true });
    if (!["queued", "running"].includes(j.status)) { if (j.status === "done") toast(label + " finished", "ok"); else toast(`${label}: ${j.status}${j.error ? " - " + j.error : ""}`, "error"); return j; }
  }
}
const encFields = (extra = []) => extra.concat([{ name: "mode", label: "Protect with", type: "select", value: "password", options: [["password", "A password (works on any PC)"], ["device", "This PC only (no password)"]] },
  { name: "password", label: "Password (for password mode)", type: "password" }, { name: "save_to_vault", label: "Save this password in my password vault", type: "checkbox", value: false }]);

page("data", { title: "Data protection", icon: "data", sub: "Encrypt, shred, clean and find sensitive files",
  subs: [["overview", "Overview"], ["encrypt", "Encrypt & decrypt"], ["shred", "File shredder"], ["cleaner", "Privacy cleaner"], ["finder", "Sensitive files"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "overview") {
      const [hl, st, jobs, sm] = await Promise.all([GET("/api/data/health"), GET("/api/data/status"), GET("/api/data/jobs?limit=12"), GET("/api/data/summary?days=30").catch(() => ({}))]);
      body.appendChild(h("div", { class: "grid g-main" }, h("section", { class: "card" }, h("div", { class: "hero" }, ring(hl.score, 150, { label: hl.grade }),
        h("div", { class: "grid g2", style: { gap: "14px 26px" } }, stat(num(hl.open_findings), "Sensitive files unprotected", null, hl.open_findings ? "var(--high)" : "var(--ok)"), stat(num(hl.encrypted_files), "Files encrypted"), stat(hl.junk_size || "0 B", "Junk that can be cleaned"), stat(hl.searched ? "Yes" : "Not yet", "Folders searched")))),
        card("Unprotected files by level", sevDonut(hl.by_severity, 120))));
      body.appendChild(h("div", { class: "grid g4" }, [["encrypt", "Encrypt files", "Lock files with AES-256 so only you can open them", "lock"], ["shred", "Shred files", "Overwrite and delete so they can't be recovered", "trash"], ["cleaner", "Clean up", "Temp files, caches, history and cookies", "bolt"], ["finder", "Find sensitive files", "Keys, password lists, card numbers, CNICs", "search"]]
        .map(([id, title, text, ic]) => h("section", { class: "card click", onclick: () => go("data", id) }, h("div", { class: "c-low", style: { width: "26px", marginBottom: "8px" } }, icon(ic)), h("div", { class: "bold" }, title), h("div", { class: "muted small" }, text)))));
      body.appendChild(tableCard("Recent jobs", [{ t: "Started", v: j => dt(j.created_at) }, { t: "Job", v: j => cap(j.kind) }, { t: "Result", v: j => badge(j.status, j.status === "done" ? "ok" : j.status === "failed" ? "critical" : "medium") },
        { t: "Progress", v: j => (j.progress || {}).percent !== undefined ? j.progress.percent + "%" : "" }, { t: "By", v: j => j.username }], (jobs.running || []).concat(jobs.history || []), { empty: "No jobs yet." }));
    }

    if (t.current === "encrypt") {
      const enc = await GET("/api/data/encrypted?limit=200");
      body.appendChild(card("Encrypt or decrypt", h("div", { class: "row" },
        btn("Encrypt files…", async () => { const v = await formDialog("Encrypt files", encFields([{ name: "paths", label: "Files or folders (one per line)", type: "textarea", required: true }]),
          { submit: "Encrypt", intro: "Each file becomes a .chx file. The original is securely deleted after the encrypted copy has been verified.", onSubmit: f => POST("/api/data/encrypt", { paths: lines(f.paths), mode: f.mode, password: f.password || null, save_to_vault: f.save_to_vault }) }); if (v) await waitDataJob(v, "Encryption"); return v ? undefined : "norefresh"; }, { kind: "primary", icon: "lock" }),
        btn("Decrypt files…", async () => { const v = await formDialog("Decrypt files", [{ name: "paths", label: ".chx files or folders (one per line)", type: "textarea", required: true }, { name: "password", label: "Password (not needed for 'this PC only' files)", type: "password" }, { name: "destination", label: "Put the files in (optional)", type: "path" }],
          { submit: "Decrypt", onSubmit: f => POST("/api/data/decrypt", { paths: lines(f.paths), password: f.password || null, destination: f.destination || null }) }); if (v) await waitDataJob(v, "Decryption"); return v ? undefined : "norefresh"; }, { icon: "key" }),
        btn("Check a .chx file…", async () => { const v = await formDialog("Check an encrypted file", [{ name: "path", label: ".chx file", type: "path", pick: "file", required: true }, { name: "password", label: "Password (optional)", type: "password" }], { submit: "Check", onSubmit: f => POST("/api/data/inspect", { path: f.path, password: f.password || null }) });
          if (v) detailDialog("Encrypted file", kv(Object.entries(v).filter(([, x]) => typeof x !== "object").map(([k, x]) => [cap(k), String(x)]))); return "norefresh"; }, { icon: "search" }))));
      body.appendChild(tableCard("Files encrypted by Cyber Hub", [{ t: "Encrypted", v: e => dt(e.created_at || e.encrypted_at) }, { t: "File", v: e => pathCell(e.path || e.encrypted_path) }, { t: "Original name", v: e => e.original_name || e.name }, { t: "Mode", v: e => e.mode === "device" ? "This PC only" : "Password" },
        { t: "Size", v: e => bytes(e.size || e.original_size), cls: "num" }, { t: "Still there", v: e => onoff(e.exists !== false && e.status !== "missing", "Yes", "No") }], enc.items, { total: enc.total, empty: "Nothing encrypted yet." }));
    }

    if (t.current === "shred") {
      const st = await GET("/api/data/status");
      body.appendChild(banner("medium", "Shredded files can't be brought back", st.shredder.home_media === "ssd" ? "On SSDs, overwriting can't guarantee every old copy is gone - for full-disk safety use BitLocker too." : "Each file is overwritten, renamed and then deleted."));
      body.appendChild(card("Shred files", h("div", { class: "row" }, btn("Choose what to shred…", async () => {
        const v = await formDialog("Shred files", [{ name: "paths", label: "Files or folders (one per line)", type: "textarea", required: true }, { name: "method", label: "Method", type: "select", value: st.shredder.method, options: Object.entries(st.shredder.methods) }], { submit: "Preview", onSubmit: f => POST("/api/data/shred/preview", { paths: lines(f.paths) }).then(p => ({ p, f })) });
        if (!v) return "norefresh";
        const p = v.p, n = p.files !== undefined ? p.files : (p.items || []).length;
        if (!(await confirmBox(`Shred ${num(n)} file(s)${p.size ? " (" + p.size + ")" : p.bytes ? " (" + bytes(p.bytes) + ")" : ""}? This cannot be undone.` + ((p.warnings || []).length ? "\n\n" + p.warnings.join("\n") : ""), "Shred for good", true))) return "norefresh";
        await waitDataJob(await POST("/api/data/shred", { paths: lines(v.f.paths), method: v.f.method, confirm: true }), "Shredding");
      }, { kind: "danger", icon: "trash" }), h("span", { class: "muted small" }, "Default method: " + (st.shredder.methods[st.shredder.method] || st.shredder.method)))));
    }

    if (t.current === "cleaner") {
      const rep = await GET("/api/data/cleaner/report");
      const picked = new Set(JSON.parse(sessionStorage.getItem("dp_clean") || '["temp"]'));
      const save = () => sessionStorage.setItem("dp_clean", JSON.stringify([...picked]));
      body.appendChild(card("Privacy cleaner", h("div", { class: "spread" }, h("div", null, h("div", { class: "bold" }, rep.ts ? `${rep.total_size} in ${num(rep.total_files)} file(s) can be cleaned` : "See what can be cleaned"), h("div", { class: "muted small" }, rep.ts ? "Analysed " + ago(rep.ts) : rep.note || "")),
        h("div", { class: "row" }, btn("Analyse", async () => { await waitDataJob(await POST("/api/data/cleaner/analyze", {}), "Analysis"); }, { icon: "search" }),
          btn("Clean selected", async () => { if (!picked.size) throw new Error("Tick at least one category first");
            let job; try { job = await POST("/api/data/cleaner/clean", { categories: [...picked] }); } catch (e) { if (e.status !== 428) throw e; if (!(await confirmBox(e.message, "Clean anyway", true))) return "norefresh"; job = await POST("/api/data/cleaner/clean", { categories: [...picked], confirm: true }); }
            await waitDataJob(job, "Cleaning"); }, { kind: "primary", icon: "bolt" })))));
      body.appendChild(tableCard("What can be cleaned", [{ t: "", v: c => h("input", { type: "checkbox", checked: picked.has(c.id), disabled: c.browser_running, onchange: e => { e.target.checked ? picked.add(c.id) : picked.delete(c.id); save(); } }) },
        { t: "Category", v: c => h("div", null, h("b", null, c.label), h("div", { class: "muted small" }, c.description), c.warning ? h("div", { class: "small c-medium" }, c.warning) : null, c.browser_running ? h("div", { class: "small c-medium" }, "Close the browser first") : null) },
        { t: "Group", v: c => cap(c.group) }, { t: "Files", v: c => num(c.files), cls: "num" }, { t: "Size", v: c => bytes(c.bytes), cls: "num" }], rep.categories, { empty: "Press Analyse to see what can be cleaned.", height: "none" }));
    }

    if (t.current === "finder") {
      const f = await GET("/api/data/finder/findings?limit=200");
      const ls = f.last_search;
      body.appendChild(card("Sensitive-file search", h("div", { class: "spread" }, h("div", null, h("div", { class: "bold" }, ls ? `Last search ${ago(ls.ts)}: ${num(ls.stats.checked)} files checked, ${ls.stats.with_findings} with sensitive data` : "Your folders have not been searched yet"),
        h("div", { class: "muted small" }, "Looks in Documents, Desktop and Downloads for private keys, password lists, API keys, card numbers, CNICs and IBANs. Only masked samples are kept.")),
        btn("Search now", async () => { await waitDataJob(await POST("/api/data/finder/scan", {}), "Search"); }, { kind: "primary", icon: "search" }))));
      body.appendChild(tableCard("Files with sensitive data", [{ t: "Level", v: x => badge(x.severity) }, { t: "File", v: x => h("div", null, h("b", null, x.name), h("div", { class: "path" }, x.folder)) },
        { t: "Contains", v: x => h("div", null, (x.types || []).map(ty => h("div", { class: "small" }, h("b", null, ty.label), ` × ${ty.count}`, h("span", { class: "muted" }, " " + (ty.samples || []).slice(0, 1).join("")))) ) }, { t: "Status", v: x => badge(x.status, x.status === "open" ? "medium" : "ok") },
        { t: "", v: x => x.status !== "open" ? (x.status === "ignored" ? btn("Stop ignoring", () => POST(`/api/data/finder/findings/${x.id}/unignore`), { sm: true }) : "") : h("div", { class: "row tight", style: { flexWrap: "nowrap" } },
          btn("Encrypt", async () => { const v = await formDialog("Encrypt " + x.name, encFields(), { submit: "Encrypt", onSubmit: fm => POST(`/api/data/finder/findings/${x.id}/encrypt`, { mode: fm.mode, password: fm.password || null, save_to_vault: fm.save_to_vault }) }); if (v && v.id) await waitDataJob(v, "Encryption"); return v ? undefined : "norefresh"; }, { sm: true, kind: "primary" }),
          btn("Shred", async () => { const j = await POST(`/api/data/finder/findings/${x.id}/shred`, { confirm: true }); if (j && j.id) await waitDataJob(j, "Shredding"); }, { sm: true, kind: "danger", confirm: `Shred ${x.name}? It can't be brought back.`, confirmLabel: "Shred" }),
          btn("Ignore", () => POST(`/api/data/finder/findings/${x.id}/ignore`, {}), { sm: true, kind: "ghost" })) }], f.items, { total: f.total, empty: "No sensitive files found (or not searched yet).", height: "none" }));
    }
    return root;
  } });

/* ================================================================== Accounts & platforms */
const TWO_FA = { done: ["On", "ok"], not_done: ["Off", "critical"], unknown: ["Not confirmed", "medium"], none_offered: ["Not offered", "off"], not_applicable: ["n/a", "off"] };
async function accountDialog(id) {
  const a = (await GET(`/api/platforms/accounts/${id}`)).account, info = a.platform_info || {};
  const state = {};
  const row = c => { const sel = h("select", { class: "input", style: { width: "150px" }, onchange: e => { state[c.id] = e.target.value; } }, [["unknown", "Not checked"], ["done", "Done"], ["not_done", "Not done"], ["not_applicable", "Doesn't apply"]].map(o => h("option", { value: o[0], selected: c.status === o[0] }, o[1])));
    if (c.source && c.source !== "user") sel.disabled = true;
    return h("div", { class: "setting" }, h("div", null, h("div", { class: "t" }, c.label, c.stale ? h("span", { class: "c-medium small" }, "  (check again)") : null), h("div", { class: "d" }, c.help, c.source && c.source !== "user" ? ` · confirmed by ${c.source}` : "")), h("div", { class: "ctl" }, sel)); };
  const m = detailDialog(a.name + (a.label ? " - " + a.label : ""), h("div", null,
    h("div", { class: "row", style: { marginBottom: "10px" } }, ring(a.score, 64), h("div", null, h("div", null, badge(a.importance + " importance", a.importance === "critical" ? "high" : "low"), " ", badge("2FA: " + (TWO_FA[a.two_factor] || [a.two_factor])[0], (TWO_FA[a.two_factor] || [, "info"])[1])),
      h("div", { class: "muted small", style: { marginTop: "4px" } }, "Where to change these: ", a.where || info.where || "the site's security settings", a.security_url ? h("span", null, " · ", h("a", { href: a.security_url, target: "_blank", rel: "noopener" }, "open security page")) : null))),
    (a.issues || []).map(i => h("div", { class: "row", style: { marginBottom: "4px" } }, badge(i.severity), i.text)),
    h("h3", { style: { margin: "16px 0 2px" } }, "Security checklist"), h("div", null, (a.checklist || []).map(row)),
    (info.tips || []).length ? h("div", null, h("h3", { style: { margin: "16px 0 4px" } }, "Tips"), h("ul", { class: "muted", style: { margin: 0 } }, info.tips.map(x => h("li", null, x)))) : null),
    [btn("Mark as reviewed", async () => { await POST(`/api/platforms/accounts/${id}/reviewed`); m.close(); }, { ok: "Reviewed" }),
     btn("Save checklist", async () => { if (Object.keys(state).length) await PUT(`/api/platforms/accounts/${id}/checklist`, { items: state }); m.close(); }, { kind: "primary", ok: "Saved" })]);
}
page("platforms", { title: "Accounts & platforms", nav: "Accounts & platforms", icon: "users", sub: "How well your online accounts are protected",
  subs: [["accounts", "My accounts"], ["breaches", "Breach monitoring"], ["links", "Link & sender check"], ["extensions", "Browser & editor extensions"], ["alerts", "Alerts"]],
  async render() {
    const t = tabs(this.subs.map(([id, label]) => ({ id, label })));
    const root = h("div", null, t.bar), body = h("div", { class: "stack" });
    root.appendChild(body);

    if (t.current === "accounts") {
      const [lst, cat] = await Promise.all([GET("/api/platforms/accounts"), GET("/api/platforms/catalog")]);
      const o = lst.overview || {}, tf = o.two_fa || {};
      if (lst.total) body.appendChild(h("div", { class: "grid g-main" }, h("section", { class: "card" }, h("div", { class: "hero" }, ring(o.score, 150, { label: o.grade }),
        h("div", { class: "grid g2", style: { gap: "14px 26px" } }, stat(num(o.accounts), "Accounts"), stat((o.two_fa_coverage || 0) + "%", "Have two-step verification"), stat(num(o.critical_without_2fa), "Key accounts without 2FA", null, o.critical_without_2fa ? "var(--critical)" : "var(--ok)"), stat(num(Object.values(o.issues || {}).reduce((a, b) => a + b, 0)), "Open issues")))),
        card("Two-step verification", donut([{ label: "On", value: tf.done, color: "var(--ok)" }, { label: "Off", value: tf.not_done, color: "var(--critical)" }, { label: "Not confirmed", value: tf.unknown, color: "var(--medium)" }, { label: "Not offered", value: tf.none_offered, color: "var(--dim)" }], 120))));
      const addAccount = async () => { const groups = {}; cat.platforms.forEach(p => { (groups[p.category_label] = groups[p.category_label] || []).push(p); });
        const v = await formDialog("Add an account", [{ name: "platform", label: "Platform", type: "select", options: cat.platforms.map(p => [p.key, `${p.name}  (${p.category_label})`]).concat([["custom", "Another website…"]]) }, { name: "custom_name", label: "Name (only for another website)" }, { name: "custom_domain", label: "Website (only for another website)", placeholder: "example.com" },
          { name: "handle", label: "User name / handle (optional)" }, { name: "email", label: "E-mail used to sign in (optional)", hint: "Stored encrypted; used to link recovery accounts and for breach monitoring." }],
          { submit: "Add", onSubmit: f => POST("/api/platforms/accounts", { platform: f.platform, handle: f.handle || null, email: f.email || null, custom_name: f.custom_name || null, custom_domain: f.custom_domain || null }) }); return v ? undefined : "norefresh"; };
      body.appendChild(tableCard("My accounts", [{ t: "Account", v: a => h("div", null, h("b", null, a.name), h("div", { class: "dim small" }, a.handle || a.email || a.category_label)) }, { t: "Score", v: a => h("b", { style: { color: scoreColor(a.score) } }, a.score === null ? "–" : a.score), cls: "num" },
        { t: "2FA", v: a => badge((TWO_FA[a.two_factor] || [a.two_factor])[0], (TWO_FA[a.two_factor] || [, "info"])[1]) }, { t: "Importance", v: a => cap(a.importance) },
        { t: "Issues", v: a => (a.issues || []).length ? h("div", null, a.issues.slice(0, 2).map(i => h("div", { class: "small" }, h("i", { class: "dot c-" + i.severity }), " ", i.text))) : h("span", { class: "c-ok" }, "None") },
        { t: "Checklist", v: a => `${a.checklist_done}/${a.checklist_total}` }, { t: "", v: a => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, btn("Review", async () => { await accountDialog(a.id); return "norefresh"; }, { sm: true, kind: "primary" }),
          btn("Remove", () => DEL(`/api/platforms/accounts/${a.id}`), { sm: true, kind: "danger", confirm: `Remove ${a.name} from Cyber Hub? (The real account is not touched.)` })) }],
        lst.items, { total: lst.total, onRow: a => run(null, async () => { await accountDialog(a.id); return "norefresh"; }), empty: "Add the accounts you use - Google, Facebook, WhatsApp, GitHub, your bank - to see how well each is protected.",
          actions: [btn("Find my accounts", async () => { const r = await POST("/api/platforms/discover", { create: true }); toast(`${(r.created || []).length || r.added || 0} account(s) added from your vault and running apps`, "ok"); }, { sm: true, icon: "search" }), btn("Add account", addAccount, { sm: true, kind: "primary", icon: "plus" })] }));
      const g = await GET("/api/platforms/recovery-graph");
      if (g.edges.length) body.appendChild(card("What can reset what", h("div", { class: "list" }, g.hubs.concat(g.weak_hubs.filter(w => !g.hubs.find(x => x.id === w.id))).slice(0, 6).map(hb => h("div", { class: "item" }, h("span", { class: "c-low" }, icon("key")), h("div", null, h("div", { class: "t" }, hb.name), h("div", { class: "d" }, `Can reset ${hb.can_reset} other account(s)` + (hb.two_factor !== "done" ? " - and has no confirmed 2FA" : "")))))) ));
    }

    if (t.current === "breaches") {
      const [em, br, st] = await Promise.all([GET("/api/platforms/emails"), GET("/api/platforms/breaches?limit=40"), GET("/api/platforms/status")]);
      body.appendChild(tableCard("My e-mail addresses", [{ t: "Address", v: e => h("b", null, e.masked) }, { t: "In breaches", v: e => e.breach_count ? h("b", { class: "c-critical" }, e.breach_count) : h("span", { class: "c-ok" }, "0"), cls: "num" },
        { t: "Checked", v: e => e.last_checked_at ? ago(e.last_checked_at) : "Never" }, { t: "Used for", v: e => (e.accounts || []).map(a => a.name).join(", ") },
        { t: "Watch", v: e => toggle(e.monitor, on => PATCH(`/api/platforms/emails/${e.id}`, { monitor: on })) },
        { t: "", v: e => h("div", { class: "row tight", style: { flexWrap: "nowrap" } }, e.breach_count ? btn("Details", async () => { const d = await GET(`/api/platforms/emails/${e.id}`); const item = d.email || d;
          detailDialog("Breaches of " + item.masked, table([{ t: "Site", v: b => h("b", null, b.title || b.name) }, { t: "When", v: b => b.breach_date || b.date }, { t: "Leaked", v: b => h("span", { class: "muted small" }, (b.data_classes || []).join(", ")) }, { t: "What to do", v: b => h("span", { class: "small" }, b.advice || "Change that password and turn on 2FA") }], item.breaches || [], {})); return "norefresh"; }, { sm: true }) : null,
          btn("Remove", () => DEL(`/api/platforms/emails/${e.id}`), { sm: true, kind: "danger" })) }], em.items,
        { empty: "Add an e-mail address to find out whether it appears in known data breaches.", actions: [
          btn("Add address", async () => { const v = await formDialog("Watch an e-mail address", [{ name: "email", label: "E-mail address", required: true }], { intro: "The address is stored encrypted. It is only sent to the breach service when you press Check.", submit: "Add", onSubmit: f => POST("/api/platforms/emails", { email: f.email }) }); return v ? undefined : "norefresh"; }, { sm: true, icon: "plus" }),
          isAdmin() ? btn("Check now", async () => { const r = await POST("/api/platforms/emails/check", {}); toast(r.message || "Checking your addresses in the background", "ok"); }, { sm: true, kind: "primary", title: st.settings.platform_breach_check === "off" ? "Turn on breach checks in Settings first" : null }) : null] }));
      body.appendChild(tableCard("Recently breached sites", [{ t: "Site", v: b => h("b", null, b.title || b.name) }, { t: "Domain", v: b => b.domain }, { t: "Breach date", v: b => b.breach_date }, { t: "Accounts", v: b => num(b.pwn_count), cls: "num" },
        { t: "Leaked data", v: b => h("span", { class: "muted small" }, (b.data_classes || []).slice(0, 5).join(", ")) }, { t: "You use it", v: b => b.yours || b.used ? badge("yes", "high") : "" }], br.items,
        { total: br.total, empty: "The public breach list has not been downloaded yet.", actions: [btn("Update list", () => POST("/api/platforms/breaches/refresh?force=true"), { sm: true, ok: r => r.error ? "Could not download: " + r.error : `${num(r.breaches || 0)} breaches known` })] }));
      if (br.attribution) body.appendChild(h("div", { class: "dim small" }, br.attribution.text));
    }

    if (t.current === "links") {
      const input = h("input", { class: "input", placeholder: "Paste a link or a sender's e-mail address, e.g. https://paypa1-login.com/verify" }), out = h("div");
      const check = async () => { const r = await POST("/api/platforms/check-link", { value: input.value.trim() });
        const verdict = r.verdict || "unknown", bad = ["malicious", "suspicious"].includes(verdict), good = r.official === true || verdict === "clean";
        const pname = x => (x && (x.name || x.key)) || x || null;
        clear(out).appendChild(h("div", { class: "stack", style: { marginTop: "14px" } }, banner(bad ? "critical" : good ? "ok" : "medium", cap(verdict) + (r.summary ? " - " + r.summary : ""), (Array.isArray(r.advice) ? r.advice : [r.advice]).filter(Boolean).join(" ")),
          kv([["Address", r.host || r.value], ["Says it is", pname(r.claimed_platform) || "-"], ["Really belongs to", pname(r.owner_platform) || "No known platform"], ["Official address", r.official === null || r.official === undefined ? "-" : r.official ? "Yes" : "No"], ["Risk score", r.score !== undefined ? r.score + " / 100" : "-"], ["On threat lists", r.feed_matches ? r.feed_matches + " match(es)" : "No"]]),
          (r.reasons || []).length ? h("ul", { class: "muted" }, r.reasons.map(x => h("li", null, typeof x === "string" ? x : x.text || x.title || ""))) : null)); return "norefresh"; };
      input.addEventListener("keydown", e => { if (e.key === "Enter") run(null, check); });
      body.appendChild(card("Is this link or sender real?", h("div", null, h("p", { class: "muted", style: { marginTop: 0 } }, "Got a message that says it's from your bank, Google or a courier? Paste the link or the sender's address before you click."),
        h("div", { class: "row", style: { flexWrap: "nowrap" } }, input, btn("Check", check, { kind: "primary", icon: "search" })), out)));
    }

    if (t.current === "extensions") {
      const ex = await GET("/api/platforms/extensions");
      body.appendChild(h("div", { class: "grid g4" }, statCard(num(ex.total), "Extensions installed"), statCard(num(ex.by_level.high), "High risk", null, ex.by_level.high ? "var(--critical)" : "var(--ok)"), statCard(num(ex.by_level.medium), "Medium risk"), statCard(num(ex.all_sites), "Can read every website")));
      body.appendChild(tableCard("Browser and editor extensions", [{ t: "Extension", v: e => h("div", null, h("b", null, e.name), h("div", { class: "dim small" }, e.app_label || e.app || e.browser)) }, { t: "Risk", v: e => badge(e.level === "none" ? "low risk" : e.level, e.level === "none" ? "ok" : e.level) },
        { t: "Score", v: e => e.risk, cls: "num" }, { t: "From", v: e => cap(e.source || e.install_type || "") }, { t: "Why", v: e => h("span", { class: "muted small" }, (e.reasons || []).slice(0, 3).join("; ")) }, { t: "Version", v: e => e.version }],
        ex.items, { empty: "No browser or editor extensions were found for this Windows user.", actions: [btn("Look again", () => GET("/api/platforms/extensions?refresh=true"), { sm: true, icon: "refresh" })] }));
    }

    if (t.current === "alerts") {
      const ev = await GET("/api/platforms/events?limit=100");
      body.appendChild(eventsCard("Account alerts", "/api/platforms", ev.items));
    }
    return root;
  } });

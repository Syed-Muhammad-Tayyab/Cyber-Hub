// ============================================================
//  Cyber Hub - Frontend API bridge (Parts 1-16)
//  Developed by Syed Muhammad Tayyab
//
//  Drop this file into your UI and include it before your app script:
//      <script src="cyberhub-api.js"></script>
//  Then use window.CyberHub.* from any page. Every later part adds
//  its functions to this same object.
// ============================================================
(function () {
  const BASE = window.CYBERHUB_BASE || (location.port === "8765" ? "" : "http://127.0.0.1:8765");
  let token = null;
  const SKEY = "cyberhub.session";
  let session = null;
  try { session = sessionStorage.getItem(SKEY); } catch (e) {}
  function setSession(t) {
    session = t;
    try { t ? sessionStorage.setItem(SKEY, t) : sessionStorage.removeItem(SKEY); } catch (e) {}
  }
  // UI can listen:  window.addEventListener("cyberhub:locked", showLockScreen)
  //                 window.addEventListener("cyberhub:signedout", showLoginScreen)
  const emit = name => window.dispatchEvent(new CustomEvent(name));

  async function boot() {
    if (token) return token;
    const r = await fetch(BASE + "/api/bootstrap");
    if (!r.ok) throw new Error("Cyber Hub engine refused bootstrap (" + r.status + ")");
    token = (await r.json()).token;
    return token;
  }

  async function api(path, { method = "GET", body } = {}) {
    await boot();
    const r = await fetch(BASE + path, {
      method,
      headers: {
        "X-CyberHub-Token": token,
        ...(session ? { "X-CyberHub-Session": session } : {}),
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    if (r.status === 423 && /Session is locked/.test(data.detail || "")) emit("cyberhub:locked");
    if (r.status === 423 && /Password vault is locked/.test(data.detail || "")) emit("cyberhub:vaultlocked");
    if (r.status === 401 && session && /Session|signed in/i.test(data.detail || "")) { setSession(null); emit("cyberhub:signedout"); }
    if (!r.ok) { const e = new Error(data.detail || ("HTTP " + r.status)); e.status = r.status; throw e; }
    return data;
  }

  window.CyberHub = {
    // ---- core
    health: () => fetch(BASE + "/api/health").then(r => r.json()),
    isOnline: () => fetch(BASE + "/api/health").then(r => r.ok).catch(() => false),
    info: () => api("/api/info"),

    // ---- system (dashboard rings, gauges, device card, history charts)
    deviceInfo: () => api("/api/system/info"),
    liveStats: () => api("/api/system/stats"),
    history: (hours = 24) => api("/api/system/history?hours=" + hours),
    snapshot: () => api("/api/system/snapshot", { method: "POST" }),

    /** Live stream: CyberHub.streamStats(stats => updateRings(stats)); returns a stop() function */
    streamStats(onData, onClose) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(wsBase + "/api/system/stream?token=" + encodeURIComponent(t));
        ws.onmessage = e => onData(JSON.parse(e.data));
        ws.onclose = () => { if (!stopped && onClose) onClose(); };
      });
      return () => { stopped = true; ws && ws.close(); };
    },

    // ---- activity log (recent activity list, timeline + donut charts)
    activity: (opts = {}) => api("/api/activity?" + new URLSearchParams(opts)),
    activitySummary: (days = 7) => api("/api/activity/summary?days=" + days),
    logActivity: (category, title, detail, severity = "info") =>
      api("/api/activity", { method: "POST", body: { category, title, detail, severity } }),
    clearActivity: () => api("/api/activity", { method: "DELETE" }),

    // ---- settings page
    getSettings: () => api("/api/settings"),
    updateSettings: changes => api("/api/settings", { method: "PATCH", body: changes }),
    resetSettings: () => api("/api/settings/reset", { method: "POST" }),

    // ---- Part 2: account & login
    isSignedIn: () => !!session,
    accountStatus: () => api("/api/account/status"),            // {setup_required}
    async setup(username, password, display_name = "", email = null) {
      const j = await api("/api/account/setup", { method: "POST", body: { username, password, display_name, email } });
      setSession(j.session_token); return j;
    },
    async login(username, password) {
      const j = await api("/api/account/login", { method: "POST", body: { username, password } });
      setSession(j.session_token); return j;
    },
    async loginWithPin(username, pin) {
      const j = await api("/api/account/login", { method: "POST", body: { username, pin } });
      setSession(j.session_token); return j;
    },
    async logout() { try { await api("/api/account/logout", { method: "POST" }); } finally { setSession(null); } },
    me: () => api("/api/account/me"),
    updateProfile: (changes) => api("/api/account/me", { method: "PATCH", body: changes }),
    passwordStrength: (password, username) => api("/api/account/password-strength", { method: "POST", body: { password, username } }),
    changePassword: (current_password, new_password) =>
      api("/api/account/change-password", { method: "POST", body: { current_password, new_password } }),
    lock: () => api("/api/account/lock", { method: "POST" }),
    unlockWithPin: (pin) => api("/api/account/unlock", { method: "POST", body: { pin } }),
    unlockWithPassword: (password) => api("/api/account/unlock", { method: "POST", body: { password } }),
    setPin: (password, pin) => api("/api/account/pin", { method: "PUT", body: { password, pin } }),
    removePin: () => api("/api/account/pin", { method: "DELETE" }),
    generateRecoveryCodes: (password) => api("/api/account/recovery-codes", { method: "POST", body: { password } }),
    recoveryStatus: () => api("/api/account/recovery-codes"),
    async recover(username, recovery_code, new_password) {
      const j = await api("/api/account/recover", { method: "POST", body: { username, recovery_code, new_password } });
      setSession(j.session_token); return j;
    },
    sessions: () => api("/api/account/sessions"),
    revokeSession: (id) => api("/api/account/sessions/" + id, { method: "DELETE" }),
    loginHistory: (limit = 50) => api("/api/account/login-history?limit=" + limit),
    deleteAccount: async (password) => { const j = await api("/api/account/delete", { method: "POST", body: { password } }); setSession(null); return j; },
    listUsers: () => api("/api/account/users"),
    addUser: (u) => api("/api/account/users", { method: "POST", body: u }),
    removeUser: (id) => api("/api/account/users/" + id, { method: "DELETE" }),

    // ---- Part 3: live system monitor (needs a signed-in session)
    monitorOverview: (top = 5) => api("/api/monitor/overview?top=" + top),
    monitorCpu: () => api("/api/monitor/cpu"),
    monitorMemory: () => api("/api/monitor/memory"),
    monitorDisks: () => api("/api/monitor/disks"),
    monitorNetwork: () => api("/api/monitor/network"),
    gpu: () => api("/api/monitor/gpu"),
    temperatures: () => api("/api/monitor/temperatures"),
    topProcesses: (by = "cpu", limit = 10) => api(`/api/monitor/top?by=${by}&limit=${limit}`),
    monitorHistory: (hours = 24, bucketMinutes) =>
      api("/api/monitor/history?hours=" + hours + (bucketMinutes ? "&bucket_minutes=" + bucketMinutes : "")),
    getThresholds: () => api("/api/monitor/thresholds"),
    setThresholds: (changes) => api("/api/monitor/thresholds", { method: "PUT", body: changes }),
    monitorAlerts: (status = "all", limit = 50) => api(`/api/monitor/alerts?status=${status}&limit=${limit}`),
    alertsSummary: (days = 7) => api("/api/monitor/alerts/summary?days=" + days),
    checkAlerts: () => api("/api/monitor/alerts/check", { method: "POST" }),
    ackAlert: (id) => api("/api/monitor/alerts/" + id + "/ack", { method: "POST" }),
    ackAllAlerts: () => api("/api/monitor/alerts/ack-all", { method: "POST" }),
    clearResolvedAlerts: () => api("/api/monitor/alerts", { method: "DELETE" }),

    // ---- Part 4: processes & startup (reads: any signed-in user; changes: admin)
    // ct = the create_time from the list row: protects against Windows reusing a PID.
    processes: ({ search, sort = "cpu", order = "desc", limit = 200, offset = 0, flaggedOnly = false, signatures = false } = {}) =>
      api("/api/processes?" + new URLSearchParams({ sort, order, limit, offset, flagged_only: flaggedOnly, signatures,
                                                   ...(search ? { search } : {}) })),
    processTree: () => api("/api/processes/tree"),
    processSummary: () => api("/api/processes/summary"),
    processDetails: (pid, withHash = false) => api(`/api/processes/${pid}?hash=${withHash}`),
    endProcess: (pid, { ct, tree = false, force = false } = {}) =>
      api(`/api/processes/${pid}/end`, { method: "POST", body: { create_time: ct ?? null, tree, force } }),
    suspendProcess: (pid, ct) => api(`/api/processes/${pid}/suspend`, { method: "POST", body: { create_time: ct ?? null } }),
    resumeProcess: (pid, ct) => api(`/api/processes/${pid}/resume`, { method: "POST", body: { create_time: ct ?? null } }),
    setProcessPriority: (pid, priority, ct) =>        // idle | below_normal | normal | above_normal | high
      api(`/api/processes/${pid}/priority`, { method: "PUT", body: { priority, create_time: ct ?? null } }),
    processActions: (limit = 50) => api("/api/processes/actions?limit=" + limit),

    startupItems: ({ source, state = "all", flaggedOnly = false, search, services = true, microsoftTasks = false,
                     manualServices = false, refresh = false } = {}) =>
      api("/api/startup?" + new URLSearchParams({ state, flagged_only: flaggedOnly, services, microsoft_tasks: microsoftTasks,
                                                 manual_services: manualServices, refresh,
                                                 ...(source ? { source } : {}), ...(search ? { search } : {}) })),
    startupSummary: () => api("/api/startup/summary"),
    startupSources: () => api("/api/startup/sources"),
    startupItem: (id) => api("/api/startup/" + id),
    enableStartup: (id) => api(`/api/startup/${id}/enable`, { method: "POST" }),
    disableStartup: (id) => api(`/api/startup/${id}/disable`, { method: "POST" }),
    acceptStartup: (id) => api(`/api/startup/${id}/accept`, { method: "POST" }),
    acceptAllStartup: () => api("/api/startup/accept-all", { method: "POST" }),
    startupChanges: (limit = 50) => api("/api/startup/changes?limit=" + limit),
    checkStartupNow: () => api("/api/startup/watch/check", { method: "POST" }),

    // ---- Part 5: antivirus scan engine (scanning: any signed-in user; signatures/exclusions/dismiss: admin)
    scanSummary: (days = 14) => api("/api/scan/summary?days=" + days),
    scanLocations: () => api("/api/scan/locations"),
    scanSelfTest: () => api("/api/scan/self-test", { method: "POST" }),
    quickScan: () => api("/api/scan/quick", { method: "POST" }),
    fullScan: () => api("/api/scan/full", { method: "POST" }),
    customScan: (paths) => api("/api/scan/custom", { method: "POST", body: { paths: [].concat(paths) } }),
    scanJobs: (limit = 20, kind) => api("/api/scan/jobs?limit=" + limit + (kind ? "&kind=" + kind : "")),
    activeScans: () => api("/api/scan/jobs/active"),
    scanJob: (id) => api("/api/scan/jobs/" + id),
    scanJobDetections: (id) => api(`/api/scan/jobs/${id}/detections`),
    pauseScan: (id) => api(`/api/scan/jobs/${id}/pause`, { method: "POST" }),
    resumeScan: (id) => api(`/api/scan/jobs/${id}/resume`, { method: "POST" }),
    cancelScan: (id) => api(`/api/scan/jobs/${id}/cancel`, { method: "POST" }),
    deleteScanJob: (id) => api("/api/scan/jobs/" + id, { method: "DELETE" }),
    scanFile: (path) => api("/api/scan/file", { method: "POST", body: { path } }),
    lookupHash: (hash) => api("/api/scan/lookup", { method: "POST", body: { hash } }),
    detections: (status = "active", limit = 100, offset = 0) =>
      api(`/api/scan/detections?status=${status}&limit=${limit}&offset=${offset}`),
    dismissDetection: (id) => api(`/api/scan/detections/${id}/dismiss`, { method: "POST" }),
    signatures: ({ search, source, limit = 100, offset = 0 } = {}) =>
      api("/api/scan/signatures?" + new URLSearchParams({ limit, offset, ...(search ? { search } : {}), ...(source ? { source } : {}) })),
    signatureStats: () => api("/api/scan/signatures/stats"),
    addSignature: (hash, name, severity = "high", family = null) =>
      api("/api/scan/signatures", { method: "POST", body: { hash, name, severity, family } }),
    importSignaturesText: (text, { severity = "high", label } = {}) =>
      api("/api/scan/signatures/import", { method: "POST", body: { text, severity, label } }),
    importSignaturesFile: (path, { severity = "high", label } = {}) =>      // .txt / .csv / MalwareBazaar .zip on this PC
      api("/api/scan/signatures/import", { method: "POST", body: { path, severity, label } }),
    setSignatureEnabled: (hash, enabled) => api("/api/scan/signatures/" + hash, { method: "PATCH", body: { enabled } }),
    deleteSignature: (hash) => api("/api/scan/signatures/" + hash, { method: "DELETE" }),
    deleteSignatureSource: (source) => api("/api/scan/signatures?source=" + encodeURIComponent(source), { method: "DELETE" }),
    getScanExclusions: () => api("/api/scan/exclusions"),
    setScanExclusions: (paths = [], extensions = []) => api("/api/scan/exclusions", { method: "PUT", body: { paths, extensions } }),
    clearScanCache: () => api("/api/scan/cache", { method: "DELETE" }),

    // ---- Part 6: quarantine & threat history
    // any signed-in user: quarantine / remove / delete / verify / rescan;  admin: restore, allow, dismiss, purge, clear
    threatSummary: (days = 30) => api("/api/threats/summary?days=" + days),
    threats: ({ status = "history", severity, search, days, limit = 100, offset = 0 } = {}) =>   // status: history|all|active|quarantined|restored|removed|allowed|dismissed|resolved
      api("/api/threats?" + new URLSearchParams({ status, limit, offset, ...(severity ? { severity } : {}),
                                                 ...(search ? { search } : {}), ...(days ? { days } : {}) })),
    threat: (id) => api("/api/threats/" + id),                         // + timeline events, quarantine item, actions[]
    quarantineThreat: (id, { killProcesses = null, force = false } = {}) =>
      api(`/api/threats/${id}/quarantine`, { method: "POST", body: { kill_processes: killProcesses, force } }),
    removeThreat: (id) => api(`/api/threats/${id}/remove`, { method: "POST" }),
    allowThreat: (id, note = null) => api(`/api/threats/${id}/allow`, { method: "POST", body: { note } }),
    dismissThreat: (id) => api(`/api/threats/${id}/dismiss`, { method: "POST" }),
    /** "Start actions": action = quarantine | remove | allow | dismiss; ids omitted = every active threat */
    threatActions: (action, ids = null) => api("/api/threats/actions", { method: "POST", body: { action, ...(ids ? { ids } : {}) } }),
    clearThreatHistory: (olderThanDays = 0) => api("/api/threats/history?older_than_days=" + olderThanDays, { method: "DELETE" }),
    async downloadThreatCsv(filters = {}) {                            // saves cyberhub-threat-history.csv
      await boot();
      const r = await fetch(BASE + "/api/threats/export.csv?" + new URLSearchParams(filters),
                            { headers: { "X-CyberHub-Token": token, ...(session ? { "X-CyberHub-Session": session } : {}) } });
      if (!r.ok) throw new Error("Export failed (" + r.status + ")");
      const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(await r.blob()),
                                                              download: "cyberhub-threat-history.csv" });
      a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    },
    allowedThreats: () => api("/api/threats/allowed"),
    addAllowedHash: (sha256, note = null) => api("/api/threats/allowed", { method: "POST", body: { sha256, note } }),
    addAllowedThreatName: (threat_name, note = null) => api("/api/threats/allowed", { method: "POST", body: { threat_name, note } }),
    removeAllowed: (id) => api("/api/threats/allowed/" + id, { method: "DELETE" }),

    quarantine: ({ status = "quarantined", search, limit = 100, offset = 0 } = {}) =>
      api("/api/quarantine?" + new URLSearchParams({ status, limit, offset, ...(search ? { search } : {}) })),
    quarantineStats: () => api("/api/quarantine/stats"),
    quarantineItem: (id) => api("/api/quarantine/" + id),
    quarantineFile: (path, { threatName = null, note = null, killProcesses = null, force = false } = {}) =>
      api("/api/quarantine", { method: "POST", body: { path, threat_name: threatName, note, kill_processes: killProcesses, force } }),
    /** conflict: rename | overwrite | fail;  allow: true = add to allowed threats so scans stop reporting it */
    restoreQuarantined: (id, { destination = null, conflict = "rename", allow = false } = {}) =>
      api(`/api/quarantine/${id}/restore`, { method: "POST", body: { destination, conflict, allow } }),
    deleteQuarantined: (id) => api("/api/quarantine/" + id, { method: "DELETE" }),
    verifyQuarantined: (id) => api(`/api/quarantine/${id}/verify`, { method: "POST" }),
    rescanQuarantined: (id) => api(`/api/quarantine/${id}/rescan`, { method: "POST" }),
    purgeQuarantine: (olderThanDays = null) => api("/api/quarantine/purge", { method: "POST", body: { older_than_days: olderThanDays } }),
    checkVault: () => api("/api/quarantine/vault/check", { method: "POST" }),

    // ---- Part 7: real-time protection
    /** { enabled, state: on|on_no_folders|snoozed|off|unavailable|error, protected, snoozed_until,
     *    folders[{label, path, kind: default|custom|usb, status: watching|missing|off|snoozed|error}],
     *    usb_connected[], queue, counters{files_scanned, threats, skipped}, last_threat, settings } */
    realtimeStatus: () => api("/api/realtime/status"),
    realtimeEnable: () => api("/api/realtime/enable", { method: "POST" }),
    realtimeDisable: () => api("/api/realtime/disable", { method: "POST" }),          // admin
    realtimePause: (minutes = 30) => api("/api/realtime/pause", { method: "POST", body: { minutes } }),   // admin, 1-480
    realtimeResume: () => api("/api/realtime/resume", { method: "POST" }),
    realtimeSelfTest: () => api("/api/realtime/self-test", { method: "POST" }),
    realtimeFolders: () => api("/api/realtime/folders"),
    addProtectedFolder: (path) => api("/api/realtime/folders", { method: "POST", body: { path } }),        // admin
    removeProtectedFolder: (path) => api("/api/realtime/folders?" + new URLSearchParams({ path }), { method: "DELETE" }),
    /** status: clean|infected|skipped|error, origin: folder|usb */
    realtimeEvents: ({ status, origin, limit = 100, offset = 0 } = {}) =>
      api("/api/realtime/events?" + new URLSearchParams({ limit, offset, ...(status ? { status } : {}), ...(origin ? { origin } : {}) })),
    clearRealtimeEvents: () => api("/api/realtime/events", { method: "DELETE" }),      // admin
    realtimeSummary: (days = 14) => api("/api/realtime/summary?days=" + days),
    usbDevices: (connectedOnly = false) => api("/api/realtime/usb?connected=" + connectedOnly),
    trustUsb: (id, trusted = true) => api("/api/realtime/usb/" + id, { method: "PATCH", body: { trusted } }), // admin
    scanUsb: (id) => api(`/api/realtime/usb/${id}/scan`, { method: "POST" }),
    forgetUsb: (id) => api("/api/realtime/usb/" + id, { method: "DELETE" }),          // admin

    // ---- Part 8: rules engine (YARA), heuristics & online hash lookup
    /** { backend{name: native|lite, label}, version, active_rules, active_sets, sets_by_status,
     *    settings{yara_enabled, heuristics_enabled, heuristics_sensitivity, heuristics_threshold, ...},
     *    verdict_cache, detections{yara|heuristic|cloud: {status: n}} } */
    rulesStatus: () => api("/api/rules/status"),
    /** charts: per_day[{day, method, n}], top_threats[{threat_name, method, severity, n}], by_severity */
    rulesSummary: (days = 30) => api("/api/rules/summary?days=" + days),
    rulesSelfTest: () => api("/api/rules/self-test", { method: "POST" }),
    heuristicChecks: () => api("/api/rules/heuristics"),
    /** method: yara | heuristic | cloud | all. Each item has details (rule + matched strings / flags + score / cloud verdict) */
    ruleDetections: ({ method = "all", status = "all", limit = 100, offset = 0 } = {}) =>
      api("/api/rules/detections?" + new URLSearchParams({ method, status, limit, offset })),
    /** Deep-dive one file (nothing is recorded): verdict, yara.matches[], heuristics{score, flags[]}, pe{sections, imports} */
    analyzeFile: (path, lookup = true) => api("/api/rules/analyze", { method: "POST", body: { path, lookup } }),
    /** Analyse bytes from a <input type=file> / drag & drop (max 20 MB) */
    async analyzeBlob(file) {
      const buf = new Uint8Array(await file.arrayBuffer());
      let bin = ""; for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
      return api("/api/rules/analyze", { method: "POST", body: { content_base64: btoa(bin), name: file.name } });
    },
    ruleSets: () => api("/api/rules"),
    ruleSet: (id) => api("/api/rules/" + id),                                          // includes source
    validateRules: (source) => api("/api/rules/validate", { method: "POST", body: { source } }),   // {valid, error, line, rules[]}
    addRuleSet: (name, source, { enabled = true, replace = false } = {}) =>
      api("/api/rules", { method: "POST", body: { name, source, enabled, replace } }),  // admin
    updateRuleSet: (id, changes) => api("/api/rules/" + id, { method: "PATCH", body: changes }),  // admin: {enabled?, name?, source?}
    deleteRuleSet: (id) => api("/api/rules/" + id, { method: "DELETE" }),               // admin (built-in: switch off only)
    importRules: (path, prefix) => api("/api/rules/import", { method: "POST", body: { path, ...(prefix ? { prefix } : {}) } }), // admin
    clearVerdictCache: () => api("/api/rules/cache/verdicts", { method: "DELETE" }),     // admin

    /** Online lookup (opt-in, only hashes leave the PC). { enabled, auto_lookup, ready, providers{virustotal, malwarebazaar}, queue } */
    lookupStatus: () => api("/api/lookup/status"),
    /** admin. Empty string removes a key. Keys are stored encrypted and never returned. */
    setLookupKeys: ({ virustotal, malwarebazaar } = {}) =>
      api("/api/lookup/keys", { method: "PUT", body: { ...(virustotal !== undefined ? { virustotal } : {}), ...(malwarebazaar !== undefined ? { malwarebazaar } : {}) } }),
    lookupHash: (hash, { providers, force = false } = {}) =>
      api("/api/lookup/hash", { method: "POST", body: { hash, force, ...(providers ? { providers } : {}) } }),
    lookupFile: (path, { force = false } = {}) => api("/api/lookup/file", { method: "POST", body: { path, force } }),
    testLookupKeys: () => api("/api/lookup/test", { method: "POST" }),                  // admin
    lookupHistory: ({ verdict, limit = 100, offset = 0 } = {}) =>
      api("/api/lookup/history?" + new URLSearchParams({ limit, offset, ...(verdict ? { verdict } : {}) })),
    runLookupQueue: () => api("/api/lookup/queue/run", { method: "POST" }),            // admin
    clearLookupCache: () => api("/api/lookup/cache", { method: "DELETE" }),             // admin

    // ---- Part 9: firewall & network protection
    /** { backend{name: windows|ufw|memory|none, label, available, reason, can_modify, supports{}}, state: on|partial|off|unavailable,
     *    shields_up, profiles[{name, enabled, default_inbound, default_outbound, block_all_inbound, notify_on_listen,
     *    log_blocked, active}], networks[{name, interface, profile, internet}], rules{total, enabled, inbound_allow,
     *    inbound_block, outbound_allow, outbound_block, cyberhub}, blocks{active, by_kind, missing, expiring_24h},
     *    score, grade, findings{critical..info}, unacknowledged_alerts, last_watch } */
    firewallStatus: () => api("/api/firewall/status"),
    firewallProfiles: (refresh = false) => api("/api/firewall/profiles?refresh=" + refresh),
    /** name = domain | private | public | all. changes: { enabled, default_inbound, default_outbound, block_all_inbound,
     *  notify_on_listen, log_blocked, log_allowed }. Lowering protection = admin. */
    setFirewallProfile: (name, changes) => api("/api/firewall/profiles/" + name, { method: "PATCH", body: changes }),
    shieldsUp: (on, profile = "all") => api("/api/firewall/shields-up", { method: "POST", body: { on, profile } }),  // off = admin
    firewallRules: ({ search, direction, action, enabled, profile, origin = "all", flagged = false, sort = "name",
                      limit = 200, offset = 0, refresh = false } = {}) =>
      api("/api/firewall/rules?" + new URLSearchParams({ origin, flagged, sort, limit, offset, refresh,
        ...(search ? { search } : {}), ...(direction ? { direction } : {}), ...(action ? { action } : {}),
        ...(enabled !== undefined ? { enabled } : {}), ...(profile ? { profile } : {}) })),
    firewallRule: (id) => api("/api/firewall/rules/" + encodeURIComponent(id)),
    setFirewallRule: (id, enabled) => api("/api/firewall/rules/" + encodeURIComponent(id), { method: "PATCH", body: { enabled } }),
    deleteFirewallRule: (id, force = false) =>
      api("/api/firewall/rules/" + encodeURIComponent(id) + "?force=" + force, { method: "DELETE" }),   // admin
    /** Blocks. minutes = null -> until removed. Result has warnings[] (e.g. LAN address) and already:true for duplicates. */
    blockApp: (path, { direction = "both", minutes = null, reason, force = false } = {}) =>
      api("/api/firewall/block/app", { method: "POST", body: { path, direction, minutes, reason, force } }),
    blockProcess: (pid, { create_time, direction = "both", minutes = null, reason, force = false } = {}) =>
      api("/api/firewall/block/process", { method: "POST", body: { pid, create_time, direction, minutes, reason, force } }),
    blockIp: (addresses, { direction = "both", minutes = null, reason, force = false } = {}) =>
      api("/api/firewall/block/ip", { method: "POST", body: { addresses: [].concat(addresses), direction, minutes, reason, force } }),
    blockPort: (ports, { protocol = "tcp", direction = "in", minutes = null, reason, force = false } = {}) =>
      api("/api/firewall/block/port", { method: "POST", body: { ports: String(ports), protocol, direction, minutes, reason, force } }),
    allowApp: (path, profiles = ["private"], reason) =>
      api("/api/firewall/allow/app", { method: "POST", body: { path, profiles, reason } }),                    // admin
    firewallBlocks: ({ status = "current", kind, limit = 200, offset = 0 } = {}) =>
      api("/api/firewall/blocks?" + new URLSearchParams({ limit, offset, ...(status ? { status } : {}), ...(kind ? { kind } : {}) })),
    unblock: (id) => api("/api/firewall/blocks/" + id, { method: "DELETE" }),                                  // admin
    repairBlock: (id) => api("/api/firewall/blocks/" + id + "/repair", { method: "POST" }),
    verifyBlocks: () => api("/api/firewall/blocks/verify", { method: "POST" }),
    /** { score 0-100, grade, counts{}, findings[{id, severity, category, title, detail, rule_ids[], fix, fix_label, fix_requires_admin}] } */
    firewallAnalysis: (refresh = false) => api("/api/firewall/analysis?refresh=" + refresh),
    fixFirewallFinding: (id) => api("/api/firewall/findings/" + encodeURIComponent(id) + "/fix", { method: "POST" }),
    firewallWatchNow: () => api("/api/firewall/watch", { method: "POST" }),
    /** Poll new alerts: firewallEvents({ after_id: last_id }) -> { items[], last_id } */
    firewallEvents: ({ after_id = 0, severity, kind, unacknowledged = false, limit = 100, offset = 0 } = {}) =>
      api("/api/firewall/events?" + new URLSearchParams({ after_id, unacknowledged, limit, offset,
        ...(severity ? { severity } : {}), ...(kind ? { kind } : {}) })),
    ackFirewallEvents: (ids) => api("/api/firewall/events/ack", { method: "POST", body: { ids: ids || null } }),
    clearFirewallEvents: () => api("/api/firewall/events", { method: "DELETE" }),                            // admin
    /** Graphs: per_day[{day, info..critical, blocks_created}], events_by_kind, blocks, rules, score, top_blocked[] */
    firewallSummary: (days = 14) => api("/api/firewall/summary?days=" + days),
    /** Packet log: by_hour[{hour, drops, allows}], top_sources[], top_ports[], port_scan_suspects[], recent_drops[] */
    firewallLog: (hours = 24, recent = 50) => api("/api/firewall/log?hours=" + hours + "&recent=" + recent),
    firewallSnapshots: () => api("/api/firewall/snapshots"),
    saveFirewallSnapshot: (note) => api("/api/firewall/snapshots", { method: "POST", body: { note: note || null } }),
    restoreFirewallSnapshot: (id) => api("/api/firewall/snapshots/" + id + "/restore", { method: "POST" }),  // admin
    deleteFirewallSnapshot: (id) => api("/api/firewall/snapshots/" + id, { method: "DELETE" }),             // admin
    resetFirewall: () => api("/api/firewall/reset", { method: "POST", body: { confirm: true } }),           // admin

    // ---- Part 10: network monitor & Wi-Fi
    /** { backend{probe, wifi, firewall, elevated}, connections{total, established, listening, incoming, outgoing,
     *    internet, lan, local, syn_sent, processes, remote_hosts, flagged}, wifi{available, connected, ssid, auth,
     *    signal, rating, nearby, error}, lan{network_id, name, subnet, home, gateway{ip, mac, vendor}, devices,
     *    new_24h, last_scan, router_alert}, score, grade, findings{critical..info}, unacknowledged_alerts,
     *    last_watch, scan{state, percent...} } */
    networkStatus: () => api("/api/network/status"),
    /** { score, grade, counts, findings[{id, severity, category: connection|behaviour|listening|wifi|lan, title, detail,
     *    fix{action: block_remote_ip|block_port|block_program|accept_gateway}, fix_label, fix_requires_admin, data}] } */
    networkFindings: (refresh = false) => api("/api/network/findings?refresh=" + refresh),
    fixNetworkFinding: (id) => api("/api/network/findings/" + encodeURIComponent(id) + "/fix", { method: "POST" }),
    /** Graphs: series[{ts, established, listening, internet, lan, remote_hosts, flagged}], events_by_day[],
     *  events_by_kind[], top_processes[], top_remote_ports[], by_scope{internet, lan, local}, by_state{ESTABLISHED..} */
    networkSummary: (hours = 24, days = 14) => api("/api/network/summary?hours=" + hours + "&days=" + days),
    /** items[{proto, local_ip, local_port, remote_ip, remote_port, status, direction, scope, service, pid,
     *  create_time, process, exe, flags[], reasons[], risk_score, risk_level, blocked_by, remote_host?}] */
    connections: ({ search, state, proto, scope, direction, pid, flagged = false, includeListening = false, resolve,
                    sort = "risk", limit = 500, offset = 0 } = {}) =>
      api("/api/network/connections?" + new URLSearchParams({ flagged, include_listening: includeListening, sort, limit,
        offset, ...(search ? { search } : {}), ...(state ? { state } : {}), ...(proto ? { proto } : {}),
        ...(scope ? { scope } : {}), ...(direction ? { direction } : {}), ...(pid != null ? { pid } : {}),
        ...(resolve != null ? { resolve } : {}) })),
    connectionsByProcess: () => api("/api/network/connections/by-process"),
    /** items[{proto, port, addresses[], exposure: local|network|all, process, pid, service, risky_service,
     *  firewall{verdict: blocked|allowed|open|unknown|not_needed, rule, reason, profile}, severity, reasons[]}] */
    listeningPorts: ({ exposedOnly = false, includeEphemeral = false } = {}) =>
      api("/api/network/listening?exposed_only=" + exposedOnly + "&include_ephemeral=" + includeEphemeral),
    /** { available, current{ssid, bssid, auth, cipher, signal, band, channel, assessment{rating, severity, text, score}},
     *    nearby[], nearby_count, nearby_open, saved[], findings[], error } - passwords are never read */
    wifi: (refresh = false) => api("/api/network/wifi?refresh=" + refresh),
    wifiHistory: (limit = 100) => api("/api/network/wifi/history?limit=" + limit),
    /** { network{id, name, kind, subnet, home, gateway{ip, mac, vendor}, gateway_alert_mac, last_scan}, devices[{id,
     *    ip, mac, vendor, hostname, nb_name, label, device_type, open_ports[], online, trusted, randomized_mac,
     *    is_gateway, flags[], severity}], counts{total, online, new_24h, untrusted, risky}, scan{}, networks[] } */
    lan: (networkId) => api("/api/network/lan" + (networkId ? "?network_id=" + networkId : "")),
    lanNetworks: () => api("/api/network/lan/networks"),
    startLanScan: (ports = true) => api("/api/network/lan/scan", { method: "POST", body: { ports } }),
    lanScanStatus: () => api("/api/network/lan/scan"),
    cancelLanScan: () => api("/api/network/lan/scan/cancel", { method: "POST" }),
    lanDevice: (id) => api("/api/network/lan/devices/" + id),
    /** changes: { label, notes, trusted } - trusted = admin */
    updateLanDevice: (id, changes) => api("/api/network/lan/devices/" + id, { method: "PATCH", body: changes }),
    forgetLanDevice: (id) => api("/api/network/lan/devices/" + id, { method: "DELETE" }),                      // admin
    setHomeNetwork: (id, home, name) =>
      api("/api/network/lan/networks/" + id + "/home", { method: "POST", body: { home, name: name || null } }), // off = admin
    acceptNewRouter: (id) => api("/api/network/lan/networks/" + id + "/accept-gateway", { method: "POST" }),    // admin
    ouiStatus: () => api("/api/network/oui"),
    importOui: ({ text, path }) => api("/api/network/oui/import", { method: "POST", body: { text, path } }),   // admin
    updateOui: (url) => api("/api/network/oui/update", { method: "POST", body: url ? { url } : {} }),           // admin
    networkWatchNow: () => api("/api/network/watch", { method: "POST" }),
    networkEvents: ({ after_id = 0, severity, kind, unacknowledged = false, limit = 100 } = {}) =>
      api("/api/network/events?" + new URLSearchParams({ after_id, unacknowledged, limit,
        ...(severity ? { severity } : {}), ...(kind ? { kind } : {}) })),
    ackNetworkEvents: (ids) => api("/api/network/events/ack", { method: "POST", body: { ids: ids || null } }),
    clearNetworkEvents: () => api("/api/network/events", { method: "DELETE" }),                               // admin

    // ---- Part 11: Windows security posture
    /** { backend{name, label, platform, available, can_modify}, score, grade, categories[{id: virus|account|network|
     *    app|device|updates, name, score, grade, passed, failed, unknown, ignored, worst}], counts{critical..info},
     *    totals{checks, passed, failed, unknown, ignored, fixable}, top_issues[{id, title, severity, value, category,
     *    fixable}], os{name, build, display_version, edition_id, portable}, elevated, pending_reboot,
     *    changes_pending_reboot, unacknowledged_alerts, last_watch, error } */
    postureStatus: () => api("/api/posture/status"),
    /** checks[{id, category, category_name, title, status: pass|fail|unknown, severity, value, detail, why, evidence,
     *  fix{label, admin, confirm, reboot, needs_elevation, blocked, reversible} | null, manual{steps[], open} | null,
     *  managed, ignored{reason, by, until} | null}] + score, grade, categories, counts, totals (failing first) */
    postureChecks: ({ category, status, refresh = false } = {}) =>
      api("/api/posture/checks?" + new URLSearchParams({ refresh, ...(category ? { category } : {}),
        ...(status ? { status } : {}) })),
    postureCheck: (id, refresh = false) => api("/api/posture/checks/" + encodeURIComponent(id) + "?refresh=" + refresh),
    /** One-click fix. Throws status 428 + the warning text when the fix needs confirm: true (show it, ask, resend).
     *  -> { status: applied | not_applied, verified, message, reboot_required, change_id, reversible, check } */
    fixPostureCheck: (id, { confirm = false, force = false } = {}) =>
      api("/api/posture/checks/" + encodeURIComponent(id) + "/fix", { method: "POST", body: { confirm, force } }),
    /** -> { applied[], not_applied[], skipped[{id, title, reason}], score_before, score, grade, reboot_required } */
    fixAllPosture: ({ categories, minSeverity = "low" } = {}) =>
      api("/api/posture/fix-all", { method: "POST", body: { categories: categories || null, min_severity: minSeverity } }),
    ignorePostureCheck: (id, { reason, days } = {}) =>                                                       // admin
      api("/api/posture/checks/" + encodeURIComponent(id) + "/ignore", { method: "POST", body: { reason: reason || null, days: days || null } }),
    unignorePostureCheck: (id) => api("/api/posture/checks/" + encodeURIComponent(id) + "/ignore", { method: "DELETE" }),
    postureIgnored: () => api("/api/posture/ignored"),
    /** items[{id, ts, check_id, title, label, ops[], username, status: applied|not_applied|failed|reverted,
     *  reboot_required, message, reverted_at, reverted_by, reversible}] */
    postureChanges: (limit = 100) => api("/api/posture/changes?limit=" + limit),
    revertPostureChange: (id) => api("/api/posture/changes/" + id + "/revert", { method: "POST" }),          // admin
    /** { defender{realtime, behavior, ioav, tamper, signature_age_days, signature_version, engine_version,
     *  quick_scan_age_days, mode...}, preferences{maps, pua, network_protection, cfa...}, exclusions[{kind, value, risk}]
     *  | null (engine not elevated), exclusions_readable, products[{name, enabled, up_to_date}], checks[] } */
    defenderStatus: (refresh = false) => api("/api/posture/defender?refresh=" + refresh),
    updateDefender: () => api("/api/posture/defender/update", { method: "POST" }),
    defenderScan: (type = "quick") => api("/api/posture/defender/scan", { method: "POST", body: { type } }),
    /** { update{last_install, last_search, history[{title, date, result}], pending_reboot, paused_until, service},
     *    support{version, end, days_left}, os, checks[], search{state, updates[{title, kb[], severity, size_mb}]} } */
    windowsUpdates: (refresh = false) => api("/api/posture/updates?refresh=" + refresh),
    searchWindowsUpdates: () => api("/api/posture/updates/search", { method: "POST" }),
    windowsUpdateSearch: () => api("/api/posture/updates/search"),
    windowsAccounts: () => api("/api/posture/accounts"),
    /** target: windows_update | virus_protection | defender_settings | app_browser | device_security | core_isolation |
     *  account_protection | firewall | remote_desktop | accounts | sign_in | lock_screen | bitlocker |
     *  device_encryption | tpm | uac | recovery | update_history */
    openWindowsSettings: (target) => api("/api/posture/open/" + encodeURIComponent(target), { method: "POST" }),
    postureWatchNow: () => api("/api/posture/watch", { method: "POST" }),
    postureRebaseline: () => api("/api/posture/rebaseline", { method: "POST" }),                              // admin
    postureEvents: ({ after_id = 0, severity, kind, unacknowledged = false, limit = 100 } = {}) =>
      api("/api/posture/events?" + new URLSearchParams({ after_id, unacknowledged, limit,
        ...(severity ? { severity } : {}), ...(kind ? { kind } : {}) })),
    ackPostureEvents: (ids) => api("/api/posture/events/ack", { method: "POST", body: { ids: ids || null } }),
    clearPostureEvents: () => api("/api/posture/events", { method: "DELETE" }),                               // admin
    /** Graphs: per_day[{day, score, failed, critical..info}], events_by_kind{}, fixes{applied, reverted...},
     *  score, grade, categories[] */
    postureSummary: (days = 30) => api("/api/posture/summary?days=" + days),

    // ---- Part 12: password vault & auditor (your own vault - nobody else, not even an admin, can open it)
    //  423 "Password vault is locked" -> show the vault unlock screen (it is NOT the app lock screen).
    //  window.addEventListener("cyberhub:vaultlocked", showVaultUnlock) fires on that 423.
    /** {exists, unlocked, counts{login,card,note,identity}, total, trash, device_bound, auto_lock_in_seconds,
     *   audit{score, grade, counts}, breach_job, unread_alerts, clipboard{available}, warning?} */
    vaultStatus: () => api("/api/passwords/status"),
    /** -> {recovery_key, status, message}. SHOW the recovery key once and ask the user to save it. */
    setupVault: (masterPassword, hint) =>
      api("/api/passwords/setup", { method: "POST", body: { master_password: masterPassword, hint: hint || null } }),
    unlockVault: (masterPassword) => api("/api/passwords/unlock", { method: "POST", body: { master_password: masterPassword } }),
    /** Forgot the master password: recovery key + new master -> {recovery_key (NEW), status} */
    unlockVaultWithRecovery: (recoveryKey, newMasterPassword) =>
      api("/api/passwords/unlock", { method: "POST", body: { recovery_key: recoveryKey, new_master_password: newMasterPassword } }),
    lockVault: () => api("/api/passwords/lock", { method: "POST" }),
    vaultHint: () => api("/api/passwords/hint"),
    changeMasterPassword: (current, next, hint) =>
      api("/api/passwords/master-password", { method: "POST", body: { current_master_password: current, new_master_password: next, hint } }),
    newRecoveryKey: (masterPassword) => api("/api/passwords/recovery-key", { method: "POST", body: { master_password: masterPassword } }),
    deleteVault: (accountPassword, confirm = false) =>
      api("/api/passwords/vault/delete", { method: "POST", body: { account_password: accountPassword, confirm } }),

    /** items[] = {id, type, title, username, host, folder, favorite, has_totp, brand, last4, strength, strength_label,
     *  reused, breached, issues[{kind, severity, detail}], damaged} - no secrets */
    vaultItems: ({ q, type, folder, favorite, trash = false, issue } = {}) =>
      api("/api/passwords/items?" + new URLSearchParams({ trash, ...(q ? { q } : {}), ...(type ? { type } : {}),
        ...(folder != null ? { folder } : {}), ...(favorite != null ? { favorite } : {}), ...(issue ? { issue } : {}) })),
    /** type: login | card | note | identity. data: {title, username, password, urls[], totp, notes, folder, favorite,
     *  tags[], fields[{name, value, hidden}]} -> {item, warnings[]} */
    addVaultItem: (type, data) => api("/api/passwords/items", { method: "POST", body: { type, data } }),
    vaultItem: (id, reveal = false) => api("/api/passwords/items/" + id + "?reveal=" + reveal),
    updateVaultItem: (id, changes) => api("/api/passwords/items/" + id, { method: "PATCH", body: changes }),
    deleteVaultItem: (id, permanent = false) => api("/api/passwords/items/" + id + "?permanent=" + permanent, { method: "DELETE" }),
    restoreVaultItem: (id) => api("/api/passwords/items/" + id + "/restore", { method: "POST" }),
    emptyVaultTrash: () => api("/api/passwords/trash", { method: "DELETE" }),
    passwordHistory: (id) => api("/api/passwords/items/" + id + "/history"),
    /** {code, remaining, period} - refresh when remaining hits 0 */
    vaultTotp: (id) => api("/api/passwords/items/" + id + "/totp"),
    /** System clipboard, kept out of Win+V history, auto-wiped. On 501 fall back to navigator.clipboard. */
    async copyVaultField(id, field = "password") {
      try { return await api("/api/passwords/items/" + id + "/copy", { method: "POST", body: { field } }); }
      catch (e) {
        if (e.status !== 501) throw e;
        const it = (await api("/api/passwords/items/" + id + "?reveal=true")).item;
        const v = field === "totp" ? (await api("/api/passwords/items/" + id + "/totp")).code
                : field === "url" ? (it.data.urls || [""])[0] : it.data[field];
        await navigator.clipboard.writeText(v || "");
        return { copied: true, backend: "browser", clears_in: null };
      }
    },
    clearClipboard: () => api("/api/passwords/clipboard/clear", { method: "POST" }),
    vaultFolders: () => api("/api/passwords/folders"),
    renameVaultFolder: (oldName, newName) => api("/api/passwords/folders/rename", { method: "POST", body: { old: oldName, new: newName } }),

    /** mode password {length, lower, upper, digits, symbols, avoid_ambiguous, exclude} | passphrase {words, separator,
     *  capitalize, include_number} | pin {length} -> {password, entropy_bits, strength{score, label, crack_times}} */
    generatePassword: (opts = {}) => api("/api/passwords/generate", { method: "POST", body: { mode: "password", ...opts } }),
    /** Strength meter (+ optional Have I Been Pwned check) - nothing is stored. Debounce while typing. */
    checkPassword: (password, { userInputs = [], breach = false } = {}) =>
      api("/api/passwords/check", { method: "POST", body: { password, user_inputs: userInputs, breach } }),

    /** {score, grade, counts{breached, reused, weak, old, insecure_url, duplicate, empty_password, expired_card},
     *   strength_distribution[5], reused_groups[], issues[{item_id, title, kind, severity, detail}]} */
    vaultAudit: () => api("/api/passwords/audit"),
    checkBreaches: (itemIds) => api("/api/passwords/audit/breaches", { method: "POST", body: { item_ids: itemIds || null } }),
    breachCheckStatus: () => api("/api/passwords/audit/breaches"),

    /** CSV from Chrome / Edge / Firefox / Bitwarden / LastPass / 1Password / KeePass, or a .chvault backup */
    importPasswords: ({ content, path, format = "auto", password, folder, deleteSource = false } = {}) =>
      api("/api/passwords/import", { method: "POST", body: { content: content || null, path: path || null, format,
        password: password || null, folder: folder || null, delete_source: deleteSource } }),
    /** format chvault (encrypted, needs exportPassword) | csv (plain text, needs confirm) -> {filename, content | path} */
    exportPasswords: ({ format = "chvault", masterPassword, exportPassword, confirm = false, path } = {}) =>
      api("/api/passwords/export", { method: "POST", body: { format, master_password: masterPassword,
        export_password: exportPassword || null, confirm, path: path || null } }),

    vaultEvents: ({ after_id = 0, severity, kind, unacknowledged = false, limit = 100 } = {}) =>
      api("/api/passwords/events?" + new URLSearchParams({ after_id, unacknowledged, limit,
        ...(severity ? { severity } : {}), ...(kind ? { kind } : {}) })),
    ackVaultEvents: (ids) => api("/api/passwords/events/ack", { method: "POST", body: { ids: ids || null } }),
    clearVaultEvents: () => api("/api/passwords/events", { method: "DELETE" }),
    /** Graphs: per_day[{day, score, weak, reused, breached, critical..info}], items_by_type{}, events_by_kind{}, audit */
    vaultSummary: (days = 30) => api("/api/passwords/summary?days=" + days),

    // ---------------------------------------------------------------- Part 13: Data Protection
    /** Card: features, encryption / shredder / cleaner / finder settings, health {score, grade, by_severity,
     *  junk_bytes, encrypted_files}, jobs_running[], unacknowledged */
    dataStatus: () => api("/api/data/status"),
    /** Graphs: per_day[{day, encrypted_files, decrypted_files, shredded_files, shredded_bytes, cleaned_bytes,
     *  findings_new}], findings_by_type[], findings_by_severity{}, score_history[], junk_by_category[] */
    dataSummary: (days = 30) => api("/api/data/summary?days=" + days),
    /** Encrypt files / folders to .chx -> job. mode "password" (any PC) | "device" (this PC only, no password).
     *  deleteOriginal: "shred" | "delete" | "keep". 422 weak password (send allowWeak), 423 vault locked (saveToVault) */
    encryptFiles: (paths, { mode = "password", password = null, deleteOriginal = null, hideNames = null,
                            saveToVault = false, allowWeak = false } = {}) =>
      api("/api/data/encrypt", { method: "POST", body: { paths, mode, password, delete_original: deleteOriginal,
                                                         hide_names: hideNames, save_to_vault: saveToVault, allow_weak: allowWeak } }),
    /** Decrypt .chx files (or every .chx in folders) -> job. conflict: rename | overwrite | skip */
    decryptFiles: (paths, { password = null, destination = null, conflict = "rename", deleteEncrypted = true } = {}) =>
      api("/api/data/decrypt", { method: "POST", body: { paths, password, destination, conflict, delete_encrypted: deleteEncrypted } }),
    inspectEncrypted: (path, password = null) => api("/api/data/inspect", { method: "POST", body: { path, password } }),
    verifyEncrypted: (path, password = null) => api("/api/data/verify", { method: "POST", body: { path, password } }),
    encryptedFiles: (status = "encrypted") => api("/api/data/encrypted?status=" + status),
    /** What would be destroyed: {files, folders, links, bytes, size, media[], warnings[], methods{}} */
    shredPreview: (paths) => api("/api/data/shred/preview", { method: "POST", body: { paths } }),
    /** Overwrite + delete -> job. 428 until confirm=true. method: zero | random | dod3 | random3 */
    shredFiles: (paths, { method = null, confirm = false, verify = null, allowHardlinks = false } = {}) =>
      api("/api/data/shred", { method: "POST", body: { paths, method, confirm, verify, allow_hardlinks: allowHardlinks } }),
    analyzePrivacy: () => api("/api/data/cleaner/analyze", { method: "POST" }),
    /** {ts, categories[{id, group, label, description, files, bytes, warning, needs_confirm, browser_running, note}]} */
    privacyReport: () => api("/api/data/cleaner/report"),
    /** Clean chosen category ids -> job. Recycle Bin / cookies -> 428 until confirm=true */
    cleanPrivacy: (categories, { secure = null, confirm = false } = {}) =>
      api("/api/data/cleaner/clean", { method: "POST", body: { categories, secure, confirm } }),
    findSensitiveFiles: (paths = null, types = null) => api("/api/data/finder/scan", { method: "POST", body: { paths, types } }),
    finderRoots: () => api("/api/data/finder/roots"),
    /** items[{id, path, name, severity, status, types[{type, label, count, severity, samples (masked), advice}], actions[]}] */
    sensitiveFindings: ({ status = "open", severity = null, type = null, q = null, limit = 100, offset = 0 } = {}) =>
      api("/api/data/finder/findings?" + new URLSearchParams({ status, limit, offset, ...(severity ? { severity } : {}),
        ...(type ? { type } : {}), ...(q ? { q } : {}) })),
    ignoreFinding: (id, note = null) => api(`/api/data/finder/findings/${id}/ignore`, { method: "POST", body: { note } }),
    unignoreFinding: (id) => api(`/api/data/finder/findings/${id}/unignore`, { method: "POST" }),
    encryptFinding: (id, { mode = "password", password = null, saveToVault = false, allowWeak = false } = {}) =>
      api(`/api/data/finder/findings/${id}/encrypt`, { method: "POST", body: { mode, password, save_to_vault: saveToVault, allow_weak: allowWeak } }),
    shredFinding: (id, confirm = false) => api(`/api/data/finder/findings/${id}/shred`, { method: "POST", body: { confirm } }),
    dataJobs: (kind = null) => api("/api/data/jobs" + (kind ? "?kind=" + kind : "")),
    dataJob: (id) => api("/api/data/jobs/" + id),
    cancelDataJob: (id) => api(`/api/data/jobs/${id}/cancel`, { method: "POST" }),
    /** Poll a job until it ends; onProgress({percent, files_done, files_total, current, phase}) */
    async waitDataJob(id, onProgress, everyMs = 700) {
      for (;;) {
        const j = await api("/api/data/jobs/" + id);
        if (onProgress) onProgress(j.progress || {}, j);
        if (j.status !== "running") return j;
        await new Promise(r => setTimeout(r, everyMs));
      }
    },
    dataEvents: ({ after_id = 0, unacknowledged = false, limit = 100 } = {}) =>
      api("/api/data/events?" + new URLSearchParams({ after_id, unacknowledged, limit })),
    ackDataEvents: (ids) => api("/api/data/events/ack", { method: "POST", body: { ids: ids || null } }),
    clearDataEvents: () => api("/api/data/events", { method: "DELETE" }),

    // ---------------------------------------------------------------- Part 14: Website / Developer Scanner
    /** Card: features, settings, health {score, grade, sites, projects, open{critical,high,medium,low},
     *  certs_expiring[], vulnerable_packages, dev_servers_exposed}, jobs_running[], vulndb, dev_servers, unacknowledged */
    webStatus: () => api("/api/web/status"),
    webHealth: () => api("/api/web/health"),
    /** Graphs: per_day[{day, sites, projects, avg_score}], findings_by_category[], grades{}, score_history{target: []},
     *  certificates[{target, days_left}], top_vulnerable_packages[], technologies[] */
    webSummary: (days = 30) => api("/api/web/summary?days=" + days),
    /** Scan a website -> job. checks: https | headers | content | tech | exposure | ports (default all).
     *  exposure + ports on a public site need confirmOwner=true (else they are skipped, or 428 if asked for). */
    scanWebsite: (target, { checks = null, confirmOwner = false, save = false, monitor = null, label = null } = {}) =>
      api("/api/web/scan", { method: "POST", body: { target, checks, confirm_owner: confirmOwner, save, monitor, label } }),
    /** Scan a code project folder -> job: vulnerable npm / PyPI / Composer packages, secrets in code, risky settings */
    scanProject: (path, { online = null, secrets = null, save = false, monitor = null, label = null } = {}) =>
      api("/api/web/project/scan", { method: "POST", body: { path, online, secrets, save, monitor, label } }),
    /** One package version: {vulnerable, severity, advisories[{id, aliases, summary, severity, fixed, url}]} */
    checkPackage: (ecosystem, name, version, online = null) =>
      api("/api/web/packages/check", { method: "POST", body: { ecosystem, name, version, online } }),
    webJobs: (kind = null) => api("/api/web/jobs" + (kind ? "?kind=" + kind : "")),
    webJob: (id) => api("/api/web/jobs/" + id),
    cancelWebJob: (id) => api(`/api/web/jobs/${id}/cancel`, { method: "POST" }),
    /** Poll a scan until it ends, then return the full report (GET /api/web/scans/{id}).
     *  onProgress({phase, percent, current}) */
    async waitWebScan(id, onProgress, everyMs = 700) {
      for (;;) {
        const j = await api("/api/web/jobs/" + id);
        if (onProgress) onProgress(j.progress || {}, j);
        if (j.status !== "running") return api("/api/web/scans/" + id);
        await new Promise(r => setTimeout(r, everyMs));
      }
    },
    webScans: ({ kind = null, targetId = null, limit = 50, offset = 0 } = {}) =>
      api("/api/web/scans?" + new URLSearchParams({ limit, offset, ...(kind ? { kind } : {}), ...(targetId ? { target_id: targetId } : {}) })),
    /** Full report: result{findings[{id, category, severity, title, detail, advice, evidence}], passed[], score{score,
     *  grade, categories{}}, tls, technologies[], cookies[], ports, packages[], changes{new, fixed, worse}} */
    webScan: (id) => api("/api/web/scans/" + id),
    deleteWebScan: (id) => api("/api/web/scans/" + id, { method: "DELETE" }),
    webTargets: (kind = null) => api("/api/web/targets" + (kind ? "?kind=" + kind : "")),
    saveWebTarget: (kind, target, { label = null, monitor = null, ownerConfirmed = null } = {}) =>
      api("/api/web/targets", { method: "POST", body: { kind, target, label, monitor, owner_confirmed: ownerConfirmed } }),
    updateWebTarget: (id, { label = null, monitor = null, ownerConfirmed = null } = {}) =>
      api("/api/web/targets/" + id, { method: "PATCH", body: { label, monitor, owner_confirmed: ownerConfirmed } }),
    deleteWebTarget: (id, deleteScans = false) => api(`/api/web/targets/${id}?delete_scans=${deleteScans}`, { method: "DELETE" }),
    webTargetHistory: (id) => api(`/api/web/targets/${id}/history`),
    rescanWebTarget: (id) => api(`/api/web/targets/${id}/scan`, { method: "POST" }),
    /** Dev servers on this PC: items[{port, name, process, exposure, reachable, severity, reason, hint, fix, url, debugger}] */
    devServers: (refresh = false) => api("/api/web/dev-servers" + (refresh ? "?refresh=true" : "")),
    blockDevServer: (port) => api(`/api/web/dev-servers/${port}/block`, { method: "POST" }),
    scanDevServer: (port) => api(`/api/web/dev-servers/${port}/scan`, { method: "POST" }),
    vulnDbStatus: () => api("/api/web/vulndb"),
    /** Admin: import an OSV all.zip from this PC, or download=true to fetch the latest from osv.dev -> job */
    importVulnDb: ({ path = null, download = false, ecosystems = null } = {}) =>
      api("/api/web/vulndb/import", { method: "POST", body: { path, download, ecosystems } }),
    webEvents: ({ after_id = 0, unacknowledged = false, limit = 100 } = {}) =>
      api("/api/web/events?" + new URLSearchParams({ after_id, unacknowledged, limit })),
    ackWebEvents: (ids) => api("/api/web/events/ack", { method: "POST", body: { ids: ids || null } }),
    clearWebEvents: () => api("/api/web/events", { method: "DELETE" }),

    // ---------------------------------------------------------------- Part 15: Threat Intelligence
    intelStatus: () => api("/api/intel/status"),
    intelHealth: () => api("/api/intel/health"),
    intelSummary: (days = 30) => api("/api/intel/summary?days=" + days),
    /** Is it dangerous? value = IP / CIDR / domain / URL / e-mail / MD5 / SHA-1 / SHA-256 (hxxp://evil[.]com works).
     *  -> {verdict: malicious|suspicious|low_risk|clean|unknown, score, summary, reasons[], matches[], phishing,
     *      page (deep), online{}, actions[{action, label, endpoint}], private, allowed} */
    checkIndicator: (value, { online = null, deep = false, fullUrl = false } = {}) =>
      api("/api/intel/check", { method: "POST", body: { value, online, deep, full_url: fullUrl } }),
    /** Paste any text (e-mail, report, chat) -> every indicator in it checked offline (online when <= 20) */
    checkText: (text, online = false) => api("/api/intel/check/bulk", { method: "POST", body: { text, online } }),
    intelChecks: (limit = 50) => api("/api/intel/checks?limit=" + limit),
    clearIntelChecks: () => api("/api/intel/checks", { method: "DELETE" }),
    searchIocs: ({ q = "", type = null, feed = null, threat = null, category = null, limit = 100, offset = 0 } = {}) =>
      api("/api/intel/iocs?" + new URLSearchParams({ limit, offset, ...(q ? { q } : {}), ...(type ? { type } : {}),
        ...(feed ? { feed } : {}), ...(threat ? { threat } : {}), ...(category ? { category } : {}) })),
    /** Where was this seen on THIS PC? (files, detections, quarantine, downloads, network / firewall / web events) */
    huntIndicator: (value) => api("/api/intel/hunt?value=" + encodeURIComponent(value)),
    intelFeeds: () => api("/api/intel/feeds"),
    intelFeed: (id) => api("/api/intel/feeds/" + id),
    refreshFeeds: ({ feedIds = null, force = false } = {}) =>
      api("/api/intel/feeds/refresh", { method: "POST", body: { feed_ids: feedIds, force } }),
    intelJob: (id) => api("/api/intel/jobs/" + id),
    /** Poll a feed update until it ends. onProgress({done, total, current, percent}) */
    async waitFeedRefresh(id, onProgress) {
      for (;;) {
        const j = await api("/api/intel/jobs/" + id);
        if (onProgress) onProgress(j.progress);
        if (j.status !== "running") return j;
        await new Promise(r => setTimeout(r, 700));
      }
    },
    setFeedEnabled: (id, enabled) => api("/api/intel/feeds/" + id, { method: "PATCH", body: { enabled } }),
    /** Admin: your own https feed (plain list / CSV / hosts file / STIX) */
    addFeed: ({ name, url, format = "auto", column = null, category = "custom", severity = "high", refreshHours = null } = {}) =>
      api("/api/intel/feeds", { method: "POST", body: { name, url, format, column, category, severity, refresh_hours: refreshHours } }),
    deleteFeed: (id) => api("/api/intel/feeds/" + id, { method: "DELETE" }),
    blocklist: (q = "", limit = 100, offset = 0) => api("/api/intel/blocklist?" + new URLSearchParams({ limit, offset, ...(q ? { q } : {}) })),
    addToBlocklist: ({ values = null, text = null, severity = "high", note = null } = {}) =>
      api("/api/intel/blocklist", { method: "POST", body: { values, text, severity, note } }),
    removeFromBlocklist: ({ ids = null, value = null } = {}) => api("/api/intel/blocklist/remove", { method: "POST", body: { ids, value } }),
    importIocs: ({ text = null, path = null, format = "auto", column = null, severity = "high", note = null } = {}) =>
      api("/api/intel/import", { method: "POST", body: { text, path, format, column, severity, note } }),
    /** Save your block list (or everything matched) as csv | txt | stix | json; what = blocklist | matches */
    async downloadIntelExport(format = "csv", what = "blocklist") {
      await boot();
      const r = await fetch(`${BASE}/api/intel/export?format=${format}&what=${what}`,
                            { headers: { "X-CyberHub-Token": token, ...(session ? { "X-CyberHub-Session": session } : {}) } });
      if (!r.ok) throw new Error("Export failed: HTTP " + r.status);
      const name = (/filename="([^"]+)"/.exec(r.headers.get("content-disposition") || "") || [])[1] || `cyberhub-${what}.${format}`;
      const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(await r.blob()), download: name });
      a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    },
    allowlist: () => api("/api/intel/allowlist"),
    allowIndicator: (value, note = null) => api("/api/intel/allowlist", { method: "POST", body: { value, note } }),
    removeAllow: (id) => api("/api/intel/allowlist/" + id, { method: "DELETE" }),
    blockAddress: (ip, minutes = null) => api("/api/intel/block-ip", { method: "POST", body: { ip, minutes } }),
    intelProviders: () => api("/api/intel/providers"),
    setAbuseIpdbKey: (key) => api("/api/intel/providers/abuseipdb/key", { method: "PUT", body: { key } }),
    runIntelWatch: () => api("/api/intel/watch/run", { method: "POST" }),
    intelEvents: ({ after_id = 0, unacknowledged = false, kind = null, limit = 100 } = {}) =>
      api("/api/intel/events?" + new URLSearchParams({ after_id, unacknowledged, limit, ...(kind ? { kind } : {}) })),
    blockFromAlert: (eventId) => api(`/api/intel/events/${eventId}/block`, { method: "POST" }),
    ackIntelEvents: (ids) => api("/api/intel/events/ack", { method: "POST", body: { ids: ids || null } }),
    clearIntelEvents: () => api("/api/intel/events", { method: "DELETE" }),

    // ---------------------------------------------------------------- Part 16: Social & Platform Accounts
    platformsStatus: () => api("/api/platforms/status"),
    platformsHealth: () => api("/api/platforms/health"),
    platformsSummary: (days = 30) => api("/api/platforms/summary?days=" + days),
    /** Every known platform (domains, 2FA / recovery options, security-page links, tips) + checklist items */
    platformCatalog: () => api("/api/platforms/catalog"),
    platformInfo: (key) => api("/api/platforms/catalog/" + encodeURIComponent(key)),
    /** Your accounts, worst first: { items:[{id, name, score, two_factor, issues[], ...}], overview:{score, grade, two_fa_coverage} } */
    platformAccounts: ({ category = null, q = null, issue = null } = {}) =>
      api("/api/platforms/accounts?" + new URLSearchParams({ ...(category ? { category } : {}), ...(q ? { q } : {}),
                                                            ...(issue ? { issue } : {}) })),
    /** addPlatformAccount("linkedin", { email, handle, label, phone_last4, importance, notes }) - "custom" needs custom_name */
    addPlatformAccount: (platform, data = {}) => api("/api/platforms/accounts", { method: "POST", body: { platform, ...data } }),
    platformAccount: (id) => api("/api/platforms/accounts/" + id),
    updatePlatformAccount: (id, data) => api("/api/platforms/accounts/" + id, { method: "PATCH", body: data }),
    deletePlatformAccount: (id) => api("/api/platforms/accounts/" + id, { method: "DELETE" }),
    /** setPlatformChecklist(id, { two_factor: "done", backup_codes: "done" }) - done | not_done | not_applicable | unknown */
    setPlatformChecklist: (id, items, note = null) =>
      api(`/api/platforms/accounts/${id}/checklist`, { method: "PUT", body: { items, note } }),
    markPlatformReviewed: (id) => api(`/api/platforms/accounts/${id}/reviewed`, { method: "POST" }),
    platformVaultMatches: (id) => api(`/api/platforms/accounts/${id}/vault-matches`),
    /** linkPlatformVault(id, itemId) | linkPlatformVault(id, null) to unlink | linkPlatformVault(id, null, { create: true, password }) */
    linkPlatformVault: (id, itemId, { create = false, password = null } = {}) =>
      api(`/api/platforms/accounts/${id}/vault-link`, { method: "POST", body: { item_id: itemId, create, password } }),
    /** GitHub, READ-ONLY token (classic: read:user + read:public_key, or fine-grained with no repo access) */
    connectGithub: (id, token) => api(`/api/platforms/accounts/${id}/github`, { method: "POST", body: { token } }),
    syncGithub: (id) => api(`/api/platforms/accounts/${id}/github/sync`, { method: "POST" }),
    disconnectGithub: (id) => api(`/api/platforms/accounts/${id}/github`, { method: "DELETE" }),
    /** { nodes, edges:[{from, to, kind: recovers|signs_in}], hubs, weak_hubs } - draw as a graph */
    platformRecoveryGraph: () => api("/api/platforms/recovery-graph"),
    /** Suggestions from the unlocked vault + running apps; create:true adds them */
    discoverPlatforms: ({ sources = null, create = false, platforms = null } = {}) =>
      api("/api/platforms/discover", { method: "POST", body: { sources, create, platforms } }),
    /** "Is this really from Facebook?" -> { official, verdict, score, reasons[], advice[] } */
    checkPlatformLink: (value, platform = null, deep = false) =>
      api("/api/platforms/check-link", { method: "POST", body: { value, platform, deep } }),
    platformEmails: () => api("/api/platforms/emails"),
    suggestPlatformEmails: () => api("/api/platforms/emails/suggest"),
    addPlatformEmail: (email, monitor = true) => api("/api/platforms/emails", { method: "POST", body: { email, monitor } }),
    platformEmail: (id, reveal = false) => api(`/api/platforms/emails/${id}?reveal=${reveal}`),
    setPlatformEmailMonitor: (id, monitor) => api("/api/platforms/emails/" + id, { method: "PATCH", body: { monitor } }),
    deletePlatformEmail: (id) => api("/api/platforms/emails/" + id, { method: "DELETE" }),
    ackEmailBreaches: (id, names = null) => api(`/api/platforms/emails/${id}/ack`, { method: "POST", body: { names } }),
    /** Start a breach check (sends only the address) -> job; then waitPlatformJob(job.id, p => ...) */
    checkPlatformEmails: (ids = null) => api("/api/platforms/emails/check", { method: "POST", body: { ids } }),
    async waitPlatformJob(id, onProgress) {
      for (;;) {
        const j = await api("/api/platforms/jobs/" + id);
        if (onProgress) onProgress(j.progress);
        if (j.status !== "running") return j;
        await new Promise(r => setTimeout(r, 700));
      }
    },
    platformBreaches: ({ q = null, domain = null, limit = 50, offset = 0 } = {}) =>
      api("/api/platforms/breaches?" + new URLSearchParams({ limit, offset, ...(q ? { q } : {}), ...(domain ? { domain } : {}) })),
    refreshBreachList: (force = false) => api("/api/platforms/breaches/refresh?force=" + force, { method: "POST" }),
    platformProviders: () => api("/api/platforms/providers"),
    setHibpKey: (key) => api("/api/platforms/providers/hibp/key", { method: "PUT", body: { key } }),
    platformExtensions: (refresh = false) => api("/api/platforms/extensions?refresh=" + refresh),
    scanExtension: (key) => api("/api/platforms/extensions/scan", { method: "POST", body: { key } }),
    platformEvents: ({ after_id = 0, unacknowledged = false, kind = null, limit = 100 } = {}) =>
      api("/api/platforms/events?" + new URLSearchParams({ after_id, unacknowledged, limit, ...(kind ? { kind } : {}) })),
    ackPlatformEvents: (ids) => api("/api/platforms/events/ack", { method: "POST", body: { ids: ids || null } }),
    clearPlatformEvents: () => api("/api/platforms/events", { method: "DELETE" }),

    /** Live platforms feed. CyberHub.streamPlatforms(({job, events, unacknowledged}) => {...}) -> stop() */
    streamPlatforms(onData, { onClose } = {}) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(`${wsBase}/api/platforms/stream?token=${encodeURIComponent(t)}&session=${encodeURIComponent(session || "")}`);
        ws.onmessage = e => { const d = JSON.parse(e.data); if (d.type === "platforms") onData(d); };
        ws.onclose = e => {
          if (e.code === 4423) emit("cyberhub:locked");
          if (e.code === 4401 && session) { setSession(null); emit("cyberhub:signedout"); }
          if (!stopped && onClose) onClose(e.code);
        };
      });
      return () => { stopped = true; ws && ws.close(); };
    },

    /** Live web-scanner feed (every second). CyberHub.streamWeb(({jobs, events, unacknowledged}) => {...}) -> stop() */
    streamWeb(onData, { onClose } = {}) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(`${wsBase}/api/web/stream?token=${encodeURIComponent(t)}&session=${encodeURIComponent(session || "")}`);
        ws.onmessage = e => { const d = JSON.parse(e.data); if (d.type === "web") onData(d); };
        ws.onclose = e => {
          if (e.code === 4423) emit("cyberhub:locked");
          if (e.code === 4401 && session) { setSession(null); emit("cyberhub:signedout"); }
          if (!stopped && onClose) onClose(e.code);
        };
      });
      return () => { stopped = true; ws && ws.close(); };
    },

    /** Live threat-intel feed (every second). CyberHub.streamIntel(({jobs, events, unacknowledged}) => {...}) -> stop() */
    streamIntel(onData, { onClose } = {}) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(`${wsBase}/api/intel/stream?token=${encodeURIComponent(t)}&session=${encodeURIComponent(session || "")}`);
        ws.onmessage = e => { const d = JSON.parse(e.data); if (d.type === "intel") onData(d); };
        ws.onclose = e => {
          if (e.code === 4423) emit("cyberhub:locked");
          if (e.code === 4401 && session) { setSession(null); emit("cyberhub:signedout"); }
          if (!stopped && onClose) onClose(e.code);
        };
      });
      return () => { stopped = true; ws && ws.close(); };
    },

    /** Live data-protection feed (every second). CyberHub.streamData(({jobs, events, unacknowledged}) => {...}) -> stop() */
    streamData(onData, { onClose } = {}) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(`${wsBase}/api/data/stream?token=${encodeURIComponent(t)}&session=${encodeURIComponent(session || "")}`);
        ws.onmessage = e => { const d = JSON.parse(e.data); if (d.type === "data") onData(d); };
        ws.onclose = e => {
          if (e.code === 4423) emit("cyberhub:locked");
          if (e.code === 4401 && session) { setSession(null); emit("cyberhub:signedout"); }
          if (!stopped && onClose) onClose(e.code);
        };
      });
      return () => { stopped = true; ws && ws.close(); };
    },

    /** Live network feed (every 3 s). CyberHub.streamNetwork(({live, events, scan, unacknowledged}) => {...}) -> stop()
     *  live = { total, established, listening, incoming, outgoing, internet, lan, syn_sent, processes, remote_hosts, flagged } */
    streamNetwork(onData, { onClose } = {}) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(`${wsBase}/api/network/stream?token=${encodeURIComponent(t)}&session=${encodeURIComponent(session || "")}`);
        ws.onmessage = e => { const d = JSON.parse(e.data); if (d.type === "network") onData(d); };
        ws.onclose = e => {
          if (e.code === 4423) emit("cyberhub:locked");
          if (e.code === 4401 && session) { setSession(null); emit("cyberhub:signedout"); }
          if (!stopped && onClose) onClose(e.code);
        };
      });
      return () => { stopped = true; ws && ws.close(); };
    },

    /** Live real-time feed. CyberHub.streamRealtime(({status, events}) => {...}) -> stop()
     *  events[] = { type: file_scanned | threat_found | threat_blocked | usb_inserted | usb_removed | burst | protection,
     *               event?, device?, warnings?, scan_job?, suggest_scan?, folder?, changes?, state? } */
    streamRealtime(onData, { onClose } = {}) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(`${wsBase}/api/realtime/stream?token=${encodeURIComponent(t)}&session=${encodeURIComponent(session || "")}`);
        ws.onmessage = e => { const d = JSON.parse(e.data); if (d.type === "realtime") onData(d); };
        ws.onclose = e => {
          if (e.code === 4423) emit("cyberhub:locked");
          if (e.code === 4401 && session) { setSession(null); emit("cyberhub:signedout"); }
          if (!stopped && onClose) onClose(e.code);
        };
      });
      return () => { stopped = true; ws && ws.close(); };
    },

    /** Live scan feed. CyberHub.streamScans(({jobs, events}) => {...}) -> stop()
     *  jobs[]  = { id, kind, status, phase, percent, files_scanned, files_total, threats_found, current_path, eta_seconds, mb_per_second }
     *  events[] = { type: job_queued | job_started | job_paused | job_resumed | threat | job_finished
     *              | quarantined | restored | quarantine_deleted (Part 6), job?, detection?, item? } */
    streamScans(onData, { onClose } = {}) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(`${wsBase}/api/scan/stream?token=${encodeURIComponent(t)}&session=${encodeURIComponent(session || "")}`);
        ws.onmessage = e => { const d = JSON.parse(e.data); if (d.type === "scan") onData(d); };
        ws.onclose = e => {
          if (e.code === 4423) emit("cyberhub:locked");
          if (e.code === 4401 && session) { setSession(null); emit("cyberhub:signedout"); }
          if (!stopped && onClose) onClose(e.code);
        };
      });
      return () => { stopped = true; ws && ws.close(); };
    },

    /** Live monitor stream. CyberHub.streamMonitor(frame => draw(frame), { top: 5 }) -> stop()
     *  frame = { cpu:{percent, per_core[]}, memory, disk_io, network, gpu_percent, cpu_temp_c, health, active_alerts, top_cpu[] } */
    streamMonitor(onData, { top = 0, onClose } = {}) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(`${wsBase}/api/monitor/stream?token=${encodeURIComponent(t)}` +
                           `&session=${encodeURIComponent(session || "")}&top=${top}`);
        ws.onmessage = e => { const d = JSON.parse(e.data); if (d.type === "monitor") onData(d); };
        ws.onclose = e => {
          if (e.code === 4423) emit("cyberhub:locked");
          if (e.code === 4401 && session) { setSession(null); emit("cyberhub:signedout"); }
          if (!stopped && onClose) onClose(e.code);
        };
      });
      return () => { stopped = true; ws && ws.close(); };
    },

    // ================================================================ Part 17: scheduler & notifications
    /** Any endpoint, for pages that need more than the helpers below: CyberHub.call("/api/scan/quick", {method:"POST"}) */
    call: (path, opts) => api(path, opts),
    notifications: ({ status = "open", source = null, severity = null, minSeverity = null, search = null, afterId = 0, limit = 50, offset = 0 } = {}) =>
      api("/api/notifications?" + new URLSearchParams(Object.entries({ status, source, severity, min_severity: minSeverity, search, after_id: afterId, limit, offset })
        .filter(([, v]) => v !== null && v !== "" && v !== 0).map(([k, v]) => [k, String(v)])).toString()),
    notificationSummary: (days = 14) => api("/api/notifications/summary?days=" + days),
    notificationStatus: () => api("/api/notifications/status"),
    notificationsRead: (ids = null) => api("/api/notifications/read", { method: "POST", body: { ids } }),
    notificationsDismiss: (ids = null) => api("/api/notifications/dismiss", { method: "POST", body: { ids } }),
    notificationsClear: (dismissedOnly = false) => api("/api/notifications?dismissed_only=" + dismissedOnly, { method: "DELETE" }),
    notificationTest: () => api("/api/notifications/test", { method: "POST" }),
    /** Live notifications: CyberHub.streamNotifications(m => { setBadge(m.unread); m.items.forEach(showToast); }) -> stop() */
    streamNotifications(onData, { onClose } = {}) {
      let ws, stopped = false;
      boot().then(t => {
        const wsBase = (BASE || location.origin).replace(/^http/, "ws");
        ws = new WebSocket(`${wsBase}/api/notifications/stream?token=${encodeURIComponent(t)}&session=${encodeURIComponent(session || "")}`);
        ws.onmessage = e => { const d = JSON.parse(e.data); if (d.type === "notifications") onData(d); };
        ws.onclose = e => { if (e.code === 4423) emit("cyberhub:locked"); if (!stopped && onClose) onClose(e.code); };
      });
      return () => { stopped = true; ws && ws.close(); };
    },
    schedulerStatus: () => api("/api/scheduler/status"),
    schedulerActions: () => api("/api/scheduler/actions"),
    schedules: () => api("/api/scheduler/schedules"),
    scheduleCreate: body => api("/api/scheduler/schedules", { method: "POST", body }),
    scheduleUpdate: (id, body) => api(`/api/scheduler/schedules/${id}`, { method: "PATCH", body }),
    scheduleDelete: id => api(`/api/scheduler/schedules/${id}`, { method: "DELETE" }),
    scheduleRun: id => api(`/api/scheduler/schedules/${id}/run`, { method: "POST" }),
    scheduleUpcoming: (hours = 168) => api("/api/scheduler/upcoming?hours=" + hours),
    scheduleRuns: ({ scheduleId = null, status = null, limit = 50, offset = 0 } = {}) =>
      api(`/api/scheduler/runs?limit=${limit}&offset=${offset}` + (scheduleId ? "&schedule_id=" + scheduleId : "") + (status ? "&status=" + status : "")),

    // ================================================================ Part 18: security score & dashboard
    /** Everything the front page needs in one call: score, tiles, recommendations, graphs. */
    dashboard: (days = 14, refresh = false) => api(`/api/dashboard?days=${days}&refresh=${refresh}`),
    score: (refresh = false) => api("/api/score?refresh=" + refresh),
    scoreHistory: (days = 30) => api("/api/score/history?days=" + days),
    recommendations: ({ severity = null, category = null } = {}) =>
      api("/api/score/recommendations?" + new URLSearchParams(Object.entries({ severity, category }).filter(([, v]) => v)).toString()),
    /** Run a recommendation's one-click fix: CyberHub.applyRecommendation(rec) */
    applyRecommendation: rec => rec.action ? api(rec.action.path, { method: rec.action.method, body: rec.action.body || {} }) : Promise.reject(new Error("No one-click fix - open " + rec.link)),

    // ================================================================ Part 19: reports, export & backup
    reportTypes: () => api("/api/reports/types"),
    reports: ({ type = null, limit = 50, offset = 0 } = {}) => api(`/api/reports?limit=${limit}&offset=${offset}` + (type ? "&type=" + type : "")),
    reportCreate: ({ type = "summary", format = null, days = null } = {}) => api("/api/reports", { method: "POST", body: { type, format, days } }),
    reportDelete: id => api(`/api/reports/${id}`, { method: "DELETE" }),
    /** Downloads need the token headers, so fetch the file and hand it to the browser: CyberHub.download(`/api/reports/${id}/download`) */
    async download(path, name) {
      await boot();
      const r = await fetch(BASE + path, { headers: { "X-CyberHub-Token": token, ...(session ? { "X-CyberHub-Session": session } : {}) } });
      if (!r.ok) throw new Error("Download failed (" + r.status + ")");
      const m = /filename="?([^";]+)"?/.exec(r.headers.get("Content-Disposition") || "");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(await r.blob()); a.download = name || (m ? m[1] : "download");
      document.body.appendChild(a); a.click(); a.remove();
    },
    backups: () => api("/api/backup"),
    backupStatus: () => api("/api/backup/status"),
    backupCreate: ({ mode = "device", password = null, includeQuarantine = null, destination = null, note = null } = {}) =>
      api("/api/backup", { method: "POST", body: { mode, password, include_quarantine: includeQuarantine, destination, note } }),
    backupVerify: ({ id = null, path = null, password = null } = {}) => api("/api/backup/verify", { method: "POST", body: { id, path, password } }),
    /** Stages the restore; it is applied when Cyber Hub restarts. */
    backupRestore: ({ id = null, path = null, password = null, confirm = false } = {}) => api("/api/backup/restore", { method: "POST", body: { id, path, password, confirm } }),
    backupDelete: id => api(`/api/backup/${id}`, { method: "DELETE" }),
    settingsExport: () => api("/api/backup/settings/export"),
    settingsImport: (payload, onlyChanged = false) => api("/api/backup/settings/import", { method: "POST", body: { payload, only_changed: onlyChanged } }),

    // ================================================================ Part 20: desktop app
    about: () => api("/api/about"),
    desktopStatus: () => api("/api/desktop/status"),
    setAutostart: enabled => api("/api/desktop/autostart", { method: "PUT", body: { enabled } }),
    /** Native file / folder dialog (only inside the Cyber Hub window; 501 in a browser). */
    pickPath: ({ kind = "folder", title = null, multiple = false } = {}) => api("/api/desktop/pick", { method: "POST", body: { kind, title, multiple } }),
    restartApp: (elevated = false) => api("/api/desktop/restart?elevated=" + elevated, { method: "POST" }),
    quitApp: () => api("/api/desktop/quit", { method: "POST" }),
  };
})();

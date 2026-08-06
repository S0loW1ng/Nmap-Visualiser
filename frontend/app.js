"use strict";

// ---------------------------------------------------------------------------
// State + helpers
// ---------------------------------------------------------------------------
const state = {
  scans: [],
  scan: null,        // full current scan (with hosts)
  hostId: null,      // selected host id
  sort: { key: "ip", dir: 1 },
  filter: "",
  flaggedOnly: false,
  portStates: { open: true, filtered: true, closed: true, openfiltered: true },
  folders: [],          // folders for organising scans
  folderOpen: {},       // folder id (or "unfiled") -> open? (persisted)
  selected: new Set(),  // scan ids ticked for merge
  shots: [],            // screenshots for the current scan
  ewStatus: null,       // last EyeWitness status
  ewPoll: null,         // poll timer id
  deepFlags: "-sCV -A -p-",  // remembered nmap flags for "deeper scan"
  deepAgent: "local",        // remembered agent choice
  deepMerge: true,           // auto-merge rescan result into the current scan
  agents: [],                // known agents
  jobs: [],                  // recent scan jobs (sidebar panel)
  jobPoll: null,             // job status poll timer (modal)
  jobsPoll: null,            // jobs list poll timer (sidebar)
  agentsPoll: null,          // agents modal poll timer
};

// ---------------------------------------------------------------------------
// Clipboard (works on localhost; falls back for insecure LAN contexts)
// ---------------------------------------------------------------------------
async function copyText(text, label) {
  const done = () => toast((label ? label + " copied" : "Copied") + ": " + truncate(text, 56));
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return done();
    }
  } catch (_) { /* fall through */ }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    return done();
  } catch (_) {
    window.prompt("Copy this:", text);
  }
}

function truncate(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

// ---------------------------------------------------------------------------
// Connect-command hints per port
// ---------------------------------------------------------------------------
const WEB_PORTS = new Set([80, 81, 443, 591, 2082, 2087, 2095, 3000, 5000, 7001,
  8000, 8008, 8080, 8081, 8082, 8088, 8180, 8443, 8444, 8834, 8888, 9000, 9080,
  9090, 9443, 10000]);
const HTTPS_PORTS = new Set([443, 8443, 8444, 9443, 10000]);

function portIsWeb(p) {
  const svc = (p.service || "").toLowerCase();
  const t = (p.tunnel || "").toLowerCase();
  return svc.includes("http") || t === "ssl" || WEB_PORTS.has(p.portid);
}
function portScheme(p) {
  const svc = (p.service || "").toLowerCase();
  const t = (p.tunnel || "").toLowerCase();
  return (t === "ssl" || svc.includes("https") || HTTPS_PORTS.has(p.portid)) ? "https" : "http";
}
function portScanFlags(p) {
  return p.protocol === "udp" ? `-sU -sCV -Pn -pU:${p.portid}` : `-sCV -Pn -p${p.portid}`;
}
function connectHints(ip, p) {
  const port = p.portid;
  const svc = (p.service || "").toLowerCase();
  const has = (...n) => n.some((x) => svc.includes(x));
  if (portIsWeb(p)) {
    const url = `${portScheme(p)}://${ip}:${port}`;
    return [
      { label: "URL", text: url, open: url },
      { label: "curl", text: `curl -sk -i ${url}` },
    ];
  }
  if (has("ssh") || port === 22) return [{ label: "ssh", text: `ssh ${ip} -p ${port}` }];
  if (has("ftp") || port === 21) return [{ label: "ftp", text: `ftp ${ip} ${port}` }];
  if (has("mysql") || port === 3306) return [{ label: "mysql", text: `mysql -h ${ip} -P ${port} -u root -p` }];
  if (has("postgres") || port === 5432) return [{ label: "psql", text: `psql -h ${ip} -p ${port} -U postgres` }];
  if (has("redis") || port === 6379) return [{ label: "redis", text: `redis-cli -h ${ip} -p ${port}` }];
  if (has("mongo") || port === 27017) return [{ label: "mongo", text: `mongosh mongodb://${ip}:${port}` }];
  if (has("microsoft-ds", "smb", "netbios") || port === 445 || port === 139)
    return [{ label: "smb", text: `smbclient -L //${ip} -N` }];
  if (has("ms-wbt", "rdp") || port === 3389) return [{ label: "rdp", text: `xfreerdp /v:${ip}:${port}` }];
  if (has("vnc") || (port >= 5900 && port <= 5910)) return [{ label: "vnc", text: `vncviewer ${ip}::${port}` }];
  if (has("telnet") || port === 23) return [{ label: "telnet", text: `telnet ${ip} ${port}` }];
  if (has("smtp") || port === 25 || port === 587) return [{ label: "smtp", text: `nc -v ${ip} ${port}` }];
  return [{ label: "nc", text: `nc -v ${ip} ${port}` }];
}

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const el = (tag, cls, txt) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (txt != null) e.textContent = txt;
  return e;
};

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch (_) {}
    throw new Error(msg);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

let toastTimer = null;
function toast(msg, isErr = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 2600);
}

function debounce(fn, ms) {
  let h;
  return (...a) => { clearTimeout(h); h = setTimeout(() => fn(...a), ms); };
}

function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function ipKey(ip) {
  // sortable key for IPv4; falls back to string
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || "");
  if (!m) return ip || "";
  return m.slice(1).map((n) => n.padStart(3, "0")).join(".");
}

// ---------------------------------------------------------------------------
// Sidebar / scan list
// ---------------------------------------------------------------------------
let draggingId = null;         // scan id currently being dragged (folder DnD)
let pendingImportFolder = null; // folder id to drop the next import into (or null)

function loadFolderOpen() {
  try { state.folderOpen = JSON.parse(localStorage.getItem("nv_folderOpen") || "{}"); }
  catch (_) { state.folderOpen = {}; }
}
function saveFolderOpen() {
  try { localStorage.setItem("nv_folderOpen", JSON.stringify(state.folderOpen)); } catch (_) {}
}

async function loadScans(selectId = null) {
  [state.scans, state.folders] = await Promise.all([
    api("/api/scans"),
    api("/api/folders").catch(() => []),
  ]);
  // drop selections for scans that no longer exist
  const ids = new Set(state.scans.map((s) => s.id));
  for (const id of [...state.selected]) if (!ids.has(id)) state.selected.delete(id);

  renderScanList();
  updateMergeUI();
  if (selectId) openScan(selectId);
}

function scanItemEl(s) {
  const li = el("li", "scan-item");
  li.dataset.id = s.id;
  li.draggable = true;
  if (state.scan && state.scan.id === s.id) li.classList.add("active");

  li.addEventListener("dragstart", (e) => {
    draggingId = s.id;
    e.dataTransfer.effectAllowed = "move";
    try { e.dataTransfer.setData("text/plain", String(s.id)); } catch (_) {}
    li.classList.add("dragging");
  });
  li.addEventListener("dragend", () => { draggingId = null; li.classList.remove("dragging"); });

  // merge-select checkbox
  const sel = el("input", "si-select");
  sel.type = "checkbox";
  sel.checked = state.selected.has(s.id);
  sel.title = "Select (merge / move / delete)";
  sel.addEventListener("click", (e) => e.stopPropagation());
  sel.addEventListener("change", () => {
    if (sel.checked) state.selected.add(s.id);
    else state.selected.delete(s.id);
    updateMergeUI();
  });
  li.append(sel);

  const body = el("div", "si-body");
  const name = el("div", "si-name");
  name.append(el("span", null, s.name));
  if (s.source_type === "merged") name.append(el("span", "tag-merged", "merged"));
  if (s.source_type === "nessus") name.append(el("span", "tag-nessus", "nessus"));
  body.append(name);
  body.append(el("div", "si-sub",
    `${s.host_count} host${s.host_count === 1 ? "" : "s"} · ${s.open_port_count} open · ${s.source_type}`));
  const when = s.started_at || s.imported_at;
  if (when) {
    const prefix = s.started_at ? "🕐 " : "⤓ ";
    body.append(el("div", "si-sub si-time", prefix + fmtTime(when)));
  }
  body.onclick = () => openScan(s.id);
  li.append(body);
  return li;
}

// make a header act as a drop target that moves the dragged scan(s) into folderId
function wireDrop(elm, folderId) {
  elm.addEventListener("dragover", (e) => {
    if (draggingId == null) return;
    e.preventDefault();
    elm.classList.add("drop-hover");
  });
  elm.addEventListener("dragleave", () => elm.classList.remove("drop-hover"));
  elm.addEventListener("drop", (e) => {
    e.preventDefault();
    elm.classList.remove("drop-hover");
    if (draggingId == null) return;
    const ids = state.selected.has(draggingId) ? [...state.selected] : [draggingId];
    moveScans(ids, folderId);
  });
}

// header checkbox that selects/deselects every scan in a group
function folderSelectCb(scans) {
  const cb = el("input", "folder-select");
  cb.type = "checkbox";
  const ids = scans.map((s) => s.id);
  const selCount = ids.filter((id) => state.selected.has(id)).length;
  cb.checked = ids.length > 0 && selCount === ids.length;
  cb.indeterminate = selCount > 0 && selCount < ids.length;
  cb.disabled = ids.length === 0;
  cb.title = "Select all scans in this folder";
  cb.addEventListener("click", (e) => e.stopPropagation());
  cb.addEventListener("change", () => {
    if (cb.checked) ids.forEach((id) => state.selected.add(id));
    else ids.forEach((id) => state.selected.delete(id));
    renderScanList();
    updateMergeUI();
  });
  return cb;
}

function folderGroupEl(f, scans) {
  const open = state.folderOpen[f.id] !== false;
  const group = el("div", "folder-group");
  const head = el("div", "folder-head");
  head.append(folderSelectCb(scans));
  head.append(el("span", "folder-caret", open ? "▾" : "▸"));
  head.append(el("span", "folder-name", f.name));
  head.append(el("span", "folder-count", String(scans.length)));

  // rename / delete menu
  const menu = el("div", "menu folder-menu-wrap");
  const menuBtn = el("button", "icon-btn", "⋯");
  menuBtn.title = "Rename or delete folder";
  const list = el("div", "menu-list"); list.hidden = true;
  const imp = el("button", "menu-item", "⤓ Import scan(s) here");
  imp.onclick = (e) => {
    e.stopPropagation(); list.hidden = true;
    pendingImportFolder = f.id;
    state.folderOpen[f.id] = true; saveFolderOpen();
    $("#fileInput").value = "";      // allow re-selecting the same file
    $("#fileInput").click();
  };
  const rn = el("button", "menu-item", "✎ Rename");
  rn.onclick = (e) => { e.stopPropagation(); list.hidden = true; renameFolder(f); };
  const del = el("button", "menu-item danger", "🗑 Delete folder");
  del.onclick = (e) => { e.stopPropagation(); list.hidden = true; deleteFolder(f); };
  list.append(imp, rn, del);
  menuBtn.onclick = (e) => { e.stopPropagation(); const o = !list.hidden; closeAllMenus(); list.hidden = o; };
  menu.append(menuBtn, list);
  head.append(menu);

  head.onclick = () => { state.folderOpen[f.id] = !open; saveFolderOpen(); renderScanList(); };
  wireDrop(head, f.id);
  group.append(head);

  if (open) {
    const bodyEl = el("div", "folder-scans");
    for (const s of scans) bodyEl.append(scanItemEl(s));
    if (!scans.length) bodyEl.append(el("div", "muted folder-empty", "Empty — drop scans here"));
    group.append(bodyEl);
  }
  return group;
}

function unfiledGroupEl(scans) {
  const key = "unfiled";
  const open = state.folderOpen[key] !== false;
  const group = el("div", "folder-group");
  const head = el("div", "folder-head unfiled");
  head.append(folderSelectCb(scans));
  head.append(el("span", "folder-caret", open ? "▾" : "▸"));
  head.append(el("span", "folder-name", "Unfiled"));
  head.append(el("span", "folder-count", String(scans.length)));
  head.onclick = () => { state.folderOpen[key] = !open; saveFolderOpen(); renderScanList(); };
  wireDrop(head, null);
  group.append(head);
  if (open) {
    const bodyEl = el("div", "folder-scans");
    for (const s of scans) bodyEl.append(scanItemEl(s));
    if (!scans.length) bodyEl.append(el("div", "muted folder-empty", "Nothing here"));
    group.append(bodyEl);
  }
  return group;
}

function renderScanList() {
  const container = $("#scanList");
  container.innerHTML = "";
  if (!state.scans.length) {
    container.append(el("div", "muted empty-scans", "No scans yet."));
    return;
  }
  const byFolder = new Map();
  const unfiled = [];
  for (const s of state.scans) {
    if (s.folder_id) {
      if (!byFolder.has(s.folder_id)) byFolder.set(s.folder_id, []);
      byFolder.get(s.folder_id).push(s);
    } else {
      unfiled.push(s);
    }
  }
  // With no folders defined, keep the classic flat list.
  if (!state.folders.length) {
    for (const s of unfiled) container.append(scanItemEl(s));
    return;
  }
  for (const f of state.folders) container.append(folderGroupEl(f, byFolder.get(f.id) || []));
  container.append(unfiledGroupEl(unfiled));
}

// ---------------------------------------------------------------------------
// Folder actions
// ---------------------------------------------------------------------------
async function createFolderPrompt() {
  const name = prompt("New folder name:");
  if (name === null) return null;
  const nn = name.trim();
  if (!nn) return null;
  try {
    const f = await api("/api/folders", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: nn }),
    });
    state.folderOpen[f.id] = true; saveFolderOpen();
    await loadScans(state.scan ? state.scan.id : null);
    toast(`Folder "${f.name}" created`);
    return f.id;
  } catch (e) { toast("Could not create folder: " + e.message, true); return null; }
}

async function renameFolder(f) {
  const name = prompt("Rename folder:", f.name);
  if (name === null) return;
  const nn = name.trim();
  if (!nn || nn === f.name) return;
  try {
    await api(`/api/folders/${f.id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: nn }),
    });
    await loadScans(state.scan ? state.scan.id : null);
    toast("Folder renamed");
  } catch (e) { toast("Rename failed: " + e.message, true); }
}

async function deleteFolder(f) {
  if (!confirm(`Delete folder "${f.name}"?\nScans inside move to Unfiled — they are NOT deleted.`)) return;
  try {
    await api(`/api/folders/${f.id}`, { method: "DELETE" });
    await loadScans(state.scan ? state.scan.id : null);
    toast(`Folder "${f.name}" deleted`);
  } catch (e) { toast("Delete failed: " + e.message, true); }
}

async function moveScans(ids, folderId) {
  if (!ids.length) return;
  try {
    const r = await api("/api/scans/move", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids, folder_id: folderId }),
    });
    state.selected.clear();
    await loadScans(state.scan ? state.scan.id : null);
    const dest = folderId
      ? (state.folders.find((x) => x.id === folderId) || {}).name || "folder"
      : "Unfiled";
    toast(`Moved ${r.moved} scan(s) → ${dest}`);
  } catch (e) { toast("Move failed: " + e.message, true); }
}

function moveSelected(folderId) {
  const ids = [...state.selected];
  if (!ids.length) { toast("Select scans first", true); return; }
  moveScans(ids, folderId);
}

function renderMoveMenu() {
  const menu = $("#moveMenu");
  menu.innerHTML = "";
  const mk = (label, folderId) => {
    const b = el("button", "menu-item", label);
    b.onclick = () => { closeAllMenus(); moveSelected(folderId); };
    return b;
  };
  for (const f of state.folders) menu.append(mk("📁 " + f.name, f.id));
  menu.append(mk("○ Unfiled (no folder)", null));
  const nf = el("button", "menu-item", "＋ New folder…");
  nf.onclick = async () => {
    closeAllMenus();
    const sel = [...state.selected];
    const id = await createFolderPrompt();
    if (id && sel.length) moveScans(sel, id);
  };
  menu.append(nf);
}

function updateMergeUI() {
  const n = state.selected.size;
  const total = state.scans.length;
  // top: merge all
  const mergeAll = $("#mergeAllBtn");
  mergeAll.disabled = total < 2;
  mergeAll.textContent = total >= 2 ? `⧉ Merge all (${total})` : "⧉ Merge all";
  // contextual selection bar
  $("#selectionBar").hidden = n === 0;
  $("#selCount").textContent = n ? `${n} selected` : "";
  $("#mergeBtn").disabled = n < 2;
  // select-all state
  const all = $("#selectAll");
  all.checked = total > 0 && n === total;
  all.indeterminate = n > 0 && n < total;
  $("#selectHint").textContent = "";
}

// lightweight dropdown menus
function setupMenus() {
  $$(".menu-toggle").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const list = btn.parentElement.querySelector(".menu-list");
      const open = !list.hidden;
      closeAllMenus();
      list.hidden = open;
    });
  });
  document.addEventListener("click", closeAllMenus);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeAllMenus(); });
}
function closeAllMenus() { $$(".menu-list").forEach((l) => (l.hidden = true)); }

async function importAndMerge(fileList) {
  const folderId = pendingImportFolder; pendingImportFolder = null;
  const files = [...fileList];
  if (!files.length) return;
  const fd = new FormData();
  for (const f of files) fd.append("files", f);
  if (folderId != null) fd.append("folder_id", folderId);
  try {
    const r = await api("/api/scans/import-merge", { method: "POST", body: fd });
    await loadScans(r.id);
    let msg = r.merged_from > 1
      ? `Imported & merged ${r.merged_from} file(s) → "${r.name}"`
      : `Imported "${r.name}"`;
    const skipped = r.skipped || [];
    if (skipped.length) {
      msg += ` — skipped ${skipped.length} bad file(s)`;
      console.warn("Skipped files:", skipped);
    }
    toast(msg);
  } catch (e) { toast("Import & merge failed: " + e.message, true); }
}

async function mergeAllScans() {
  const ids = state.scans.map((s) => s.id);
  if (ids.length < 2) { toast("Need at least two scans to merge", true); return; }
  const name = prompt(`Merge ALL ${ids.length} scans into a new scan.\nName:`, "Merged: all scans");
  if (name === null) return;
  try {
    const r = await api("/api/scans/merge", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_ids: ids, name: name.trim() }),
    });
    state.selected.clear();
    await loadScans(r.id);
    toast(`Merged ${ids.length} scans → "${r.name}"`);
  } catch (e) { toast("Merge failed: " + e.message, true); }
}

async function deleteSelected() {
  const ids = [...state.selected];
  if (!ids.length) return;
  if (!confirm(`Delete ${ids.length} selected scan(s)? This cannot be undone.`)) return;
  try {
    await api("/api/scans/delete", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids }),
    });
    if (state.scan && ids.includes(state.scan.id)) {
      state.scan = null;
      $("#scanView").hidden = true; $("#emptyState").hidden = false;
    }
    state.selected.clear();
    await loadScans();
    toast(`Deleted ${ids.length} scan(s)`);
  } catch (e) { toast("Delete failed: " + e.message, true); }
}

async function clearDatabase() {
  const total = state.scans.length;
  if (!total) { toast("No scans to delete"); return; }
  if (!confirm(`Delete ALL ${total} scan(s) from the database? This cannot be undone.\n\n` +
               `Tip: use ⤓ Backup first if you might want them later.`)) return;
  try {
    const r = await api("/api/scans/delete-all", { method: "POST" });
    state.scan = null; state.selected.clear();
    $("#scanView").hidden = true; $("#emptyState").hidden = false;
    await loadScans();
    await loadJobs();
    toast(`Cleared ${r.deleted} scan(s)`);
  } catch (e) { toast("Clear failed: " + e.message, true); }
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------
async function importFiles(fileList) {
  const folderId = pendingImportFolder; pendingImportFolder = null;
  let lastId = null;
  for (const file of fileList) {
    const fd = new FormData();
    fd.append("file", file);
    if (folderId != null) fd.append("folder_id", folderId);
    try {
      const r = await api("/api/scans/import", { method: "POST", body: fd });
      lastId = r.id;
      toast(`Imported "${r.name}" — ${r.host_count} host(s)`);
    } catch (e) {
      toast(`Import failed: ${e.message}`, true);
    }
  }
  await loadScans(lastId);
}

// ---------------------------------------------------------------------------
// Open scan
// ---------------------------------------------------------------------------
async function openScan(id) {
  state.scan = await api(`/api/scans/${id}`);
  state.hostId = null;
  $("#emptyState").hidden = true;
  $("#scanView").hidden = false;
  $$("#scanList .scan-item").forEach((li) =>
    li.classList.toggle("active", Number(li.dataset.id) === id));
  renderScanHeader();
  $("#scanNotes").value = state.scan.notes || "";
  $("#scanNotesHint").textContent = "";
  renderHostTable();
  renderHostDetail();

  // EyeWitness screenshots for this scan
  stopEwPoll();
  state.shots = [];
  await loadScreenshots(id);
  refreshEwStatus(id); // resume showing progress if a run is in flight
  loadAgents();        // keep the deeper-scan agent picker fresh
}

// ---------------------------------------------------------------------------
// EyeWitness screenshots
// ---------------------------------------------------------------------------
async function loadScreenshots(scanId) {
  try {
    state.shots = await api(`/api/scans/${scanId}/screenshots`);
  } catch (_) { state.shots = []; }
  renderGallery();
  renderHostDetail();
}

function shotsForIp(ip) {
  return (state.shots || []).filter((s) => s.ip === ip);
}

function renderGallery() {
  const gal = $("#shotsGallery");
  const block = $("#shotsBlock");
  const shots = state.shots || [];
  $("#shotsCount").textContent = shots.length ? `${shots.length}` : "";
  gal.innerHTML = "";
  for (const s of shots) {
    gal.append(thumbEl(s));
  }
  // Show the block if there are shots or a run is active/reported
  const st = state.ewStatus && state.ewStatus.state;
  block.hidden = !(shots.length || (st && st !== "idle"));
  if (shots.length && block.hidden === false && !block.open) block.open = true;
}

function thumbEl(s) {
  const fig = el("figure", "thumb");
  const img = el("img");
  img.src = `/api/screenshots/${s.id}`;
  img.loading = "lazy";
  img.alt = s.url || `${s.ip}:${s.port}`;
  const cap = el("figcaption", null, s.url || `${s.ip}:${s.port}`);
  fig.append(img, cap);
  fig.onclick = () => openLightbox(s);
  return fig;
}

function openLightbox(s) {
  $("#lightboxImg").src = `/api/screenshots/${s.id}`;
  $("#lightboxLabel").textContent = s.url || `${s.ip}:${s.port}`;
  $("#lightbox").hidden = false;
}

async function refreshEwStatus(scanId) {
  try {
    const st = await api(`/api/scans/${scanId}/eyewitness/status`);
    state.ewStatus = st;
    renderEwStatus();
    if (st.state === "running") startEwPoll(scanId);
  } catch (_) {}
}

function renderEwStatus() {
  const st = state.ewStatus || {};
  const elx = $("#shotsStatus");
  if (!st.state || st.state === "idle") { elx.textContent = ""; elx.className = "ew-status"; return; }
  let txt = st.message || st.state;
  if (st.state === "running" && st.total) txt = `${st.message || "running…"}`;
  elx.textContent = txt;
  elx.className = "ew-status " + st.state;
  $("#shotsBlock").hidden = false;
}

function startEwPoll(scanId) {
  stopEwPoll();
  state.ewPoll = setInterval(async () => {
    if (!state.scan || state.scan.id !== scanId) { stopEwPoll(); return; }
    try {
      const st = await api(`/api/scans/${scanId}/eyewitness/status`);
      state.ewStatus = st;
      renderEwStatus();
      if (st.state !== "running") {
        stopEwPoll();
        await loadScreenshots(scanId);
        setEwBtnBusy(false);
        if (st.state === "done") toast(st.message || "EyeWitness done");
        else if (st.state === "error") toast(st.message || "EyeWitness error", true);
      }
    } catch (_) { stopEwPoll(); setEwBtnBusy(false); }
  }, 1500);
}

function stopEwPoll() {
  if (state.ewPoll) { clearInterval(state.ewPoll); state.ewPoll = null; }
}

function setEwBtnBusy(busy) {
  const b = $("#eyewitnessBtn");
  b.disabled = busy;
  b.innerHTML = busy ? "📷 Running…" : '📷 EyeWitness <span class="caret">▾</span>';
}

// Populate the EyeWitness "Run locally / Run on <agent>" menu.
function renderEwMenu() {
  const menu = $("#ewMenu");
  menu.innerHTML = "";
  const mk = (label, agent) => {
    const b = el("button", "menu-item", label);
    b.onclick = () => { closeAllMenus(); startEyewitness(agent); };
    return b;
  };
  menu.append(mk("▶ Run locally", "local"));
  const ewAgents = (state.agents || []).filter((a) => a.online && a.has_eyewitness);
  for (const a of ewAgents) menu.append(mk(`⛓ Run on ${a.name}`, a.agent_uid));
  if (!ewAgents.length) {
    const hint = el("div", "menu-item ew-hint", "No online agents have EyeWitness");
    menu.append(hint);
  }
}

async function startEyewitness(agent) {
  if (!state.scan) return;
  const sid = state.scan.id;
  setEwBtnBusy(true);
  $("#shotsBlock").hidden = false;
  try {
    const q = agent && agent !== "local" ? `?agent=${encodeURIComponent(agent)}` : "";
    const st = await api(`/api/scans/${sid}/eyewitness${q}`, { method: "POST" });
    state.ewStatus = st;
    renderEwStatus();
    if (st.state === "running") startEwPoll(sid);
    else {
      setEwBtnBusy(false);
      await loadScreenshots(sid);
      if (st.state === "error") toast(st.message || "EyeWitness error", true);
    }
  } catch (e) {
    setEwBtnBusy(false);
    toast("EyeWitness failed: " + e.message, true);
  }
}

async function renameScanPrompt() {
  if (!state.scan) return;
  const name = prompt("Rename scan:", state.scan.name);
  if (name === null) return;
  const nn = name.trim();
  if (!nn || nn === state.scan.name) return;
  try {
    await api(`/api/scans/${state.scan.id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: nn }),
    });
    state.scan.name = nn;
    $("#scanName").textContent = nn;
    $("#scanName").title = nn;
    loadScans();
    toast("Renamed");
  } catch (e) { toast("Rename failed: " + e.message, true); }
}

function renderScanHeader() {
  const s = state.scan;
  $("#scanName").textContent = s.name;
  $("#scanName").title = s.name;
  $("#scanSource").textContent = s.source_type;
  const meta = [];
  if (s.scanner_version) meta.push(`nmap ${s.scanner_version}`);
  const up = s.hosts.filter((h) => h.state === "up").length;
  const openPorts = s.hosts.reduce((n, h) => n + h.ports.filter((p) => p.state === "open").length, 0);
  meta.push(`${s.hosts.length} host(s), ${up} up`);
  meta.push(`${openPorts} open port(s)`);
  const parts = [`<span>${meta.join(" &nbsp;·&nbsp; ")}</span>`];
  if (s.args) parts.push(`<div class="cmd" title="${escapeHtml(s.args)}">Command: <code>${escapeHtml(s.args)}</code></div>`);
  const times = [];
  if (s.started_at) times.push(`🕐 Started: ${escapeHtml(fmtTime(s.started_at))}`);
  if (s.imported_at) times.push(`Imported: ${escapeHtml(fmtTime(s.imported_at))}`);
  if (times.length) parts.push(`<div class="scan-times">${times.join(" &nbsp;·&nbsp; ")}</div>`);
  $("#scanMeta").innerHTML = parts.join("");
}

// ---------------------------------------------------------------------------
// Host table
// ---------------------------------------------------------------------------
function hostMatchesFilter(h) {
  const f = state.filter.trim().toLowerCase();
  if (!f) return true;
  if ((h.ip || "").toLowerCase().includes(f)) return true;
  if ((h.hostname || "").toLowerCase().includes(f)) return true;
  if ((h.os_name || "").toLowerCase().includes(f)) return true;
  for (const p of h.ports) {
    if (String(p.portid).includes(f)) return true;
    if ((p.service || "").toLowerCase().includes(f)) return true;
    if ((p.product || "").toLowerCase().includes(f)) return true;
    if ((p.version || "").toLowerCase().includes(f)) return true;
  }
  return false;
}

function openPortCount(h) {
  return h.ports.filter((p) => p.state === "open").length;
}

function portVisible(p) {
  // Only the exact state nmap reported controls visibility — never inferred.
  const st = (p.state || "").toLowerCase();
  if (st === "open") return state.portStates.open;
  if (st === "closed") return state.portStates.closed;
  if (st === "filtered") return state.portStates.filtered;
  if (st === "open|filtered") return state.portStates.openfiltered;
  return true; // any other state shown as-is, not assumed
}

function extraVisible(ep) {
  if (!ep.count) return false;
  const st = (ep.state || "").toLowerCase();
  if (st === "open") return state.portStates.open;
  if (st === "closed") return state.portStates.closed;
  if (st === "filtered") return state.portStates.filtered;
  return true;
}

// a host is shown when it has at least one port or extraports bucket in an enabled state
function hostHasVisiblePorts(h) {
  const ps = state.portStates;
  if (ps.open && ps.filtered && ps.closed && ps.openfiltered) return true; // all on → no filtering
  for (const p of h.ports) if (portVisible(p)) return true;
  for (const ep of (h.extraports || [])) if (extraVisible(ep)) return true;
  return false;
}

// counts of each state for a host (individual ports + extraports buckets)
function stateCounts(h) {
  // Count only exact states nmap reported. Ambiguous states like "open|filtered"
  // are NOT counted as open/closed/filtered — we do not assume.
  const c = { open: 0, closed: 0, filtered: 0, openfiltered: 0 };
  for (const p of h.ports) {
    const st = (p.state || "").toLowerCase();
    if (st === "open") c.open += 1;
    else if (st === "closed") c.closed += 1;
    else if (st === "filtered") c.filtered += 1;
    else if (st === "open|filtered") c.openfiltered += 1;
  }
  for (const ep of (h.extraports || [])) {
    const st = (ep.state || "").toLowerCase();
    if (st === "open") c.open += ep.count || 0;
    else if (st === "closed") c.closed += ep.count || 0;
    else if (st === "filtered") c.filtered += ep.count || 0;
    else if (st === "open|filtered") c.openfiltered += ep.count || 0;
  }
  return c;
}

function renderHostTable() {
  const body = $("#hostTableBody");
  body.innerHTML = "";
  let hosts = state.scan.hosts.filter(hostMatchesFilter);
  if (state.flaggedOnly) hosts = hosts.filter((h) => h.flagged);
  hosts = hosts.filter(hostHasVisiblePorts);

  const { key, dir } = state.sort;
  hosts.sort((a, b) => {
    let va, vb;
    switch (key) {
      case "hostname": va = a.hostname || ""; vb = b.hostname || ""; break;
      case "state": va = a.state || ""; vb = b.state || ""; break;
      case "open": va = stateCounts(a).open; vb = stateCounts(b).open; break;
      case "closed": va = stateCounts(a).closed; vb = stateCounts(b).closed; break;
      case "filtered": va = stateCounts(a).filtered; vb = stateCounts(b).filtered; break;
      case "openfiltered": va = stateCounts(a).openfiltered; vb = stateCounts(b).openfiltered; break;
      case "os": va = a.os_name || ""; vb = b.os_name || ""; break;
      case "checked": va = a.checked ? 1 : 0; vb = b.checked ? 1 : 0; break;
      case "flagged": va = a.flagged ? 1 : 0; vb = b.flagged ? 1 : 0; break;
      default: va = ipKey(a.ip); vb = ipKey(b.ip);
    }
    if (va < vb) return -dir;
    if (va > vb) return dir;
    return 0;
  });

  for (const h of hosts) {
    const tr = el("tr");
    tr.dataset.id = h.id;
    if (h.id === state.hostId) tr.classList.add("active");
    if (h.checked) tr.classList.add("checked");

    // checked / reviewed checkbox
    const cbTd = el("td", "chk-col");
    const cb = el("input");
    cb.type = "checkbox";
    cb.checked = !!h.checked;
    cb.title = "Mark this host as checked";
    cb.addEventListener("click", (e) => e.stopPropagation());
    cb.addEventListener("change", async () => {
      const val = cb.checked;
      try {
        await api(`/api/hosts/${h.id}/checked`, {
          method: "PUT", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ checked: val }),
        });
        h.checked = val ? 1 : 0;
        tr.classList.toggle("checked", val);
      } catch (err) {
        cb.checked = !val;
        toast("Could not save: " + err.message, true);
      }
    });
    cbTd.append(cb);
    tr.append(cbTd);

    // flag-for-later toggle
    if (h.flagged) tr.classList.add("flagged");
    const flagTd = el("td", "flag-col");
    const flag = el("button", "flag-btn" + (h.flagged ? " on" : ""), h.flagged ? "⚑" : "⚐");
    flag.title = h.flagged ? "Flagged — click to unflag" : "Flag for later";
    flag.addEventListener("click", async (e) => {
      e.stopPropagation();
      const val = !h.flagged;
      try {
        await api(`/api/hosts/${h.id}/flagged`, {
          method: "PUT", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ flagged: val }),
        });
        h.flagged = val ? 1 : 0;
        flag.textContent = val ? "⚑" : "⚐";
        flag.classList.toggle("on", val);
        flag.title = val ? "Flagged — click to unflag" : "Flag for later";
        tr.classList.toggle("flagged", val);
        if (state.flaggedOnly && !val) renderHostTable();
      } catch (err) { toast("Could not save flag: " + err.message, true); }
    });
    flagTd.append(flag);
    tr.append(flagTd);

    tr.append(tdHtml(`<span class="ip">${escapeHtml(h.ip)}</span>`));
    tr.append(el("td", null, h.hostname || "—"));
    const st = el("td");
    st.innerHTML = `<span class="state-${h.state === "up" ? "up" : "down"}">${escapeHtml(h.state || "?")}</span>`;
    tr.append(st);
    const c = stateCounts(h);
    const openTd = el("td", "num");
    openTd.innerHTML = `<span class="pill ${c.open ? "pill-open" : "pill-zero"}">${c.open}</span>`;
    tr.append(openTd);
    const closedTd = el("td", "num");
    closedTd.innerHTML = c.closed ? `<span class="pill pill-closed">${c.closed}</span>` : `<span class="muted">—</span>`;
    tr.append(closedTd);
    const filteredTd = el("td", "num");
    filteredTd.innerHTML = c.filtered ? `<span class="pill pill-filtered">${c.filtered}</span>` : `<span class="muted">—</span>`;
    tr.append(filteredTd);
    const ofTd = el("td", "num");
    ofTd.innerHTML = c.openfiltered ? `<span class="pill pill-openfiltered">${c.openfiltered}</span>` : `<span class="muted">—</span>`;
    tr.append(ofTd);
    tr.append(el("td", null, h.os_name || "—"));
    tr.onclick = () => selectHost(h.id);
    body.append(tr);
  }

  // update sort indicators
  $$("#hostTable thead th").forEach((th) => {
    const base = th.textContent.replace(/[▲▼]/g, "").trim();
    th.textContent = base + (th.dataset.sort === key ? (dir === 1 ? " ▲" : " ▼") : "");
  });

  if (!hosts.length) {
    const tr = el("tr");
    const td = el("td", "num");
    td.colSpan = 10; td.style.textAlign = "center"; td.style.color = "var(--muted)";
    td.style.padding = "26px"; td.textContent = "No hosts match.";
    tr.append(td); body.append(tr);
  }
}

function tdHtml(html) { const td = el("td"); td.innerHTML = html; return td; }

// Select a host and bring its (now full-width, below-the-list) results into view.
function selectHost(id) {
  state.hostId = id;
  renderHostTable();
  renderHostDetail();
  const d = $("#hostDetail");
  if (d) d.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ---------------------------------------------------------------------------
// Host detail
// ---------------------------------------------------------------------------
function renderHostDetail() {
  const pane = $("#hostDetail");
  const host = state.scan.hosts.find((h) => h.id === state.hostId);
  if (!host) {
    pane.innerHTML = '<div class="host-detail-empty">Select a host to see its ports and notes.</div>';
    return;
  }
  pane.innerHTML = "";
  const head = el("div");
  head.innerHTML = `<span class="hd-ip">${escapeHtml(host.ip)}</span>` +
    (host.hostname ? `<span class="hd-host">${escapeHtml(host.hostname)}</span>` : "");
  pane.append(head);

  const meta = [];
  meta.push(`State: <span class="state-${host.state === "up" ? "up" : "down"}">${escapeHtml(host.state || "?")}</span>`);
  if (host.os_name) meta.push(`OS: ${escapeHtml(host.os_name)}${host.os_accuracy ? ` (${host.os_accuracy}%)` : ""}`);
  const m = el("div", "hd-meta"); m.innerHTML = meta.join(" &nbsp;·&nbsp; ");
  pane.append(m);

  const shown = host.ports.filter(portVisible);
  const visibleExtra = (host.extraports || []).filter(extraVisible);
  if (!shown.length && !visibleExtra.length) {
    const anyData = host.ports.length || (host.extraports || []).length;
    pane.append(el("div", "muted",
      anyData ? "No ports match the current state filter." : "No ports to show."));
  }
  for (const p of shown) {
    const row = el("div", "port-row");
    const ph = el("div", "port-head");
    ph.innerHTML =
      `<span class="port-num">${p.portid}/${escapeHtml(p.protocol)}</span>` +
      `<span class="port-state state-${p.state === "open" ? "up" : "down"}">${escapeHtml(p.state)}</span>` +
      `<span class="port-svc">${escapeHtml(p.service || "")}</span>` +
      `<span class="port-ver">${escapeHtml(versionStr(p))}</span>`;
    row.append(ph);

    // --- per-port notes (built first so the toggle button can reference it) ---
    const noteWrap = el("div", "port-note");
    noteWrap.hidden = !p.notes;
    const ta = el("textarea", "notes small");
    ta.value = p.notes || "";
    ta.placeholder = "Notes about this port…";
    const nhint = el("span", "save-hint");
    const saveNote = debounce(async () => {
      try {
        await api(`/api/ports/${p.id}/notes`, {
          method: "PUT", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ notes: ta.value }),
        });
        p.notes = ta.value;
        noteBtn.textContent = p.notes ? "✎ note" : "＋ note";
        nhint.textContent = "saved ✓";
        setTimeout(() => (nhint.textContent = ""), 1200);
      } catch (e) { toast("Note save failed: " + e.message, true); }
    }, 500);
    ta.oninput = () => { nhint.textContent = "saving…"; saveNote(); };
    noteWrap.append(ta, nhint);

    // --- action chips: connect commands + note toggle ---
    const actions = el("div", "port-actions");
    for (const hint of connectHints(host.ip, p)) {
      const b = el("button", "chip", `⧉ ${hint.label}`);
      b.title = "Copy: " + hint.text;
      b.onclick = () => copyText(hint.text, hint.label);
      actions.append(b);
      if (hint.open) {
        const ob = el("button", "chip", "↗ open");
        ob.title = "Open " + hint.open + " in a new tab";
        ob.onclick = () => window.open(hint.open, "_blank", "noopener");
        actions.append(ob);
      }
    }
    // nmap: quick -sCV scan of this port (choose where to run), or copy command
    const nflags = portScanFlags(p);
    const parentId = () => (state.deepMerge !== false ? state.scan.id : null);
    const online = (state.agents || []).filter((a) => a.online);

    if (online.length) {
      // dropdown: Run locally / Run on <agent>
      const menu = el("div", "menu chip-menu");
      const toggle = el("button", "chip chip-nmap", "⚡ nmap -sCV ▾");
      toggle.title = `Run: nmap ${nflags} ${host.ip}`;
      const list = el("div", "menu-list");
      list.hidden = true;
      const addItem = (label, agentId) => {
        const it = el("button", "menu-item", label);
        it.onclick = () => { list.hidden = true; runScan(host.ip, nflags, agentId, parentId()); };
        list.append(it);
      };
      addItem("▶ Run locally", "local");
      for (const a of online) addItem(`⛓ Run on ${a.name}`, a.agent_uid);
      toggle.onclick = (e) => { e.stopPropagation(); const open = !list.hidden; closeAllMenus(); list.hidden = open; };
      menu.append(toggle, list);
      actions.append(menu);
    } else {
      const nmapRun = el("button", "chip chip-nmap", "⚡ nmap -sCV");
      nmapRun.title = `Run locally: nmap ${nflags} ${host.ip}`;
      nmapRun.onclick = () => runScan(host.ip, nflags, "local", parentId());
      actions.append(nmapRun);
    }

    const nmapCopy = el("button", "chip", "⧉ cmd");
    nmapCopy.title = "Copy: nmap " + nflags + " " + host.ip;
    nmapCopy.onclick = () => copyText(`nmap ${nflags} ${host.ip}`, "nmap command");
    actions.append(nmapCopy);

    const noteBtn = el("button", "chip chip-note", p.notes ? "✎ note" : "＋ note");
    noteBtn.title = "Add a note to this port";
    noteBtn.onclick = () => { noteWrap.hidden = !noteWrap.hidden; if (!noteWrap.hidden) ta.focus(); };
    actions.append(noteBtn);
    row.append(actions);
    row.append(noteWrap);

    // --- port state disagreement (from a merge): compact per-file panel ---
    const disagree = (p.scripts || []).find((s) => s.id === "port-state-disagreement");
    if (disagree) row.append(portDisagreeEl(disagree.output));

    // --- merge provenance notes: fold into one collapsed section ---
    const mergeNotes = (p.scripts || []).filter((s) => s.id === "🔀 merge");
    if (mergeNotes.length) row.append(mergeNotesEl(mergeNotes));

    // --- script output (excluding the structured markers handled above) ---
    const scripts = (p.scripts || []).filter(
      (s) => s.id !== "port-state-disagreement" && s.id !== "🔀 merge");
    if (scripts.length) {
      const sc = el("div", "scripts");
      for (const s of scripts) {
        const d = el("div", "script");
        d.innerHTML = `<span class="script-id">${escapeHtml(s.id)}</span>` +
          (s.output ? `<pre>${escapeHtml(s.output)}</pre>` : "");
        sc.append(d);
      }
      row.append(sc);
    }

    // --- Nessus findings that pertain to THIS port (matched by port/proto) ---
    const pf = (host.findings || []).filter(
      (f) => f.port === p.portid && (f.protocol || "tcp") === (p.protocol || "tcp"));
    if (pf.length) {
      const wrap = el("div", "port-findings");
      const crit = pf.filter((f) => (f.severity || 0) >= 3).length;
      const label = `Nessus — ${pf.length} finding${pf.length > 1 ? "s" : ""}` +
        (crit ? ` (${crit} high/critical)` : "");
      wrap.append(el("div", "pf-label", label));
      for (const f of pf) wrap.append(findingEl(f));
      row.append(wrap);
    }

    pane.append(row);
  }

  // extraports summary (nmap collapses closed/filtered ports into a count)
  for (const ep of visibleExtra) {
    const row = el("div", "extraports-row");
    const cls = ep.state === "open" ? "up" : "down";
    row.innerHTML =
      `<span class="ep-count state-${cls}">${ep.count}</span> ` +
      `${escapeHtml(ep.state)} port(s)` +
      (ep.reason ? ` <span class="muted">(${escapeHtml(ep.reason)})</span>` : "");
    pane.append(row);
  }

  // Nessus findings for this host (severity summary + collapsible detail)
  if (host.findings && host.findings.length) renderFindings(pane, host.findings);

  // --- deeper scan: copy the command, or run it locally / on an agent ---
  pane.append(el("div", "hd-notes-label", "Deeper scan"));
  const ds = el("div", "deepscan");
  const flags = el("input", "filter");
  flags.value = state.deepFlags;
  flags.placeholder = "nmap flags, e.g. -sCV -A -p-";
  const cmdPreview = el("div", "deepscan-cmd");
  const buildCmd = () => `nmap ${flags.value} ${host.ip}`.replace(/\s+/g, " ").trim();
  const refresh = () => { cmdPreview.textContent = buildCmd(); };
  flags.addEventListener("input", () => { state.deepFlags = flags.value; refresh(); });

  // agent picker: Local + any online agents
  const agentRow = el("div", "deepscan-agent");
  agentRow.append(el("span", "muted", "Run on:"));
  const sel = el("select", "agent-select");
  const online = (state.agents || []).filter((a) => a.online);
  sel.append(optionEl("local", "Local (this machine)"));
  for (const a of online) sel.append(optionEl(a.agent_uid, `${a.name} · agent`));
  sel.value = online.some((a) => a.agent_uid === state.deepAgent) ? state.deepAgent : "local";
  sel.onchange = () => { state.deepAgent = sel.value; };
  agentRow.append(sel);

  // auto-merge toggle
  const mergeRow = el("label", "deepscan-merge");
  const mergeCb = el("input");
  mergeCb.type = "checkbox";
  mergeCb.checked = state.deepMerge !== false;
  mergeCb.onchange = () => { state.deepMerge = mergeCb.checked; };
  mergeRow.append(mergeCb, document.createTextNode(" merge results into this scan"));

  const dsActions = el("div", "deepscan-actions");
  const copyCmd = el("button", "btn btn-sm", "📋 Copy command");
  copyCmd.onclick = () => copyText(buildCmd(), "nmap command");
  const runBtn = el("button", "btn btn-sm btn-primary", "▶ Run scan");
  runBtn.onclick = () => runScan(host.ip, flags.value, sel.value,
                                 mergeCb.checked ? state.scan.id : null);
  dsActions.append(copyCmd, runBtn);

  ds.append(flags, cmdPreview, agentRow, mergeRow, dsActions);
  pane.append(ds);
  refresh();

  // screenshots for this host, if any
  const hshots = shotsForIp(host.ip);
  if (hshots.length) {
    pane.append(el("div", "hd-notes-label", "Screenshots"));
    const strip = el("div", "gallery");
    for (const s of hshots) strip.append(thumbEl(s));
    pane.append(strip);
  }

  pane.append(el("div", "hd-notes-label", "Host notes"));
  const ta = el("textarea", "notes");
  ta.value = host.notes || "";
  ta.placeholder = "Notes about this host…";
  const hint = el("span", "save-hint");
  const save = debounce(async () => {
    try {
      await api(`/api/hosts/${host.id}/notes`, {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: ta.value }),
      });
      host.notes = ta.value;
      hint.textContent = "saved ✓";
      setTimeout(() => (hint.textContent = ""), 1200);
    } catch (e) { toast("Note save failed: " + e.message, true); }
  }, 500);
  ta.oninput = () => { hint.textContent = "saving…"; save(); };
  pane.append(ta);
  pane.append(hint);
}

function versionStr(p) {
  return [p.product, p.version, p.extrainfo].filter(Boolean).join(" ").trim();
}

// Fold merge-provenance notes into one collapsed section; colour the
// "Found in" lines green and "Not seen in" lines red.
function mergeNotesEl(notes) {
  const d = el("details", "merge-notes");
  const sum = el("summary");
  sum.innerHTML = `<span class="mn-ico">🔀</span> Merge provenance ` +
    `<span class="mn-count">${notes.length}</span>`;
  d.append(sum);
  const body = el("div", "mn-body");
  for (const n of notes) {
    const block = el("div", "mn-block");
    for (const raw of (n.output || "").split("\n")) {
      const line = el("div", "mn-line");
      const t = raw.trim();
      if (t.startsWith("Found in:")) line.classList.add("mn-found");
      else if (t.startsWith("Not seen in:")) line.classList.add("mn-missing");
      else if (t.startsWith("Differs") || t.startsWith("•") || raw.startsWith("  "))
        line.classList.add("mn-diff");
      line.textContent = raw;
      block.append(line);
    }
    body.append(block);
  }
  d.append(body);
  return d;
}

// Compact panel showing which merged file reported which state for a port,
// rendered only when the files disagreed on the state.
function portDisagreeEl(jsonStr) {
  let prov;
  try { prov = JSON.parse(jsonStr); } catch (_) { return el("span"); }
  const box = el("div", "port-disagree");
  box.append(el("div", "pd-title", "⚠ Files disagree on state"));
  const pillClass = (state) => {
    const st = (state || "").toLowerCase();
    if (st === "open") return "pill-open";
    if (st === "closed") return "pill-closed";
    if (st === "filtered") return "pill-filtered";
    if (st === "open|filtered") return "pill-openfiltered";
    return "pill-zero";
  };
  for (const entry of prov) {
    const r = el("div", "pd-row");
    r.append(el("span", "pill " + pillClass(entry.state), entry.state));
    r.append(el("span", "pd-scans", (entry.scans || []).join(", ")));
    box.append(r);
  }
  return box;
}

// ---------------------------------------------------------------------------
// Nessus findings (per host)
// ---------------------------------------------------------------------------
const SEV_LABELS = { 4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info" };

function renderFindings(pane, findings) {
  pane.append(el("div", "hd-notes-label", "Nessus findings"));

  // severity summary badges (Critical → Info)
  const counts = { 4: 0, 3: 0, 2: 0, 1: 0, 0: 0 };
  for (const f of findings) counts[f.severity || 0] = (counts[f.severity || 0] || 0) + 1;
  const summary = el("div", "sev-summary");
  for (const s of [4, 3, 2, 1, 0]) {
    if (!counts[s]) continue;
    summary.append(el("span", `sev-badge sev-${s}`, `${SEV_LABELS[s]} ${counts[s]}`));
  }
  pane.append(summary);

  // "hide info" toggle — info findings are noisy; default to hidden if there are non-info ones
  const hasReal = findings.some((f) => (f.severity || 0) > 0);
  const list = el("div", "findings");
  const draw = (showInfo) => {
    list.innerHTML = "";
    for (const f of findings) {
      if (!showInfo && (f.severity || 0) === 0) continue;
      list.append(findingEl(f));
    }
  };
  if (counts[0] && hasReal) {
    const toggle = el("label", "chk findings-info-toggle");
    const cb = el("input"); cb.type = "checkbox";
    toggle.append(cb, document.createTextNode(` show ${counts[0]} info finding(s)`));
    cb.onchange = () => draw(cb.checked);
    pane.append(toggle);
    draw(false);
  } else {
    draw(true);
  }
  pane.append(list);
}

function findingEl(f) {
  const sev = f.severity || 0;
  const d = el("details", `finding sev-border-${sev}`);
  const sum = el("summary");
  sum.append(el("span", `sev-tag sev-${sev}`, SEV_LABELS[sev] || "Info"));
  sum.append(el("span", "finding-name", f.name || "(unnamed)"));
  if (f.port) sum.append(el("span", "finding-port", `${f.port}/${f.protocol || "tcp"}`));
  if (f.cvss) sum.append(el("span", "finding-cvss", `CVSS ${f.cvss}`));
  d.append(sum);

  const body = el("div", "finding-body");
  const addText = (label, val) => {
    if (!val) return;
    const sec = el("div", "finding-sec");
    if (label) sec.append(el("div", "finding-sec-label", label));
    sec.append(el("div", "finding-sec-text", val));
    body.append(sec);
  };
  const addPre = (label, val) => {
    if (!val) return;
    const sec = el("div", "finding-sec");
    sec.append(el("div", "finding-sec-label", label));
    const pre = el("pre"); pre.textContent = val;
    sec.append(pre);
    body.append(sec);
  };

  const meta = [];
  if (f.plugin_id) meta.push(`Plugin ${f.plugin_id}`);
  if (f.family) meta.push(f.family);
  if (f.risk_factor && f.risk_factor.toLowerCase() !== "none") meta.push(`Risk: ${f.risk_factor}`);
  if ((f.cve || []).length) meta.push((f.cve || []).join(", "));
  if ((f.sources || []).length) meta.push(`from: ${(f.sources || []).join(", ")}`);
  addText("", meta.join("  ·  "));
  addText("Synopsis", f.synopsis);
  addText("Description", f.description);
  addText("Solution", f.solution);
  addPre("Output", f.output);
  d.append(body);
  return d;
}

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------------------------------------------------------------------------
// Phase 2 — rescan jobs + agents
// ---------------------------------------------------------------------------
function optionEl(value, label) { const o = el("option", null, label); o.value = value; return o; }

async function loadAgents() {
  try { state.agents = await api("/api/agents"); }
  catch (_) { state.agents = []; }
  updateAgentsBadge();
}
function updateAgentsBadge() {
  const n = (state.agents || []).filter((a) => a.online).length;
  const b = $("#agentsBadge");
  if (n > 0) { b.textContent = n; b.hidden = false; } else { b.hidden = true; }
}

async function runScan(ip, flags, agent, parentScanId) {
  try {
    const body = { target: ip, flags, agent };
    if (parentScanId) body.parent_scan_id = parentScanId;
    const job = await api("/api/jobs", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    openJobModal(job);
    loadJobs(); // reflect the new job in the sidebar immediately
  } catch (e) { toast("Scan failed: " + e.message, true); }
}

function openJobModal(job) {
  $("#jobTitle").textContent = `Scan job #${job.id} — ${job.target}`;
  $("#jobOutput").textContent = job.output || "(waiting for output…)";
  $("#jobOpenResult").hidden = true;
  $("#jobModal").hidden = false;
  renderJobStatus(job);
  startJobPoll(job.id);
}
function renderJobStatus(job) {
  const s = $("#jobStatus");
  s.textContent = job.status + (job.error ? " — " + job.error : "");
  const running = job.status === "running" || job.status === "queued";
  s.className = "ew-status " + (running ? "running" : job.status === "done" ? "done" : "error");
  $("#jobStop").disabled = !running;
}
function startJobPoll(jobId) {
  stopJobPoll();
  state.jobPoll = setInterval(async () => {
    let job;
    try { job = await api(`/api/jobs/${jobId}`); } catch (_) { stopJobPoll(); return; }
    const out = $("#jobOutput");
    const atBottom = out.scrollTop + out.clientHeight >= out.scrollHeight - 24;
    out.textContent = job.output || "";
    if (atBottom) out.scrollTop = out.scrollHeight;
    renderJobStatus(job);
    if (job.status !== "running" && job.status !== "queued") {
      stopJobPoll();
      if (job.result_scan_id) {
        const rb = $("#jobOpenResult");
        rb.hidden = false;
        rb.onclick = () => { $("#jobModal").hidden = true; loadScans(job.result_scan_id); };
        const merged = job.parent_scan_id && job.parent_scan_id === job.result_scan_id;
        toast(merged ? `Scan merged into scan #${job.result_scan_id}`
                     : `Scan complete → new scan #${job.result_scan_id}`);
        // if we're viewing the scan that just got updated, refresh it in place
        if (state.scan && state.scan.id === job.result_scan_id) {
          const keepHost = state.hostId;
          await openScan(job.result_scan_id);
          if (keepHost) { state.hostId = keepHost; renderHostTable(); renderHostDetail(); }
        }
      } else if (job.status === "error") {
        toast("Scan error: " + (job.error || ""), true);
      }
      loadScans();
    }
  }, 1000);
}
function stopJobPoll() { if (state.jobPoll) { clearInterval(state.jobPoll); state.jobPoll = null; } }

async function openJobById(id) {
  try { openJobModal(await api(`/api/jobs/${id}`)); }
  catch (e) { toast("Could not open job: " + e.message, true); }
}

// --- sidebar jobs panel ---
function agentLabel(agentId) {
  if (agentId === "local") return "Local";
  const a = (state.agents || []).find((x) => x.agent_uid === agentId);
  return a ? a.name : agentId.slice(0, 8) + "…";
}
async function loadJobs() {
  try { state.jobs = await api("/api/jobs?limit=25"); }
  catch (_) { state.jobs = []; }
  renderJobs();
}
function renderJobs() {
  const panel = $("#jobsPanel");
  const list = $("#jobsList");
  const jobs = state.jobs || [];
  panel.hidden = jobs.length === 0;
  const active = jobs.filter((j) => j.status === "running" || j.status === "queued").length;
  $("#jobsHint").textContent = active ? `${active} active` : "";
  list.innerHTML = "";
  for (const j of jobs) {
    const li = el("li", "job-item");
    const running = j.status === "running" || j.status === "queued";
    li.append(tdDot(j.status));
    const body = el("div", "job-body");
    body.append(el("div", "job-target", j.target));
    body.append(el("div", "job-sub", `${j.status} · ${agentLabel(j.agent)}`));
    li.append(body);
    const btn = el("button", "chip job-view", running ? "▸ output" : (j.result_scan_id ? "✓ scan" : "output"));
    btn.title = running ? "Watch live output" : "View output";
    btn.onclick = () => {
      if (!running && j.result_scan_id) { loadScans(j.result_scan_id); }
      else { openJobById(j.id); }
    };
    li.append(btn);
    list.append(li);
  }
}
function tdDot(status) {
  const d = el("span", "job-dot " + status);
  return d;
}
function startJobsPoll() {
  stopJobsPoll();
  state.jobsPoll = setInterval(loadJobs, 2500);
}
function stopJobsPoll() { if (state.jobsPoll) { clearInterval(state.jobsPoll); state.jobsPoll = null; } }

async function openAgentsModal() {
  try { $("#agentTokenField").value = (await api("/api/agent-token")).token; } catch (_) {}
  await loadAgents();
  renderAgentsList();
  $("#agentsModal").hidden = false;
  stopAgentsPoll();
  state.agentsPoll = setInterval(async () => { await loadAgents(); renderAgentsList(); }, 3000);
}
function stopAgentsPoll() { if (state.agentsPoll) { clearInterval(state.agentsPoll); state.agentsPoll = null; } }
function renderAgentsList() {
  const list = $("#agentsList");
  list.innerHTML = "";
  if (!state.agents.length) {
    list.append(el("div", "muted", "No agents yet. Download the agent and run it on another machine."));
    return;
  }
  for (const a of state.agents) {
    const row = el("div", "agent-item");
    row.innerHTML =
      `<span class="agent-dot ${a.online ? "on" : "off"}"></span>` +
      `<div class="agent-meta"><div class="agent-name">${escapeHtml(a.name || a.agent_uid)}</div>` +
      `<div class="muted agent-sub">${escapeHtml(a.platform || "")} · ` +
      `${a.online ? "online" : "offline"} · last seen ${escapeHtml((a.last_seen || "").replace("T", " ").slice(0, 19))}</div></div>`;
    list.append(row);
  }
}

// ---------------------------------------------------------------------------
// Wire up events
// ---------------------------------------------------------------------------
function init() {
  $("#fileInput").addEventListener("change", (e) => importFiles(e.target.files));
  $("#fileInput2").addEventListener("change", (e) => importFiles(e.target.files));
  // Nessus: multiple files aggregate by IP into one scan (single file just imports).
  $("#nessusInput").addEventListener("change", (e) => { importAndMerge(e.target.files); e.target.value = ""; });
  $("#importMergeInput").addEventListener("change", (e) => { importAndMerge(e.target.files); e.target.value = ""; });
  // Top-level import targets Unfiled — clear any pending folder from a cancelled "Import here".
  ["fileInput", "fileInput2", "nessusInput", "importMergeInput"].forEach((id) => {
    const lbl = document.querySelector(`label[for="${id}"]`);
    if (lbl) lbl.addEventListener("click", () => { pendingImportFolder = null; });
  });

  // scan notes autosave
  const scanNotesSave = debounce(async () => {
    if (!state.scan) return;
    try {
      await api(`/api/scans/${state.scan.id}/notes`, {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: $("#scanNotes").value }),
      });
      state.scan.notes = $("#scanNotes").value;
      $("#scanNotesHint").textContent = "saved ✓";
      setTimeout(() => ($("#scanNotesHint").textContent = ""), 1200);
    } catch (e) { toast("Note save failed: " + e.message, true); }
  }, 500);
  $("#scanNotes").addEventListener("input", () => {
    $("#scanNotesHint").textContent = "saving…"; scanNotesSave();
  });

  // rename scan (click to edit)
  const nameEl = $("#scanName");
  nameEl.addEventListener("click", () => {
    nameEl.contentEditable = "true"; nameEl.focus();
    document.execCommand && document.getSelection().selectAllChildren(nameEl);
  });
  nameEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); nameEl.blur(); }
  });
  nameEl.addEventListener("blur", async () => {
    nameEl.contentEditable = "false";
    const newName = nameEl.textContent.trim();
    if (!state.scan || !newName || newName === state.scan.name) {
      nameEl.textContent = state.scan ? state.scan.name : ""; return;
    }
    try {
      await api(`/api/scans/${state.scan.id}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newName }),
      });
      state.scan.name = newName; loadScans(); toast("Renamed");
    } catch (e) { toast("Rename failed: " + e.message, true); nameEl.textContent = state.scan.name; }
  });

  // rename (button + click name)
  $("#renameBtn").addEventListener("click", renameScanPrompt);

  // exports
  $("#exportTableBtn").addEventListener("click", () => {
    if (state.scan) window.location = `/api/scans/${state.scan.id}/export/table`;
  });
  $("#exportReportBtn").addEventListener("click", () => {
    if (state.scan) window.location = `/api/scans/${state.scan.id}/export/report`;
  });

  // EyeWitness — the toggle opens a "Run locally / Run on <agent>" menu
  $("#eyewitnessBtn").addEventListener("click", renderEwMenu);
  // agents modal
  $("#agentsBtn").addEventListener("click", openAgentsModal);
  $("#agentsClose").addEventListener("click", () => { $("#agentsModal").hidden = true; stopAgentsPoll(); });
  $("#agentsModal").addEventListener("click", (e) => { if (e.target.id === "agentsModal") { $("#agentsModal").hidden = true; stopAgentsPoll(); } });
  $("#copyTokenBtn").addEventListener("click", () => copyText($("#agentTokenField").value, "Token"));

  // job modal
  $("#jobClose").addEventListener("click", () => { $("#jobModal").hidden = true; stopJobPoll(); });
  $("#jobStop").addEventListener("click", async () => {
    const title = $("#jobTitle").textContent;
    const m = title.match(/#(\d+)/);
    if (!m) return;
    try { await api(`/api/jobs/${m[1]}/stop`, { method: "POST" }); toast("Stop requested"); }
    catch (e) { toast("Stop failed: " + e.message, true); }
  });

  // lightbox close
  $("#lightboxClose").addEventListener("click", () => { $("#lightbox").hidden = true; });
  $("#lightbox").addEventListener("click", (e) => { if (e.target.id === "lightbox") $("#lightbox").hidden = true; });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#lightbox").hidden = true; });

  // delete
  $("#deleteScanBtn").addEventListener("click", async () => {
    if (!state.scan) return;
    if (!confirm(`Delete scan "${state.scan.name}"? This cannot be undone.`)) return;
    try {
      await api(`/api/scans/${state.scan.id}`, { method: "DELETE" });
      const gone = state.scan.id; state.scan = null;
      $("#scanView").hidden = true; $("#emptyState").hidden = false;
      await loadScans();
      toast("Scan deleted");
    } catch (e) { toast("Delete failed: " + e.message, true); }
  });

  // filter + flagged-only + port-state toggles + sorting
  $("#hostFilter").addEventListener("input", (e) => { state.filter = e.target.value; renderHostTable(); });
  $("#flaggedOnly").addEventListener("change", (e) => { state.flaggedOnly = e.target.checked; renderHostTable(); });
  const wirePortState = (id, key) => $(id).addEventListener("change", (e) => {
    state.portStates[key] = e.target.checked; renderHostTable(); renderHostDetail();
  });
  wirePortState("#stOpen", "open");
  wirePortState("#stFiltered", "filtered");
  wirePortState("#stOpenFiltered", "openfiltered");
  wirePortState("#stClosed", "closed");
  $$("#hostTable thead th").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (state.sort.key === key) state.sort.dir *= -1;
      else state.sort = { key, dir: 1 };
      renderHostTable();
    });
  });

  setupMenus();

  // folders: create + move selected
  $("#newFolderBtn").addEventListener("click", createFolderPrompt);
  $("#moveBtn").addEventListener("click", renderMoveMenu);

  // merge all + bulk delete + select-all + clear database
  $("#mergeAllBtn").addEventListener("click", mergeAllScans);
  $("#deleteSelBtn").addEventListener("click", deleteSelected);
  $("#clearSelBtn").addEventListener("click", () => { state.selected.clear(); loadScans(); });
  $("#clearAllBtn").addEventListener("click", clearDatabase);
  $("#selectAll").addEventListener("change", (e) => {
    state.selected.clear();
    if (e.target.checked) for (const s of state.scans) state.selected.add(s.id);
    loadScans();
  });

  // backup / restore whole database
  $("#backupBtn").addEventListener("click", () => { window.location = "/api/backup"; });
  $("#restoreInput").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append("file", file);
    try {
      const r = await api("/api/restore", { method: "POST", body: fd });
      await loadScans();
      toast(`Restored ${r.imported} scan(s) from backup`);
    } catch (err) {
      toast("Restore failed: " + err.message, true);
    }
    e.target.value = ""; // allow re-selecting the same file
  });

  // merge selected scans
  $("#mergeBtn").addEventListener("click", async () => {
    const ids = [...state.selected];
    if (ids.length < 2) { toast("Select at least two scans", true); return; }
    const selNames = state.scans.filter((s) => state.selected.has(s.id)).map((s) => s.name);
    const suggested = "Merged: " + selNames.join(", ");
    const name = prompt(`Merge ${ids.length} scans into a new scan.\nName:`, suggested);
    if (name === null) return; // cancelled
    try {
      const r = await api("/api/scans/merge", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_ids: ids, name: name.trim() }),
      });
      state.selected.clear();
      await loadScans(r.id);
      toast(`Merged into "${r.name}" — ${r.host_count} host(s)`);
    } catch (e) { toast("Merge failed: " + e.message, true); }
  });

  // markdown import modal (sidebar button + empty-state button)
  const openMdModal = () => { $("#mdModal").hidden = false; $("#mdText").focus(); };
  $("#importMdBtn").addEventListener("click", openMdModal);
  $("#importMdBtn2").addEventListener("click", openMdModal);
  $("#mdCancel").addEventListener("click", () => { $("#mdModal").hidden = true; });
  $("#mdModal").addEventListener("click", (e) => { if (e.target.id === "mdModal") $("#mdModal").hidden = true; });
  $("#mdSubmit").addEventListener("click", async () => {
    const text = $("#mdText").value.trim();
    const name = $("#mdName").value.trim() || "Imported table";
    if (!text) { toast("Paste a table first", true); return; }
    try {
      const r = await api("/api/import/markdown", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, text }),
      });
      $("#mdModal").hidden = true; $("#mdText").value = "";
      await loadScans(r.id);
      toast(`Imported "${name}" — ${r.host_count} host(s)`);
    } catch (e) { toast("Import failed: " + e.message, true); }
  });

  loadFolderOpen();
  loadScans();
  loadAgents();
  loadJobs();
  startJobsPoll();
}

document.addEventListener("DOMContentLoaded", init);

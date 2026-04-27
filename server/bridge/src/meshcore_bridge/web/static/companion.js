/* MeshCore Companion-Detail-UI.
   Bootstrap (IDENTITY_ID, IDENTITY_NAME, AT_TARGETS) kommt als JSON-Block
   <script id="companion-bootstrap" type="application/json">…</script> aus
   dem Template — kein Jinja2-Inlining mehr. */

(() => {
  const _bootstrapEl = document.getElementById("companion-bootstrap");
  const CFG = _bootstrapEl ? JSON.parse(_bootstrapEl.textContent) : {};
  const IDENTITY_ID = CFG.identityId;
  const IDENTITY_NAME = CFG.identityName || "";
  const AT_TARGETS = CFG.atTargets || [];

  const API = "/api/v1/companion";
  // SSE liefert Push-Updates; Polling ist nur noch Fallback (zähe Verbindung,
  // verschluckte Events).
  const POLL_THREADS_FALLBACK_MS = 120000;
  const PAGE_LIMIT = 50;

  const LS_KEY = `meshcore.companion.${IDENTITY_ID}.lastConv`;
  const LS_TAB = `meshcore.companion.${IDENTITY_ID}.lastTab`;
  const LS_UNREAD = `meshcore.companion.${IDENTITY_ID}.unread`;
  const MQ_MOBILE = window.matchMedia("(max-width: 640px)");

  // ---------- Hash + LocalStorage state ----------
  function parseHash() {
    const out = {};
    const h = (location.hash || "").replace(/^#/, "");
    for (const kv of h.split("&")) {
      const [k, v] = kv.split("=");
      if (k) out[k] = decodeURIComponent(v || "");
    }
    return out;
  }
  function writeHash(s) {
    const enc = Object.entries(s).map(([k,v]) => k+"="+encodeURIComponent(v)).join("&");
    history.replaceState(null, "", "#"+enc);
  }
  function patchHash(p) { writeHash({...parseHash(), ...p}); }
  function persistConv(spec) { try { localStorage.setItem(LS_KEY, spec || ""); } catch (e) {} }
  function persistTab(name) { try { localStorage.setItem(LS_TAB, name); } catch (e) {} }
  function restoredConv() { try { return localStorage.getItem(LS_KEY) || ""; } catch (e) { return ""; } }
  function restoredTab() { try { return localStorage.getItem(LS_TAB) || ""; } catch (e) { return ""; } }

  // ---------- Unread (per Konversation) ----------
  let unread = {};
  try { unread = JSON.parse(localStorage.getItem(LS_UNREAD) || "{}") || {}; } catch (e) { unread = {}; }
  const _baseTitle = document.title;

  function persistUnread() {
    try { localStorage.setItem(LS_UNREAD, JSON.stringify(unread)); } catch (e) {}
  }
  function unreadKey(active) {
    if (!active) return null;
    if (active.kind === "dm") return "dm:" + active.peer;
    if (active.kind === "channel") return "ch:" + active.channel_id;
    return null;
  }
  function bumpUnread(key) {
    if (!key) return;
    unread[key] = (unread[key] || 0) + 1;
    persistUnread();
    updateTitle();
  }
  function clearUnread(key) {
    if (!key) return;
    if (unread[key]) {
      delete unread[key];
      persistUnread();
      updateTitle();
    }
  }
  function totalUnread() {
    return Object.values(unread).reduce((a, b) => a + b, 0);
  }
  function updateTitle() {
    const n = totalUnread();
    document.title = n > 0 ? `(${n}) ${_baseTitle}` : _baseTitle;
  }
  updateTitle();

  // ---------- Mobile-Toggle ----------
  let mobileView = "threads";
  function setMobileView(v) {
    mobileView = v;
    const wrap = document.querySelector(".messenger");
    if (wrap) wrap.dataset.mobileView = v;
  }
  setMobileView("threads");
  // Bei Wechsel Mobile↔Desktop ggf. Defaults setzen
  MQ_MOBILE.addEventListener("change", () => { /* CSS macht den Rest */ });

  // ---------- visualViewport (Software-Tastatur-aware) ----------
  if (window.visualViewport) {
    const updateVV = () => {
      const h = visualViewport.height + "px";
      document.documentElement.style.setProperty("--vv-height", h);
    };
    visualViewport.addEventListener("resize", updateVV);
    visualViewport.addEventListener("scroll", updateVV);
    updateVV();
  }

  // ---------- Tabs ----------
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabPanels = document.querySelectorAll(".tab-panel");
  function showTab(name) {
    tabBtns.forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    tabPanels.forEach(p => p.classList.toggle("active", p.dataset.tab === name));
  }
  tabBtns.forEach(b => b.addEventListener("click", () => {
    patchHash({tab: b.dataset.tab});
    persistTab(b.dataset.tab);
    showTab(b.dataset.tab);
    if (b.dataset.tab === "chats") loadThreads();
    else if (b.dataset.tab === "map") ensureMap();
  }));

  // ---------- State ----------
  let active = null;  // {kind:"dm"|"channel", peer?, peer_name?, channel_id?, channel_name?}
  let threadCache = {dms: [], channels: []};
  let dmFilter = "";
  let nextCursor = null;        // für Pagination der aktiven Konvo
  let isLoadingOlder = false;
  let searchAbort = null;
  let searchHits = [];

  function fmtTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"});
  }
  function fmtDate(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleDateString() + " " + fmtTime(iso);
  }
  function shortHex(hex, n=8) { return hex ? hex.slice(0,n)+"…" : ""; }
  function escText(s) { const d = document.createElement("div"); d.textContent = s ?? ""; return d.innerHTML; }

  function liveClass(iso) {
    // Liveness-Indikator pro Sidebar-Zeile aus last_ts. Schwellen
    // pragmatisch nach Mesh-Verkehrsmustern (Adverts ~1 h, ACK/Status
    // sofort). null/undef → kein Dot.
    if (!iso) return "live-dot--gone";
    const age = Date.now() - new Date(iso).getTime();
    if (isNaN(age)) return "live-dot--gone";
    if (age < 15 * 60_000) return "live-dot--fresh";
    if (age < 60 * 60_000) return "live-dot--recent";
    if (age < 24 * 60 * 60_000) return "live-dot--stale";
    return "live-dot--gone";
  }

  // ---------- DM-Suche (filtert die Sidebar-Liste direkt) ----------
  function normalizeForSearch(s) {
    return (s || "").toLowerCase()
      .replace(/[äà-å]/g, "a")
      .replace(/[ëè-ê]/g, "e")
      .replace(/[ïì-î]/g, "i")
      .replace(/[öò-ô]/g, "o")
      .replace(/[üù-û]/g, "u")
      .replace(/ß/g, "ss")
      .replace(/[ck]/g, "k")
      .replace(/y/g, "i");
  }

  function applyDmFilter(dms) {
    const q = (dmFilter || "").trim();
    if (!q || q.startsWith("?")) return dms;
    if (/^[0-9a-fA-F]{64}$/.test(q)) {
      const target = q.toLowerCase();
      return dms.filter(t => t.peer_pubkey_hex.toLowerCase() === target);
    }
    const qN = normalizeForSearch(q);
    const haveByPk = new Map(dms.map(t => [t.peer_pubkey_hex.toLowerCase(), t]));
    const out = dms.filter(t => normalizeForSearch(t.peer_name || "").includes(qN));
    for (const t of AT_TARGETS) {
      if (!t.pubkey_hex) continue;
      const k = t.pubkey_hex.toLowerCase();
      if (haveByPk.has(k)) continue;
      if (!normalizeForSearch(t.name).includes(qN)) continue;
      out.push({
        id: null,
        peer_pubkey_hex: t.pubkey_hex,
        peer_name: t.name,
        favorite: false,
        last_ts: null,
        last_text: null,
        last_direction: null,
        _from_targets: true,
      });
      if (out.length > 50) break;
    }
    return out;
  }

  // ---------- Threads ----------
  async function loadThreads() {
    try {
      const r = await fetch(`${API}/identities/${IDENTITY_ID}/threads`, {credentials:"same-origin"});
      if (!r.ok) return;
      const j = await r.json();
      threadCache = {dms: j.dms || [], channels: j.channels || []};
      renderChannelList(threadCache.channels);
      renderDmList(threadCache.dms);
      if (active && active.kind === "channel" && (!active.channel_name || active.channel_name.length <= 8)) {
        const ch = threadCache.channels.find(c => c.id === active.channel_id);
        if (ch) {
          active.channel_name = ch.name;
          updateConvHeader("#" + ch.name);
        }
      }
      if (active && active.kind === "dm" && !active.peer_name) {
        const dm = threadCache.dms.find(d => d.peer_pubkey_hex === active.peer);
        if (dm && dm.peer_name) {
          active.peer_name = dm.peer_name;
          updateConvHeader(dm.peer_name + " · " + shortHex(active.peer, 16));
        }
      }
    } catch (e) {
      console.warn("threads load failed", e);
    }
  }

  function renderChannelList(chs) {
    const box = document.getElementById("ch-list");
    if (!chs.length) {
      box.innerHTML = '<div class="thread-empty" style="color:var(--muted);padding:.5rem">Keine Kanäle.</div>';
      return;
    }
    box.innerHTML = "";
    for (const ch of chs) {
      const wrap = document.createElement("div");
      wrap.className = "thread-row";
      const key = "ch:" + ch.id;
      if (unread[key] && unread[key] > 0) wrap.classList.add("has-unread");
      if (active && active.kind === "channel" && active.channel_id === ch.id) wrap.classList.add("active");
      // Kanäle haben (noch) keinen Stern; reservierte Spalte für Layout-Konsistenz
      const spacer = document.createElement("span");
      spacer.style.minWidth = "44px";
      wrap.appendChild(spacer);

      const item = document.createElement("button");
      item.type = "button";
      item.className = "thread-item thread-item-bare";
      const last = ch.last_text ? escText(ch.last_text).slice(0,40) : '<span style="color:var(--muted)">—</span>';
      item.innerHTML = `<div class="thread-top"><span class="thread-name">#${escText(ch.name)}</span><span class="thread-time">${fmtTime(ch.last_ts)}</span></div>
                        <div class="thread-snip">${last}</div>`;
      item.addEventListener("click", () => selectChannel(ch.id, ch.name));
      wrap.appendChild(item);

      const badge = document.createElement("span");
      badge.className = "unread-badge";
      badge.textContent = unread[key] || "";
      wrap.appendChild(badge);

      box.appendChild(wrap);
    }
  }

  function renderDmList(dms) {
    const box = document.getElementById("dm-list");
    const filtered = applyDmFilter(dms);
    if (!filtered.length) {
      const hint = dmFilter
        ? `kein Treffer für "${escText(dmFilter)}"`
        : "Keine DMs. Tippe oben einen Namen oder Pubkey-Hex.";
      box.innerHTML = `<div class="thread-empty" style="color:var(--muted);padding:.5rem">${hint}</div>`;
      return;
    }
    box.innerHTML = "";
    for (const t of filtered) {
      const wrap = document.createElement("div");
      const key = "dm:" + t.peer_pubkey_hex;
      const isActive = active && active.kind === "dm" && active.peer === t.peer_pubkey_hex;
      wrap.className = "thread-row" + (isActive ? " active" : "");
      if (unread[key] && unread[key] > 0) wrap.classList.add("has-unread");

      const star = document.createElement("button");
      star.type = "button";
      star.className = "thread-star";
      star.textContent = t.favorite ? "★" : "☆";
      star.style.color = t.favorite ? "gold" : "var(--muted)";
      if (!t.id) {
        star.disabled = true;
        star.style.opacity = ".35";
        star.title = "Erst öffnen, dann markieren";
      } else {
        star.title = t.favorite ? "Favorit entfernen" : "Als Favorit markieren";
        star.addEventListener("click", async (e) => {
          e.stopPropagation();
          try {
            const r = await fetch(`${API}/contacts/${t.id}/favorite`, {
              method: "POST", credentials: "same-origin",
            });
            if (r.ok) await loadThreads();
          } catch (err) { console.warn("favorite toggle failed", err); }
        });
      }
      wrap.appendChild(star);

      const item = document.createElement("button");
      item.type = "button";
      item.className = "thread-item thread-item-bare";
      const peer = escText(t.peer_name || shortHex(t.peer_pubkey_hex, 12));
      const last = t.last_text
        ? escText(t.last_text).slice(0, 40)
        : '<span style="color:var(--muted)">—</span>';
      const dot = `<span class="live-dot ${liveClass(t.last_ts)}" title="letzter Verkehr: ${t.last_ts || 'nie'}"></span>`;
      item.innerHTML = `<div class="thread-top"><span class="thread-name">${dot}${peer}</span><span class="thread-time">${fmtTime(t.last_ts)}</span></div>
                        <div class="thread-snip">${last}</div>`;
      item.addEventListener("click", () => selectDm(t.peer_pubkey_hex, t.peer_name));
      wrap.appendChild(item);

      const badge = document.createElement("span");
      badge.className = "unread-badge";
      badge.textContent = unread[key] || "";
      wrap.appendChild(badge);

      box.appendChild(wrap);
    }
  }

  // ---------- Conv selection ----------
  function updateConvHeader(text) {
    const titleEl = document.getElementById("conv-title");
    if (titleEl) titleEl.textContent = text;
    else {
      const hdr = document.getElementById("conv-header");
      if (hdr) hdr.textContent = text;
    }
  }

  async function selectDm(peerHex, peerName, opts={}) {
    active = {kind:"dm", peer: peerHex, peer_name: peerName || null};
    nextCursor = null;
    const spec = "dm:" + peerHex;
    patchHash({tab:"chats", conv: spec});
    persistConv(spec);
    persistTab("chats");
    updateConvHeader((peerName ? peerName+" · " : "") + shortHex(peerHex, 16));
    document.getElementById("conv-messages").innerHTML = "";
    setComposeMode("dm");
    await loadDmMessages(peerHex, {replace: true});
    clearUnread("dm:" + peerHex);
    markActiveThread();
    if (MQ_MOBILE.matches) setMobileView("conv");
    if (opts.scrollToId) scrollToMessageId(opts.scrollToId);
  }

  async function selectChannel(channelId, channelName, opts={}) {
    active = {kind:"channel", channel_id: channelId, channel_name: channelName};
    nextCursor = null;
    const spec = "ch:" + channelId;
    patchHash({tab:"chats", conv: spec});
    persistConv(spec);
    persistTab("chats");
    updateConvHeader("#" + channelName);
    document.getElementById("conv-messages").innerHTML = "";
    setComposeMode("channel");
    await loadChannelMessages(channelId, {replace: true});
    clearUnread("ch:" + channelId);
    markActiveThread();
    if (MQ_MOBILE.matches) setMobileView("conv");
    if (opts.scrollToId) scrollToMessageId(opts.scrollToId);
  }

  function setComposeMode(kind) {
    const form = document.getElementById("conv-compose");
    const input = document.getElementById("conv-text");
    form.style.display = "flex";
    if (kind === "dm") {
      input.maxLength = 200;
      input.placeholder = "Nachricht… (@ für Auto-Complete)";
    } else {
      input.maxLength = 140;
      input.placeholder = `Wird mit '${IDENTITY_NAME}: ' präfixiert. @ für Auto-Complete.`;
    }
    // Action-Buttons (Status/Telemetrie) nur bei DMs zeigen
    const actions = document.getElementById("conv-actions");
    if (actions) actions.hidden = kind !== "dm";
  }

  async function loadDmMessages(peerHex, opts={}) {
    const params = new URLSearchParams();
    params.set("limit", String(PAGE_LIMIT));
    if (opts.beforeTs) params.set("before_ts", opts.beforeTs);
    const url = `${API}/identities/${IDENTITY_ID}/dms/${peerHex}?${params.toString()}`;
    const r = await fetch(url, {credentials:"same-origin"});
    if (!r.ok) return;
    const j = await r.json();
    const list = j.messages || [];
    nextCursor = j.next_cursor;
    if (opts.replace) {
      renderMessagesReplace(list);
    } else {
      prependMessages(list);
    }
  }

  async function loadChannelMessages(channelId, opts={}) {
    const params = new URLSearchParams();
    params.set("limit", String(PAGE_LIMIT));
    if (opts.beforeTs) params.set("before_ts", opts.beforeTs);
    const url = `${API}/identities/${IDENTITY_ID}/channels/${channelId}/messages?${params.toString()}`;
    const r = await fetch(url, {credentials:"same-origin"});
    if (!r.ok) return;
    const j = await r.json();
    const list = j.messages || [];
    nextCursor = j.next_cursor;
    if (opts.replace) {
      renderMessagesReplace(list);
    } else {
      prependMessages(list);
    }
  }

  function fmtHops(n) {
    if (n == null) return "";
    if (n === 0) return ` · <span class="msg-hops" title="0 Hops — Direkt-Empfang">·0</span>`;
    return ` · <span class="msg-hops" title="${n} Hop${n === 1 ? "" : "s"} im Mesh">↗${n}</span>`;
  }

  function renderMessageEl(m) {
    const cls = m.direction === "system"
      ? "system"
      : (m.direction === "out" ? "out" : "in");
    const who = m.direction === "out"
      ? "me"
      : (m.peer_name || (m.peer_pubkey_hex ? shortHex(m.peer_pubkey_hex, 8) : "?"));
    const hopsTxt = m.direction === "in" ? fmtHops(m.hops) : "";
    const div = document.createElement("div");
    div.className = "message " + cls;
    div.dataset.msgId = m.id;
    if (cls === "system") {
      div.innerHTML = `<div class="msg-text">${escText(m.text || "")} · ${fmtTime(m.ts)}</div>`;
    } else {
      div.innerHTML = `<div class="msg-meta">${escText(who)} · ${fmtDate(m.ts)}${hopsTxt}</div>
                       <div class="msg-text">${escText(m.text || "")}</div>`;
    }
    return div;
  }

  function renderMessagesReplace(list) {
    const box = document.getElementById("conv-messages");
    box.innerHTML = "";
    for (const m of list) box.appendChild(renderMessageEl(m));
    box.scrollTop = box.scrollHeight;
  }

  function prependMessages(list) {
    const box = document.getElementById("conv-messages");
    if (!list.length) return;
    const prevHeight = box.scrollHeight;
    const prevTop = box.scrollTop;
    const frag = document.createDocumentFragment();
    for (const m of list) frag.appendChild(renderMessageEl(m));
    box.insertBefore(frag, box.firstChild);
    box.scrollTop = prevTop + (box.scrollHeight - prevHeight);
  }

  function appendIncomingMessage(m) {
    const box = document.getElementById("conv-messages");
    const atBottom = (box.scrollHeight - box.scrollTop - box.clientHeight) < 80;
    box.appendChild(renderMessageEl(m));
    if (atBottom) box.scrollTop = box.scrollHeight;
  }

  function scrollToMessageId(id) {
    const el = document.querySelector(`[data-msg-id="${id}"]`);
    if (el) el.scrollIntoView({block: "center", behavior: "smooth"});
  }

  function markActiveThread() {
    document.querySelectorAll(".thread-row").forEach(el => el.classList.remove("active"));
  }

  // Scroll-Listener: bei scrollTop < 80 nächste Page laden
  document.getElementById("conv-messages").addEventListener("scroll", async (e) => {
    const box = e.currentTarget;
    if (box.scrollTop > 80) return;
    if (isLoadingOlder) return;
    if (!nextCursor) return;
    if (!active) return;
    isLoadingOlder = true;
    try {
      if (active.kind === "dm") {
        await loadDmMessages(active.peer, {beforeTs: nextCursor});
      } else if (active.kind === "channel") {
        await loadChannelMessages(active.channel_id, {beforeTs: nextCursor});
      }
    } finally {
      isLoadingOlder = false;
    }
  });

  // ---------- Send ----------
  document.getElementById("conv-compose").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!active) return;
    const t = document.getElementById("conv-text");
    const text = t.value.trim();
    if (!text) return;
    const fd = new FormData();
    fd.append("identity_id", IDENTITY_ID);
    fd.append("text", text);
    let endpoint;
    if (active.kind === "dm") {
      fd.append("peer_pubkey_hex", active.peer);
      endpoint = `${API}/messages/dm`;
    } else {
      fd.append("channel_id", active.channel_id);
      endpoint = `${API}/messages/channel`;
    }
    const r = await fetch(endpoint, {method:"POST", body: fd, credentials:"same-origin"});
    if (r.ok) {
      t.value = "";
      // SSE liefert das Event normalerweise zurück (type=sent); zur Sicherheit
      // hier auch reload der ersten Page für robustes Verhalten.
      if (active.kind === "dm") await loadDmMessages(active.peer, {replace: true});
      else await loadChannelMessages(active.channel_id, {replace: true});
      loadThreads();
    } else {
      alert("send failed: " + r.status);
    }
  });

  // ---------- Sidebar-Suche (clientseitig + Server-FTS bei "?"-Prefix) ----------
  const searchInput = document.getElementById("dm-search");
  searchInput.setAttribute("enterkeyhint", "search");
  searchInput.addEventListener("input", (e) => {
    dmFilter = e.target.value;
    renderDmList(threadCache.dms);
    const trimmed = dmFilter.trim();
    if (trimmed.startsWith("?") && trimmed.length >= 2) {
      runServerSearch(trimmed.slice(1).trim());
    } else {
      renderSearchHits([]);
    }
  });
  searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      searchInput.value = "";
      dmFilter = "";
      renderDmList(threadCache.dms);
      renderSearchHits([]);
      return;
    }
    if (e.key !== "Enter") return;
    e.preventDefault();
    const v = (dmFilter || "").trim();
    if (!v) return;
    if (v.startsWith("?")) {
      runServerSearch(v.slice(1).trim());
      return;
    }
    if (/^[0-9a-fA-F]{64}$/.test(v)) {
      selectDm(v.toLowerCase(), null);
      searchInput.value = "";
      dmFilter = "";
      renderDmList(threadCache.dms);
      return;
    }
    const filtered = applyDmFilter(threadCache.dms);
    if (filtered.length > 0) {
      selectDm(filtered[0].peer_pubkey_hex.toLowerCase(), filtered[0].peer_name);
      searchInput.value = "";
      dmFilter = "";
      renderDmList(threadCache.dms);
    }
  });

  async function runServerSearch(q) {
    if (!q || q.length < 2) { renderSearchHits([]); return; }
    if (searchAbort) searchAbort.abort();
    searchAbort = new AbortController();
    try {
      const r = await fetch(`${API}/identities/${IDENTITY_ID}/search?q=${encodeURIComponent(q)}&limit=30`,
        {credentials: "same-origin", signal: searchAbort.signal});
      if (!r.ok) { renderSearchHits([]); return; }
      const j = await r.json();
      searchHits = j.hits || [];
      renderSearchHits(searchHits);
    } catch (e) {
      if (e.name !== "AbortError") console.warn("search failed", e);
    }
  }

  function renderSearchHits(hits) {
    let box = document.getElementById("search-hits");
    if (!box) return;
    if (!hits.length) { box.innerHTML = ""; box.style.display = "none"; return; }
    box.style.display = "block";
    box.innerHTML = `<div class="thread-section-label">Treffer</div>`;
    for (const h of hits) {
      const where = h.kind === "dm"
        ? (h.peer_name || shortHex(h.peer_pubkey_hex || "", 12))
        : "#" + (h.channel_name || "?");
      const el = document.createElement("div");
      el.className = "search-hit";
      // h.snippet ist Server-side <mark>…</mark> mit Snippet-Tokens —
      // wir trauen dem (FTS5 snippet() ist sicher) und parsen als HTML.
      el.innerHTML = `<div class="search-hit-where">${escText(where)}</div>
                      <div class="search-hit-snippet">${h.snippet}</div>`;
      el.addEventListener("click", () => {
        if (h.kind === "dm" && h.peer_pubkey_hex) {
          selectDm(h.peer_pubkey_hex, h.peer_name, {scrollToId: h.id});
        } else if (h.kind === "channel" && h.channel_id) {
          selectChannel(h.channel_id, h.channel_name || "?", {scrollToId: h.id});
        }
      });
      box.appendChild(el);
    }
  }

  // ---------- @-Auto-Complete ----------
  function attachAtComplete(input, popup, opts={}) {
    const mode = opts.mode || "insert";
    const onPick = opts.onPick || (() => {});
    const filter = opts.filter || (() => true);
    if (opts.placement === "below") popup.classList.add("at-popup-below");
    let activeIdx = 0;
    let matches = [];
    let atIdx = -1;

    function close() { popup.hidden = true; popup.innerHTML = ""; atIdx = -1; matches = []; }

    function render() {
      popup.innerHTML = "";
      matches.forEach((t, i) => {
        const el = document.createElement("div");
        el.className = "at-item" + (i === activeIdx ? " active" : "");
        const sub = t.pubkey_hex
          ? `<span class="at-sub">${t.pubkey_hex.slice(0,8)}…</span>`
          : '<span class="at-sub">channel</span>';
        el.innerHTML = `<span class="at-name">${escText(t.name)}</span>${sub}`;
        el.addEventListener("mousedown", (e) => { e.preventDefault(); apply(i); });
        popup.appendChild(el);
      });
      popup.hidden = matches.length === 0;
    }

    function apply(idx) {
      const t = matches[idx];
      if (!t) return;
      if (mode === "pick") { onPick(t); input.value = ""; close(); return; }
      if (atIdx < 0) return;
      const v = input.value;
      const cursor = input.selectionStart;
      const insert = `@[${t.name}] `;
      input.value = v.slice(0, atIdx) + insert + v.slice(cursor);
      const newCursor = atIdx + insert.length;
      input.focus();
      input.setSelectionRange(newCursor, newCursor);
      close();
    }

    function update() {
      const v = input.value;
      let q;
      if (mode === "pick") {
        if (/^[0-9a-fA-F]{64}$/.test(v.trim())) { close(); return; }
        const trimmed = v.trim().replace(/^@/, "");
        if (!trimmed) { close(); return; }
        q = trimmed;
        atIdx = -1;
      } else {
        const cursor = input.selectionStart;
        const before = v.slice(0, cursor);
        const m = before.match(/(^|[\s])@([^@\s\[\]]*)$/);
        if (!m) { close(); return; }
        atIdx = before.length - m[2].length - 1;
        q = m[2];
      }
      const qNorm = normalizeForSearch(q);
      matches = AT_TARGETS
        .filter(filter)
        .filter(t => normalizeForSearch(t.name).includes(qNorm))
        .slice(0, 20);
      activeIdx = 0;
      if (!matches.length) {
        popup.innerHTML = '<div class="at-empty">kein Treffer</div>';
        popup.hidden = false;
        return;
      }
      render();
    }

    input.addEventListener("input", update);
    input.addEventListener("click", update);
    input.addEventListener("keydown", (e) => {
      if (popup.hidden) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        activeIdx = (activeIdx + 1) % matches.length;
        render();
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        activeIdx = (activeIdx - 1 + matches.length) % matches.length;
        render();
      } else if (e.key === "Enter" || e.key === "Tab") {
        e.preventDefault();
        apply(activeIdx);
      } else if (e.key === "Escape") {
        e.preventDefault();
        close();
      }
    });
    input.addEventListener("blur", () => setTimeout(close, 100));
  }

  attachAtComplete(
    document.getElementById("conv-text"),
    document.getElementById("conv-at-popup"),
  );

  // ---------- Mobile Back-Button ----------
  const convBack = document.querySelector(".conv-back");
  if (convBack) convBack.addEventListener("click", () => setMobileView("threads"));

  // ---------- DM-Action-Buttons (Status/Telemetrie anfragen) ----------
  async function requestDmAction(kind) {
    if (!active || active.kind !== "dm") return;
    const btn = document.getElementById(kind === "status" ? "btn-status" : "btn-telemetry");
    if (btn) btn.disabled = true;
    try {
      const url = `${API}/identities/${IDENTITY_ID}/contacts/${active.peer}/${kind}`;
      const r = await fetch(url, {method: "POST", credentials: "same-origin"});
      if (!r.ok) {
        appendIncomingMessage({
          direction: "system",
          ts: new Date().toISOString(),
          text: `⚠ ${kind} fehlgeschlagen (${r.status})`,
        });
      } else {
        const label = kind === "status" ? "ℹ Status" : "📡 Telemetrie";
        appendIncomingMessage({
          direction: "system",
          ts: new Date().toISOString(),
          text: `${label} angefragt — warte auf Antwort…`,
        });
      }
    } catch (e) {
      appendIncomingMessage({
        direction: "system",
        ts: new Date().toISOString(),
        text: `⚠ ${kind}: ${e}`,
      });
    } finally {
      if (btn) setTimeout(() => { btn.disabled = false; }, 5000);
    }
  }
  const btnStatus = document.getElementById("btn-status");
  if (btnStatus) btnStatus.addEventListener("click", () => requestDmAction("status"));
  const btnTele = document.getElementById("btn-telemetry");
  if (btnTele) btnTele.addEventListener("click", () => requestDmAction("telemetry"));

  // ---------- Map ----------
  let mapInstance = null;
  let mapMarkers = null;
  let mapAutoTimer = null;
  let userTouchedMap = false;

  async function ensureMap() {
    const status = document.getElementById("map-status");
    if (typeof L === "undefined") {
      status.textContent = "Leaflet konnte nicht geladen werden.";
      return;
    }
    if (!mapInstance) {
      mapInstance = L.map("node-map").setView([51.0, 7.0], 8);
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 19,
        attribution: "© OpenStreetMap-Mitwirkende",
      }).addTo(mapInstance);
      mapMarkers = L.layerGroup().addTo(mapInstance);
      const markTouched = () => { userTouchedMap = true; };
      const c = mapInstance.getContainer();
      c.addEventListener("wheel", markTouched, {passive: true});
      c.addEventListener("mousedown", markTouched);
      c.addEventListener("touchstart", markTouched, {passive: true});
      c.addEventListener("dblclick", markTouched);
      c.addEventListener("keydown", markTouched);
    } else {
      setTimeout(() => mapInstance.invalidateSize(), 50);
    }
    await refreshMap();
    await refreshTelemetryList();
  }

  async function refreshTelemetryList() {
    const box = document.getElementById("telemetry-list");
    try {
      const r = await fetch(`${API}/identities/${IDENTITY_ID}/contacts`, {credentials:"same-origin"});
      if (!r.ok) { box.textContent = "Fehler: " + r.status; return; }
      const list = await r.json();
      if (!list.length) {
        box.innerHTML = '<div class="thread-empty" style="color:var(--muted);padding:.5rem">Keine Kontakte.</div>';
        return;
      }
      list.sort((a, b) => {
        const aHasGeo = a.lat != null && a.lon != null;
        const bHasGeo = b.lat != null && b.lon != null;
        if (aHasGeo !== bHasGeo) return aHasGeo ? 1 : -1;
        return (b.last_seen_at || "").localeCompare(a.last_seen_at || "");
      });
      box.innerHTML = "";
      for (const c of list) {
        const row = document.createElement("div");
        row.className = "telemetry-row";
        const hasGeo = c.lat != null && c.lon != null;
        const geo = hasGeo
          ? `<span class="telemetry-geo">📍 ${c.lat.toFixed(4)}, ${c.lon.toFixed(4)}</span>`
          : '<span class="telemetry-geo telemetry-geo-missing">— kein Geo</span>';
        const star = document.createElement("button");
        star.type = "button";
        star.className = "telemetry-star";
        star.textContent = c.favorite ? "★" : "☆";
        star.style.color = c.favorite ? "gold" : "var(--muted)";
        star.title = c.favorite ? "Favorit entfernen" : "Als Favorit markieren";
        star.addEventListener("click", async (e) => {
          e.stopPropagation();
          try {
            const r = await fetch(`${API}/contacts/${c.id}/favorite`, {
              method: "POST", credentials: "same-origin",
            });
            if (r.ok) await refreshTelemetryList();
          } catch (e) { console.warn("favorite toggle failed", e); }
        });
        row.appendChild(star);
        const nameDiv = document.createElement("div");
        nameDiv.className = "telemetry-name";
        nameDiv.textContent = c.peer_name || c.peer_pubkey_hex.slice(0, 8);
        row.appendChild(nameDiv);
        const meta = document.createElement("div");
        meta.className = "telemetry-meta";
        meta.innerHTML = `<code>${c.peer_pubkey_hex.slice(0,12)}…</code> · ${fmtTime(c.last_seen_at)}`;
        row.appendChild(meta);
        const geoDiv = document.createElement("div");
        geoDiv.innerHTML = geo;
        row.appendChild(geoDiv);
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = "📡";
        btn.className = "telemetry-btn";
        btn.title = "Telemetrie anfragen";
        btn.addEventListener("click", () => requestTelemetry(c.peer_pubkey_hex, c.peer_name || c.peer_pubkey_hex.slice(0,8)));
        row.appendChild(btn);
        box.appendChild(row);
      }
    } catch (e) {
      box.textContent = "Fehler: " + e;
    }
  }

  async function requestTelemetry(peerHex, label) {
    const status = document.getElementById("telemetry-status");
    status.textContent = `Anfrage an ${label} gesendet — warte auf RESPONSE…`;
    try {
      const r = await fetch(
        `${API}/identities/${IDENTITY_ID}/contacts/${peerHex}/telemetry`,
        {method: "POST", credentials: "same-origin"},
      );
      if (!r.ok) { status.textContent = `Fehler ${r.status} bei ${label}`; return; }
    } catch (e) {
      status.textContent = `Sendefehler: ${e}`;
      return;
    }
    let attempts = 0;
    if (mapAutoTimer) clearInterval(mapAutoTimer);
    mapAutoTimer = setInterval(async () => {
      attempts++;
      await refreshMap();
      await refreshTelemetryList();
      if (attempts >= 6) {
        clearInterval(mapAutoTimer);
        mapAutoTimer = null;
        const cur = document.getElementById("telemetry-status").textContent;
        if (cur.startsWith("Anfrage")) {
          status.textContent = `${label}: keine Antwort innerhalb 30 s (Knoten offline oder kein Geo).`;
        }
      }
    }, 5000);
  }

  async function refreshMap() {
    const status = document.getElementById("map-status");
    try {
      const r = await fetch(`${API}/identities/${IDENTITY_ID}/map`, {credentials:"same-origin"});
      if (!r.ok) { status.textContent = "Fehler: " + r.status; return; }
      const pins = await r.json();
      mapMarkers.clearLayers();
      const bounds = [];
      for (const p of pins) {
        if (typeof p.lat !== "number" || typeof p.lon !== "number") continue;
        const popup = `<strong>${escText(p.peer_name || "?")}</strong><br>` +
                      `<code>${p.peer_pubkey_hex.slice(0,16)}…</code><br>` +
                      `<small>last seen: ${fmtDate(p.last_seen_at)}</small>`;
        const marker = L.circleMarker([p.lat, p.lon], {
          radius: p.favorite ? 8 : 6,
          color: p.favorite ? "#ffd866" : "#82aaff",
          weight: 2,
          fillColor: p.favorite ? "#ffd866" : "#82aaff",
          fillOpacity: 0.7,
        }).bindPopup(popup);
        mapMarkers.addLayer(marker);
        bounds.push([p.lat, p.lon]);
      }
      status.textContent = pins.length + " Knoten (letzte 7 Tage)";
      if (!userTouchedMap) {
        if (bounds.length === 1) mapInstance.setView(bounds[0], 12);
        else if (bounds.length > 1) mapInstance.fitBounds(bounds, {padding: [40, 40], maxZoom: 13});
      }
    } catch (e) {
      status.textContent = "Fehler: " + e;
    }
  }

  // ---------- SSE Push-Updates ----------
  function setSseDot(state) {
    const dot = document.getElementById("sse-dot");
    if (!dot) return;
    dot.classList.remove("connected", "error");
    if (state === "connected") dot.classList.add("connected");
    else if (state === "error") dot.classList.add("error");
    dot.title = state === "connected" ? "Live verbunden" : state === "error" ? "Verbindung weg — versuche neu" : "verbinde…";
  }

  function startSse() {
    let es;
    try {
      es = new EventSource(`${API}/identities/${IDENTITY_ID}/stream`, {withCredentials: true});
    } catch (e) {
      console.warn("EventSource init failed", e);
      return;
    }
    es.onopen = () => setSseDot("connected");
    es.onerror = () => setSseDot("error");
    es.onmessage = (ev) => {
      let evt;
      try { evt = JSON.parse(ev.data); } catch (e) { return; }
      handleSseEvent(evt);
    };
    return es;
  }

  function handleSseEvent(evt) {
    const t = evt.type;
    if (t === "dm" || t === "sent_dm") {
      // Eingehender DM: peer ist Sender; ausgehender DM (sent_dm): peer ist Empfänger.
      const peerHex = evt.peer_pubkey_hex;
      if (active && active.kind === "dm" && active.peer === peerHex) {
        appendIncomingMessage(evt);
        clearUnread("dm:" + peerHex);
      } else if (t === "dm") {
        bumpUnread("dm:" + peerHex);
        maybeNotify(evt);
      }
      loadThreads();
    } else if (t === "channel" || t === "sent_channel") {
      const chId = evt.channel_id;
      if (active && active.kind === "channel" && active.channel_id === chId) {
        appendIncomingMessage(evt);
        clearUnread("ch:" + chId);
      } else if (t === "channel") {
        bumpUnread("ch:" + chId);
        maybeNotify(evt);
      }
      loadThreads();
    } else if (t === "status_response" || t === "telemetry_response") {
      // System-Antwort auf einen Status/Telemetrie-Request — nur in der
      // betroffenen DM-Konvo inline rendern, keinen Unread-Counter
      // hochzählen (war ein User-getriggerter Request).
      const peerHex = evt.peer_pubkey_hex;
      if (active && active.kind === "dm" && active.peer === peerHex) {
        appendIncomingMessage(evt);
      }
      loadThreads();
    } else if (t === "contact_update") {
      loadThreads();
    }
  }

  function maybeNotify(evt) {
    if (!document.hidden) return;
    if (navigator.vibrate) try { navigator.vibrate(60); } catch (e) {}
    if (typeof Notification === "undefined") return;
    if (Notification.permission !== "granted") return;
    const title = evt.peer_name || (evt.channel_name ? "#" + evt.channel_name : "MeshCore");
    try { new Notification(title, {body: evt.text || "", silent: false}); } catch (e) {}
  }

  // Permission-Request lazy beim ersten Klick
  function setupNotificationPermission() {
    if (typeof Notification === "undefined") return;
    if (Notification.permission !== "default") return;
    const ask = () => {
      Notification.requestPermission().catch(() => {});
      document.removeEventListener("click", ask);
    };
    document.addEventListener("click", ask, {once: true});
  }
  setupNotificationPermission();

  // ---------- Init / Restore ----------
  function applyConvSpec(spec) {
    if (!spec) return false;
    if (spec.startsWith("dm:")) {
      const peer = spec.slice(3);
      if (/^[0-9a-fA-F]{64}$/.test(peer)) { selectDm(peer.toLowerCase(), null); return true; }
    } else if (spec.startsWith("ch:")) {
      const id = spec.slice(3);
      selectChannel(id, id.slice(0,8));
      return true;
    }
    return false;
  }

  const VALID_TABS = ["chats", "map", "settings"];

  function restoreState() {
    const s = parseHash();
    let tab = s.tab;
    if (tab === "dms" || tab === "channels") tab = "chats";
    if (!VALID_TABS.includes(tab)) tab = restoredTab() || "chats";
    showTab(tab);

    let convSpec = s.conv || "";
    if (!convSpec) convSpec = restoredConv();
    if (tab === "chats") {
      loadThreads().then(() => {
        if (applyConvSpec(convSpec)) {
          // Wenn auf Mobile eine gespeicherte Konvo aktiv ist, auf "conv" wechseln
        } else if (MQ_MOBILE.matches) {
          setMobileView("threads");
        }
      });
    } else if (tab === "map") {
      ensureMap();
    }
  }

  setInterval(loadThreads, POLL_THREADS_FALLBACK_MS);
  restoreState();
  startSse();
  window.addEventListener("hashchange", () => {
    const s = parseHash();
    let tab = s.tab;
    if (tab === "dms" || tab === "channels") tab = "chats";
    if (VALID_TABS.includes(tab)) {
      showTab(tab);
      if (tab === "map") ensureMap();
    }
    if (s.conv) applyConvSpec(s.conv);
  });
})();

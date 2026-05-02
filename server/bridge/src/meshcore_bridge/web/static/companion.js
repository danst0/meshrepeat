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
    else if (b.dataset.tab === "reach") ensureReach();
    else stopReachAutoRefresh();
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

  // ADV_TYPE → Icon-Prefix für Sidebar-Einträge.
  // 1=Chat (kein Icon), 2=Repeater, 3=Room, 4=Sensor.
  function nodeTypeIcon(t) {
    if (t === 3) return "🏠 ";
    if (t === 2) return "📡 ";
    if (t === 4) return "🌡 ";
    return "";
  }

  function liveTier(iso) {
    // Frische-Klassifikation aus last_ts. Tier-Namen werden 1:1 für
    // .live-dot--<tier> (Sidebar) und Pin-Farbe (Map) genutzt.
    if (!iso) return "gone";
    const age = Date.now() - new Date(iso).getTime();
    if (isNaN(age)) return "gone";
    if (age < 15 * 60_000) return "fresh";
    if (age < 60 * 60_000) return "recent";
    if (age < 24 * 60 * 60_000) return "stale";
    return "gone";
  }
  function liveClass(iso) { return "live-dot--" + liveTier(iso); }
  // Map-Pin-Farben pro Tier — passend zu .live-dot--*-CSS-Variablen,
  // damit Karten-Farben und Sidebar-Dots dieselbe Sprache sprechen.
  const TIER_COLORS = {
    fresh:  "#addb67",  // var(--ok)
    recent: "#ffd866",
    stale:  "#82aaff",  // var(--accent)
    gone:   "#5f7e97",  // var(--muted)
  };

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
      // contact_id + favorite kommen aus dem Backend (companion_detail) —
      // wenn der Kontakt schon in der DB ist, behalten wir id und
      // favorite-Flag, damit der Stern korrekt rendert und beim Klick der
      // normale toggle-Endpoint verwendet wird statt Upsert.
      out.push({
        id: t.contact_id || null,
        peer_pubkey_hex: t.pubkey_hex,
        peer_name: t.name,
        favorite: !!t.favorite,
        node_type: t.node_type ?? null,
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
        // AT_TARGETS-Eintrag (z.B. aus Channel-Posts), kein DB-Contact.
        // Klick legt Contact an + setzt favorite=true.
        star.title = "Als Favorit markieren (legt Kontakt an)";
        star.addEventListener("click", async (e) => {
          e.stopPropagation();
          e.preventDefault();
          const fd = new FormData();
          fd.append("peer_pubkey_hex", t.peer_pubkey_hex);
          if (t.peer_name) fd.append("peer_name", t.peer_name);
          fd.append("favorite", "true");
          try {
            const r = await fetch(`${API}/identities/${IDENTITY_ID}/contacts`, {
              method: "POST", body: fd, credentials: "same-origin",
            });
            if (!r.ok) {
              console.warn("upsert contact failed:", r.status);
              alert("Kontakt anlegen fehlgeschlagen (HTTP " + r.status + ")");
              return;
            }
            const data = await r.json().catch(() => null);
            // AT_TARGETS lokal updaten: contact_id und favorite ziehen,
            // sonst rendert der nächste Filter-Pass den stale Bootstrap-
            // Stand und zeigt den Stern wieder hohl, obwohl der Backend-
            // Toggle erfolgreich war.
            if (data) {
              for (const at of AT_TARGETS) {
                if (at.pubkey_hex === t.peer_pubkey_hex) {
                  if (data.id) at.contact_id = data.id;
                  at.favorite = !!data.favorite;
                }
              }
            }
            await loadThreads();
          } catch (err) {
            console.warn("upsert contact failed", err);
            alert("Kontakt anlegen fehlgeschlagen: " + (err && err.message || err));
          }
        });
      } else {
        star.title = t.favorite ? "Favorit entfernen" : "Als Favorit markieren";
        star.addEventListener("click", async (e) => {
          e.stopPropagation();
          e.preventDefault();
          try {
            const r = await fetch(`${API}/contacts/${t.id}/favorite`, {
              method: "POST", credentials: "same-origin",
            });
            if (!r.ok) {
              console.warn("favorite toggle failed:", r.status);
              alert("Favorit-Toggle fehlgeschlagen (HTTP " + r.status + ")");
              return;
            }
            const data = await r.json().catch(() => null);
            // AT_TARGETS-Mirror updaten — wenn der Kontakt nur noch über
            // den AT_TARGETS-Pfad in der gefilterten Liste auftaucht
            // (z.B. raus aus /threads-Top-100), sonst zeigt das
            // Re-Render nach loadThreads den stale favorite-Wert.
            if (data) {
              for (const at of AT_TARGETS) {
                if (at.contact_id === t.id) at.favorite = !!data.favorite;
              }
            }
            await loadThreads();
          } catch (err) {
            console.warn("favorite toggle failed", err);
            alert("Favorit-Toggle fehlgeschlagen: " + (err && err.message || err));
          }
        });
      }
      wrap.appendChild(star);

      const item = document.createElement("button");
      item.type = "button";
      item.className = "thread-item thread-item-bare";
      const peer = escText(t.peer_name || shortHex(t.peer_pubkey_hex, 12));
      const icon = nodeTypeIcon(t.node_type);
      const last = t.last_text
        ? escText(t.last_text).slice(0, 40)
        : '<span style="color:var(--muted)">—</span>';
      const dot = `<span class="live-dot ${liveClass(t.last_ts)}" title="letzter Verkehr: ${t.last_ts || 'nie'}"></span>`;
      item.innerHTML = `<div class="thread-top"><span class="thread-name">${dot}${icon}${peer}</span><span class="thread-time">${fmtTime(t.last_ts)}</span></div>
                        <div class="thread-snip">${last}</div>`;
      item.addEventListener("click", () => selectDm(t.peer_pubkey_hex, t.peer_name, {node_type: t.node_type}));
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
    active = {
      kind: "dm",
      peer: peerHex,
      peer_name: peerName || null,
      node_type: opts.node_type ?? null,
    };
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
    refreshLoginPill();
    if (MQ_MOBILE.matches) setMobileView("conv");
    if (opts.scrollToId) scrollToMessageId(opts.scrollToId);
  }

  // ---------- Login-Pill ----------
  function fmtLoginPill(payload) {
    if (!payload || !payload.logged_in) return null;
    const role = payload.is_admin ? "admin" : "guest";
    let until = "";
    if (payload.expires_at) {
      try {
        const d = new Date(payload.expires_at);
        until = " · bis " + d.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
      } catch(_) { /* ignore */ }
    }
    return `🔓 ${role}${until}`;
  }
  function setLoginPill(text, expired) {
    const el = document.getElementById("login-pill");
    if (!el) return;
    if (!text) { el.hidden = true; el.textContent = ""; return; }
    el.hidden = false;
    el.textContent = text;
    el.classList.toggle("expired", !!expired);
  }
  async function refreshLoginPill() {
    if (!active || active.kind !== "dm") { setLoginPill(null); return; }
    const peer = active.peer;
    try {
      const url = `${API}/identities/${IDENTITY_ID}/contacts/${peer}/login-state`;
      const r = await fetch(url, {credentials: "same-origin"});
      if (!r.ok) { setLoginPill(null); return; }
      const j = await r.json();
      // Active könnte sich währenddessen geändert haben.
      if (!active || active.kind !== "dm" || active.peer !== peer) return;
      setLoginPill(fmtLoginPill(j), false);
    } catch(_) { setLoginPill(null); }
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
    setLoginPill(null);
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
    // Bei einem Room-Push (room_sender_prefix_hex gesetzt) ist peer_name
    // der Room — der eigentliche Autor steckt nur als 4-Byte-Prefix drin,
    // ggf. schon zu einem Namen aufgelöst.
    const isRoomPost = !!m.room_sender_prefix_hex;
    let who;
    if (m.direction === "out") {
      who = "me";
    } else if (isRoomPost) {
      who = m.room_sender_name || ("…" + (m.room_sender_prefix_hex || ""));
    } else {
      who = m.peer_name || (m.peer_pubkey_hex ? shortHex(m.peer_pubkey_hex, 8) : "?");
    }
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

  // ---------- Pending-Request-Countdown ----------
  // msgId → { handle, expires, baseText } — der Server persistiert die
  // "warte auf Antwort"-Bubble samt Initial-Text "(10s)", wir tauschen
  // die Sekunden-Zahl alle 250 ms gegen den verbleibenden Rest aus.
  const _pendingTimers = new Map();

  function _setPendingText(msgId, text) {
    const el = document.querySelector(`[data-msg-id="${msgId}"] .msg-text`);
    if (!el) return false;
    el.textContent = text;
    return true;
  }

  function startPendingCountdown(msgId, expiresAtIso, baseText) {
    const expires = new Date(expiresAtIso).getTime();
    if (isNaN(expires)) return;
    stopPendingCountdown(msgId);
    const tick = () => {
      const left = Math.max(0, Math.ceil((expires - Date.now()) / 1000));
      const txt = baseText.replace(/\(\d+s\)/, `(${left}s)`);
      const ok = _setPendingText(msgId, txt);
      if (!ok || left <= 0) stopPendingCountdown(msgId);
    };
    tick();
    const handle = setInterval(tick, 250);
    _pendingTimers.set(msgId, handle);
  }

  function stopPendingCountdown(msgId) {
    const handle = _pendingTimers.get(msgId);
    if (handle != null) clearInterval(handle);
    _pendingTimers.delete(msgId);
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

  // ---------- DM-Action-Buttons (Login/Status/Telemetrie anfragen) ----------
  const ACTION_LABELS = {
    login: "🔑 Login",
    status: "ℹ Status",
    telemetry: "📡 Telemetrie",
  };
  async function requestDmAction(kind) {
    if (!active || active.kind !== "dm") return;
    const btnId = {login: "btn-login", status: "btn-status", telemetry: "btn-telemetry"}[kind];
    const btn = btnId ? document.getElementById(btnId) : null;
    let password = null;
    if (kind === "login") {
      // Rooms brauchen typischerweise ein Passwort (z.B. „hello"),
      // Repeater oft nur Guest. Cancel = Login abbrechen.
      password = window.prompt("Passwort für Login (leer = Guest):", "");
      if (password === null) return;
    }
    if (btn) btn.disabled = true;
    try {
      const url = `${API}/identities/${IDENTITY_ID}/contacts/${active.peer}/${kind}`;
      const init = {method: "POST", credentials: "same-origin"};
      if (kind === "login") {
        const fd = new FormData();
        fd.append("password", password || "");
        init.body = fd;
      }
      const r = await fetch(url, init);
      const label = ACTION_LABELS[kind] || kind;
      if (!r.ok) {
        appendIncomingMessage({
          direction: "system",
          ts: new Date().toISOString(),
          text: `⚠ ${label} fehlgeschlagen (${r.status})`,
        });
      }
      // Bei Erfolg: Server persistiert die "warte auf Antwort"-Bubble
      // selbst und pusht sie als pending_request-SSE-Event — wir
      // brauchen hier nichts lokal zu rendern, sonst Doppel-Bubble.
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
  const btnLogin = document.getElementById("btn-login");
  if (btnLogin) btnLogin.addEventListener("click", () => requestDmAction("login"));
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
      // Event-Delegation: Klick auf "Chat öffnen"-Link in einem Popup
      c.addEventListener("click", (ev) => {
        const t = ev.target;
        if (!(t instanceof HTMLElement) || !t.classList.contains("map-open-dm")) return;
        ev.preventDefault();
        openDmFromMap(t.dataset.peerHex, t.dataset.peerName);
      });
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
          e.preventDefault();
          try {
            const r = await fetch(`${API}/contacts/${c.id}/favorite`, {
              method: "POST", credentials: "same-origin",
            });
            if (!r.ok) {
              console.warn("favorite toggle failed:", r.status);
              alert("Favorit-Toggle fehlgeschlagen (HTTP " + r.status + ")");
              return;
            }
            const data = await r.json().catch(() => null);
            if (data) {
              for (const at of AT_TARGETS) {
                if (at.contact_id === c.id) at.favorite = !!data.favorite;
              }
            }
            await refreshTelemetryList();
          } catch (err) {
            console.warn("favorite toggle failed", err);
            alert("Favorit-Toggle fehlgeschlagen: " + (err && err.message || err));
          }
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
        const tier = liveTier(p.last_seen_at);
        const fillColor = TIER_COLORS[tier];
        // Favorit: gold-Border über dem Tier-Fill — Frische bleibt
        // erkennbar, Lieblingsknoten stechen zusätzlich heraus.
        const borderColor = p.favorite ? "#ffd866" : fillColor;
        const radius = p.favorite ? 9 : 7;
        const tierLabel = {
          fresh: "letzte 15 Min",
          recent: "letzte Stunde",
          stale: "letzte 24 h",
          gone: "älter",
        }[tier];
        const peerHexEsc = escText(p.peer_pubkey_hex);
        const peerNameEsc = escText(p.peer_name || "?");
        const popup =
          `<strong>${peerNameEsc}</strong><br>` +
          `<code>${p.peer_pubkey_hex.slice(0,16)}…</code><br>` +
          `<small>letzter Verkehr: ${fmtDate(p.last_seen_at)} · ${tierLabel}</small><br>` +
          `<a href="#" class="map-open-dm" ` +
          `   data-peer-hex="${peerHexEsc}" data-peer-name="${peerNameEsc}">→ Chat öffnen</a>`;
        const marker = L.circleMarker([p.lat, p.lon], {
          radius,
          color: borderColor,
          weight: p.favorite ? 3 : 2,
          fillColor,
          fillOpacity: 0.75,
        }).bindPopup(popup);
        mapMarkers.addLayer(marker);
        bounds.push([p.lat, p.lon]);
      }
      status.textContent = pins.length + " Knoten (letzte 72 h + Favoriten/DMs)";
      if (!userTouchedMap) {
        if (bounds.length === 1) mapInstance.setView(bounds[0], 12);
        else if (bounds.length > 1) mapInstance.fitBounds(bounds, {padding: [40, 40], maxZoom: 13});
      }
    } catch (e) {
      status.textContent = "Fehler: " + e;
    }
  }

  function openDmFromMap(peerHex, peerName) {
    if (!peerHex) return;
    // Tab-Switch: "chats" → showTab + Hash + LocalStorage
    showTab("chats");
    patchHash({tab: "chats"});
    persistTab("chats");
    selectDm(peerHex.toLowerCase(), peerName || null);
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
    } else if (t === "pending_request") {
      // Server hat "warte auf Antwort"-Bubble persistiert + pusht uns das
      // Event — wir rendern sie und starten den Countdown.
      const peerHex = evt.peer_pubkey_hex;
      if (active && active.kind === "dm" && active.peer === peerHex) {
        appendIncomingMessage({...evt, direction: "system"});
        startPendingCountdown(evt.id, evt.expires_at, evt.text);
      }
      loadThreads();
    } else if (t === "request_timeout") {
      const peerHex = evt.peer_pubkey_hex;
      if (active && active.kind === "dm" && active.peer === peerHex) {
        appendIncomingMessage({...evt, direction: "system"});
      }
      loadThreads();
    } else if (t === "status_response" || t === "telemetry_response" || t === "login_response") {
      // System-Antwort auf einen Status/Telemetrie-Request — nur in der
      // betroffenen DM-Konvo inline rendern, keinen Unread-Counter
      // hochzählen (war ein User-getriggerter Request).
      const peerHex = evt.peer_pubkey_hex;
      if (active && active.kind === "dm" && active.peer === peerHex) {
        appendIncomingMessage(evt);
      }
      if (t === "login_response" && active && active.kind === "dm" && active.peer === peerHex) {
        // Frische Login-Pill direkt aus dem Event ableiten — vermeidet
        // ein zusätzliches /login-state-Roundtrip.
        const text = fmtLoginPill({
          logged_in: true,
          is_admin: evt.is_admin,
          expires_at: evt.logged_in_until,
        });
        setLoginPill(text, false);
      }
      loadThreads();
    } else if (t === "room_post") {
      // Push vom Room-Server: peer_pubkey_hex ist der Room, room_sender_*
      // identifiziert den eigentlichen Autor. Sonst wie bei "dm".
      const peerHex = evt.peer_pubkey_hex;
      if (active && active.kind === "dm" && active.peer === peerHex) {
        appendIncomingMessage(evt);
        clearUnread("dm:" + peerHex);
      } else {
        bumpUnread("dm:" + peerHex);
        maybeNotify(evt);
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

  // ---------- Erreichbarkeits-Tab ----------
  let reachTimer = null;
  let reachLoading = false;

  function fmtAge(iso) {
    if (!iso) return "—";
    const ms = Date.now() - new Date(iso).getTime();
    if (isNaN(ms) || ms < 0) return "—";
    const s = Math.floor(ms / 1000);
    if (s < 60) return s + "s";
    const m = Math.floor(s / 60);
    if (m < 60) return m + "m";
    const h = Math.floor(m / 60);
    if (h < 48) return h + "h";
    return Math.floor(h / 24) + "d";
  }

  function reachWindow() {
    const sel = document.getElementById("reach-window");
    return sel ? parseInt(sel.value, 10) || 24 : 24;
  }

  async function loadReach() {
    if (reachLoading) return;
    reachLoading = true;
    const status = document.getElementById("reach-status");
    const tbody = document.getElementById("reach-tbody");
    if (!tbody) { reachLoading = false; return; }
    try {
      const hours = reachWindow();
      if (status) status.textContent = "lädt …";
      const r = await fetch(`${API}/identities/${IDENTITY_ID}/reachability?hours=${hours}`);
      if (!r.ok) throw new Error("HTTP " + r.status);
      const data = await r.json();
      renderReach(data);
      if (status) status.textContent = `aktualisiert ${fmtTime(data.generated_at)} · ${data.contacts.length} Kontakte`;
    } catch (e) {
      if (status) status.textContent = "Fehler: " + e.message;
    } finally {
      reachLoading = false;
    }
  }

  function renderReach(data) {
    const tbody = document.getElementById("reach-tbody");
    if (!tbody) return;
    if (!data.contacts.length) {
      tbody.innerHTML = `<tr><td colspan="8" style="color:var(--muted);padding:.5rem">Noch keine Kontakte.</td></tr>`;
      return;
    }
    const winLabel = data.window_hours + "h";
    const ths = document.querySelectorAll(".reach-table thead th");
    if (ths.length >= 4) ths[3].textContent = `Probes (${winLabel})`;
    const NODE_TYPE_LABEL = {2: "Repeater", 3: "Room", 4: "Sensor"};
    const rows = data.contacts.map(c => {
      const typeIcon = nodeTypeIcon(c.node_type);
      const name = typeIcon + (c.peer_name || shortHex(c.peer_pubkey_hex)) + (c.favorite ? " ⭐" : "");
      const seenAge = fmtAge(c.last_seen_at);
      let outPath;
      if (c.out_path_known) {
        const hops = c.hop_count != null ? `${c.hop_count} hop${c.hop_count === 1 ? "" : "s"}` : "direct";
        outPath = `<span class="reach-pill reach-pill--ok" title="gelernt ${fmtDate(c.out_path_updated_at) || ""}">${hops}</span>`;
      } else {
        outPath = `<span class="reach-pill reach-pill--unknown">flood</span>`;
      }
      let probesCell, lossCell, rttCell, lastProbeCell, actionCell;
      if (!c.probe_eligible) {
        // Repeater/Room/Sensor: ACKen keine DMs. Probes-Spalten leer +
        // Hinweis statt Button.
        const label = NODE_TYPE_LABEL[c.node_type] || "n/a";
        probesCell = lossCell = rttCell = lastProbeCell = `<span class="reach-pill reach-pill--unknown" title="${label} ACKt keine DMs">n/a</span>`;
        actionCell = `<span style="color:var(--muted);font-size:.8em" title="${label} ACKt keine DMs — Probe ist hier nicht aussagekräftig.">${label}</span>`;
      } else {
        probesCell = c.probes_total
          ? `${c.probes_ack}/${c.probes_total}` + (c.probes_pending ? ` <span style="color:var(--muted)">(+${c.probes_pending} pend)</span>` : "")
          : (c.probes_pending ? `<span style="color:var(--muted)">${c.probes_pending} pend</span>` : "—");
        lossCell = "—";
        if (c.loss_pct != null) {
          const cls = c.loss_pct >= 50 ? "reach-pill--bad" : c.loss_pct >= 20 ? "reach-pill--warn" : "reach-pill--ok";
          lossCell = `<span class="reach-pill ${cls}">${c.loss_pct}%</span>`;
        }
        rttCell = c.rtt_ms_median != null ? c.rtt_ms_median + " ms" : "—";
        lastProbeCell = "—";
        if (c.last_probe_status) {
          const st = c.last_probe_status;
          const cls = st === "ack" ? "reach-pill--ok" : st === "timeout" ? "reach-pill--bad" : "reach-pill--unknown";
          lastProbeCell = `<span class="reach-pill ${cls}" title="${st} ${c.last_probe_route || ""}">${fmtAge(c.last_probe_at)}</span>`;
        }
        actionCell = `<button type="button" class="reach-probe-btn" data-peer="${c.peer_pubkey_hex}">Probe</button>`;
      }
      return `<tr data-peer="${c.peer_pubkey_hex}">
        <td><a href="#tab=chats&conv=dm:${c.peer_pubkey_hex}" title="${c.peer_pubkey_hex}">${escText(name)}</a></td>
        <td><span class="live-dot ${liveClass(c.last_seen_at)}"></span> ${seenAge}</td>
        <td>${outPath}</td>
        <td>${probesCell}</td>
        <td>${lossCell}</td>
        <td>${rttCell}</td>
        <td>${lastProbeCell}</td>
        <td>${actionCell}</td>
      </tr>`;
    });
    tbody.innerHTML = rows.join("");
    tbody.querySelectorAll(".reach-probe-btn").forEach(btn => {
      btn.addEventListener("click", () => triggerProbe(btn.dataset.peer, btn));
    });
  }

  async function triggerProbe(peerHex, btn) {
    if (!peerHex) return;
    const orig = btn ? btn.textContent : "";
    if (btn) { btn.disabled = true; btn.textContent = "…"; }
    try {
      const r = await fetch(
        `${API}/identities/${IDENTITY_ID}/contacts/${peerHex}/probe`,
        {method: "POST"}
      );
      if (!r.ok) throw new Error("HTTP " + r.status);
      // ACK/timeout kommt asynchron; nach _PROBE_TIMEOUT_S (30s) ist der
      // Eintrag final. Wir refreshen nach 5s und nochmal nach 35s.
      setTimeout(loadReach, 5000);
      setTimeout(loadReach, 35000);
    } catch (e) {
      const status = document.getElementById("reach-status");
      if (status) status.textContent = "Probe-Fehler: " + e.message;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = orig || "Probe"; }
    }
  }

  async function probeFavorites() {
    const btn = document.getElementById("btn-probe-favs");
    const orig = btn ? btn.textContent : "";
    if (btn) { btn.disabled = true; btn.textContent = "läuft …"; }
    try {
      const r = await fetch(`${API}/identities/${IDENTITY_ID}/reachability?hours=${reachWindow()}`);
      const data = await r.json();
      const favs = data.contacts.filter(c => c.favorite && c.probe_eligible);
      if (!favs.length) {
        const status = document.getElementById("reach-status");
        if (status) status.textContent = "Keine probe-fähigen Favoriten (Chat-Knoten) markiert.";
        return;
      }
      // Sequenziell mit kleiner Pause, damit das Mesh nicht überfährt.
      for (const c of favs) {
        await fetch(`${API}/identities/${IDENTITY_ID}/contacts/${c.peer_pubkey_hex}/probe`, {method: "POST"}).catch(() => {});
        await new Promise(r => setTimeout(r, 800));
      }
      setTimeout(loadReach, 5000);
      setTimeout(loadReach, 35000);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = orig || "Favoriten jetzt proben"; }
    }
  }

  function ensureReach() {
    loadReach();
    stopReachAutoRefresh();
    // Kleine Auto-Refresh-Schleife, solange der Tab offen ist.
    reachTimer = setInterval(loadReach, 30000);
    const sel = document.getElementById("reach-window");
    if (sel && !sel.dataset.bound) {
      sel.dataset.bound = "1";
      sel.addEventListener("change", loadReach);
    }
    const btnFav = document.getElementById("btn-probe-favs");
    if (btnFav && !btnFav.dataset.bound) {
      btnFav.dataset.bound = "1";
      btnFav.addEventListener("click", probeFavorites);
    }
  }
  function stopReachAutoRefresh() {
    if (reachTimer) { clearInterval(reachTimer); reachTimer = null; }
  }

  const VALID_TABS = ["chats", "map", "reach", "settings"];

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
    } else if (tab === "reach") {
      ensureReach();
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
      else if (tab === "reach") ensureReach();
      else stopReachAutoRefresh();
    }
    if (s.conv) applyConvSpec(s.conv);
  });
})();

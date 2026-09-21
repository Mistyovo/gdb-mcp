/* gdb-mcp session dashboard.
 *
 * Consumes the Phase 1 contract (docs/dashboard-design.md):
 *   GET /api/v1/snapshot  - full state incl. per-session extras
 *   GET /api/v1/events    - SSE: session.updated (embeds info()),
 *                           session.request (verb/duration/outcome),
 *                           resync (refetch the snapshot)
 *
 * Correctness rules:
 *  - session.updated events carry info() only (no pending_requests/
 *    age_sec), so enriched fields are refreshed by a periodic snapshot
 *    poll (REFRESH_MS) rather than guessed from events.
 *  - a seq gap or a resync marker means events were missed: refetch
 *    the snapshot instead of rendering a stale patchwork.
 * All DOM is built via createElement/textContent - no innerHTML, so
 * target-controlled strings (inferior paths, stop reasons) cannot
 * inject markup, and the strict CSP stays satisfiable.
 */
"use strict";

const REFRESH_MS = 5000;
const TIMELINE_CAP = 300;

const listEl = document.getElementById("session-list");
const countEl = document.getElementById("session-count");
const emptyEl = document.getElementById("no-sessions");
const timelineEl = document.getElementById("timeline");
const noEventsEl = document.getElementById("no-events");
const connEl = document.getElementById("conn");
const seqEl = document.getElementById("seq");

/** session_id -> <article> card element (rebuilt content on update) */
const cards = new Map();
/** session_id -> latest view (snapshot info() or event info()) */
const views = new Map();
/** session_ids whose detail panel is expanded (survives re-renders) */
const expanded = new Set();
/** session_id -> generation counter guarding async detail fills */
const detailGen = new Map();
let lastSeq = 0;

// -- tiny DOM helpers --------------------------------------------------------

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function fmtAge(sec) {
  if (sec == null) return "";
  if (sec < 60) return sec.toFixed(1) + "s";
  if (sec < 3600) return Math.floor(sec / 60) + "m " + Math.floor(sec % 60) + "s";
  return Math.floor(sec / 3600) + "h " + String(Math.floor((sec % 3600) / 60)).padStart(2, "0") + "m";
}

function fmtTime(ts) {
  return new Date(ts * 1000).toTimeString().slice(0, 8);
}

function shortSid(sid) {
  return sid || "";
}

function stopSummary(info) {
  const stop = info.last_stop;
  if (!stop) return "";
  const where = stop.pc ? " @ " + stop.pc : "";
  if (stop.signal) return "stop: " + stop.signal + where;
  return "stop: " + (stop.reason || "?") + where;
}

// -- connection badge --------------------------------------------------------

const CONN_STATES = {
  live: ["conn-live", "live"],
  reconnecting: ["conn-reconnecting", "reconnecting\u2026"],
  offline: ["conn-offline", "offline"],
  connecting: ["conn-connecting", "connecting\u2026"],
};

function setConn(state) {
  const [cls, text] = CONN_STATES[state] || CONN_STATES.offline;
  connEl.className = "conn " + cls;
  connEl.textContent = text;
}

// -- session cards -----------------------------------------------------------

function buildCard(info) {
  const card = el("article", "card");
  card.dataset.sid = info.session_id;
  cards.set(info.session_id, card);
  return card;
}

/** Rebuild a card's compact content from an info() dict; extras
 *  (pending_requests, age_sec, journal_entries, last_event) are present
 *  only on snapshot views and are skipped gracefully when absent.
 *  An expanded detail node is carried over instead of being rebuilt, so
 *  frequent event-driven re-renders never blank the deep view. */
function renderCard(card, view) {
  const sid = view.session_id;
  views.set(sid, view);
  const oldDetail = card.querySelector(":scope > .detail");
  card.textContent = "";

  const head = el("div", "card-head");
  const left = el("div", "head-left");
  const title = el("span", "sid mono", shortSid(sid));
  title.title = "toggle details";
  title.addEventListener("click", () => toggleDetail(sid));
  const toggle = el("button", "toggle", expanded.has(sid) ? "\u25be" : "\u25b8");
  toggle.type = "button";
  toggle.title = "toggle details";
  toggle.setAttribute("aria-expanded", String(expanded.has(sid)));
  toggle.addEventListener("click", () => toggleDetail(sid));
  left.append(title, toggle);
  head.append(left, el("span", "badge st-" + view.state, view.state));
  card.appendChild(head);

  const rows = el("dl", "rows");
  function row(dt, dd) {
    rows.appendChild(el("dt", null, dt));
    rows.appendChild(dd);
  }
  if (view.gdb_pid != null) row("pid", el("dd", "mono", String(view.gdb_pid)));
  if (view.inferior) {
    const dd = el("dd", "truncate", view.inferior);
    dd.title = view.inferior;
    row("inferior", dd);
  }
  const archDd = el("dd", "mono", view.arch || "");
  if (view.pwndbg) archDd.appendChild(el("span", "chip", "pwndbg"));
  if (view.arch) row("arch", archDd);
  if (view.age_sec != null) row("age", el("dd", "mono", fmtAge(view.age_sec)));
  if (view.pending_requests != null) {
    const dd = el("dd", "mono", String(view.pending_requests));
    if (view.pending_requests > 0) dd.style.color = "#f2c977";
    row("pending", dd);
  }
  if (view.journal_entries != null) {
    row("journal", el("dd", "mono", String(view.journal_entries)));
  }

  const summary =
    (view.last_event && view.last_event.event === "stop" && stopSummary(view)) ||
    (view.last_event && "last: " + view.last_event.event) ||
    stopSummary(view);
  card.appendChild(rows);
  if (summary) card.appendChild(el("div", "last-line", summary));

  if (expanded.has(sid)) {
    if (oldDetail) {
      card.appendChild(oldDetail);
    } else {
      const shell = el("div", "detail", "loading\u2026");
      shell.dataset.sid = sid;
      card.appendChild(shell);
      refreshDetail(sid);
    }
  }
}

function renderSnapshot(snap) {
  seqEl.textContent = "seq " + snap.sequence;
  const seen = new Set();
  for (const view of snap.sessions || []) {
    let card = cards.get(view.session_id);
    if (!card) {
      card = buildCard(view);
      listEl.appendChild(card);
    }
    renderCard(card, view);
    seen.add(view.session_id);
  }
  for (const [sid, card] of cards) {
    if (!seen.has(sid)) {
      card.remove();
      cards.delete(sid);
      views.delete(sid);
      expanded.delete(sid);
      detailGen.delete(sid);
    }
  }
  const n = (snap.sessions || []).length;
  countEl.textContent = n ? "(" + n + ")" : "";
  emptyEl.classList.toggle("hidden", n > 0);
}

async function fetchSnapshot() {
  try {
    const r = await fetch("/api/v1/snapshot");
    if (!r.ok) throw new Error("HTTP " + r.status);
    renderSnapshot(await r.json());
    // keep deep views of expanded cards fresh (details are not in events)
    for (const sid of expanded) refreshDetail(sid);
  } catch (e) {
    setConn("offline");
  }
}

// -- detail panel (Phase 3) ----------------------------------------------------

function toggleDetail(sid) {
  if (expanded.has(sid)) {
    expanded.delete(sid);
    detailGen.delete(sid);
  } else {
    expanded.add(sid);
  }
  const card = cards.get(sid);
  const view = views.get(sid);
  if (card && view) renderCard(card, view);
}

/** Fetch detail + journal tail for an expanded card and fill its box.
 *  Generation-guarded: a newer refresh, a collapse, or a card removal
 *  happening mid-flight cancels the fill instead of clobbering. */
async function refreshDetail(sid) {
  const card = cards.get(sid);
  const box = card && card.querySelector(":scope > .detail");
  if (!box) return;
  const gen = (detailGen.get(sid) || 0) + 1;
  detailGen.set(sid, gen);
  const base = "/api/v1/sessions/" + encodeURIComponent(sid);
  try {
    const [dResp, jResp] = await Promise.all([
      fetch(base),
      fetch(base + "/journal?last=30"),
    ]);
    if (!dResp.ok || !jResp.ok) throw new Error("HTTP error");
    const [detail, journal] = await Promise.all([dResp.json(), jResp.json()]);
    if (detailGen.get(sid) !== gen || !box.isConnected) return;
    renderDetail(box, detail, journal);
  } catch (e) {
    if (detailGen.get(sid) === gen && box.isConnected) {
      box.textContent = "";
      box.appendChild(el("span", "dim", "detail unavailable"));
    }
  }
}

function detailSection(title, content) {
  const section = el("div", "detail-section");
  section.appendChild(el("div", "detail-title", title));
  const body = el("div", "detail-body");
  if (content) body.appendChild(content);
  section.appendChild(body);
  return section;
}

function kvRows(dict) {
  const dl = el("dl", "rows");
  for (const [key, value] of Object.entries(dict || {})) {
    if (value === null || value === undefined || value === "") continue;
    const text =
      typeof value === "object" ? safeJson(value) : String(value);
    dl.appendChild(el("dt", null, key));
    dl.appendChild(el("dd", "mono", text));
  }
  return dl;
}

function safeJson(value, cap) {
  try {
    const s = JSON.stringify(value);
    return s.length > (cap || 90) ? s.slice(0, cap || 90) + "\u2026" : s;
  } catch (e) {
    return "";
  }
}

function renderDetail(box, detail, journal) {
  box.textContent = "";

  if (detail.stop) {
    box.appendChild(detailSection("stop", kvRows(detail.stop)));
  }

  const camp = detail.campaign || {};
  const counts = camp.counts || {};
  const parts = [];
  if (counts.primitives) parts.push(counts.primitives + " primitives");
  if (counts.offsets) parts.push(counts.offsets + " offsets");
  if (counts.libc) parts.push(counts.libc + " libc facts");
  if (counts.notes) parts.push(counts.notes + " notes");
  const prot = camp.protections || {};
  const protText = Object.keys(prot)
    .map((k) => k + (prot[k] ? " \u2713" : " \u2717"))
    .join("   ");
  const campLines = camp.summary || [];
  if (campLines.length || protText || parts.length) {
    const body = el("div");
    if (protText) body.appendChild(el("div", "mono prot", protText));
    for (const line of campLines) body.appendChild(el("div", "camp-line", line));
    if (parts.length) {
      body.appendChild(el("div", "dim mono", "(" + parts.join(", ") + ")"));
    }
    box.appendChild(detailSection("campaign", body));
  }

  const ring = detail.recent_events || [];
  if (ring.length) {
    const ol = el("ol", "mini-events");
    for (const ev of ring.slice(-8).reverse()) {
      const li = el("li");
      li.appendChild(el("span", "tl-time", fmtTime(ev.ts)));
      li.appendChild(el("span", "tl-evt", ev.event));
      const reason = ev.payload && (ev.payload.reason || ev.payload.signal);
      if (reason) li.appendChild(el("span", "tl-dur", reason));
      ol.appendChild(li);
    }
    box.appendChild(detailSection("events \u00b7 " + ring.length, ol));
  }

  const jList = el("ol", "journal");
  const entries = (journal.entries || []).slice().reverse();
  for (const entry of entries) jList.appendChild(journalLine(entry));
  const jTitle =
    "journal \u00b7 " + (journal.total || 0) +
    (journal.head_truncated ? " (head truncated)" : "");
  box.appendChild(
    detailSection(
      jTitle,
      entries.length ? jList : el("span", "dim", "no entries yet")
    )
  );
}

function journalLine(entry) {
  const li = el("li", "jl");
  li.appendChild(el("span", "tl-time", fmtTime(entry.ts)));
  if (entry.kind === "request") {
    li.appendChild(el("span", null, entry.verb || "?"));
    const params = safeJson(entry.params, 70);
    if (params) li.appendChild(el("span", "tl-dur", params));
    if (entry.ok) {
      const result = safeJson(entry.result, 60);
      li.appendChild(el("span", "tl-ok", result ? "\u2713 " + result : "\u2713"));
    } else {
      li.appendChild(el("span", "tl-err", "\u2717 " + (entry.error || "failed")));
    }
  } else if (entry.kind === "notification") {
    li.appendChild(el("span", "tl-evt", "\u2190 " + (entry.event || "?")));
    const payload = entry.payload || {};
    const bits = payload.reason || payload.signal || "";
    if (bits) li.appendChild(el("span", "tl-dur", bits));
  } else {
    li.appendChild(el("span", null, entry.kind));
  }
  return li;
}

// -- timeline -----------------------------------------------------------------

function timelineAdd(frame) {
  const li = el("li", "tl-row");
  li.appendChild(el("span", "tl-time", fmtTime(frame.timestamp)));
  const sid = frame.data && frame.data.session_id;
  if (sid) li.appendChild(el("span", "tl-sid", shortSid(sid)));

  const body = el("span", "tl-body");
  if (frame.type === "session.updated") {
    const d = frame.data;
    body.appendChild(el("span", null, d.event + " "));
    const state = d.session && d.session.state;
    if (state) {
      body.appendChild(
        el("span", state === "running" ? "tl-run" : state === "stopped" ? "tl-stop" : null, "\u2192 " + state)
      );
      const reason = d.payload && d.payload.reason;
      if (reason) body.appendChild(el("span", "tl-dur", "  (" + reason + ")"));
    }
  } else if (frame.type === "session.request") {
    const d = frame.data;
    body.appendChild(el("span", null, d.verb + " "));
    if (d.phase === "finished") {
      body.appendChild(el("span", d.ok ? "tl-ok" : "tl-err", d.ok ? "\u2713" : "\u2717 " + (d.error || "failed")));
      if (d.duration_ms != null) body.appendChild(el("span", "tl-dur", " " + d.duration_ms + "ms"));
    }
  } else {
    body.appendChild(el("span", null, frame.type));
  }
  li.appendChild(body);

  timelineEl.prepend(li); // newest on top
  while (timelineEl.children.length > TIMELINE_CAP) timelineEl.lastChild.remove();
  noEventsEl.classList.add("hidden");
}

// -- SSE wiring ----------------------------------------------------------------

function applyFrame(frame) {
  if (frame.seq) {
    // a gap means missed events (reconnect / overflow): resync
    if (lastSeq && frame.seq !== lastSeq + 1) fetchSnapshot();
    lastSeq = frame.seq;
    seqEl.textContent = "seq " + lastSeq;
  }
  if (frame.type === "resync") {
    fetchSnapshot();
    return;
  }
  if (frame.type === "session.updated") {
    const d = frame.data;
    const card = cards.get(d.session_id) || buildCard(d.session);
    if (!card.isConnected) listEl.appendChild(card);
    renderCard(card, d.session);
    emptyEl.classList.add("hidden");
  }
  if (frame.type === "session.request" && frame.data.phase === "finished") {
    timelineAdd(frame);
  } else if (frame.type === "session.updated") {
    timelineAdd(frame);
  }
}

function connect() {
  const es = new EventSource("/api/v1/events");
  es.onopen = () => setConn("live");
  es.onerror = () => setConn("reconnecting"); // EventSource retries itself
  es.onmessage = (msg) => {
    let frame;
    try {
      frame = JSON.parse(msg.data);
    } catch (e) {
      return;
    }
    applyFrame(frame);
  };
}

// -- boot -----------------------------------------------------------------------

setInterval(fetchSnapshot, REFRESH_MS);
fetchSnapshot().then(connect);

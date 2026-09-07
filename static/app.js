/* TSPO Secret Slice Chat: browser client for the JSON-over-WebSocket protocol.
 *
 * Two screens in one document: the auth page (#view-auth) and the chat
 * workspace (#view-chat), switched by a hash route (#/login, #/chat).
 * Same protocol as cli.py/client.py: one JSON object per frame, requests carry a
 * unique string id + action + token, responses echo the id, events carry
 * action=room_message. No identity is taken from the client; the server decides.
 * All rendering uses textContent; user data is never inserted as markup. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const REQUEST_TIMEOUT_MS = 30000;
  const MAX_LOG_LINES = 80;
  const STORAGE_KEY = "tspo.session";

  const state = {
    ws: null,
    token: null,
    username: null,
    room: null,          // selected room name on this connection
    rooms: [],
    mode: "login",       // auth tab: login | signup
    pending: new Map(),  // id -> {resolve, timer, action}
    reasons: { security: {}, errors: {} },
    logLines: [],
    manualClose: false,
    rejections: 0,
  };

  // ------------------------------------------------------------------ helpers

  function wsUrl() {
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    return `${protocol}://${location.host}/ws`;
  }

  function newId() {
    // 1-64 character string; crypto.randomUUID is unavailable on plain-http LAN origins.
    return Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
  }

  function now() {
    return new Date().toLocaleTimeString([], { hour12: false });
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function setPill(baseId, text, kind) {
    for (const id of [baseId, baseId + "-chat"]) {
      const pill = $(id);
      if (!pill) continue;
      pill.textContent = text;
      pill.className = `pill pill-${kind}`;
    }
  }

  function saveSession() {
    try {
      if (state.token) {
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ token: state.token, username: state.username, room: state.room }));
      } else {
        sessionStorage.removeItem(STORAGE_KEY);
      }
    } catch (_) { /* storage unavailable: session lives for this page only */ }
  }

  function loadSession() {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const saved = JSON.parse(raw);
      state.token = saved.token || null;
      state.username = saved.username || null;
      state.room = saved.room || null;
    } catch (_) { /* ignore corrupt storage */ }
  }

  function log(direction, payload) {
    const line = `${now()} ${direction} ${JSON.stringify(payload)}`;
    state.logLines.push(line);
    if (state.logLines.length > MAX_LOG_LINES) state.logLines.shift();
    const pre = $("protocol-log");
    pre.textContent = state.logLines.join("\n");
    pre.scrollTop = pre.scrollHeight;
  }

  function toast(kind, text) {
    const node = el("div", `toast ${kind}`, text);
    $("toasts").appendChild(node);
    setTimeout(() => node.remove(), 3800);
  }

  function banner(kind, text, code) {
    const node = $("banner");
    node.className = `banner ${kind}`;
    node.textContent = "";
    if (code) {
      node.appendChild(el("code", null, code));
      node.appendChild(document.createTextNode(" "));
    }
    node.appendChild(document.createTextNode(text));
  }

  function clearBanner() {
    $("banner").className = "banner hidden";
  }

  function explain(code) {
    const security = state.reasons.security[code];
    if (security) return `${security.control}: ${security.title}. ${security.explanation}`;
    return state.reasons.errors[code] || "";
  }

  // ------------------------------------------------------------------ routing

  function showView(name) {
    document.body.dataset.view = name;
    $("view-auth").classList.toggle("hidden", name !== "auth");
    $("view-chat").classList.toggle("hidden", name !== "chat");
    const wanted = name === "chat" ? "#/chat" : "#/login";
    if (location.hash !== wanted) history.replaceState(null, "", wanted);
    window.scrollTo(0, 0);
  }

  function setAuthMode(mode) {
    state.mode = mode;
    for (const tab of document.querySelectorAll(".tab")) {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    }
    $("btn-login").classList.toggle("hidden", mode !== "login");
    $("btn-signup").classList.toggle("hidden", mode !== "signup");
    $("btn-login").type = mode === "login" ? "submit" : "button";
    $("btn-signup").type = mode === "signup" ? "submit" : "button";
    for (const hint of document.querySelectorAll('[data-hint="signup"]')) hint.classList.toggle("hidden", mode !== "signup");
    for (const text of document.querySelectorAll("[data-mode-text]")) {
      text.classList.toggle("hidden", text.dataset.modeText !== mode);
    }
    $("auth-heading").textContent = mode === "login" ? "Welcome back" : "Join the organization";
    $("auth-subtitle").textContent = mode === "login"
      ? "Sign in to join your rooms."
      : "Pick a username and a strong password. Names are checked by DLP too.";
    $("password").autocomplete = mode === "login" ? "current-password" : "new-password";
    setAuthMessage("", "");
  }

  function setAuthMessage(text, kind, code) {
    const node = $("auth-message");
    node.className = `form-message ${kind || ""}`.trim();
    node.textContent = "";
    if (code) {
      node.appendChild(el("code", null, code));
      node.appendChild(document.createTextNode(" "));
    }
    node.appendChild(document.createTextNode(text));
  }

  // ------------------------------------------------------------ connection

  function connect() {
    return new Promise((resolve, reject) => {
      let settled = false;
      const ws = new WebSocket(wsUrl());
      ws.onopen = () => {
        state.ws = ws;
        state.manualClose = false;
        settled = true;
        setPill("ws-status", "connected", "ok");
        systemMessage("Connected to " + wsUrl());
        log("open", { url: wsUrl() });
        resolve();
      };
      ws.onmessage = (event) => {
        let message;
        try { message = JSON.parse(event.data); } catch (_) { return; }
        handleMessage(message);
      };
      ws.onclose = (event) => {
        if (state.ws === ws) state.ws = null;
        setPill("ws-status", "disconnected", "off");
        systemMessage(state.manualClose
          ? "Disconnected by user. Use Reconnect to continue; the server keeps running."
          : `Connection closed (code ${event.code}). Use Reconnect.`);
        log("close", { code: event.code, manual: state.manualClose });
        failPending();
        updateControls();
        if (!settled) { settled = true; reject(new Error("connection failed")); }
      };
      ws.onerror = () => { /* onclose follows and reports it */ };
    });
  }

  function disconnect() {
    if (!state.ws) return;
    state.manualClose = true;
    state.ws.close(1000, "client disconnect");
  }

  async function reconnect() {
    if (state.ws) disconnect();
    try {
      await connect();
    } catch (_) {
      toast("bad", "Could not reach the server. Is it running?");
      updateControls();
      return;
    }
    await restoreSession();
    updateControls();
  }

  // Sessions are server-side and survive the socket; re-establish this connection's identity and room.
  async function restoreSession() {
    if (!state.token) return false;
    const check = await request("list_groups");
    if (!check.ok) {
      const reason = check.error;
      state.token = null; state.username = null; state.room = null;
      saveSession();
      showView("auth");
      setAuthMessage("Your session is no longer valid (server restarted?). Please sign in again.", "error", reason);
      return false;
    }
    renderRooms(check.groups);
    showView("chat");
    if (state.room) {
      const selected = await request("select_room", { room_name: state.room });
      if (selected.ok) {
        systemMessage(`Reconnected: room "${state.room}" selected again; loading history.`);
        await loadHistory();
      } else {
        state.room = null;
        saveSession();
        systemMessage("Reconnected, but the previous room could not be selected: " + selected.error);
      }
    }
    return true;
  }

  function failPending() {
    for (const [id, entry] of state.pending) {
      clearTimeout(entry.timer);
      entry.resolve({ ok: false, error: "disconnected" });
      state.pending.delete(id);
    }
  }

  function request(action, fields) {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
      return Promise.resolve({ ok: false, error: "not_connected" });
    }
    const id = newId();
    const payload = Object.assign({ id, action, token: state.token }, fields || {});
    log("send", Object.assign({}, payload, { token: payload.token ? "<token>" : null, password: payload.password ? "<hidden>" : undefined }));
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        state.pending.delete(id);
        resolve({ ok: false, error: "timeout" });
      }, REQUEST_TIMEOUT_MS);
      state.pending.set(id, { resolve, timer, action });
      state.ws.send(JSON.stringify(payload));
    });
  }

  function handleMessage(message) {
    log("recv", message);
    if (message.type === "event") {
      if (message.action === "room_message" && message.room_name === state.room) appendMessage(message, null);
      return;
    }
    const entry = state.pending.get(message.id);
    if (!entry) return;
    clearTimeout(entry.timer);
    state.pending.delete(message.id);
    if (message.ok === false) recordRejection(entry.action, message);
    entry.resolve(message);
  }

  // ------------------------------------------------------------- rendering

  function hideEmptyState() {
    const empty = $("empty-state");
    if (empty) empty.remove();
  }

  function systemMessage(text) {
    hideEmptyState();
    const node = el("div", "msg system", `${now()} ${text}`);
    $("messages").appendChild(node);
    scrollMessages();
  }

  function appendMessage(message, sentAt) {
    hideEmptyState();
    const node = el("div", "msg" + (message.username === state.username ? " own" : ""));
    const meta = el("div", "meta");
    meta.appendChild(el("span", "who", message.username));
    meta.appendChild(el("span", "when", sentAt ? sentAt + " UTC" : now()));
    if (message.message_id !== undefined) meta.appendChild(el("span", "id", "#" + message.message_id));
    node.appendChild(meta);
    node.appendChild(el("div", "text", message.content));
    $("messages").appendChild(node);
    scrollMessages();
  }

  function scrollMessages() {
    const box = $("messages");
    box.scrollTop = box.scrollHeight;
  }

  function renderRooms(groups) {
    if (groups) state.rooms = groups;
    const filter = ($("room-filter").value || "").trim().toLowerCase();
    const list = $("room-list");
    list.textContent = "";
    const visible = state.rooms.filter((g) => g.room_name.toLowerCase().includes(filter));
    if (!visible.length) {
      list.appendChild(el("li", "room-empty", state.rooms.length ? "No rooms match the filter." : "No rooms yet. Create the first one above."));
      return;
    }
    for (const group of visible) {
      const item = el("li", "room-item" + (group.room_name === state.room ? " selected" : ""));
      item.appendChild(el("span", "room-name", group.room_name));
      const actions = el("div", "room-actions");
      const join = el("button", "btn btn-small", "Join");
      join.type = "button";
      join.title = "join_group";
      join.onclick = () => joinRoom(group.room_name);
      const open = el("button", "btn btn-small btn-primary", "Open");
      open.type = "button";
      open.title = "select_room";
      open.onclick = () => selectRoom(group.room_name);
      actions.appendChild(join);
      actions.appendChild(open);
      item.appendChild(actions);
      list.appendChild(item);
    }
  }

  function recordRejection(action, response) {
    const code = response.error;
    const security = response.security || null;
    const kind = security ? security.action : "error";
    const item = el("li", `decision ${kind}`);
    const head = el("div", "head");
    head.appendChild(el("span", `badge ${kind}`, security ? security.action : "rejected"));
    const info = state.reasons.security[code];
    if (info) head.appendChild(el("span", "badge control", info.control));
    head.appendChild(el("span", "code", code));
    head.appendChild(el("span", "time", `${now()} · ${action}`));
    item.appendChild(head);
    item.appendChild(el("div", "explanation", explain(code) || "No description available for this code."));
    if (security) {
      item.appendChild(el("div", "facts",
        `risk_score=${security.risk_score} source=${security.source} reason_code=${security.reason_code}`));
    }
    const empty = $("decisions-empty");
    if (empty) empty.remove();
    const list = $("decisions");
    list.insertBefore(item, list.firstChild);
    state.rejections += 1;
  }

  function updateControls() {
    const connected = !!state.ws && state.ws.readyState === WebSocket.OPEN;
    const loggedIn = !!state.token;
    $("btn-login").disabled = !connected;
    $("btn-signup").disabled = !connected;
    $("me").textContent = state.username || "";
    $("avatar").textContent = state.username ? state.username[0] : "?";
    $("btn-refresh-rooms").disabled = !connected || !loggedIn;
    $("new-room").disabled = !connected || !loggedIn;
    $("room-title").textContent = state.room ? `# ${state.room}` : "No room selected";
    $("room-subtitle").textContent = state.room
      ? "Live messages for this room appear here. Blocked messages are never stored or delivered."
      : "Pick a room on the left or create a new one.";
    const canChat = connected && loggedIn && !!state.room;
    $("message").disabled = !canChat;
    $("btn-send").disabled = !canChat;
    $("btn-history").disabled = !canChat;
    $("btn-leave").disabled = !canChat;
    $("message").placeholder = canChat ? `Message #${state.room}` : (connected ? "Open a room to chat" : "Disconnected");
    $("btn-disconnect").disabled = !connected;
    $("btn-reconnect").disabled = connected;
    $("btn-reconnect-auth").classList.toggle("hidden", connected);
    for (const item of document.querySelectorAll(".room-item")) {
      item.classList.toggle("selected", item.firstChild.textContent === state.room);
    }
  }

  // --------------------------------------------------------------- actions

  async function authenticate(action) {
    const username = $("username").value.trim();
    const password = $("password").value;
    if (!username || !password) {
      setAuthMessage("Enter a username and a password.", "error");
      return;
    }
    const button = $(action === "signup" ? "btn-signup" : "btn-login");
    button.classList.add("loading");
    button.disabled = true;
    const response = await request(action, { username, password });
    button.classList.remove("loading");
    button.disabled = false;
    if (!response.ok) {
      const text = explain(response.error) || `${action} was rejected.`;
      setAuthMessage(text, "error", response.error);
      return;
    }
    if (action === "signup") {
      setAuthMode("login");
      $("username").value = response.username;
      $("password").value = "";
      $("password").focus();
      setAuthMessage(`Account "${response.username}" created. Sign in to continue.`, "success");
      toast("ok", `Account ${response.username} created`);
      return;
    }
    state.token = response.token;
    state.username = response.username;
    saveSession();
    $("password").value = "";
    setAuthMessage("", "");
    showView("chat");
    systemMessage(`Signed in as ${state.username}.`);
    toast("ok", `Welcome, ${state.username}`);
    clearBanner();
    updateControls();
    await refreshRooms();
    $("new-room").focus();
  }

  function logout() {
    state.token = null;
    state.username = null;
    state.room = null;
    saveSession();
    $("messages").textContent = "";
    renderRooms([]);
    clearBanner();
    updateControls();
    setAuthMode("login");
    showView("auth");
    setAuthMessage("Signed out on this client. The server will reject protected requests without a valid token.", "success");
    $("username").focus();
  }

  async function refreshRooms() {
    const response = await request("list_groups");
    if (response.ok) renderRooms(response.groups);
    else toast("bad", explain(response.error) || "Could not list rooms.");
  }

  async function createRoom(name) {
    const response = await request("create_group", { room_name: name });
    if (!response.ok) {
      banner("block", explain(response.error) || "Room not created.", response.error);
      toast("bad", `Room not created: ${response.error}`);
      return;
    }
    $("new-room").value = "";
    clearBanner();
    toast("ok", `Room ${response.room_name} created`);
    await enterRoom(response.room_name, `Created and opened room "${response.room_name}".`);
    await refreshRooms();
  }

  async function joinRoom(name) {
    const response = await request("join_group", { room_name: name });
    if (!response.ok) {
      if (response.error === "already_member") {
        await selectRoom(name);
        return;
      }
      banner("block", explain(response.error) || "Could not join.", response.error);
      return;
    }
    clearBanner();
    toast("ok", `Joined ${response.room_name}`);
    await enterRoom(response.room_name, `Joined and opened room "${response.room_name}".`);
    await refreshRooms();
  }

  async function selectRoom(name) {
    const response = await request("select_room", { room_name: name });
    if (!response.ok) {
      banner("block", (explain(response.error) || "Could not open the room.") +
        (response.error === "not_active_member" ? " Click Join first." : ""), response.error);
      return;
    }
    clearBanner();
    await enterRoom(response.room_name, `Opened room "${response.room_name}". Live messages for this room will appear here.`);
    await refreshRooms();
  }

  async function enterRoom(name, note) {
    state.room = name;
    saveSession();
    $("messages").textContent = "";
    systemMessage(note);
    updateControls();
    await loadHistory();
    $("message").focus();
  }

  async function loadHistory() {
    if (!state.room) return;
    const response = await request("history", { room_name: state.room });
    if (!response.ok) {
      banner("block", explain(response.error) || "History unavailable.", response.error);
      return;
    }
    const box = $("messages");
    const keepSystem = Array.from(box.querySelectorAll(".msg.system"));
    box.textContent = "";
    for (const node of keepSystem) box.appendChild(node);
    for (const message of response.messages) appendMessage(message, message.sent_at);
    systemMessage(`History loaded: ${response.messages.length} stored message(s). Blocked messages are never stored.`);
  }

  async function leaveRoom() {
    if (!state.room) return;
    const name = state.room;
    const response = await request("leave_group", { room_name: name });
    if (!response.ok) {
      banner("block", explain(response.error) || "Could not leave.", response.error);
      return;
    }
    state.room = null;
    saveSession();
    systemMessage(`Left room "${name}". You will not receive its messages until you join again.`);
    toast("info", `Left ${name}`);
    clearBanner();
    updateControls();
    await refreshRooms();
  }

  async function sendMessage() {
    const input = $("message");
    const content = input.value;
    if (!content.trim() || !state.room) return;
    $("btn-send").disabled = true;
    const response = await request("send_message", { room_name: state.room, content });
    $("btn-send").disabled = false;
    if (response.ok) {
      input.value = "";
      clearBanner();
      // The server echoes the stored message as a room_message event to every
      // connection with this room selected, including this one; no local echo.
      return;
    }
    const security = response.security;
    const text = explain(response.error) || "The message was rejected.";
    banner("block", (security ? `[${security.action.toUpperCase()} · score ${security.risk_score} · ${security.source}] ` : "") +
      text + " The message was not stored and nobody received it.", response.error);
    input.focus();
  }

  // ------------------------------------------------------------ REST calls

  async function checkHealth() {
    try {
      const response = await fetch("/health", { cache: "no-store" });
      const body = await response.json();
      setPill("health-status", `health: ${body.status}`, body.ok ? "ok" : "warn");
    } catch (_) {
      setPill("health-status", "health: unreachable", "off");
    }
  }

  async function loadReasons() {
    try {
      const response = await fetch("/api/reasons", { cache: "no-store" });
      state.reasons = await response.json();
    } catch (_) {
      state.reasons = { security: {}, errors: {} };
    }
  }

  // ------------------------------------------------------------------ wiring

  function wire() {
    $("server-label").textContent = location.host;
    for (const tab of document.querySelectorAll(".tab")) tab.onclick = () => setAuthMode(tab.dataset.mode);
    for (const link of document.querySelectorAll("[data-switch]")) {
      link.onclick = (event) => { event.preventDefault(); setAuthMode(link.dataset.switch); $("username").focus(); };
    }
    $("auth-form").onsubmit = (event) => { event.preventDefault(); authenticate(state.mode); };
    $("btn-login").onclick = (event) => { event.preventDefault(); authenticate("login"); };
    $("btn-signup").onclick = (event) => { event.preventDefault(); authenticate("signup"); };
    $("toggle-password").onclick = () => {
      const field = $("password");
      const show = field.type === "password";
      field.type = show ? "text" : "password";
      $("toggle-password").setAttribute("aria-label", show ? "Hide password" : "Show password");
      $("toggle-password").title = show ? "Hide password" : "Show password";
    };
    $("btn-logout").onclick = logout;
    $("btn-refresh-rooms").onclick = refreshRooms;
    $("room-filter").oninput = () => renderRooms();
    $("create-form").onsubmit = (event) => {
      event.preventDefault();
      const name = $("new-room").value;
      if (name.trim()) createRoom(name);
    };
    $("btn-history").onclick = loadHistory;
    $("btn-leave").onclick = leaveRoom;
    $("send-form").onsubmit = (event) => { event.preventDefault(); sendMessage(); };
    $("btn-disconnect").onclick = disconnect;
    $("btn-reconnect").onclick = reconnect;
    $("btn-reconnect-auth").onclick = reconnect;
    $("btn-clear-decisions").onclick = () => { $("decisions").textContent = ""; };
    $("btn-clear-log").onclick = () => { state.logLines = []; $("protocol-log").textContent = ""; };
    window.addEventListener("hashchange", () => {
      if (location.hash === "#/chat" && !state.token) showView("auth");
      if (location.hash === "#/login" && state.token) showView("chat");
    });
  }

  async function main() {
    wire();
    loadSession();
    setAuthMode("login");
    showView("auth");
    updateControls();
    await Promise.all([loadReasons(), checkHealth()]);
    setInterval(checkHealth, 15000);
    try {
      await connect();
    } catch (_) {
      setAuthMessage("Could not connect to the chat server. Start it and click Reconnect, or reload this page.", "error");
    }
    if (state.token) await restoreSession();  // page reload keeps you signed in while the server runs
    updateControls();
    if (!state.token) $("username").focus();
  }

  document.addEventListener("DOMContentLoaded", main);
})();

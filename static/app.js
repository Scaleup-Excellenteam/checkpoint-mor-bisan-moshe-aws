/* TSPO Secret Slice Chat: browser client for the JSON-over-WebSocket protocol.
 *
 * Same protocol as cli.py/client.py: one JSON object per frame, requests carry a
 * unique string id + action + token, responses echo the id, events carry
 * action=room_message. No identity is taken from the client; the server decides.
 * All rendering uses textContent; user data is never inserted as markup. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const REQUEST_TIMEOUT_MS = 30000;
  const MAX_LOG_LINES = 60;

  const state = {
    ws: null,
    token: null,
    username: null,
    room: null,          // selected room name on this connection
    pending: new Map(),  // id -> {resolve, reject, timer, action}
    reasons: { security: {}, errors: {} },
    logLines: [],
    manualClose: false,
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

  function setPill(id, text, kind) {
    const pill = $(id);
    pill.textContent = text;
    pill.className = `pill pill-${kind}`;
  }

  function log(direction, payload) {
    const line = `${now()} ${direction} ${JSON.stringify(payload)}`;
    state.logLines.push(line);
    if (state.logLines.length > MAX_LOG_LINES) state.logLines.shift();
    const pre = $("protocol-log");
    pre.textContent = state.logLines.join("\n");
    pre.scrollTop = pre.scrollHeight;
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
        failPending("Disconnected; reconnect and try again.");
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
      banner("block", "Could not reach the server. Is it running?");
      return;
    }
    // Sessions are server-side and survive the socket; re-establish this connection's identity and room.
    if (state.token) {
      const check = await request("list_groups");
      if (!check.ok) {
        state.token = null; state.username = null; state.room = null;
        banner("info", "Session no longer valid (server restarted?). Please log in again.", check.error);
        updateControls();
        return;
      }
      renderRooms(check.groups);
      if (state.room) {
        const selected = await request("select_room", { room_name: state.room });
        if (selected.ok) {
          systemMessage(`Reconnected: room "${state.room}" selected again; loading history.`);
          await loadHistory();
        } else {
          state.room = null;
          systemMessage("Reconnected, but the previous room could not be selected: " + selected.error);
        }
      }
    }
    updateControls();
  }

  function failPending(reason) {
    for (const [id, entry] of state.pending) {
      clearTimeout(entry.timer);
      entry.reject(new Error(reason));
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
      state.pending.set(id, {
        resolve,
        reject: (err) => resolve({ ok: false, error: "disconnected", detail: err.message }),
        timer,
        action,
      });
      state.ws.send(JSON.stringify(payload));
    });
  }

  function handleMessage(message) {
    log("recv", message);
    if (message.type === "event") {
      if (message.action === "room_message") {
        if (message.room_name === state.room) appendMessage(message, null);
      }
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

  function systemMessage(text) {
    const node = el("div", "msg system", `${now()} ${text}`);
    $("messages").appendChild(node);
    scrollMessages();
  }

  function appendMessage(message, sentAt) {
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
    const list = $("room-list");
    list.textContent = "";
    if (!groups.length) {
      list.appendChild(el("li", "hint", "No rooms yet. Create one."));
      return;
    }
    for (const group of groups) {
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
    const list = $("decisions");
    list.insertBefore(item, list.firstChild);
  }

  function updateControls() {
    const connected = !!state.ws && state.ws.readyState === WebSocket.OPEN;
    const loggedIn = !!state.token;
    $("auth-form").classList.toggle("hidden", loggedIn);
    $("auth-info").classList.toggle("hidden", !loggedIn);
    $("me").textContent = state.username || "";
    $("btn-signup").disabled = !connected;
    $("btn-login").disabled = !connected;
    $("btn-refresh-rooms").disabled = !connected || !loggedIn;
    $("new-room").disabled = !connected || !loggedIn;
    $("room-title").textContent = state.room ? `# ${state.room}` : "No room selected";
    const canChat = connected && loggedIn && !!state.room;
    $("message").disabled = !canChat;
    $("btn-send").disabled = !canChat;
    $("btn-history").disabled = !canChat;
    $("btn-leave").disabled = !canChat;
    $("message").placeholder = canChat ? `Message #${state.room}` : "Log in and open a room to chat";
    $("btn-disconnect").disabled = !connected;
    $("btn-reconnect").disabled = connected;
  }

  // --------------------------------------------------------------- actions

  async function authenticate(action) {
    const username = $("username").value;
    const password = $("password").value;
    if (!username || !password) {
      $("auth-message").textContent = "Enter a username and a password.";
      return;
    }
    const response = await request(action, { username, password });
    if (!response.ok) {
      $("auth-message").textContent = `${action} rejected: ${response.error}. ${explain(response.error)}`;
      return;
    }
    if (action === "signup") {
      $("auth-message").textContent = `Account "${response.username}" created. Now log in.`;
      return;
    }
    state.token = response.token;
    state.username = response.username;
    $("password").value = "";
    $("auth-message").textContent = "";
    systemMessage(`Logged in as ${state.username}.`);
    clearBanner();
    updateControls();
    await refreshRooms();
  }

  function logout() {
    state.token = null;
    state.username = null;
    state.room = null;
    $("messages").textContent = "";
    systemMessage("Token forgotten on this client. Protected requests will now be rejected as unauthenticated.");
    renderRooms([]);
    updateControls();
  }

  async function refreshRooms() {
    const response = await request("list_groups");
    if (response.ok) renderRooms(response.groups);
    else banner("info", explain(response.error) || "Could not list rooms.", response.error);
  }

  async function createRoom(name) {
    const response = await request("create_group", { room_name: name });
    if (!response.ok) {
      banner("block", explain(response.error) || "Room not created.", response.error);
      return;
    }
    $("new-room").value = "";
    clearBanner();
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
    systemMessage(`Left room "${name}". You will not receive its messages until you join again.`);
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
    $("btn-signup").onclick = () => authenticate("signup");
    $("btn-login").onclick = () => authenticate("login");
    $("auth-form").onsubmit = (event) => { event.preventDefault(); authenticate("login"); };
    $("btn-logout").onclick = logout;
    $("btn-refresh-rooms").onclick = refreshRooms;
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
    $("btn-clear-decisions").onclick = () => { $("decisions").textContent = ""; };
    $("btn-clear-log").onclick = () => { state.logLines = []; $("protocol-log").textContent = ""; };
  }

  async function main() {
    wire();
    updateControls();
    await Promise.all([loadReasons(), checkHealth()]);
    setInterval(checkHealth, 15000);
    try {
      await connect();
    } catch (_) {
      systemMessage("Could not connect to the chat server. Click Reconnect once it is running.");
    }
    updateControls();
  }

  document.addEventListener("DOMContentLoaded", main);
})();

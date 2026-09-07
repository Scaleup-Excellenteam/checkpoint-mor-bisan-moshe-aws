// Browser-only transport. Credentials are never persisted or logged.
export const errors = {
  invalid_username: 'Use 3–20 English letters, digits, or underscores.',
  invalid_password: 'Use 8–32 characters and at least two of: letters, digits, or @#$%^&*.',
  username_taken: 'That username is already taken.',
  invalid_credentials: 'Incorrect username or password.',
  unauthenticated: 'Please log in to continue.',
  forbidden_term: 'This name or message is not allowed.',
  recipe_blocked: 'This message was blocked by the security policy.',
  malicious_url: 'This message contains an unsafe link.',
  security_check_unavailable: 'The security check is unavailable. Try again later.',
  reputation_unavailable: 'The security check is unavailable. Try again later.',
  reputation_review_required: 'The security check is unavailable. Try again later.',
  invalid_room_name: 'Enter a room name without surrounding whitespace.',
  group_not_found: 'Room not found.',
  group_already_exists: 'A room with that name already exists.',
  already_member: 'You are already a member. Select the room to view it.',
  not_active_member: 'You are not a member of this room. Join it first.',
  room_not_selected: 'Select the room before sending a message.',
  invalid_request: 'The request is invalid. Check your input and try again.',
  invalid_json: 'The server could not read the request.',
  unsupported_operation: 'The server does not support this operation.',
  internal_error: 'The server could not complete the request. Try again later.',
  disconnected: 'Disconnected. Reconnect, log in, and select a room. Pending messages may have been delivered; check history before retrying.',
  timeout: 'The server is taking too long. Reconnect and check history before retrying; delivery is unknown.',
  too_large: 'This request exceeds the server’s 64 KiB limit. Shorten your message or room name.',
};
export const friendlyError = code => errors[code] || 'The request could not be completed. Try again later.';
export const normalizeUsername = value => value.trim().toLowerCase();
export const validUsername = value => /^[a-z0-9_]{3,20}$/.test(value);
export function validPassword(value) {
  return /^[a-zA-Z0-9@#$%^&*]{8,32}$/.test(value) &&
    [/[a-zA-Z]/, /[0-9]/, /[@#$%^&*]/].filter(pattern => pattern.test(value)).length >= 2;
}
export class ChatError extends Error {
  constructor(code) { super(friendlyError(code)); this.code = code; }
}

export class ChatConnection {
  #socket; #token = null; #pending = new Map(); #generation = 0;
  constructor({WebSocketClass = globalThis.WebSocket, onEvent = () => {}, onStatus = () => {}, timeout = 180000} = {}) {
    Object.assign(this, {WebSocketClass, onEvent, onStatus, timeout});
  }
  disconnect() {
    this.#generation++;
    this.#token = null;
    for (const pending of this.#pending.values()) pending.reject(new ChatError('disconnected'));
    this.#pending.clear();
    this.#socket?.close();
    this.#socket = null;
    this.onStatus('disconnected');
  }
  connect(address) {
    const url = new URL(address);
    if (!['ws:', 'wss:'].includes(url.protocol) || url.username || url.password || url.hash || url.search) {
      throw new Error('Enter a ws:// or wss:// server address without credentials, query, or fragment.');
    }
    this.disconnect();
    const generation = this.#generation;
    this.onStatus('connecting');
    return new Promise((resolve, reject) => {
      let socket;
      try { socket = this.#socket = new this.WebSocketClass(url.href); }
      catch { this.disconnect(); reject(new ChatError('disconnected')); return; }
      const timer = setTimeout(() => { if (generation === this.#generation) this.disconnect(); reject(new ChatError('timeout')); }, 10000);
      socket.onopen = () => {
        clearTimeout(timer);
        if (generation !== this.#generation) { reject(new ChatError('disconnected')); return; }
        this.onStatus('connected'); resolve();
      };
      socket.onmessage = ({data}) => {
        if (generation !== this.#generation) return;
        let packet;
        try { packet = JSON.parse(data); } catch { this.disconnect(); return; }
        if (!packet || typeof packet !== 'object') { this.disconnect(); return; }
        if (packet.type === 'event' && packet.action === 'room_message') this.onEvent(packet);
        else if (packet.type === 'response') this.#pending.get(packet.id)?.resolve(packet);
      };
      socket.onerror = () => { clearTimeout(timer); if (generation === this.#generation) this.disconnect(); reject(new ChatError('disconnected')); };
      socket.onclose = () => { clearTimeout(timer); if (generation === this.#generation) this.disconnect(); reject(new ChatError('disconnected')); };
    });
  }
  async request(action, fields = {}) {
    if (this.#socket?.readyState !== 1) throw new ChatError('disconnected');
    const generation = this.#generation;
    // getRandomValues also works when a development UI is served over LAN HTTP.
    const id = Array.from(globalThis.crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');
    const raw = JSON.stringify({...fields, id, action, token: this.#token});
    if (new TextEncoder().encode(raw).length > 65536) throw new ChatError('too_large');
    const response = await new Promise((resolve, reject) => {
      const finish = callback => value => { clearTimeout(timer); this.#pending.delete(id); callback(value); };
      const timer = setTimeout(() => {
        this.#pending.get(id)?.reject(new ChatError('timeout'));
        // A timed-out operation may still mutate server state. Require a fresh session.
        this.disconnect();
      }, this.timeout);
      this.#pending.set(id, {resolve: finish(resolve), reject: finish(reject)});
      try { this.#socket.send(raw); } catch { this.#pending.get(id)?.reject(new ChatError('disconnected')); this.disconnect(); }
    });
    if (generation !== this.#generation) throw new ChatError('disconnected');
    if (!response.ok) throw new ChatError(response.error);
    if (action === 'login') this.#token = response.token;
    return response;
  }
}

// Merge history with events that arrived while history was pending.
export class MessageStore {
  rooms = new Map();
  add(roomId, messages) {
    const room = this.rooms.get(roomId) || new Map();
    for (const message of messages) {
      if (message.room_id === roomId && message.message_id != null) {
        room.set(message.message_id, {...room.get(message.message_id), ...message});
      }
    }
    this.rooms.set(roomId, room);
  }
  get(roomId) { return [...(this.rooms.get(roomId)?.values() || [])].sort((a, b) => a.message_id - b.message_id); }
  clear() { this.rooms.clear(); }
}

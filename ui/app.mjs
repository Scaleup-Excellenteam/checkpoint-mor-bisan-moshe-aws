import {ChatError, MessageStore, normalizeUsername, normalizePassword, passwordHasWhitespace, validUsername, validPassword} from './protocol.mjs';
import {AutoConnection} from './connection.mjs';
import {HealthMonitor, defaultWebSocketURL} from './health.mjs';

const $ = id => document.getElementById(id);
const address = defaultWebSocketURL(window.location);
const health = new HealthMonitor({onStatus: text => { $('health-status').textContent = text; }});
const store = new MessageStore();
let status = 'disconnected', username = null, selected = null, groups = [], memberships = new Map();
let mode = 'login', busy = false, sending = false, loggingOut = false, epoch = 0;
const client = new AutoConnection({address, onStatus: connectionStatus, onEvent: event => {
  store.add(event.room_id, [event]);
  if (selected?.room_id === event.room_id) renderMessages();
}});

function notice(text, error = false, scope = 'notice') {
  $(scope).textContent = text;
  $(scope).hidden = !text;
  $(scope).classList.toggle('error', error);
}
function connectionStatus(next) {
  status = next;
  if (next !== 'connected') {
    epoch++; username = null; selected = null; groups = []; memberships.clear(); store.clear();
    busy = false; sending = false;
    notice('', false, 'room-notice'); notice('', false, 'composer-notice');
    renderRooms(); renderMessages();
  }
  $('connection-status').textContent = {connecting: 'Connecting…', reconnecting: 'Reconnecting…', connected: 'Connected', disconnected: 'Disconnected'}[next];
  $('connection-status').className = `badge ${next}`;
  if (next === 'reconnecting' && !loggingOut) notice('Connection lost. Reconnecting automatically. Please log in again when connected; check history before retrying a pending message.');
  if (next === 'connected') notice('');
  renderControls();
}
function renderControls() {
  const ready = status === 'connected';
  $('logout').hidden = !username;
  $('logout').disabled = loggingOut;
  $('logout').textContent = loggingOut ? 'Logging out…' : 'Log out';
  $('auth-view').hidden = !!username; $('chat-view').hidden = !username;
  $('identity').textContent = username ? `Logged in as ${username}` : 'Your conversations, connected.';
  for (const id of ['auth-submit', 'username', 'password', 'login-tab', 'signup-tab']) $(id).disabled = !ready || busy || loggingOut;
  for (const button of $('chat-view').querySelectorAll('button')) button.disabled = !ready || !username || busy || loggingOut;
  for (const id of ['history', 'leave', 'send']) $(id).disabled ||= !selected;
  $('message').disabled = !ready || !username || !selected;
  $('room-name').disabled = !ready || !username;
  $('send-status').textContent = sending ? 'Checking message…' : 'Messages are checked before delivery.';
  $('auth-submit').textContent = busy && !username ? 'Please wait…' : mode === 'login' ? 'Log in' : 'Create account';
  $('room-title').textContent = selected ? `# ${selected.room_name}` : 'Select a room';
  $('room-subtitle').textContent = selected ? 'Live messages arrive only for this selected room.' : 'Choose a room from the sidebar to get started.';
}
async function run(operation, isSend = false, scope = 'room-notice') {
  if (busy || loggingOut) return;
  notice('', false, scope);
  const current = epoch;
  busy = true; sending = isSend; renderControls();
  try { await operation(); }
  catch (error) {
    // Transport failures remain useful after they have reset the session.
    if (!loggingOut && (current === epoch || ['disconnected', 'timeout'].includes(error.code))) {
      if (error.code === 'unauthenticated') { client.restart(); scope = 'auth-notice'; }
      const text = error.code === 'disconnected' ? 'Connection lost. Please wait while we reconnect.' :
        error.code === 'timeout' ? 'This is taking longer than expected. Delivery may be unknown; check history after logging in again.' :
        error instanceof ChatError ? error.message : 'Could not complete the request. Please try again.';
      if (scope === 'auth-notice') notice('');
      notice(text, true, scope);
    }
  } finally { if (current === epoch) { busy = false; sending = false; renderControls(); } }
}
async function roomRequest(action, fields) {
  const target = groups.find(group => group.room_name === fields.room_name) ||
    (selected?.room_name === fields.room_name ? selected : null);
  try { return await client.request(action, fields); }
  catch (error) {
    // A rejected selection of another room must not invalidate the current room.
    if (target && ['not_active_member', 'room_not_selected'].includes(error.code)) {
      if (error.code === 'not_active_member') memberships.set(target.room_id, false);
      if (selected?.room_id === target.room_id) selected = null;
      renderRooms(); renderMessages();
    }
    throw error;
  }
}
function setMode(next) {
  mode = next; $('password').value = '';
  notice('', false, 'auth-notice');
  $('login-tab').setAttribute('aria-pressed', String(mode === 'login'));
  $('signup-tab').setAttribute('aria-pressed', String(mode === 'signup'));
  $('auth-title').textContent = mode === 'login' ? 'Welcome back' : 'Make yourself at home';
  $('auth-description').textContent = mode === 'login' ? 'Log in to join the conversation.' : 'Create an account, then log in to get started.';
  renderControls();
}
$('login-tab').onclick = () => setMode('login');
$('signup-tab').onclick = () => setMode('signup');
$('logout').onclick = async () => {
  if (loggingOut) return;
  loggingOut = true; renderControls();
  let failed = false;
  try { await client.request('logout'); } catch { failed = true; }
  // Always leave the account view, even if revocation could not be confirmed.
  client.stop(); $('password').value = ''; $('message').value = '';
  notice(''); setMode('login'); loggingOut = false;
  notice(failed ? 'Logged out on this device. Server logout could not be confirmed.' : 'You have logged out.', failed, 'auth-notice');
  client.start(); renderControls();
};
window.addEventListener('pagehide', () => { health.stop(); client.stop(); });
window.addEventListener('pageshow', event => { if (event.persisted) { health.start(address); client.start(); } });
$('auth-form').onsubmit = event => {
  event.preventDefault();
  const name = normalizeUsername($('username').value);
  $('username').value = name;
  const password = normalizePassword($('password').value);
  if (!validUsername(name) || !validPassword(password)) {
    const code = mode === 'login' ? 'invalid_credentials' : !validUsername(name) ? 'invalid_username' : 'invalid_password';
    const text = code === 'invalid_password' && passwordHasWhitespace(password) ? 'Spaces are not allowed in passwords.' : new ChatError(code).message;
    $('password').value = ''; notice(text, true, 'auth-notice'); return;
  }
  run(async () => {
    // Clear the masked field immediately after serialization; retain no credential state.
    const pending = client.request(mode, {username: name, password});
    $('password').value = '';
    const result = await pending;
    if (mode === 'signup') { setMode('login'); notice('Account created. Log in with your new account.', false, 'auth-notice'); $('password').focus(); }
    else { username = result.username; notice('', false, 'auth-notice'); renderControls();
      try { await listRooms(); } catch (error) { notice(error instanceof ChatError ? error.message : 'Could not load rooms. Please try again.', true, 'room-notice'); }
    }
  }, false, 'auth-notice');
};
async function listRooms() {
  const result = await client.request('list_groups'); groups = result.groups; renderRooms();
}
function renderRooms() {
  const query = $('room-filter').value.toLowerCase();
  const visible = groups.filter(group => group.room_name.toLowerCase().includes(query));
  $('rooms').replaceChildren(); $('rooms-empty').hidden = visible.length > 0;
  $('rooms-empty').textContent = groups.length ? 'No rooms match your filter.' : 'No rooms yet. Create the first one.';
  for (const group of visible) {
    const item = document.createElement('li'); item.className = 'room';
    item.classList.toggle('selected', selected?.room_id === group.room_id);
    const name = document.createElement('div'); name.className = 'room-name'; name.textContent = `# ${group.room_name}`;
    const meta = document.createElement('span'); meta.className = 'room-meta';
    meta.textContent = selected?.room_id === group.room_id ? 'Selected · live' : memberships.get(group.room_id) === true ? 'Member · not selected' : memberships.get(group.room_id) === false ? 'Not a member' : 'Public room · membership not checked';
    const actions = document.createElement('div'); actions.className = 'button-row';
    for (const [label, action] of [['Join', 'join_group'], ['Select', 'select_room']]) {
      const button = document.createElement('button'); button.type = 'button'; button.className = 'secondary'; button.textContent = label;
      button.setAttribute('aria-label', `${label} ${group.room_name}`);
      button.onclick = () => run(() => chooseRoom(action, group.room_name)); actions.append(button);
    }
    item.append(name, meta, actions); $('rooms').append(item);
  }
  renderControls();
}
async function chooseRoom(action, name) {
  if (!name.trim() || name !== name.trim()) throw new ChatError('invalid_room_name');
  const result = await roomRequest(action, {room_name: name});
  selected = {room_id: result.room_id, room_name: groups.find(g => g.room_id === result.room_id)?.room_name || result.room_name};
  memberships.set(selected.room_id, true); $('message').value = '';
  notice('', false, 'composer-notice');
  renderRooms(); renderMessages(); renderControls();
  notice(`Selected ${selected.room_name}. You’re receiving this room’s live messages.`, false, 'room-notice');
  await loadHistory();
  if (action === 'create_group') { $('room-name').value = ''; await listRooms(); }
}
$('room-form').onsubmit = event => { event.preventDefault(); run(() => chooseRoom(event.submitter?.dataset.action || 'create_group', $('room-name').value)); };
$('refresh-rooms').onclick = () => run(listRooms);
$('room-filter').oninput = renderRooms;
async function loadHistory() {
  if (!selected) return;
  const room = selected;
  const result = await roomRequest('history', {room_name: room.room_name});
  store.add(room.room_id, result.messages); renderMessages();
}
$('history').onclick = () => run(loadHistory);
$('leave').onclick = () => run(async () => {
  const room = selected;
  await roomRequest('leave_group', {room_name: room.room_name});
  memberships.set(room.room_id, false); store.rooms.delete(room.room_id); selected = null; $('message').value = '';
  notice('', false, 'composer-notice');
  renderRooms(); renderMessages(); notice(`You left ${room.room_name}. Join again to participate.`, false, 'room-notice');
});
function renderMessages() {
  const box = $('messages');
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const messages = selected ? store.get(selected.room_id) : [];
  // Keep existing nodes so a new event doesn't re-announce all history to screen readers.
  const roomKey = String(selected?.room_id ?? '');
  if (box.dataset.room !== roomKey) { box.replaceChildren(); box.dataset.room = roomKey; }
  const existing = new Map([...box.children].map(node => [node.dataset.id, node]));
  for (const message of messages) {
    const key = String(message.message_id);
    if (existing.has(key)) {
      const item = existing.get(key);
      item.querySelector('.message-meta').textContent = message.username + (message.sent_at ? ` · ${message.sent_at}` : '');
      item.querySelector('.message-body').textContent = message.content;
      continue;
    }
    const item = document.createElement('article'); item.className = 'message'; item.dataset.id = key;
    item.classList.toggle('own', message.username === username);
    const meta = document.createElement('div'); meta.className = 'message-meta';
    meta.textContent = message.username + (message.sent_at ? ` · ${message.sent_at}` : '');
    const body = document.createElement('div'); body.className = 'message-body'; body.textContent = message.content;
    item.append(meta, body);
    const next = [...box.children].find(node => Number(node.dataset.id) > message.message_id);
    box.insertBefore(item, next || null);
  }
  $('messages-empty').hidden = messages.length > 0;
  if (nearBottom) box.scrollTop = box.scrollHeight;
}
$('message-form').onsubmit = event => {
  event.preventDefault();
  if (!selected || busy) return;
  const content = $('message').value;
  if (!content.trim()) { notice('Write a message before sending.', true, 'composer-notice'); return; }
  const room = selected;
  run(async () => {
    await roomRequest('send_message', {room_name: room.room_name, content});
    // Only room_message events render sent content. Preserve edits made during checking.
    if ($('message').value === content) $('message').value = '';
    notice('', false, 'composer-notice');
  }, true, 'composer-notice');
};
$('message').oninput = () => notice('', false, 'composer-notice');
renderControls();
health.start(address);
client.start();

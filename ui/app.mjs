import {ChatConnection, ChatError, MessageStore, normalizeUsername, validUsername, validPassword} from './protocol.mjs';

const $ = id => document.getElementById(id);
const store = new MessageStore();
let status = 'disconnected', username = null, selected = null, groups = [], memberships = new Map();
let mode = 'login', busy = false, sending = false, epoch = 0;
const client = new ChatConnection({onStatus: connectionStatus, onEvent: event => {
  store.add(event.room_id, [event]);
  if (selected?.room_id === event.room_id) renderMessages();
}});

function notice(text, error = false) {
  $('notice').textContent = text;
  $('notice').classList.toggle('error', error);
}
function connectionStatus(next) {
  status = next;
  if (next !== 'connected') {
    epoch++; username = null; selected = null; groups = []; memberships.clear(); store.clear();
    busy = false; sending = false; $('password').value = ''; $('message').value = '';
    renderRooms(); renderMessages();
  }
  $('connection-status').textContent = next[0].toUpperCase() + next.slice(1);
  $('connection-status').className = `badge ${next}`;
  if (next === 'disconnected') notice('Disconnected. Reconnect, log in, and select a room. Check history before retrying any pending message.');
  if (next === 'connected') notice('Connected. Log in or create an account.');
  renderControls();
}
function renderControls() {
  const ready = status === 'connected';
  $('connect').disabled = status === 'connecting';
  $('connect').textContent = ready ? 'Reconnect' : 'Connect';
  $('disconnect').disabled = status === 'disconnected';
  $('address').disabled = status === 'connecting';
  $('auth-view').hidden = !!username; $('chat-view').hidden = !username;
  $('identity').textContent = username ? `Logged in as ${username}` : 'Your conversations, connected.';
  for (const id of ['auth-submit', 'username', 'password', 'login-tab', 'signup-tab']) $(id).disabled = !ready || busy;
  for (const button of $('chat-view').querySelectorAll('button')) button.disabled = !ready || !username || busy;
  for (const id of ['history', 'leave', 'send']) $(id).disabled ||= !selected;
  $('message').disabled = !ready || !username || !selected;
  $('room-name').disabled = !ready || !username;
  $('send-status').textContent = sending ? 'Checking message…' : 'Messages are checked before delivery.';
  $('auth-submit').textContent = busy && !username ? 'Please wait…' : mode === 'login' ? 'Log in' : 'Create account';
  $('room-title').textContent = selected ? `# ${selected.room_name}` : 'Select a room';
  $('room-subtitle').textContent = selected ? 'Live messages arrive only for this selected room.' : 'Choose a room from the sidebar to get started.';
}
async function run(operation, isSend = false) {
  if (busy) return;
  const current = epoch;
  busy = true; sending = isSend; renderControls();
  try { await operation(); }
  catch (error) {
    // Transport failures remain useful after they have reset the session.
    if (current === epoch || ['disconnected', 'timeout'].includes(error.code)) {
      if (error.code === 'unauthenticated') client.disconnect();
      if (['not_active_member', 'room_not_selected'].includes(error.code) && selected) {
        if (error.code === 'not_active_member') memberships.set(selected.room_id, false);
        selected = null; renderRooms(); renderMessages();
      }
      notice(error instanceof ChatError ? error.message : 'Could not complete the operation. Check the server address and connection.', true);
    }
  } finally { if (current === epoch) { busy = false; sending = false; renderControls(); } }
}
function setMode(next) {
  mode = next; $('password').value = '';
  $('login-tab').setAttribute('aria-pressed', String(mode === 'login'));
  $('signup-tab').setAttribute('aria-pressed', String(mode === 'signup'));
  $('auth-title').textContent = mode === 'login' ? 'Welcome back' : 'Make yourself at home';
  $('auth-description').textContent = mode === 'login' ? 'Log in to join the conversation.' : 'Create an account, then log in to get started.';
  renderControls();
}
$('login-tab').onclick = () => setMode('login');
$('signup-tab').onclick = () => setMode('signup');
$('connect').onclick = async () => {
  try { await client.connect($('address').value.trim()); }
  catch (error) { notice(error instanceof ChatError ? error.message : 'Enter a valid ws:// or wss:// server address (for example ws://127.0.0.1:8000/ws).', true); }
};
$('disconnect').onclick = () => client.disconnect();
window.addEventListener('pagehide', () => client.disconnect());
$('auth-form').onsubmit = event => {
  event.preventDefault();
  const name = normalizeUsername($('username').value);
  $('username').value = name;
  if (!validUsername(name) || !validPassword($('password').value)) {
    const code = mode === 'login' ? 'invalid_credentials' : !validUsername(name) ? 'invalid_username' : 'invalid_password';
    $('password').value = ''; notice(new ChatError(code).message, true); return;
  }
  run(async () => {
    // Clear the masked field immediately after serialization; retain no credential state.
    const pending = client.request(mode, {username: name, password: $('password').value});
    $('password').value = '';
    const result = await pending;
    if (mode === 'signup') { setMode('login'); notice('Account created. Log in with your new account.'); $('password').focus(); }
    else { username = result.username; notice(`Welcome, ${username}. Join a room or select one you already belong to.`); await listRooms(); }
  });
};
async function listRooms() {
  const result = await client.request('list_groups'); groups = result.groups; renderRooms();
}
function renderRooms() {
  $('rooms').replaceChildren(); $('rooms-empty').hidden = groups.length > 0;
  for (const group of groups) {
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
  const result = await client.request(action, {room_name: name});
  selected = {room_id: result.room_id, room_name: groups.find(g => g.room_id === result.room_id)?.room_name || result.room_name};
  memberships.set(selected.room_id, true); $('message').value = '';
  renderRooms(); renderMessages(); renderControls();
  notice(`Selected ${selected.room_name}. You’re receiving this room’s live messages.`);
  await loadHistory();
  if (action === 'create_group') { $('room-name').value = ''; await listRooms(); }
}
$('room-form').onsubmit = event => { event.preventDefault(); run(() => chooseRoom(event.submitter?.dataset.action || 'create_group', $('room-name').value)); };
$('refresh-rooms').onclick = () => run(listRooms);
async function loadHistory() {
  if (!selected) return;
  const room = selected;
  const result = await client.request('history', {room_name: room.room_name});
  store.add(room.room_id, result.messages); renderMessages();
}
$('history').onclick = () => run(loadHistory);
$('leave').onclick = () => run(async () => {
  const room = selected;
  await client.request('leave_group', {room_name: room.room_name});
  memberships.set(room.room_id, false); store.rooms.delete(room.room_id); selected = null; $('message').value = '';
  renderRooms(); renderMessages(); notice(`You left ${room.room_name}. Join again to participate.`);
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
    if (existing.has(key)) continue;
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
  if (!content.trim()) { notice('Write a message before sending.', true); return; }
  const room = selected;
  run(async () => {
    notice('Checking your message. Incoming messages will continue to appear.');
    await client.request('send_message', {room_name: room.room_name, content});
    // Only room_message events render sent content. Preserve edits made during checking.
    if ($('message').value === content) $('message').value = '';
    notice('Message accepted.');
  }, true);
};
renderControls();

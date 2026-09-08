import test from 'node:test';
import assert from 'node:assert/strict';
import {ChatConnection, MessageStore, normalizeUsername, normalizePassword, passwordHasWhitespace, validUsername, validPassword, friendlyError} from '../protocol.mjs';

class Socket {
  static instances = [];
  readyState = 0;
  sent = [];
  constructor() { Socket.instances.push(this); queueMicrotask(() => { this.readyState = 1; this.onopen(); }); }
  send(raw) { this.sent.push(JSON.parse(raw)); }
  close() { this.readyState = 3; }
  receive(packet) { this.onmessage({data: JSON.stringify(packet)}); }
  response(index, fields = {}) { this.receive({type: 'response', id: this.sent[index].id, ok: true, ...fields}); }
}
test('authentication contract boundaries and category combinations', () => {
  assert.equal(normalizeUsername('  BiSAN_1 '), 'bisan_1');
  for (const name of ['abc', 'a_1', 'a'.repeat(20)]) assert.ok(validUsername(name));
  for (const name of ['ab', 'a'.repeat(21), 'ABC', 'abc!', 'éabc', 'abc\n']) assert.equal(validUsername(name), false);
  for (const value of ['abcd1234', 'abcd@#$%', '1234@#$%', 'a1'.repeat(16), ' abcd1234', 'abcd1234 ', 'abcd1234\n']) assert.ok(validPassword(value));
  for (const value of ['abcdefgh', 'ABCDEFGH', '12345678', '@#$%^&*@', 'abc123!', 'abc123', 'a1'.repeat(17), 'Pass 123@', 'Pass\t123@', '  short1  ']) assert.equal(validPassword(value), false);
  for (const edge of [' ', '\t', '\n', '\u0085', '\u001c', '\u3000']) assert.equal(normalizePassword(edge + 'Pass123@' + edge), 'Pass123@');
  assert.equal(normalizePassword('Pass123@'), 'Pass123@');
  assert.ok(passwordHasWhitespace('Pass\t123@'));
  assert.equal(friendlyError('username_taken'), 'Username is already taken.');
  assert.equal(friendlyError('invalid_credentials'), 'Incorrect username or password.');
  const securityCodes = ['security_check_unavailable', 'reputation_unavailable', 'reputation_review_required', 'malicious_url', 'forbidden_term', 'recipe_blocked'];
  assert.equal(new Set(securityCodes.map(friendlyError)).size, 6);
  for (const code of securityCodes) assert.doesNotMatch(friendlyError(code), /score|pineapple|prompt|token|VirusTotal|Ollama/i);
  assert.ok(!friendlyError('secret exception').includes('secret'));
});
test('one receiver correlates out-of-order responses while events arrive; authoritative token', async () => {
  const events = [];
  const client = new ChatConnection({WebSocketClass: Socket, onEvent: event => events.push(event)});
  await client.connect('ws://localhost:8000/ws');
  const socket = Socket.instances.at(-1);
  try {
    const signup = client.request('signup', {username: 'alice', password: 'Password1'});
    socket.response(0); await signup;
    const login = client.request('login'); assert.equal(socket.sent[1].token, null);
    socket.response(1, {token: 'private-token'}); await login;
    const a = client.request('send_message', {token: 'untrusted', content: 'hello'});
    const b = client.request('history');
    assert.equal(socket.sent[2].token, 'private-token');
    socket.receive({type: 'event', action: 'room_message', message_id: 1});
    socket.response(3, {messages: []}); assert.deepEqual((await b).messages, []);
    socket.response(2); await a;
    assert.equal(events.length, 1);
    assert.ok(!JSON.stringify(client).includes('private-token'));
  } finally { client.disconnect(); }
});
test('disconnect rejects pending requests, clears token, and ignores old socket events', async () => {
  const events = [];
  const client = new ChatConnection({WebSocketClass: Socket, onEvent: e => events.push(e)});
  await client.connect('ws://localhost/ws');
  const old = Socket.instances.at(-1);
  const login = client.request('login'); old.response(0, {token: 'old-token'}); await login;
  const pending = client.request('history');
  const rejected = assert.rejects(pending, {code: 'disconnected'});
  client.disconnect(); await rejected;
  await client.connect('ws://localhost/ws');
  const socket = Socket.instances.at(-1);
  old.receive({type: 'event', action: 'room_message'}); assert.equal(events.length, 0);
  const request = client.request('list_groups'); assert.equal(socket.sent[0].token, null);
  socket.response(0, {ok: false, error: 'unauthenticated'});
  await assert.rejects(request, {code: 'unauthenticated'}); client.disconnect();
});
test('timeout resets connection without retrying an uncertain send', async () => {
  const client = new ChatConnection({WebSocketClass: Socket, timeout: 10});
  await client.connect('ws://localhost/ws');
  const socket = Socket.instances.at(-1);
  await assert.rejects(client.request('send_message'), {code: 'timeout'});
  assert.equal(socket.sent.length, 1); assert.equal(socket.readyState, 3);
});
test('UTF-8 envelope limit is checked before sending', async () => {
  const client = new ChatConnection({WebSocketClass: Socket});
  await client.connect('ws://localhost/ws');
  await assert.rejects(client.request('send_message', {content: '🙂'.repeat(17000)}), {code: 'too_large'});
  assert.equal(Socket.instances.at(-1).sent.length, 0); client.disconnect();
});
test('history and live events merge by id without loss, duplication, or room leakage', () => {
  const store = new MessageStore();
  store.add(2, [{message_id: 3, room_id: 2, username: 'server_name', content: '<script>bad()</script>'}]);
  store.add(2, [{message_id: 1, room_id: 2, content: 'old'}, {message_id: 3, room_id: 2, sent_at: 'time'}, {message_id: 4, room_id: 99}]);
  assert.deepEqual(store.get(2).map(m => m.message_id), [1, 3]);
  assert.equal(store.get(2)[1].username, 'server_name');
  store.clear(); assert.deepEqual(store.get(2), []);
});

test('successful logout clears the private token without changing response correlation', async () => {
  const client = new ChatConnection({WebSocketClass: Socket});
  await client.connect('ws://localhost/ws');
  const socket = Socket.instances.at(-1);
  const login = client.request('login'); socket.response(0, {token: 'test-only-token'}); await login;
  const logout = client.request('logout'); assert.equal(socket.sent[1].token, 'test-only-token');
  socket.response(1); await logout;
  const again = client.request('list_groups'); assert.equal(socket.sent[2].token, null);
  socket.response(2, {ok: false, error: 'unauthenticated'});
  await assert.rejects(again, {code: 'unauthenticated'}); client.disconnect();
});

// Runs the exact browser transport against the existing real WebSocket server.
import assert from 'node:assert/strict';
import {ChatConnection, MessageStore} from '../protocol.mjs';
const uri = process.argv[2];
const messages = new MessageStore();
const clients = [new ChatConnection({onEvent: e => messages.add(e.room_id, [e])}), new ChatConnection()];
const [a, b] = clients;
try {
  await Promise.all(clients.map(c => c.connect(uri)));
  for (const [client, name] of [[a, ' ALICE '], [b, 'bobby']]) {
    await client.request('signup', {username: name, password: 'Password1'});
    await assert.rejects(client.request('list_groups'), {code: 'unauthenticated'});
    assert.equal((await client.request('login', {username: name, password: 'Password1'})).username, name.trim().toLowerCase());
  }
  const room = await a.request('create_group', {room_name: 'General'});
  await b.request('join_group', {room_name: 'General'});
  assert.equal((await a.request('list_groups')).groups.length, 1);
  await assert.rejects(b.request('join_group', {room_name: 'General'}), {code: 'already_member'});
  await a.request('send_message', {room_name: 'General', content: 'hello', username: 'forged'});
  assert.equal(messages.get(room.room_id)[0].username, 'alice');
  await assert.rejects(a.request('send_message', {room_name: 'General', content: 'pineapple'}), {code: 'forbidden_term'});
  await assert.rejects(a.request('send_message', {room_name: 'General', content: 'https://evil.example.com'}), {code: 'malicious_url'});
  const history = await a.request('history', {room_name: 'General'});
  messages.add(room.room_id, history.messages);
  assert.deepEqual(messages.get(room.room_id).map(m => m.content), ['hello']);
  await a.request('create_group', {room_name: 'Other'});
  await b.request('send_message', {room_name: 'General', content: 'missed while away'});
  await a.request('history', {room_name: 'Other'}); // Server round trip before checking isolation.
  assert.equal(messages.get(room.room_id).length, 1);
  await a.request('select_room', {room_name: 'General'});
  const restored = await a.request('history', {room_name: 'General'});
  assert.equal(restored.messages.length, 2);
  await a.request('leave_group', {room_name: 'General'});
  await assert.rejects(a.request('select_room', {room_name: 'General'}), {code: 'not_active_member'});
  await a.request('join_group', {room_name: 'General'});
  a.disconnect(); await a.connect(uri);
  await assert.rejects(a.request('history', {room_name: 'General'}), {code: 'unauthenticated'});
  await a.request('login', {username: 'alice', password: 'Password1'});
  await assert.rejects(a.request('send_message', {room_name: 'General', content: 'not selected'}), {code: 'room_not_selected'});
  await a.request('select_room', {room_name: 'General'});
  assert.equal((await a.request('history', {room_name: 'General'})).messages.length, 2);
  console.log('Browser transport: real-server authentication, rooms, live events, history, security rejection, and reconnect passed.');
} finally { clients.forEach(c => c.disconnect()); }

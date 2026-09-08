import test from 'node:test';
import assert from 'node:assert/strict';
import {AutoConnection} from '../connection.mjs';

const settle = () => new Promise(resolve => setImmediate(resolve));
class Connection {
  constructor({onStatus}) { this.onStatus = onStatus; this.calls = 0; this.open = 0; }
  async connect(address) {
    this.address = address; this.calls++;
    this.onStatus('disconnected');
    if (this.fail) throw new Error('private technical detail');
    assert.equal(this.open, 0); this.open = 1; this.onStatus('connected');
  }
  disconnect() { this.open = 0; this.onStatus('disconnected'); }
  request(action) { return Promise.resolve({ok: true, action}); }
}
function setup() {
  const statuses = [], timers = new Map(); let id = 0;
  const client = new AutoConnection({address: 'ws://192.168.1.20:8000/ws', Connection,
    onStatus: status => statuses.push(status),
    schedule: (fn, delay) => { timers.set(++id, {fn, delay}); return id; }, cancel: id => timers.delete(id)});
  const tick = async () => { const [id, task] = [...timers][0]; timers.delete(id); task.fn(); await settle(); return task.delay; };
  return {client, statuses, timers, tick};
}
test('automatic startup and unexpected close retry use one connection and one timer', async () => {
  const {client, statuses, timers, tick} = setup();
  client.start(); client.start(); await settle();
  assert.equal(client.client.calls, 1); assert.equal(timers.size, 0);
  assert.equal(client.client.address, 'ws://192.168.1.20:8000/ws');
  client.client.disconnect(); client.client.onStatus('disconnected');
  assert.equal(statuses.at(-1), 'reconnecting'); assert.equal(timers.size, 1);
  assert.equal(await tick(), 1000); assert.equal(client.client.calls, 2);
  assert.equal(statuses.at(-1), 'connected');
  client.stop(); assert.equal(timers.size, 0); assert.equal(client.client.open, 0);
});
test('failed connections back off to 30 seconds and stop cancels retries', async () => {
  const {client, timers, tick, statuses} = setup(); client.client.fail = true;
  client.start(); await settle(); const delays = [];
  for (let i=0;i<7;i++) delays.push(await tick());
  assert.deepEqual(delays, [1000,2000,4000,8000,16000,30000,30000]);
  assert.ok(statuses.every(status => !status.includes('private')));
  client.stop(); assert.equal(timers.size, 0);
});
test('immediate close after open is retried, and stop/start ignores stale completions', async () => {
  const {client, timers} = setup();
  const connect = client.client.connect.bind(client.client);
  client.client.connect = async address => { await connect(address); client.client.disconnect(); };
  client.start(); await settle(); assert.equal(timers.size, 1);
  client.stop(); client.client.connect = connect;
  client.start(); await settle(); assert.equal(client.client.open, 1); assert.equal(timers.size, 0);
  client.stop();
});

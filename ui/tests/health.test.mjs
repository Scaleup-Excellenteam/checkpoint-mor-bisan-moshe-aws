import test from 'node:test';
import assert from 'node:assert/strict';
import {HealthMonitor, defaultWebSocketURL, healthURL} from '../health.mjs';

const settle = () => new Promise(resolve => setImmediate(resolve));
function setup(fetcher) {
  const statuses = [], timers = new Map(); let next = 0;
  const monitor = new HealthMonitor({fetcher, onStatus: s => statuses.push(s),
    schedule: (fn, delay) => { timers.set(++next, {fn, delay}); return next; },
    cancel: id => timers.delete(id)});
  return {monitor, statuses, timers};
}
test('page protocol/host determine WebSocket default and health address', () => {
  assert.equal(defaultWebSocketURL({protocol: 'http:', host: '192.168.1.8:8000'}), 'ws://192.168.1.8:8000/ws');
  assert.equal(defaultWebSocketURL({protocol: 'https:', host: 'chat.example'}), 'wss://chat.example/ws');
  assert.equal(healthURL('wss://chat.example/ws'), 'https://chat.example/health');
  for (const bad of ['http://chat.example/ws', 'ws://user:secret@chat.example/ws', 'ws://chat.example/ws?token=x']) assert.throws(() => healthURL(bad));
});
test('health succeeds, polls every 30 seconds, and stop removes timers', async () => {
  let calls = 0;
  const {monitor, statuses, timers} = setup(async (url, options) => {
    calls++; assert.equal(url, 'http://localhost:8000/health');
    assert.equal(options.credentials, 'omit');
    return {ok: true, json: async () => ({ok: true, status: 'healthy'})};
  });
  monitor.start('ws://localhost:8000/ws'); await settle();
  assert.deepEqual(statuses, ['Connecting…', 'Server online']);
  const [id, timer] = [...timers][0]; assert.equal(timer.delay, 30000);
  timers.delete(id); timer.fn(); await settle(); assert.equal(calls, 2);
  monitor.stop(); assert.equal(timers.size, 0);
});
test('HTTP failures and malformed responses report unavailable without throwing', async () => {
  for (const fetcher of [async () => { throw new Error('offline'); },
    async () => ({ok: false}), async () => ({ok: true, json: async () => ({ok: true})})]) {
    const {monitor, statuses} = setup(fetcher);
    monitor.start('ws://localhost/ws'); await settle();
    assert.equal(statuses.at(-1), 'Server unavailable'); monitor.stop();
  }
});
test('timeout aborts and stale health responses cannot overwrite a new address', async () => {
  const {monitor, statuses, timers} = setup((url, {signal}) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(new Error('aborted')));
  }));
  monitor.start('ws://localhost/ws');
  [...timers.values()][0].fn(); await settle();
  assert.equal(statuses.at(-1), 'Server unavailable'); monitor.stop();
  let finish;
  monitor.fetcher = () => new Promise(resolve => { finish = resolve; });
  monitor.start('ws://old/ws');
  monitor.stop();
  finish({ok: true, json: async () => ({ok: true, status: 'healthy'})}); await settle();
  assert.equal(statuses.at(-1), 'Connecting…'); assert.equal(timers.size, 0);
});

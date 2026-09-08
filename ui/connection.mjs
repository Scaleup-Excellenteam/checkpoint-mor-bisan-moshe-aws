import {ChatConnection} from './protocol.mjs';

// One owner for retries; ChatConnection retains its single reader and stale-socket guards.
export class AutoConnection {
  constructor({address, onStatus = () => {}, onEvent = () => {}, Connection = ChatConnection,
    schedule = (fn, delay) => globalThis.setTimeout(fn, delay), cancel = id => globalThis.clearTimeout(id)} = {}) {
    Object.assign(this, {address, onStatus, schedule, cancel});
    this.active = false; this.connecting = false; this.generation = 0; this.failures = 0;
    this.client = new Connection({onEvent, onStatus: status => {
      if (!this.active) return;
      this.ready = status === 'connected';
      if (status === 'connected') { this.failures = 0; this.onStatus('connected'); }
      if (status === 'disconnected' && !this.connecting) this.retry();
    }});
  }
  start() {
    if (this.active) return;
    this.active = true; this.connect();
  }
  async connect() {
    if (!this.active || this.connecting) return;
    const generation = this.generation;
    this.connecting = true;
    this.onStatus(this.failures ? 'reconnecting' : 'connecting');
    let failed = false;
    try { await this.client.connect(this.address); } catch { failed = true; }
    if (generation !== this.generation) return;
    this.connecting = false;
    if (failed || !this.ready) this.retry();
  }
  retry() {
    if (!this.active || this.timer != null) return;
    this.onStatus('reconnecting');
    const delay = Math.min(1000 * 2 ** Math.min(this.failures++, 5), 30000);
    this.timer = this.schedule(() => { this.timer = null; this.connect(); }, delay);
  }
  request(action, fields) { return this.client.request(action, fields); }
  stop() {
    this.active = false; this.generation++; this.connecting = false;
    this.cancel(this.timer); this.timer = null;
    this.client.disconnect(); this.onStatus('disconnected');
  }
  restart() { this.stop(); this.failures = 0; this.start(); }
}

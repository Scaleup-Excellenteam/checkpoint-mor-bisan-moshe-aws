// HTTP liveness is independent of the authenticated WebSocket connection.
export const defaultWebSocketURL = location => `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`;
export function healthURL(address) {
  const url = new URL(address);
  if (!['ws:', 'wss:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('Invalid address');
  url.protocol = url.protocol === 'wss:' ? 'https:' : 'http:';
  url.pathname = '/health';
  return url.href;
}

export class HealthMonitor {
  constructor({fetcher = (...args) => globalThis.fetch(...args), onStatus = () => {}, interval = 30000, timeout = 5000,
    schedule = (fn, delay) => globalThis.setTimeout(fn, delay), cancel = id => globalThis.clearTimeout(id)} = {}) {
    Object.assign(this, {fetcher, onStatus, interval, timeout, schedule, cancel});
    this.generation = 0;
  }
  start(address) {
    this.stop();
    this.onStatus('Connecting…');
    let url;
    try { url = healthURL(address); }
    catch { this.onStatus('Server unavailable'); return; }
    this.check(url, this.generation);
  }
  stop() {
    this.generation++;
    this.cancel(this.timer); this.cancel(this.deadline);
    this.controller?.abort();
  }
  async check(url, generation) {
    const controller = this.controller = new AbortController();
    this.deadline = this.schedule(() => controller.abort(), this.timeout);
    let online = false;
    try {
      const response = await this.fetcher(url, {signal: controller.signal, cache: 'no-store', credentials: 'omit', redirect: 'error'});
      const body = response.ok ? await response.json() : null;
      online = body?.ok === true && body?.status === 'healthy';
    } catch { /* Offline, CORS, malformed responses and timeouts are liveness failures. */ }
    if (generation !== this.generation) return;
    this.cancel(this.deadline);
    this.onStatus(online ? 'Server online' : 'Server unavailable');
    this.timer = this.schedule(() => this.check(url, generation), this.interval);
  }
}

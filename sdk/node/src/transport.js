import https from 'node:https';
import { ICredsError, discovery, encrypt, fail, parse } from './protocol.js';

export function endpoint(input) {
  let url; try { url = new URL(input); } catch { fail('invalid_endpoint'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !/^\/(?:[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*)?\/?$/.test(url.pathname)) fail('https_endpoint_required');
  url.pathname = url.pathname.replace(/\/$/, '');
  return url;
}
function abortError(signal) { return new ICredsError(signal.reason?.name === 'TimeoutError' ? 'request_timeout' : 'request_cancelled'); }
export function duration(value, maximum = 120000) { if (!Number.isInteger(value) || value < 1 || value > maximum) fail('invalid_timeout'); return value; }
async function credential(provider, signal) {
  if (signal.aborted) throw abortError(signal);
  let listener;
  try { return await Promise.race([Promise.resolve().then(provider), new Promise((_, reject) => { listener = () => reject(abortError(signal)); signal.addEventListener('abort', listener, { once: true }); })]); }
  catch (e) { if (e instanceof ICredsError) throw e; fail('credential_unavailable'); }
  finally { if (listener) signal.removeEventListener('abort', listener); }
}
export class Transport {
  #base; #scheme; #agent; #provider; #organization; #timeout; #discovery; #closed = false; #active = 0; #shutdown = new AbortController();
  constructor(options, device) {
    this.#base = endpoint(options.endpoint ?? 'https://api.indyzai.com/icreds');
    if (options.rejectUnauthorized === false || options.insecure || options.transport || options.fetch) fail('unsupported_transport_option');
    this.#timeout = duration(options.timeoutMs ?? 30000);
    if ((options.token !== undefined) === (options.credentialProvider !== undefined) && !device) fail('choose_one_credential_provider');
    this.#scheme = device ? 'Device-Certificate' : 'Bearer';
    const tokenValue = options.token;
    this.#provider = device?.provider ?? options.credentialProvider ?? (() => tokenValue);
    if (typeof this.#provider !== 'function') fail('invalid_credential_provider');
    this.#organization = options.organizationId ?? '';
    if (this.#organization && !validId(this.#organization)) fail('invalid_organization');
    this.#agent = new https.Agent({ keepAlive: true, maxSockets: 8, maxTotalSockets: 8, maxFreeSockets: 2, rejectUnauthorized: true, minVersion: device ? 'TLSv1.3' : 'TLSv1.2', ca: options.ca, ...(device ? { cert: device.cert, key: device.key } : {}) });
  }
  close() { this.#closed = true; this.#shutdown.abort(); this.#discovery = undefined; this.#agent.destroy(); }
  refreshKeys() { this.#discovery = undefined; }
  async #wire(url, method, headers, body, signal, limit) {
    if (signal.aborted) throw abortError(signal);
    return new Promise((resolve, reject) => {
      let complete = false;
      const chunks = []; let size = 0;
      const finish = (error, value) => { if (complete) return; complete = true; for (const chunk of chunks) chunk.fill(0); error ? reject(error) : resolve(value); };
      const req = https.request(url, { method, agent: this.#agent, headers, signal, maxHeaderSize: 32768, rejectUnauthorized: true }, res => {
        if (res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity') { res.destroy(); finish(new ICredsError('invalid_response_encoding')); return; }
        if (!/^application\/json(?:\s*;|$)/i.test(res.headers['content-type'] ?? '')) { res.destroy(); finish(new ICredsError('invalid_response')); return; }
        res.on('data', chunk => { size += chunk.length; if (size > limit) { chunk.fill(0); res.destroy(); finish(new ICredsError('response_too_large')); } else chunks.push(chunk); });
        res.on('end', () => finish(null, { raw: Buffer.concat(chunks), status: res.statusCode, headers: res.headers }));
        res.on('error', () => finish(signal.aborted ? abortError(signal) : new ICredsError('connection_unavailable')));
        res.on('aborted', () => finish(new ICredsError('response_incomplete')));
      });
      req.on('error', () => finish(signal.aborted ? abortError(signal) : new ICredsError('connection_unavailable')));
      if (body) req.end(body); else req.end();
    });
  }
  async request(method, path, body, options = {}, organizationRequired = true) {
    if (this.#closed) fail('client_closed');
    if (this.#active >= 32) fail('concurrency_limit');
    if (organizationRequired && !this.#organization) fail('organization_required');
    if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) fail('invalid_abort_signal');
    const signal = AbortSignal.any([this.#shutdown.signal, AbortSignal.timeout(duration(options.timeoutMs ?? this.#timeout)), ...(options.signal ? [options.signal] : [])]);
    this.#active++;
    let exchange, bodySize = 0;
    try {
      const headers = { Accept: 'application/json', 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
      const token = await credential(this.#provider, signal);
      if (typeof token !== 'string' || !token || token.length > 16384 || /[\x00-\x20\x7f]/.test(token)) fail('invalid_credential');
      headers.Authorization = `${this.#scheme} ${token}`;
      if (this.#organization) headers['X-Tenant-ID'] = this.#organization;
      for (const [option, name] of [['idempotencyKey', 'Idempotency-Key'], ['ifMatch', 'If-Match']]) {
        if (options[option] !== undefined) { const value = options[option]; if (typeof value !== 'string' || !value || value.length > 128 || /[\x00-\x1f\x7f]/.test(value)) fail('invalid_request_option'); headers[name] = value; }
      }
      if (body !== undefined) {
        let raw; try { raw = Buffer.from(JSON.stringify(body)); } catch { fail('invalid_request_body'); }
        try { if (raw.length > 131072) fail('request_too_large'); bodySize = raw.length; body = parse(raw); } finally { raw.fill(0); }
      }
      if (!this.#discovery || this.#discovery.expires <= Date.now()) {
        const url = new URL(this.#base); url.pathname += '/jwe/config';
        const result = await this.#wire(url, 'GET', { Accept: 'application/json', 'Cache-Control': 'no-store' }, null, signal, 65536);
        try { if (result.status !== 200) fail('discovery_unavailable'); this.#discovery = { value: discovery(parse(result.raw)), expires: Date.now() + 60000 }; } finally { result.raw.fill(0); }
      }
      if (bodySize > this.#discovery.value.max) fail('request_too_large');
      // Paths originate in typed SDK methods; never accept a caller-supplied URL.
      if (!path.startsWith('/api/v1/') || /[#\r\n]/.test(path)) fail('invalid_api_path');
      const url = new URL(this.#base.href.replace(/\/$/, '') + path);
      exchange = encrypt(this.#discovery.value, method, url, headers, body);
      const response = await this.#wire(url, method, exchange.headers, exchange.wire, signal, 8 * 1024 * 1024);
      let result; try { result = exchange.decrypt(response.status, response.headers, response.raw); } finally { response.raw.fill(0); }
      if (result.status < 200 || result.status >= 300) throw new ICredsError(/^[a-z0-9_]{1,80}$/.test(result.body?.code ?? '') ? result.body.code : 'request_rejected', result.status, result.headers);
      return Object.freeze(result);
    } catch (e) { throw e instanceof ICredsError ? e : new ICredsError(signal.aborted ? abortError(signal).code : 'connection_unavailable'); }
    finally { exchange?.wire?.fill(0); exchange?.close(); this.#active--; }
  }
}
export function validId(value) { return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value); }
export function id(value) { if (!validId(value)) fail('invalid_id'); return value; }

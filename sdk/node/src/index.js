import { randomUUID } from 'node:crypto';
import { inspect } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { ICredsError, fail } from './protocol.js';
import { Transport, duration, id } from './transport.js';
import { SecretValue, decodeSecret } from './secret.js';
export { SecretValue } from './secret.js';
export { ICredsError } from './protocol.js';
export { DeviceClient } from './device.js';
export const newIdempotencyKey = () => randomUUID();

function encodeSecret(value) {
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > 65536) fail('invalid_secret_input');
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('base64');
}
function text(value, maximum = 256) { if (typeof value !== 'string' || !value || Buffer.byteLength(value) > maximum || /[\x00-\x1f\x7f]/.test(value)) fail('invalid_input'); return value; }
function version(value) { if (!Number.isSafeInteger(value) || value < 1) fail('invalid_version'); return value; }
function write(options, existing = false) {
  if (!options?.idempotencyKey) fail('idempotency_key_required');
  if (existing && !/^"[1-9][0-9]*"$/.test(options.ifMatch ?? '')) fail('if_match_required');
  return options;
}
function pathQuery(path, filters = {}, names = ['limit', 'cursor', 'projectId', 'environment', 'namespace']) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (!names.includes(key)) fail('unsupported_filter');
    if (value === undefined) continue;
    if (key === 'limit') { if (!Number.isInteger(value) || value < 1 || value > 100) fail('invalid_page_size'); }
    else if (typeof value !== 'string' || value.length > 4096) fail('invalid_filter');
    query.set(key, String(value));
  }
  return path + (query.size ? `?${query}` : '');
}
async function* pages(read, filters, options) {
  let cursor = filters?.cursor;
  const seen = new Set();
  do {
    const result = await read({ ...filters, cursor }, options);
    if (!Array.isArray(result.body?.items)) fail('invalid_page_response');
    yield result;
    cursor = result.body.nextCursor;
    if (cursor !== undefined && (typeof cursor !== 'string' || cursor.length > 4096)) fail('invalid_page_response');
    if (cursor && seen.has(cursor)) fail('pagination_cycle');
    if (cursor) seen.add(cursor);
  } while (cursor);
}
export class SecretClient {
  #transport;
  constructor(options) {
    this.#transport = new Transport(options ?? {});
    const call = (...args) => this.#transport.request(...args);
    const list = (filters, opts) => call('GET', pathQuery('/api/v1/secrets', filters), undefined, opts);
    this.secrets = Object.freeze({
      get: (secretId, opts) => call('GET', `/api/v1/secrets/${id(secretId)}`, undefined, opts),
      list,
      pages: (filters, opts) => pages(list, filters, opts),
      versions: Object.freeze({ list: (secretId, opts) => call('GET', `/api/v1/secrets/${id(secretId)}/versions`, undefined, opts) }),
      access: async (secretId, input, opts) => {
        const body = { reason: text(input?.reason) }; if (input?.version !== undefined) body.version = version(input.version);
        const result = await call('POST', `/api/v1/secrets/${id(secretId)}:access`, body, opts);
        if (result.body?.secretId !== secretId) fail('invalid_secret_response');
        version(result.body.version);
        const secret = decodeSecret(result.body.value);
        result.body.value = undefined;
        return Object.freeze({ ...result, body: Object.freeze({ secretId, version: result.body.version, value: secret }) });
      },
    });
    this.session = Object.freeze({ current: opts => call('GET', '/api/v1/session', undefined, opts), tenants: opts => call('GET', '/api/v1/tenants', undefined, opts, false) });
  }
  close() { this.#transport.close(); }
  refreshKeys() { this.#transport.refreshKeys(); }
  [inspect.custom]() { return 'ICredsClient [credentials redacted]'; }
  toJSON() { return { client: this.constructor.name }; }
}
export class ManagementClient extends SecretClient {
  #management;
  constructor(options) {
    super(options);
    this.#management = new Transport(options ?? {});
    const call = (...args) => this.#management.request(...args);
    const mutate = (method, path, input, opts, existing = true) => call(method, path, input, write(opts, existing));
    this.secrets = Object.freeze({ ...this.secrets,
      create: (input, opts) => {
        if (!input) fail('invalid_input');
        const body = { projectId: id(input.projectId), environment: text(input.environment), namespace: text(input.namespace), name: text(input.name), value: encodeSecret(input.value) };
        return mutate('POST', '/api/v1/secrets', body, opts, false);
      },
      versions: Object.freeze({ ...this.secrets.versions, create: (secretId, value, opts) => mutate('PUT', `/api/v1/secrets/${id(secretId)}/versions`, { value: encodeSecret(value) }, opts) }),
      rotate: (secretId, opts) => mutate('POST', `/api/v1/secrets/${id(secretId)}:rotate`, {}, opts),
      revoke: (secretId, opts) => mutate('POST', `/api/v1/secrets/${id(secretId)}:revoke`, {}, opts),
      restore: (secretId, selected, opts) => mutate('POST', `/api/v1/secrets/${id(secretId)}:restore`, { version: version(selected) }, opts),
    });
    this.keyRings = Object.freeze({ get: (keyId, opts) => call('GET', `/api/v1/key-rings/${id(keyId)}`, undefined, opts), rotate: (keyId, opts) => mutate('POST', `/api/v1/key-rings/${id(keyId)}:rotate`, {}, opts) });
    this.cryptoMigrations = Object.freeze({ create: (input, opts) => mutate('POST', '/api/v1/crypto-migrations', input, opts, false) });
    const getOperation = (operationId, opts) => call('GET', `/api/v1/operations/${id(operationId)}`, undefined, opts);
    this.operations = Object.freeze({ get: getOperation, approve: (operationId, opts) => mutate('POST', `/api/v1/operations/${id(operationId)}:approve`, {}, opts), wait: async (operationId, options = {}) => {
      id(operationId); const timeout = duration(options.waitTimeoutMs ?? 120000, 3600000); const interval = duration(options.pollIntervalMs ?? 1000, 30000);
      const signal = AbortSignal.any([AbortSignal.timeout(timeout), ...(options.signal ? [options.signal] : [])]);
      try {
        for (;;) {
          const result = await getOperation(operationId, { ...options, signal });
          if (result.body?.id !== operationId) fail('invalid_operation_response');
          if (result.body.status === 'succeeded') return result;
          if (result.body.status === 'failed') throw new ICredsError('operation_failed', 409);
          if (!['pending', 'running'].includes(result.body.status)) fail('invalid_operation_status');
          await delay(interval, undefined, { signal });
        }
      } catch (e) { if (signal.aborted) throw new ICredsError(signal.reason?.name === 'TimeoutError' ? 'operation_timeout' : 'request_cancelled'); throw e; }
    } });
    this.leases = Object.freeze({ get: (leaseId, opts) => call('GET', `/api/v1/leases/${id(leaseId)}`, undefined, opts), revoke: (leaseId, opts) => mutate('POST', `/api/v1/leases/${id(leaseId)}:revoke`, {}, opts) });
    const auditList = (filters, opts) => call('GET', pathQuery('/api/v1/audit-events', filters), undefined, opts);
    this.audit = Object.freeze({ list: auditList, pages: (filters, opts) => pages(auditList, filters, opts) });
    this.devices = Object.freeze({
      list: opts => call('GET', '/api/v1/devices', undefined, opts),
      get: (deviceId, opts) => call('GET', `/api/v1/devices/${id(deviceId)}`, undefined, opts),
      configure: (deviceId, input, opts) => mutate('PUT', `/api/v1/devices/${id(deviceId)}`, input, opts),
      disable: (deviceId, opts) => mutate('POST', `/api/v1/devices/${id(deviceId)}:disable`, {}, opts),
      revoke: (deviceId, opts) => mutate('POST', `/api/v1/devices/${id(deviceId)}:revoke`, {}, opts),
      reconcileRenewal: (deviceId, input, opts) => mutate('POST', `/api/v1/devices/${id(deviceId)}:reconcile-renewal`, input, opts),
    });
    this.enrollments = Object.freeze({
      create: async (input, opts) => {
        const result = await mutate('POST', '/api/v1/device-enrollments', input, opts, false);
        if (typeof result.body?.authId !== 'string') fail('invalid_enrollment_response');
        const raw = Buffer.from(result.body.authId);
        try { const value = new SecretValue(raw); result.body.authId = value; return result; } finally { raw.fill(0); }
      },
      get: (grantId, opts) => call('GET', `/api/v1/device-enrollments/${id(grantId)}`, undefined, opts),
      approve: (grantId, fingerprint, opts) => mutate('POST', `/api/v1/device-enrollments/${id(grantId)}:approve`, { fingerprint: text(fingerprint) }, opts),
      revoke: (grantId, opts) => mutate('POST', `/api/v1/device-enrollments/${id(grantId)}:revoke`, {}, opts),
      reconcile: (grantId, certificate, opts) => mutate('POST', `/api/v1/device-enrollments/${id(grantId)}:reconcile`, { certificate }, opts),
    });
  }
  close() { super.close(); this.#management.close(); }
  refreshKeys() { super.refreshKeys(); this.#management.refreshKeys(); }
}

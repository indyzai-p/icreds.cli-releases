import { inspect } from 'node:util';
import { fail } from './protocol.js';

export class SecretValue {
  #value; #disposed = false;
  constructor(value) { if (!(value instanceof Uint8Array)) fail('secret_bytes_required'); this.#value = Buffer.from(value); }
  bytes() { if (this.#disposed) fail('secret_disposed'); return Buffer.from(this.#value); }
  async withBytes(callback) { const copy = this.bytes(); try { return await callback(copy); } finally { copy.fill(0); } }
  dispose() { this.#value.fill(0); this.#disposed = true; }
  toJSON() { return '[REDACTED]'; }
  toString() { return '[REDACTED]'; }
  [inspect.custom]() { return 'SecretValue [REDACTED]'; }
}
export function decodeSecret(value) {
  if (typeof value !== 'string' || value.length > 87384 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail('invalid_secret_response');
  const raw = Buffer.from(value, 'base64');
  try { if (raw.length < 1 || raw.length > 65536 || raw.toString('base64') !== value) fail('invalid_secret_response'); return new SecretValue(raw); } finally { raw.fill(0); }
}

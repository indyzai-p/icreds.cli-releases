import { constants, createCipheriv, createDecipheriv, createHash, createPublicKey, publicEncrypt, randomBytes } from 'node:crypto';

export class ICredsError extends Error {
  constructor(code, status = 0, headers = {}) {
    super(/^[a-z0-9_]{1,80}$/.test(code) ? code : 'request_failed');
    this.name = 'ICredsError';
    this.code = this.message;
    this.status = status;
    this.headers = Object.freeze({ ...headers });
  }
  toJSON() { return { name: this.name, code: this.code, status: this.status }; }
}
export function fail(code, status = 0) { throw new ICredsError(code, status); }
export function exact(object, names) {
  if (!object || Array.isArray(object) || typeof object !== 'object' || Object.keys(object).length !== names.length || names.some(name => !Object.hasOwn(object, name))) fail('invalid_encrypted_response');
}
export function b64(raw) { return Buffer.from(raw).toString('base64url'); }
export function unb64(value, max = 8 * 1024 * 1024) {
  if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3) || !/^[A-Za-z0-9_-]*$/.test(value)) fail('invalid_encrypted_response');
  const raw = Buffer.from(value, 'base64url');
  if (b64(raw) !== value || raw.length > max) fail('invalid_encrypted_response');
  return raw;
}
// Reject duplicate keys before JSON.parse can silently discard a binding. Keep
// this parser bounded and use native JSON.parse for the final value construction.
export function parse(raw) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); } catch { fail('invalid_json_response'); }
  let i = 0;
  const ws = () => { while (i < text.length && /[\x20\t\r\n]/.test(text[i])) i++; };
  function string() {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === '"') {
        const value = JSON.parse(text.slice(start, i));
        for (let n = 0; n < value.length; n++) {
          const unit = value.charCodeAt(n);
          if (unit >= 0xd800 && unit <= 0xdbff) { const next = value.charCodeAt(++n); if (!(next >= 0xdc00 && next <= 0xdfff)) throw Error(); }
          else if (unit >= 0xdc00 && unit <= 0xdfff) throw Error();
        }
        return value;
      }
      if (c === '\\') i++;
    }
    throw Error();
  }
  function value(depth) {
    if (depth > 32) throw Error();
    ws();
    if (text[i] === '"') { string(); return; }
    if (text[i] === '{') {
      i++; ws(); const keys = new Set();
      if (text[i] === '}') { i++; return; }
      for (;;) {
        ws(); if (text[i] !== '"') throw Error(); const key = string();
        if (keys.has(key) || ['__proto__', 'prototype', 'constructor'].includes(key)) throw Error(); keys.add(key);
        ws(); if (text[i++] !== ':') throw Error(); value(depth + 1); ws();
        const end = text[i++]; if (end === '}') return; if (end !== ',') throw Error();
      }
    }
    if (text[i] === '[') {
      i++; ws(); if (text[i] === ']') { i++; return; }
      for (;;) { value(depth + 1); ws(); const end = text[i++]; if (end === ']') return; if (end !== ',') throw Error(); }
    }
    const match = /^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));
    if (!match) throw Error();
    if (/^-?[0-9]/.test(match[0])) { const n = Number(match[0]); if (!Number.isFinite(n) || (Number.isInteger(n) && !Number.isSafeInteger(n))) throw Error(); }
    i += match[0].length;
  }
  try { value(0); ws(); if (i !== text.length) throw Error(); return JSON.parse(text); } catch { fail('invalid_json_response'); }
}
export function discovery(cfg) {
  const j = cfg?.jwk;
  if (cfg?.enabled !== true || cfg.alg !== 'RSA-OAEP-256' || cfg.enc !== 'A256GCM' || cfg.ttl_seconds !== 60 || !Number.isInteger(cfg.max_plaintext_bytes) || cfg.max_plaintext_bytes < 1 || cfg.max_plaintext_bytes > 131072 || j?.kty !== 'RSA' || j.alg !== 'RSA-OAEP-256' || j.use !== 'enc' || j.e !== 'AQAB') fail('invalid_jwe_discovery');
  if (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some(k => Object.hasOwn(j, k))) fail('invalid_jwe_discovery');
  try {
    const n = unb64(j.n, 512);
    if (n.length < 256 || n[0] === 0) fail('invalid_jwe_discovery');
    const canonical = JSON.stringify({ e: j.e, kty: 'RSA', n: j.n });
    if (b64(createHash('sha256').update(canonical).digest()) !== j.kid) fail('invalid_jwe_discovery');
    const key = createPublicKey({ key: { kty: 'RSA', n: j.n, e: j.e }, format: 'jwk' });
    if (key.asymmetricKeyDetails.modulusLength < 2048 || key.asymmetricKeyDetails.modulusLength > 4096) fail('invalid_jwe_discovery');
    return { key, kid: j.kid, max: cfg.max_plaintext_bytes };
  } catch { fail('invalid_jwe_discovery'); }
}
function seal(header, plain, key, wrapped) {
  const encoded = b64(Buffer.from(JSON.stringify(header)));
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(encoded, 'ascii'));
  return [encoded, b64(wrapped), b64(iv), b64(Buffer.concat([cipher.update(plain), cipher.final()])), b64(cipher.getAuthTag())].join('.');
}
export function encrypt(cfg, method, url, headers, body) {
  const responseKey = randomBytes(32), cek = randomBytes(32);
  const id = b64(randomBytes(16)), now = Math.floor(Date.now() / 1000);
  let used = false;
  const close = () => { used = true; responseKey.fill(0); };
  try {
    const env = { v: 1, jti: id, iat: now, exp: now + 60, method, path: url.pathname, query: url.search.slice(1), authorization_hash: b64(createHash('sha256').update(headers.Authorization ?? '').digest()), tenant_id: headers['X-Tenant-ID'] ?? '', idempotency_key: headers['Idempotency-Key'] ?? '', if_match: headers['If-Match'] ?? '', response_key: b64(responseKey), body: body ?? null };
    const plain = Buffer.from(JSON.stringify(env));
    let compact;
    try { compact = seal({ alg: 'RSA-OAEP-256', enc: 'A256GCM', kid: cfg.kid, typ: 'icreds-request+jwe', cty: 'application/json' }, plain, cek, publicEncrypt({ key: cfg.key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, cek)); }
    finally { plain.fill(0); cek.fill(0); }
    const wireHeaders = { ...headers, 'X-ICREDS-JWE': 'v1' };
    let wire;
    if (method === 'GET') { if (compact.length > 8192) fail('request_too_large'); wireHeaders['X-ICREDS-JWE-Request'] = compact; }
    else wire = Buffer.from(JSON.stringify({ jwe: compact }));
    return { headers: wireHeaders, wire, close, decrypt(status, received, raw) {
      if (used) fail('encrypted_response_consumed');
      try {
        if (received['x-icreds-jwe'] !== 'v1' || received['x-icreds-jwe-id'] !== id) fail('encrypted_response_invalid');
        const outer = parse(raw); exact(outer, ['jwe']);
        if (typeof outer.jwe !== 'string') fail('encrypted_response_invalid');
        const parts = outer.jwe.split('.'); if (parts.length !== 5 || parts[1] !== '') fail('encrypted_response_invalid');
        const header = parse(unb64(parts[0], 1024)); exact(header, ['alg', 'enc', 'kid', 'typ', 'cty']);
        if (header.alg !== 'dir' || header.enc !== 'A256GCM' || header.kid !== id || header.typ !== 'icreds-response+jwe' || header.cty !== 'application/json') fail('encrypted_response_invalid');
        const iv = unb64(parts[2], 12), tag = unb64(parts[4], 16);
        if (iv.length !== 12 || tag.length !== 16) fail('encrypted_response_invalid');
        const decipher = createDecipheriv('aes-256-gcm', responseKey, iv, { authTagLength: 16 });
        decipher.setAAD(Buffer.from(parts[0], 'ascii')); decipher.setAuthTag(tag);
        let plain;
        try { plain = Buffer.concat([decipher.update(unb64(parts[3])), decipher.final()]);
          const result = parse(plain); exact(result, ['v', 'jti', 'status', 'method', 'path', 'headers', 'body']);
          if (result.v !== 1 || result.jti !== id || result.status !== status || result.method !== method || result.path !== url.pathname || !result.headers || Array.isArray(result.headers) || typeof result.headers !== 'object') fail('encrypted_response_invalid');
          const verified = {};
          for (const [key, value] of Object.entries(result.headers)) { if (!['ETag', 'Location', 'Retry-After'].includes(key) || typeof value !== 'string' || value.length > 8192 || /[\x00-\x1f\x7f]/.test(value)) fail('encrypted_response_invalid'); verified[key] = value; }
          return { body: result.body, headers: Object.freeze(verified), status };
        } finally { plain?.fill(0); }
      } catch { fail('encrypted_response_invalid'); } finally { close(); }
    } };
  } catch (e) { close(); cek.fill(0); throw e instanceof ICredsError ? e : new ICredsError('encryption_failed'); }
}

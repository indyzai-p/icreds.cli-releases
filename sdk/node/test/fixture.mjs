import { generateKeyPairSync, createHash, privateDecrypt, constants, createDecipheriv, createCipheriv, randomBytes } from 'node:crypto';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after } from 'node:test';

const directory = mkdtempSync(join(tmpdir(), 'icreds-node-tls-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem')], { stdio: 'ignore' });
const key = readFileSync(join(directory, 'key.pem')), cert = readFileSync(join(directory, 'cert.pem'));
after(() => { key.fill(0); rmSync(directory, { recursive: true, force: true }); });
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJWK = publicKey.export({ format: 'jwk' });
const kid = createHash('sha256').update(JSON.stringify({ e: publicJWK.e, kty: 'RSA', n: publicJWK.n })).digest('base64url');
export const ID = '11111111-1111-4111-8111-111111111111';
export const ORG = '22222222-2222-4222-8222-222222222222';
const b64 = bytes => Buffer.from(bytes).toString('base64url');
export async function fixture(t) {
  const state = { mode: '', records: [], discovery: 0, seen: new Set(), operations: 0 };
  const server = https.createServer({ key, cert }, async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store, private');
    const url = new URL(req.url, 'https://fixture.invalid');
    if (url.pathname === '/icreds/jwe/config' || url.pathname === '/jwe/config') {
      state.discovery++;
      const cfg = { enabled: true, required: true, alg: 'RSA-OAEP-256', enc: 'A256GCM', ttl_seconds: 60, max_plaintext_bytes: 131072, jwk: { ...publicJWK, kid, alg: 'RSA-OAEP-256', use: 'enc' } };
      if (state.mode === 'discovery-alg') cfg.alg = 'RSA1_5';
      res.end(JSON.stringify(cfg)); return;
    }
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const wire = Buffer.concat(chunks);
      const compact = req.method === 'GET' ? req.headers['x-icreds-jwe-request'] : JSON.parse(wire).jwe;
      const parts = compact.split('.'), header = JSON.parse(Buffer.from(parts[0], 'base64url'));
      if (parts.length !== 5 || header.alg !== 'RSA-OAEP-256' || header.enc !== 'A256GCM' || header.kid !== kid || req.headers['x-icreds-jwe'] !== 'v1') throw Error('profile');
      const cek = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(parts[1], 'base64url'));
      const decipher = createDecipheriv('aes-256-gcm', cek, Buffer.from(parts[2], 'base64url'));
      decipher.setAAD(Buffer.from(parts[0])); decipher.setAuthTag(Buffer.from(parts[4], 'base64url'));
      const env = JSON.parse(Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64url')), decipher.final()])); cek.fill(0);
      if (env.path !== url.pathname || env.method !== req.method || env.query !== url.search.slice(1) || env.tenant_id !== (req.headers['x-tenant-id'] ?? '') || env.authorization_hash !== createHash('sha256').update(req.headers.authorization ?? '').digest('base64url') || env.idempotency_key !== (req.headers['idempotency-key'] ?? '') || env.if_match !== (req.headers['if-match'] ?? '') || env.exp - env.iat !== 60 || Math.abs(env.iat - Math.floor(Date.now() / 1000)) > 5 || Buffer.from(env.jti, 'base64url').length !== 16) throw Error('binding');
      if (state.seen.has(env.jti)) throw Error('replay'); state.seen.add(env.jti);
      state.records.push({ env, authorization: req.headers.authorization });
      if (state.mode === 'delay') { await new Promise(resolve => setTimeout(resolve, 200)); if (res.destroyed) return; }
      if (state.mode === 'plaintext') { res.end(JSON.stringify({ value: 'must-not-escape' })); return; }
      if (state.mode === 'redirect') { res.writeHead(302, { Location: 'https://example.invalid/steal' }); res.end('{}'); return; }
      let status = 200, body = { id: ID, status: 'active', resourceVersion: 1 };
      if (url.pathname.endsWith(':access')) body = { secretId: ID, version: 1, value: Buffer.from([0, 255, 10, 65]).toString('base64') };
      else if (url.pathname.endsWith('/operations/' + ID)) body = { id: ID, status: ++state.operations > 1 ? 'succeeded' : 'pending' };
      else if (url.pathname.endsWith('/secrets') && req.method === 'GET') body = { items: [{ id: ID }], ...(env.query.includes('cursor=') ? {} : { nextCursor: 'opaque<& +/=' }) };
      else if (url.pathname.endsWith('/device-enrollments') && req.method === 'POST') body = { id: ID, authId: 'disposable-enrollment-credential' };
      if (state.mode === 'denied') { status = 403; body = { code: 'access_denied', message: 'server-secret-must-not-escape' }; }
      const responseKey = Buffer.from(env.response_key, 'base64url');
      const responseHeader = b64(Buffer.from(JSON.stringify({ alg: 'dir', enc: 'A256GCM', kid: env.jti, typ: 'icreds-response+jwe', cty: 'application/json' })));
      const payload = { v: 1, jti: state.mode === 'wrong-jti' ? 'wrong' : env.jti, status: state.mode === 'wrong-status' ? 201 : status, method: req.method, path: state.mode === 'wrong-path' ? '/wrong' : url.pathname, headers: { ETag: '"1"', 'Retry-After': '2' }, body };
      const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', responseKey, iv); cipher.setAAD(Buffer.from(responseHeader));
      const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final()]); responseKey.fill(0);
      const tag = cipher.getAuthTag(); if (state.mode === 'tamper') tag[0] ^= 1;
      res.writeHead(status, { 'X-ICREDS-JWE': 'v1', 'X-ICREDS-JWE-ID': env.jti, ETag: '"999"' });
      res.end(JSON.stringify({ jwe: [responseHeader, '', b64(iv), b64(ciphertext), b64(tag)].join('.') }));
    } catch { res.writeHead(400); res.end('{"code":"fixture_rejected"}'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const clients = [];
  state.endpoint = `https://127.0.0.1:${server.address().port}/icreds`;
  state.ca = cert;
  state.track = client => { clients.push(client); return client; };
  t.after(async () => { for (const client of clients) client.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return state;
}

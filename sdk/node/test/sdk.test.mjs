import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { SecretClient, ManagementClient, SecretValue, ICredsError, newIdempotencyKey } from '../src/index.js';
import { fixture, ID, ORG } from './fixture.mjs';
import { parse } from '../src/protocol.js';

const options = state => ({ endpoint: state.endpoint, ca: state.ca, organizationId: ORG, token: 'disposable-fixture-token' });
test('secret bytes, redaction, authenticated ETags and independent concurrent envelopes', async t => {
  const state = await fixture(t); const client = state.track(new SecretClient(options(state)));
  const results = await Promise.all(Array.from({ length: 4 }, () => client.secrets.access(ID, { reason: 'test' })));
  for (const result of results) {
    assert.equal(result.headers.ETag, '"1"');
    assert.deepEqual(result.body.value.bytes(), Buffer.from([0, 255, 10, 65]));
    assert.match(inspect(result), /REDACTED/); assert.equal(JSON.stringify(result).includes('AP8KQQ=='), false);
    let held; await result.body.value.withBytes(bytes => { held = bytes; assert.equal(bytes[1], 255); }); assert.equal(held.every(n => n === 0), true);
    result.body.value.dispose(); assert.throws(() => result.body.value.bytes(), { code: 'secret_disposed' });
  }
  assert.equal(new Set(state.records.map(r => r.env.jti)).size, 4);
  assert.equal(new Set(state.records.map(r => r.env.response_key)).size, 4);
});
test('management writes require explicit concurrency/idempotency and preserve logical bytes', async t => {
  const state = await fixture(t); const client = state.track(new ManagementClient(options(state)));
  assert.throws(() => client.secrets.revoke(ID, { idempotencyKey: newIdempotencyKey() }), { code: 'if_match_required' });
  assert.throws(() => client.secrets.create({ projectId: ID, environment: 'test', namespace: 'default', name: 'fixture', value: Buffer.from('value') }), { code: 'idempotency_key_required' });
  const logical = { idempotencyKey: newIdempotencyKey(), ifMatch: '"1"' };
  await client.secrets.versions.create(ID, Buffer.from([0, 255]), logical);
  await client.secrets.versions.create(ID, Buffer.from([0, 255]), logical);
  assert.deepEqual(state.records.map(r => r.env.idempotency_key), [logical.idempotencyKey, logical.idempotencyKey]);
  assert.notEqual(state.records[0].env.jti, state.records[1].env.jti);
  assert.equal(state.records[0].env.body.value, 'AP8=');
  const grant = await client.enrollments.create({ label: 'fixture', scope: {}, bindings: [] }, { idempotencyKey: newIdempotencyKey() });
  assert.equal(inspect(grant).includes('disposable-enrollment-credential'), false);
});
test('GET pagination binds exact encoded query and does not place encrypted payload in URL', async t => {
  const state = await fixture(t); const client = state.track(new SecretClient(options(state)));
  let count = 0; for await (const page of client.secrets.pages({ namespace: 'a<& +/=' })) { count++; assert.equal(page.body.items[0].id, ID); }
  assert.equal(count, 2);
  assert.equal(state.records[0].env.body, null);
  assert.match(state.records[1].env.query, /cursor=opaque%3C%26\+%2B%2F%3D/);
  assert.equal(state.records.some(r => r.env.query.includes('jwe')), false);
});
test('rejects downgrade, tampering, response substitution, redirects and unsupported discovery', async t => {
  const state = await fixture(t); const client = state.track(new SecretClient(options(state)));
  for (const mode of ['plaintext', 'tamper', 'wrong-jti', 'wrong-path', 'wrong-status', 'redirect']) {
    state.mode = mode;
    await assert.rejects(client.secrets.get(ID), { code: 'encrypted_response_invalid' });
  }
  state.mode = 'discovery-alg'; client.refreshKeys();
  await assert.rejects(client.secrets.get(ID), { code: 'invalid_jwe_discovery' });
});
test('encrypted application errors expose safe codes only; certificate trust cannot be bypassed', async t => {
  const state = await fixture(t); state.mode = 'denied'; const client = state.track(new SecretClient(options(state)));
  await assert.rejects(client.secrets.access(ID, { reason: 'test' }), error => {
    assert.ok(error instanceof ICredsError); assert.equal(error.status, 403); assert.equal(error.code, 'access_denied');
    assert.equal(error.headers.ETag, '"1"'); assert.equal(inspect(error).includes('server-secret'), false); return true;
  });
  const untrusted = state.track(new SecretClient({ ...options(state), ca: undefined }));
  await assert.rejects(untrusted.secrets.get(ID), { code: 'connection_unavailable' });
  assert.throws(() => new SecretClient({ ...options(state), rejectUnauthorized: false }), { code: 'unsupported_transport_option' });
  assert.throws(() => new SecretClient({ ...options(state), endpoint: 'http://127.0.0.1' }), { code: 'https_endpoint_required' });
});
test('cancellation, credential-provider timeout, close and operation wait are bounded', async t => {
  const state = await fixture(t); const client = state.track(new ManagementClient(options(state)));
  const operation = await client.operations.wait(ID, { pollIntervalMs: 1 }); assert.equal(operation.body.status, 'succeeded');
  state.mode = 'delay'; await assert.rejects(client.secrets.get(ID, { timeoutMs: 15 }), { code: 'request_timeout' });
  const controller = new AbortController(); controller.abort('sensitive-reason');
  await assert.rejects(client.secrets.get(ID, { signal: controller.signal }), { code: 'request_cancelled' });
  const pending = state.track(new SecretClient({ ...options(state), token: undefined, credentialProvider: () => new Promise(() => {}) }));
  await assert.rejects(pending.secrets.get(ID, { timeoutMs: 15 }), { code: 'request_timeout' });
  const request = pending.secrets.get(ID); pending.close(); await assert.rejects(request, { code: 'request_cancelled' });
  client.close(); await assert.rejects(client.secrets.get(ID), { code: 'client_closed' });
});
test('strict JSON, byte boundaries and download-only consumer surface', () => {
  for (const raw of ['{"v":1,"v":2}', '{"__proto__":{}}', '{"v":9007199254740992}', '{"v":"\\ud800"}', '[1,]', '{"x":NaN}']) assert.throws(() => parse(Buffer.from(raw)), ICredsError);
  const client = new SecretClient({ token: 'fixture', organizationId: ORG });
  assert.equal(client.devices, undefined); assert.equal(client.secrets.create, undefined); assert.equal(client.secrets.revoke, undefined);
  assert.equal(inspect(client).includes('fixture'), false); client.close();
  const value = new SecretValue(Buffer.from('sensitive-fixture')); assert.equal(String(value), '[REDACTED]'); value.dispose();
});
test('concurrent clients preserve organization/token pairing and constructor input is immutable', async t => {
  const state = await fixture(t);
  const original = { ...options(state), token: 'first-token' };
  const first = state.track(new SecretClient(original));
  original.token = 'changed-token'; original.organizationId = ID;
  const second = state.track(new SecretClient({ ...options(state), organizationId: ID, credentialProvider: async () => 'second-token', token: undefined }));
  await Promise.all([first.secrets.get(ID), second.secrets.get(ID)]);
  for (const record of state.records) {
    assert.equal(record.authorization, record.env.tenant_id === ORG ? 'Bearer first-token' : 'Bearer second-token');
  }
});

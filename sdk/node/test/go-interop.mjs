// Invoked only by the private Go middleware conformance test with disposable TLS.
import assert from 'node:assert/strict';
import { ManagementClient, DeviceClient, newIdempotencyKey } from '../src/index.js';
const ID = '11111111-1111-4111-8111-111111111111';
const client = new ManagementClient({ endpoint: process.env.ICREDS_SDK_TEST_ENDPOINT, ca: process.env.ICREDS_SDK_TEST_CA, organizationId: '22222222-2222-4222-8222-222222222222', token: 'disposable-conformance-token' });
try {
  const result = await client.secrets.access(ID, { reason: 'conformance <&> 雪\u2028', version: 1 });
  assert.deepEqual(result.body.value.bytes(), Buffer.from([0, 255, 10, 65])); result.body.value.dispose();
  assert.equal(result.headers.ETag, '"3"');
  await client.secrets.versions.create(ID, Buffer.from([0, 255]), { idempotencyKey: newIdempotencyKey(), ifMatch: '"3"' });
  await client.secrets.list({ namespace: 'a<& +/=' });
  await assert.rejects(client.secrets.access(ID, { reason: 'deny' }), { status: 403, code: 'access_denied' });
} finally { client.close(); }
if (process.env.ICREDS_SDK_TEST_DEVICE) {
  const options = JSON.parse(process.env.ICREDS_SDK_TEST_DEVICE);
  const device = new DeviceClient(options);
  try {
    await device.configuration();
    const downloaded = await device.download({ ids: [ID], reason: 'node conformance' });
    assert.deepEqual(downloaded.body.values[0].value.bytes(), Buffer.from([0, 255, 10, 65]));
    downloaded.body.values[0].value.dispose();
    assert.equal(device.secrets, undefined); assert.equal(device.enrollments, undefined);
    await device.heartbeat();
    assert.throws(() => new DeviceClient({ ...options, verificationKey: 'wrong' }), { code: 'device_trust_invalid' });
  } finally { device.close(); }
}
console.log('Node SDK interoperates with Go HTTPS/JWE and signed mTLS descriptors.');

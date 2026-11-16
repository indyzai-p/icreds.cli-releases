import { SecretClient, ManagementClient, DeviceClient, newIdempotencyKey, type ClientOptions, type Descriptor } from '../src/index.js';
const options: ClientOptions = { token: 'fixture', organizationId: '00000000-0000-4000-8000-000000000000' };
const consumer = new SecretClient(options);
const admin = new ManagementClient(options);
const metadata = await consumer.secrets.get('id');
metadata.body.currentVersion satisfies number;
const accessed = await consumer.secrets.access('id', { reason: 'type check' });
await accessed.body.value.withBytes(bytes => bytes.readUInt8(0));
// @ts-expect-error Consumer clients cannot mutate secrets.
consumer.secrets.revoke('id', { idempotencyKey: 'key', ifMatch: '"1"' });
// @ts-expect-error Writes require a known idempotency key.
admin.secrets.create({ projectId: 'id', environment: 'test', namespace: '/', name: 'name', value: new Uint8Array([1]) });
await admin.secrets.create({ projectId: 'id', environment: 'test', namespace: '/', name: 'name', value: new Uint8Array([1]) }, { idempotencyKey: newIdempotencyKey() });
await admin.operations.wait('id', { signal: AbortSignal.timeout(1000) });
declare const descriptor: Descriptor;
const device = new DeviceClient({ descriptor, verificationKey: 'pin', identity: { certificate: 'cert', key: 'key' } });
// @ts-expect-error Workload clients cannot access management methods.
device.enrollments.create({});
consumer.close(); admin.close(); device.close();

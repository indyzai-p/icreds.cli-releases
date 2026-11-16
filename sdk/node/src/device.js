import { createHash, createPrivateKey, createPublicKey, verify, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { decodeSecret } from './secret.js';
import { exact, fail, unb64 } from './protocol.js';
import { endpoint, id, Transport } from './transport.js';

const fields = ['trustRevision', 'expiresAt', 'verificationKey', 'signature', 'id', 'tenantId', 'orgId', 'label', 'scope', 'bindings', 'status', 'revision', 'workloadUrl', 'ca', 'maxStalenessSeconds'];
function goJSON(value) { return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`); }
export function verifyDescriptor(value, pin, previous) {
  try {
    exact(value, fields);
    if (typeof pin !== 'string' || value.verificationKey !== pin) fail('device_trust_invalid');
    const key = unb64(pin, 32), signature = unb64(value.signature, 64);
    if (key.length !== 32 || signature.length !== 64) fail('device_trust_invalid');
    exact(value.scope, ['tenantId', 'projectId', 'environment', 'namespace']);
    if (!Array.isArray(value.bindings) || value.bindings.length < 1 || value.bindings.length > 100) fail('device_trust_invalid');
    const canonical = {};
    for (const name of fields) canonical[name] = value[name];
    canonical.signature = '';
    canonical.scope = Object.fromEntries(['tenantId', 'projectId', 'environment', 'namespace'].map(name => [name, value.scope[name]]));
    canonical.bindings = value.bindings.map(binding => { exact(binding, ['id', 'env', 'version', 'required']); return { id: binding.id, env: binding.env, version: binding.version, required: binding.required }; });
    if (!verify(null, Buffer.from(goJSON(canonical)), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: pin }, format: 'jwk' }), signature)) fail('device_trust_invalid');
    const expires = Date.parse(value.expiresAt), now = Date.now();
    if (!Number.isFinite(expires) || expires < now - 5000 || expires > now + 3600000 || !Number.isSafeInteger(value.trustRevision) || value.trustRevision < 1 || !Number.isSafeInteger(value.revision) || value.revision < 1 || value.status !== 'active' || !Number.isSafeInteger(value.maxStalenessSeconds) || value.maxStalenessSeconds < 30 || value.maxStalenessSeconds > 300) fail('device_trust_invalid');
    id(value.id); id(value.orgId); id(value.tenantId); endpoint(value.workloadUrl);
    if (previous && (value.id !== previous.id || value.orgId !== previous.orgId || value.tenantId !== previous.tenantId || value.revision < previous.revision || value.trustRevision < previous.trustRevision || value.workloadUrl !== previous.workloadUrl || (value.trustRevision === previous.trustRevision && value.ca !== previous.ca))) fail('device_trust_invalid');
    const ids = new Set(), env = new Set();
    for (const binding of value.bindings) {
      id(binding.id);
      if (ids.has(binding.id) || typeof binding.env !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(binding.env) || /^(ICREDS_|ADICREDS_)/i.test(binding.env) || env.has(binding.env.toUpperCase()) || typeof binding.required !== 'boolean' || !/^(latest|[1-9][0-9]*)$/.test(binding.version)) fail('device_trust_invalid');
      ids.add(binding.id); env.add(binding.env.toUpperCase());
    }
    return structuredClone(value);
  } catch { fail('device_trust_invalid'); }
}
export class DeviceClient {
  #transport; #descriptor; #pin;
  constructor(options) {
    if (!options?.identity || options.token || options.credentialProvider) fail('device_identity_required');
    this.#pin = options.verificationKey;
    this.#descriptor = verifyDescriptor(options.descriptor, this.#pin);
    let leaf, key;
    try {
      leaf = new X509Certificate(options.identity.certificate); key = createPrivateKey(options.identity.key);
      if (!leaf.checkPrivateKey(key) || leaf.ca || key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' || leaf.keyUsage?.length !== 1 || leaf.keyUsage[0] !== '1.3.6.1.5.5.7.3.2' || Date.parse(leaf.validFrom) > Date.now() || leaf.subjectAltName !== `URI:spiffe://indyzai/icreds/device/${this.#descriptor.id}` || Date.parse(leaf.validTo) <= Date.now()) fail('device_identity_invalid');
    } catch { fail('device_identity_invalid'); }
    const fingerprint = createHash('sha256').update(leaf.raw).digest('base64url');
    this.#transport = new Transport({ endpoint: this.#descriptor.workloadUrl, organizationId: this.#descriptor.orgId, ca: this.#descriptor.ca, timeoutMs: options.timeoutMs }, { provider: () => fingerprint, cert: options.identity.certificate, key: options.identity.key });
  }
  async configuration(options) {
    const result = await this.#transport.request('GET', '/api/v1/device/config', undefined, options);
    const next = verifyDescriptor(result.body, this.#pin, this.#descriptor);
    // A changed CA needs a newly constructed client after explicit trust review;
    // do not silently keep stale TLS trust while reporting a successful update.
    if (next.ca !== this.#descriptor.ca) fail('device_trust_update_required');
    this.#descriptor = next;
    return result;
  }
  heartbeat(options) { return this.#transport.request('POST', '/api/v1/device:heartbeat', {}, options); }
  async download(input, options) {
    verifyDescriptor(this.#descriptor, this.#pin);
    if (!Array.isArray(input?.ids) || input.ids.length < 1 || input.ids.length > 16 || new Set(input.ids).size !== input.ids.length) fail('invalid_download');
    const allowed = new Map(this.#descriptor.bindings.map(binding => [binding.id, binding]));
    for (const key of input.ids) if (!allowed.has(id(key))) fail('binding_not_allowed');
    const result = await this.#transport.request('POST', '/api/v1/device/secrets:download', { ids: input.ids, revision: this.#descriptor.revision, known: input.known ?? {}, reason: input.reason }, options);
    const snapshot = result.body;
    if (snapshot?.revision !== this.#descriptor.revision || !Array.isArray(snapshot.values) || !snapshot.versions || Object.keys(snapshot.versions).length !== input.ids.length) fail('invalid_download');
    const values = [], seen = new Set();
    try {
      for (const value of snapshot.values) {
        if (!input.ids.includes(value.id) || seen.has(value.id) || !Number.isSafeInteger(value.version) || value.version < 1 || snapshot.versions[value.id] !== value.version) fail('invalid_download');
        seen.add(value.id); values.push({ id: value.id, version: value.version, value: decodeSecret(value.value) }); value.value = undefined;
      }
      for (const key of input.ids) { const v = snapshot.versions[key]; if (!Number.isSafeInteger(v) || v < 0 || (v === 0 && allowed.get(key).required) || (v > 0 && !seen.has(key) && input.known?.[key] !== v)) fail('invalid_download'); }
      return Object.freeze({ ...result, body: { ...snapshot, values } });
    } catch (e) { for (const value of values) value.value.dispose(); throw e; }
  }
  close() { this.#transport.close(); }
  refreshKeys() { this.#transport.refreshKeys(); }
  toJSON() { return { client: 'DeviceClient' }; }
  [inspect.custom]() { return 'DeviceClient [identity redacted]'; }
}

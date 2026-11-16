# @indyzai/icreds

Node.js ESM SDK for iCreds, with TypeScript declarations and no runtime dependencies.
Requires Node.js 22 or later. TypeScript projects should include `@types/node`
as a development dependency. The API is initially versioned at 0.1.0.

## Install

After npm publication:

```sh
npm install @indyzai/icreds@0.1.0
```

## Retrieve a secret

```js
import { SecretClient } from '@indyzai/icreds';

const client = new SecretClient({
  endpoint: 'https://api.indyzai.com/icreds',
  organizationId: process.env.ICREDS_ORG_ID,
  credentialProvider: async () => obtainShortLivedAccessToken(),
});
try {
  const result = await client.secrets.access(secretId, {
    reason: 'connect payments database',
  });
  try {
    await result.body.value.withBytes(async bytes => {
      await connectApplication(bytes); // application-owned integration
    });
  } finally {
    result.body.value.dispose();
  }
} finally {
  client.close();
}
```

`obtainShortLivedAccessToken` and `connectApplication` are your application code.
The provider returns the raw token, without `Bearer `. Authentication remains with
indyzai.auth-api-svc; this SDK does not invent token issuance/refresh endpoints.
Alternatively pass `token` explicitly. Credentials and organization are per client;
no implicit `.env`, keyring access, global token or global tenant is used.

`SecretValue` redacts inspection, string conversion and JSON serialization.
`bytes()` returns an owned Buffer copy that the caller must clear. `withBytes`
clears its temporary copy after the callback settles; `dispose()` clears the
SDK-owned bytes. Application copies and immutable JSON strings cannot be guaranteed
to disappear from runtime memory. Values are never cached or written to disk.

## Manage resources

```js
import { ManagementClient, newIdempotencyKey } from '@indyzai/icreds';

const admin = new ManagementClient({
  organizationId,
  credentialProvider: obtainShortLivedAccessToken,
});
try {
  const metadata = await admin.secrets.get(secretId);
  const logicalKey = newIdempotencyKey(); // preserve for an explicit logical retry
  const operation = await admin.secrets.rotate(secretId, {
    ifMatch: metadata.headers.ETag,
    idempotencyKey: logicalKey,
  });
  await admin.operations.wait(operation.body.id, {
    waitTimeoutMs: 120_000,
    signal: shutdownSignal,
  });
} finally {
  admin.close();
}
```

Every mutation requires an explicit `idempotencyKey`. Existing-resource mutations
also require the caller's quoted `ifMatch` revision; the SDK never silently fetches
a replacement ETag. There are no automatic retries. A fresh JWE envelope is made
for every explicit attempt, including repeated logical idempotency keys.
A cancelled wait leaves the durable operation running; retain its ID to resume.

Supported surfaces:

- `secrets.get/list/pages/access/versions.list` on SecretClient.
- ManagementClient additionally provides secret create/version/rotate/revoke/restore;
  key-ring get/rotate; crypto-migration create; operation get/approve/wait; lease
  get/revoke; audit list/pages; device management and enrollment management.
- `session.current/tenants` expose the verified session and organization membership.
- `enrollments.create` returns its one-time `authId` as a redacted `SecretValue`.
  Explicitly transfer those bytes through your approved enrollment channel. Do not
  log them or retry creation after an uncertain response; create a new grant.

Methods return `{ body, status, headers }`. Only authenticated ETag, Location and
Retry-After values appear in `headers`. Paginated iterators fetch one page per
iteration and reject repeated cursors. Device listing is bounded by the server
(currently 100), not a cursor-based full listing.

## Enrolled-device downloads

```js
import { DeviceClient } from '@indyzai/icreds';

const device = new DeviceClient({
  descriptor,                   // signed descriptor from your existing enrollment
  verificationKey: pinnedKey,    // independently retained enrollment signer pin
  identity: { certificate, key }, // local certificate chain and private key
});
try {
  await device.configuration();
  const snapshot = await device.download({ ids: [secretId], reason: 'application start' });
  for (const entry of snapshot.body.values) {
    try { await entry.value.withBytes(connectApplication); }
    finally { entry.value.dispose(); }
  }
} finally {
  device.close();
}
```

DeviceClient has only own-configuration, bounded download and heartbeat methods;
no management routes. It verifies the pinned Ed25519 descriptor, identity, expiry,
revisions and binding set and uses TLS 1.3 mTLS plus JWE. Versions of zero represent
unavailable optional bindings; values with a matching `known` version are omitted.
A CA change returns `device_trust_update_required`: construct a new client using
the explicitly verified overlapping trust bundle. Signer/origin changes require
reenrollment. Enrollment, certificate renewal, process supervision, environment
injection, scheduling and stale-value cleanup remain in the `icreds` worker.

## Transport and errors

HTTPS certificate verification and the constrained RSA-OAEP-256/A256GCM JWE
profile are mandatory. Redirects, plaintext downgrade, unsupported JOSE headers,
response substitution and duplicate JSON fields fail closed. Discovery keys are
cached for at most one minute; call `refreshKeys()` after an operator-directed
rotation if needed. `ca` supplies explicit enterprise CA trust for human clients;
it does not alter system trust. Device CA trust comes from the signed descriptor.

Requests default to a 30-second overall deadline (including credential provider,
discovery, connection and response), with a configurable maximum of two minutes.
Pass `signal`/`timeoutMs` per request. Operation waiters have a separate overall
wait deadline. `close()` aborts in-flight requests and closes pooled connections.
Concurrency, JSON depth, body size and response size are bounded. No implicit
proxy configuration, request/response tracing or response recording is installed.

Catch `ICredsError` and inspect `code`/`status`; raw tokens, private keys, response
bodies and arbitrary server messages are never attached to SDK errors. API errors
remain encrypted; malformed middleware/LB responses become generic transport errors.
Do not add application logging around secret result bytes.

## Development

```sh
npm ci --ignore-scripts
npm run build
npm test
npm pack --ignore-scripts --dry-run
```

Tests use disposable certificates generated with OpenSSL. The platform Go suite
also runs a Node interoperability test against the actual Go HTTPS/JWE middleware
and an mTLS listener, including Go-signed descriptors. Release artifacts contain
only `src/`, README, license and npm-required package metadata. No tests, keys,
backend implementation, credentials or development dependencies are bundled.

License: MIT. Report vulnerabilities privately through the repository security
policy; do not include live secrets in public issues.

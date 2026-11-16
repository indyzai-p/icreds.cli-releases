/// <reference types="node" />
/** Node.js ESM SDK. HTTPS and JWE are mandatory. No automatic retries or secret cache. */
export interface ClientOptions {
  endpoint?: string;
  organizationId?: string;
  token?: string;
  credentialProvider?: () => string | Promise<string>;
  /** Explicit enterprise CA bundle, replacing the system trust roots for this client. */
  ca?: string | Buffer | Array<string | Buffer>;
  timeoutMs?: number;
}
export interface RequestOptions { signal?: AbortSignal; timeoutMs?: number }
export interface WriteOptions extends RequestOptions { idempotencyKey: string }
export interface MutationOptions extends WriteOptions { ifMatch: string }
export interface Result<T> { readonly body: T; readonly status: number; readonly headers: Readonly<{ ETag?: string; Location?: string; 'Retry-After'?: string }> }
export interface Page<T> { items: T[]; nextCursor?: string }
export interface Filters { projectId?: string; environment?: string; namespace?: string; limit?: number; cursor?: string }
export interface Scope { projectId: string; environment: string; namespace: string }
export interface SecretMetadata extends Scope { id: string; name: string; status: 'active' | 'revoked'; currentVersion: number; resourceVersion: number; createdAt: string }
export interface SecretVersion { version: number; status: string; createdAt: string }
export interface SecretAccess { secretId: string; version: number; value: SecretValue }
export interface AccessInput { reason: string; version?: number }
export interface CreateSecret extends Scope { name: string; value: Uint8Array }
export interface Operation { id: string; kind: string; status: 'pending' | 'running' | 'succeeded' | 'failed'; createdAt: string; errorCode?: string }
export interface WaitOptions extends RequestOptions { waitTimeoutMs?: number; pollIntervalMs?: number }
export interface AuditEvent { id: string; action: string; principalId: string; resourceId: string; outcome: string; createdAt: string }
export interface KeyRing { id: string; resourceVersion: number; activeKeyVersion: string }
export interface Lease { id: string; resourceVersion: number }
export interface CryptoMigration { projectId: string; environment: string; keyRingId: string; mode: 'rewrap' | 'reencrypt'; targetKeyVersion: string; targetEnvelopeVersion: 1 }
export interface Binding { id: string; env: string; version: string; required: boolean }
export interface GrantInput { label: string; scope: Scope & { tenantId?: string }; bindings: Binding[] }
export interface Grant { id: string; deviceId: string; fingerprint: string; status: string; revision: number; expiresAt: string }
export interface Descriptor { trustRevision: number; expiresAt: string; verificationKey: string; signature: string; id: string; tenantId: string; orgId: string; label: string; scope: Scope & { tenantId: string }; bindings: Binding[]; status: string; revision: number; workloadUrl: string; ca: string; maxStalenessSeconds: number }
export class ICredsError extends Error { readonly code: string; readonly status: number; readonly headers: Result<unknown>['headers']; toJSON(): { name: string; code: string; status: number } }
export class SecretValue {
  constructor(value: Uint8Array);
  /** Returns an owned copy; caller must clear it. */
  bytes(): Buffer;
  /** Clears the temporary copy after the callback settles; callback copies remain caller-owned. */
  withBytes<T>(callback: (bytes: Buffer) => T | Promise<T>): Promise<T>;
  dispose(): void;
  toJSON(): '[REDACTED]';
  toString(): '[REDACTED]';
}
export function newIdempotencyKey(): string;
export interface VersionReader { list(id: string, options?: RequestOptions): Promise<Result<Page<SecretVersion>>> }
export interface SecretReader {
  get(id: string, options?: RequestOptions): Promise<Result<SecretMetadata>>;
  list(filters?: Filters, options?: RequestOptions): Promise<Result<Page<SecretMetadata>>>;
  pages(filters?: Filters, options?: RequestOptions): AsyncGenerator<Result<Page<SecretMetadata>>>;
  access(id: string, input: AccessInput, options?: RequestOptions): Promise<Result<SecretAccess>>;
  versions: VersionReader;
}
export interface SecretManager extends SecretReader {
  create(input: CreateSecret, options: WriteOptions): Promise<Result<SecretMetadata>>;
  rotate(id: string, options: MutationOptions): Promise<Result<Operation>>;
  revoke(id: string, options: MutationOptions): Promise<Result<SecretMetadata>>;
  restore(id: string, version: number, options: MutationOptions): Promise<Result<SecretMetadata>>;
  versions: VersionReader & { create(id: string, value: Uint8Array, options: MutationOptions): Promise<Result<SecretVersion>> };
}
export class SecretClient {
  constructor(options: ClientOptions);
  readonly secrets: SecretReader;
  readonly session: {
    current(options?: RequestOptions): Promise<Result<{ userId: string; orgId: string; tenantId: string; principalId: string }>>;
    tenants(options?: RequestOptions): Promise<Result<{ items: Array<{ id: string; name: string }> }>>;
  };
  close(): void;
  refreshKeys(): void;
}
export class ManagementClient extends SecretClient {
  readonly secrets: SecretManager;
  readonly keyRings: { get(id: string, options?: RequestOptions): Promise<Result<KeyRing>>; rotate(id: string, options: MutationOptions): Promise<Result<Operation>> };
  readonly cryptoMigrations: { create(input: CryptoMigration, options: WriteOptions): Promise<Result<Operation>> };
  readonly operations: { get(id: string, options?: RequestOptions): Promise<Result<Operation>>; approve(id: string, options: MutationOptions): Promise<Result<{ operationId: string; approved: boolean }>>; wait(id: string, options?: WaitOptions): Promise<Result<Operation>> };
  readonly leases: { get(id: string, options?: RequestOptions): Promise<Result<Lease>>; revoke(id: string, options: MutationOptions): Promise<Result<Operation>> };
  readonly audit: { list(filters?: Filters, options?: RequestOptions): Promise<Result<Page<AuditEvent>>>; pages(filters?: Filters, options?: RequestOptions): AsyncGenerator<Result<Page<AuditEvent>>> };
  readonly devices: {
    list(options?: RequestOptions): Promise<Result<{ items: Descriptor[] }>>;
    get(id: string, options?: RequestOptions): Promise<Result<Descriptor>>;
    configure(id: string, input: GrantInput, options: MutationOptions): Promise<Result<Descriptor>>;
    disable(id: string, options: MutationOptions): Promise<Result<Descriptor>>;
    revoke(id: string, options: MutationOptions): Promise<Result<Descriptor>>;
    reconcileRenewal(id: string, input: { certificate: string; requestId: string }, options: MutationOptions): Promise<Result<{ status: string }>>;
  };
  readonly enrollments: {
    create(input: GrantInput, options: WriteOptions): Promise<Result<Grant & { authId: SecretValue }>>;
    get(id: string, options?: RequestOptions): Promise<Result<Grant>>;
    approve(id: string, fingerprint: string, options: MutationOptions): Promise<Result<Grant>>;
    revoke(id: string, options: MutationOptions): Promise<Result<Grant>>;
    reconcile(id: string, certificate: string, options: MutationOptions): Promise<Result<{ status: string }>>;
  };
}
export interface DeviceOptions { identity: { certificate: string; key: string | Buffer }; descriptor: Descriptor; verificationKey: string; timeoutMs?: number }
export interface DownloadInput { ids: string[]; reason: string; known?: Record<string, number> }
export interface Snapshot { revision: number; values: Array<{ id: string; version: number; value: SecretValue }>; versions: Record<string, number> }
/** Existing enrolled identities only. Enrollment, renewal and local scheduling stay in icreds. */
export class DeviceClient {
  constructor(options: DeviceOptions);
  configuration(options?: RequestOptions): Promise<Result<Descriptor>>;
  heartbeat(options?: RequestOptions): Promise<Result<{ id: string; revision: number }>>;
  download(input: DownloadInput, options?: RequestOptions): Promise<Result<Snapshot>>;
  refreshKeys(): void;
  close(): void;
}

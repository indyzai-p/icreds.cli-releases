# iCreds CLI releases and SDKs

Public distribution repository for `icreds` (download worker), `adicreds`
(management CLI), and language SDKs. Backend/KMS implementations, deployment
configuration and private platform history are not distributed here.

## CLI downloads

Use [Releases](https://github.com/indyzai-p/icreds.cli-releases/releases) for
Linux, macOS and Windows CLI binaries on amd64/arm64. Download and inspect the
shell or PowerShell installer included in the selected release. CLI install
behavior and the `vX.Y.Z` CLI tag namespace remain unchanged. An SDK release is
never marked as the default latest CLI release.

```sh
sh install.sh
# Explicit management client:
ICREDS_PRODUCT=adicreds sh install.sh
```

```powershell
.\install.ps1
.\install.ps1 -Product adicreds
```

A published compatible CLI release is required. Verify checksums; independently
verify the publisher signature when signed inventories are available. Check the
specific release's documented capabilities rather than assuming planned SDK or
CLI features are already available in older releases.

## SDK catalog

| Language | Public source | Planned registry identity | Status |
| --- | --- | --- | --- |
| Go | `sdk/go` | `github.com/indyzai-p/icreds.cli-releases/sdk/go` | Planned |
| Python | `sdk/python` | PyPI `icreds-sdk`, import `icreds` | Planned |
| Java | `sdk/java` | Maven `com.indyzai:icreds-sdk` | Planned |
| Node.js / TypeScript | `sdk/node` | npm `@indyzai/icreds` | Planned |
| Rust | `sdk/rust` | crates.io `icreds-sdk` | Planned |

These directories are reserved; no placeholder package is published. Each SDK
must pass implementation, protocol/security and packaging gates before its status
changes to ready. Names require registry ownership/availability verification.
SDK versions are independent: `sdk/LANGUAGE/vX.Y.Z`. Go uses the exact nested-module
`sdk/go/vX.Y.Z` Git tag convention.

SDKs will provide explicit secret-access and management clients over verified
HTTPS plus constrained JWE, safe byte handling, cancellation, ETags/idempotency
and encrypted application errors. Device adapters require enrolled local key
possession and the download-only mTLS listener. Private keys, bearer tokens and
secret values are never public source or package content.

See [publishing and repository hardening](SDK-PUBLISHING.md) and
[security reporting](SECURITY.md).

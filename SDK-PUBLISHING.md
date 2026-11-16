# SDK publishing and public repository hardening

All five SDKs use this repository. Node.js v0.1.0 is published to npm; the other SDK
implementations are pending. Publishing
is deliberately disabled until real code, tests, license and registry ownership
are ready. No registry names or security certification are implied by placeholders.

## Source boundary

A private platform export must list every public file and its reviewed SHA-256 in
`sdk/LANGUAGE/export-files.txt`. The export tool checks hashes, bounded regular
files, path/symlink safety, custody/credential patterns and private backend imports.
A separate redacted Gitleaks scan runs on exported source. Only the selected SDK
subtree is submitted as a public pull request. Never mirror private history, copy
a whole working directory, use private `.env` files in examples, or export a CA,
KMS custody, backend binaries, database schemas or production config.

Human review of the exact diff remains necessary; scanners cannot prove arbitrary
source contains no confidential material. Tests generate disposable keys at runtime
instead of checking private PEM keys into SDK source. Public source has no access
to the private platform repository or its Actions secrets.

## Required repository settings before enabling releases

The workflows supply least-privilege tokens and immutable action pins. Repository
settings below must be configured by an administrator; this document does not
claim those settings have been applied:

- Protect `main` with pull requests, CODEOWNERS review and the
  `source-boundary` check. Require review from someone other than the author when
  the maintainer team supports it. Disable force pushes/deletion and apply rules
  to administrators where possible. Protect `sdk/**` tags against movement and
  restrict their creation to release maintainers/automation.
- Enable secret scanning, push protection, private vulnerability reporting,
  dependency graph and Dependabot security alerts. Restrict Actions to approved
  actions; default workflow token permissions are read-only. Fork pull requests
  receive no publishing credentials. Do not use `pull_request_target` to run code.
- Create `sdk-release`, `sdk-pypi`, `sdk-npm`, `sdk-crates`, `sdk-maven` environments.
  Require maintainer review, prevent self-review, restrict deployment refs to
  protected main/SDK tags and keep registry/signing credentials environment-scoped.
  Creating an environment name in YAML does not configure these protections.
- Review pinned action/dependency updates via pull requests. Keep publisher tokens
  scoped to this repository/package, rotate them on compromise, and retain an
  independently trusted signing/provenance verification procedure.

Set repository variable `SDK_PUBLISH_ENABLED=true` only after these settings,
SDK acceptance tests and package identities have been checked. Missing ready
metadata, source hashes, package files or identities must fail publication.

## Release contract

For a ready SDK, `release.json` contains `status: ready`, stable `version` without
`v`, exact `package` identity and an approved `license`. Include README, LICENSE
and all build/runtime/test source files in the export manifest. No wildcard export
or automated manifest regeneration is allowed at the point of public export.

Go uses the public nested module path. Python supplies `requirements-test.lock`
with hashes for its build/test tools and dependencies. Java's POM explicitly sets
`com.indyzai:icreds-sdk:VERSION` and builds binary/source/Javadoc jars. Node supplies
a lockfile, explicit package `files`, build/test commands and no consumer install
hooks. Rust supplies Cargo.lock, package include rules and an explicit MSRV;
release CI uses pinned Rust 1.90.0.

Push `sdk/LANGUAGE/vX.Y.Z`, or manually run Publish reviewed SDK from `main`.
The commit must be reachable from main. Tests/builds have no registry credentials;
reviewed source and distributable archives are scanned before uploading artifacts.
Build outputs carry SHA-256 inventories and dependency metadata. Protected publisher
jobs consume those artifacts, and GitHub SDK releases always use `latest=false`.
Do not change an existing version/tag or replace published assets.

## Registry identities

| Target | Environment configuration |
| --- | --- |
| Go | Protected SDK tag and public source; `GITHUB_TOKEN` writes only this repo's SDK release |
| PyPI | Trusted publisher bound to this owner/repo, `publish-sdk.yml` and environment `sdk-pypi`; OIDC and attestations, no stored PyPI token |
| npm | Trusted publisher bound to this owner/repo/workflow/environment; Node 24 and pinned npm 11.6.2; OIDC provenance, no stored npm token |
| crates.io | `CRATES_IO_TOKEN` scoped to `icreds-sdk` and publish only, in `sdk-crates`; Cargo upload uses no-verify after exact archive comparison, so no SDK build scripts run with that token |
| Maven Central | Verified `com.indyzai` namespace; `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD`, `MAVEN_SIGNING_KEY`, `MAVEN_SIGNING_PASSPHRASE`, and `MAVEN_SIGNING_FINGERPRINT` in `sdk-maven` |

npm publishes a version-specific `sdk-vX.Y.Z` dist-tag so an older retry cannot
roll back `latest`. A maintainer promotes `latest` after checking the current
channel order; until then consumers install the explicit version/tag. Configure
first-package registration/trusted-publisher ownership before enabling automation.
Prefer a supported short-lived crates.io identity once configured and verified;
the supplied workflow uses the documented scoped token mechanism.

A repeated registry upload may report an already-existing immutable version.
Investigate its identity/checksum/provenance rather than enabling unconditional
skip/overwrite behavior. Maven prints the Central deployment ID and polls for
PUBLISHED; reconcile unknown/pending uploads before retrying. GitHub assets can
exist while a registry publication fails; report each channel independently.

References: [Go modules](https://go.dev/doc/modules/publishing),
[PyPI OIDC](https://docs.pypi.org/trusted-publishers/),
[npm OIDC](https://docs.npmjs.com/trusted-publishers/),
[Cargo publishing](https://doc.rust-lang.org/cargo/reference/publishing.html),
[Central Portal API](https://central.sonatype.org/publish/publish-portal-api/).

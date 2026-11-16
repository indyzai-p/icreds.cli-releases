#!/usr/bin/env bash
# No Maven/project code runs while registry/signing credentials are present.
set -euo pipefail
[[ $# == 2 && "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
version="$1";assets="$(cd "$2" && pwd)"
: "${MAVEN_SIGNING_KEY:?}" "${MAVEN_SIGNING_FINGERPRINT:?}" "${CENTRAL_TOKEN_USERNAME:?}" "${CENTRAL_TOKEN_PASSWORD:?}"
[[ "$MAVEN_SIGNING_FINGERPRINT" =~ ^[A-Fa-f0-9]{40,64}$ ]] || exit 2
(cd "$assets" && sha256sum --check SHA256SUMS)
work="$(mktemp -d)";trap 'rm -rf "$work"' EXIT
export GNUPGHOME="$work/gpg";mkdir -m 0700 "$GNUPGHOME"
printf '%s' "$MAVEN_SIGNING_KEY" | gpg --batch --import
printf '%s' "${MAVEN_SIGNING_PASSPHRASE:-}" > "$work/passphrase";chmod 600 "$work/passphrase"
base="$work/bundle/com/indyzai/icreds-sdk/$version";mkdir -p "$base"
for suffix in .jar -sources.jar -javadoc.jar .pom;do
 file="icreds-sdk-$version$suffix";cp "$assets/$file" "$base/$file"
 gpg --batch --yes --pinentry-mode loopback --passphrase-file "$work/passphrase" --local-user "$MAVEN_SIGNING_FINGERPRINT" --armor --detach-sign "$base/$file"
 sha256sum "$base/$file" | awk '{print $1}' > "$base/$file.sha256"
done
(cd "$work/bundle" && zip -qr "$work/bundle.zip" .)
auth="$(printf '%s:%s' "$CENTRAL_TOKEN_USERNAME" "$CENTRAL_TOKEN_PASSWORD" | base64 -w0)"
printf 'header = "Authorization: Bearer %s"\n' "$auth" > "$work/curl.conf";chmod 600 "$work/curl.conf";unset auth
# An uncertain upload is investigated by its deployment ID; never blindly retried.
curl --fail --silent --show-error --config "$work/curl.conf" \
 --form "bundle=@$work/bundle.zip" \
 "https://central.sonatype.com/api/v1/publisher/upload?publishingType=AUTOMATIC&name=icreds-sdk-$version" > "$work/id"
id="$(cat "$work/id")";[[ "$id" =~ ^[a-zA-Z0-9-]+$ ]] || { echo 'Central upload response requires investigation.' >&2;exit 1; }
printf 'Central deployment ID: %s\n' "$id"
for attempt in {1..60};do
 curl --fail --silent --show-error --config "$work/curl.conf" --request POST \
  "https://central.sonatype.com/api/v1/publisher/status?id=$id" > "$work/status.json"
 state="$(jq -r .deploymentState "$work/status.json")"
 case "$state" in PUBLISHED)echo 'Maven Central publication completed.';exit 0;;FAILED)echo 'Central validation failed; inspect deployment privately.' >&2;exit 1;;esac
 sleep 10
done
echo 'Central publication still pending; reconcile the deployment ID before retrying.' >&2;exit 1

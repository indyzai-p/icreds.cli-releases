#!/usr/bin/env bash
# Run only in the unprivileged build job. Registry/signing secrets are absent.
set -euo pipefail
[[ $# == 3 ]] || exit 2
sdk="$1";version="$2";output="$3"
python3 scripts/check_sdk.py "$sdk" "$version"
mkdir -p "$output";output="$(cd "$output" && pwd)"
cd "sdk/$sdk"
case "$sdk" in
 go)
  go mod verify
  go vet ./...
  go test -race ./...
  go list -m -json all > "$output/dependencies.json"
  git archive --format=tar.gz --prefix="icreds-go-$version/" HEAD:sdk/go > "$output/icreds-go-$version.tar.gz"
  ;;
 python)
  # This reviewed hash lock must include build, twine, pytest and project deps.
  python3 -m pip install --require-hashes -r requirements-test.lock
  python3 -m pip install --no-deps --no-build-isolation .
  python3 -m pytest
  python3 -m build --no-isolation --outdir "$output"
  python3 -m twine check "$output"/*.whl "$output"/*.tar.gz
  python3 -m pip list --format=json > "$output/dependencies.json"
  ;;
 java)
  mvn --batch-mode --no-transfer-progress verify
  # POM must build source/Javadoc jars and reproducibly named artifacts.
  for suffix in .jar -sources.jar -javadoc.jar;do cp "target/icreds-sdk-$version$suffix" "$output/";done
  cp pom.xml "$output/icreds-sdk-$version.pom"
  mvn --batch-mode --no-transfer-progress dependency:tree -DoutputFile="$output/dependencies.txt"
  ;;
 node)
  npm ci --ignore-scripts
  npm run build
  npm test
  npm pack --ignore-scripts --pack-destination "$output"
  npm ls --all --json > "$output/dependencies.json"
  ;;
 rust)
  cargo test --locked --all-features
  cargo clippy --locked --all-targets --all-features -- -D warnings
  cargo package --locked
  cp "target/package/icreds-sdk-$version.crate" "$output/"
  cargo metadata --locked --format-version 1 > "$output/dependencies.json"
  ;;
 *) exit 2 ;;
esac
cd "$output"
find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS

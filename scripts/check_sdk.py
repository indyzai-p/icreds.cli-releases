#!/usr/bin/env python3
"""Validate an SDK release's reviewed source and public package identity."""
import argparse
import json
from pathlib import Path
import re
import tempfile
import sdk_export

PACKAGES = {"go": "github.com/indyzai-p/icreds.cli-releases/sdk/go", "python": "icreds-sdk", "java": "com.indyzai:icreds-sdk", "node": "@indyzai/icreds", "rust": "icreds-sdk"}


def validate(root, sdk, version):
    if sdk not in PACKAGES or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("supported SDK and stable semantic version required")
    base = root / "sdk" / sdk
    meta = json.loads((base / "release.json").read_text())
    if meta.get("status") != "ready" or meta.get("version") != version or meta.get("package") != PACKAGES[sdk] or not meta.get("license"):
        raise ValueError("SDK is not approved and ready for this version")
    with tempfile.TemporaryDirectory() as temp:
        sdk_export.export(root, sdk, Path(temp) / "checked")
        expected = {p.relative_to(Path(temp) / "checked/sdk" / sdk).as_posix() for p in (Path(temp) / "checked/sdk" / sdk).rglob("*") if p.is_file()}
    actual = {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file() or p.is_symlink()}
    if expected != actual:
        raise ValueError("SDK tree contains files absent from the reviewed export manifest")
    required = {"go": "go.mod", "python": "pyproject.toml", "java": "pom.xml", "node": "package.json", "rust": "Cargo.toml"}[sdk]
    if required not in actual:
        raise ValueError("SDK implementation/build metadata missing")
    if sdk == "go":
        if not re.search(r"^module " + re.escape(PACKAGES[sdk]) + r"\s*$", (base / required).read_text(), re.M):
            raise ValueError("wrong Go public module path")
    if sdk == "node":
        package = json.loads((base / required).read_text())
        if package.get("name") != PACKAGES[sdk] or package.get("version") != version or package.get("private") is not False or not package.get("files"):
            raise ValueError("npm identity/version/explicit files allowlist required")
        if {"preinstall", "install", "postinstall"} & package.get("scripts", {}).keys():
            raise ValueError("consumer installation hooks are prohibited")
    if sdk in ("python", "rust"):
        import tomllib
        package = tomllib.loads((base / required).read_text())["project" if sdk == "python" else "package"]
        if package.get("name") != PACKAGES[sdk] or package.get("version") != version:
            raise ValueError("package identity/version mismatch")
    if sdk == "java":
        import xml.etree.ElementTree as ET
        tree = ET.parse(base / required)
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        if [tree.findtext("m:" + name, namespaces=ns) for name in ("groupId", "artifactId", "version")] != ["com.indyzai", "icreds-sdk", version]:
            raise ValueError("Maven identity/version must be explicit")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdk", choices=PACKAGES)
    parser.add_argument("version")
    args = parser.parse_args()
    try:
        validate(Path.cwd(), args.sdk, args.version)
    except (ValueError, OSError, KeyError):
        parser.exit(1, "SDK release refused: ready metadata, exact reviewed export files and correct package identity are required.\n")

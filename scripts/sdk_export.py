#!/usr/bin/env python3
"""Export only individually reviewed, hash-pinned SDK files, never private history."""
import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile

LANGUAGES = {"go", "python", "java", "node", "rust"}
FORBIDDEN = {".git", ".github", ".env", ".aws", ".npmrc", ".pypirc", ".netrc", "node_modules", "target", "dist", "build", "__pycache__", ".venv", "cmd", "migrations", "deployments"}
SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".sql", ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".whl", ".crate", ".tgz", ".zip"}
PATTERNS = [rb"-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----", rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|npg_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16})\b", rb"(?:postgres(?:ql)?|https?)://[^\s/:]+:[^\s/@]+@", rb"github\.com/indyzai-p/icreds\.platform/(?:internal|cmd)"]


def safe_path(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or "\\" in value or str(path) != value or any(part in ("", ".", "..") or part.startswith(".") or part in FORBIDDEN for part in path.parts):
        raise ValueError("unsafe export path")
    if path.suffix.lower() in SUFFIXES or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise ValueError("disallowed export file")
    return path


def export(source, language, output):
    if language not in LANGUAGES or output.exists():
        raise ValueError("select a supported SDK and a new output directory")
    base = source / "sdk" / language
    if base.is_symlink() or not base.is_dir() or source.is_symlink() or (source / "sdk").is_symlink():
        raise ValueError("SDK source unavailable")
    manifest = base / "export-files.txt"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 262144:
        raise ValueError("reviewed SDK export-files.txt required")
    rows = manifest.read_text(encoding="ascii").splitlines()
    if not rows or len(rows) > 2000:
        raise ValueError("invalid export manifest")
    files = []
    seen = set()
    for row in rows:
        match = re.fullmatch(r"([a-f0-9]{64})  ([^\r\n]+)", row)
        if not match:
            raise ValueError("manifest requires SHA256, two spaces and relative path")
        digest, name = match.groups()
        path = safe_path(name)
        if name in seen or name == "export-files.txt":
            raise ValueError("duplicate or recursive export manifest entry")
        seen.add(name)
        current = base
        for part in path.parts:
            current /= part
            if current.is_symlink():
                raise ValueError("symlink export refused")
        if not current.is_file() or current.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("export requires bounded regular files")
        raw = current.read_bytes()
        if b"\x00" in raw or any(re.search(pattern, raw) for pattern in PATTERNS):
            raise ValueError("export content requires security review")
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("file changed since export review")
        files.append((name, raw))
    if not {"README.md", "LICENSE", "release.json"}.issubset(seen):
        raise ValueError("SDK README, license and release metadata required")
    output.parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=".sdk-export-", dir=output.parent))
    try:
        for name, raw in files:
            dest = scratch / "sdk" / language / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            dest.chmod(0o644)
        (scratch / "sdk" / language / "export-files.txt").write_text("\n".join(rows) + "\n", encoding="ascii")
        os.rename(scratch, output)
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sdk", choices=sorted(LANGUAGES), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        export(args.source, args.sdk, args.output)
    except (ValueError, OSError, UnicodeError):
        parser.exit(1, "SDK export refused; inspect the reviewed manifest and source locally. No content printed.\n")

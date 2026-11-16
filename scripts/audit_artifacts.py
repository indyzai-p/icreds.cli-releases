#!/usr/bin/env python3
"""Inspect distributable archive contents without extracting or executing them."""
import io
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import zipfile
import sdk_export


def content(name, data):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or any(p in {".git", ".env", ".aws", ".npmrc", ".pypirc", "node_modules", "migrations", "deployments"} or p.startswith(".env.") for p in path.parts):
        raise ValueError("unsafe package path")
    if path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}:
        raise ValueError("custody material in package")
    if len(data) > 20 * 1024 * 1024 or any(re.search(pattern, data) for pattern in sdk_export.PATTERNS):
        raise ValueError("package content requires review")


def audit(path):
    if path.stat().st_size > 50 * 1024 * 1024:
        raise ValueError("artifact too large")
    total = 0
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > 5000:
                raise ValueError("too many package entries")
            for item in archive.infolist():
                total += item.file_size
                if total > 100 * 1024 * 1024 or item.file_size > 20 * 1024 * 1024 or (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("unsafe archive entry")
                content(item.filename, archive.read(item))
    elif tarfile.is_tarfile(path):
        with tarfile.open(path) as archive:
            count = 0
            for item in archive:
                count += 1
                total += item.size
                if count > 5000 or total > 100 * 1024 * 1024 or item.size > 20 * 1024 * 1024 or not (item.isfile() or item.isdir()):
                    raise ValueError("unsafe archive entry")
                content(item.name, archive.extractfile(item).read() if item.isfile() else b"")
    else:
        content(path.name, path.read_bytes())


if __name__ == "__main__":
    try:
        for file in Path(sys.argv[1]).iterdir():
            if file.is_symlink() or not file.is_file():
                raise ValueError("artifact must be a regular file")
            audit(file)
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile):
        sys.exit("Artifact audit refused publication. No package contents printed.")

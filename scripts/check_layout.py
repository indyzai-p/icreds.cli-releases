#!/usr/bin/env python3
"""Keep this public repository within its CLI-assets/SDK-source boundary."""
import json
from pathlib import Path
import subprocess
import sys
import re
import sdk_export

try:
    files = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
    for name in filter(None, files):
        path = Path(name)
        if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("public source contains a symlink or oversized file")
        if not (name in {"README.md", "SECURITY.md", "SDK-PUBLISHING.md", ".gitignore"} or name.startswith(("sdk/", "scripts/", ".github/"))):
            raise ValueError("unapproved repository root content")
        if name.startswith("sdk/"):
            parts = path.parts
            if len(parts) < 3 or parts[1] not in sdk_export.LANGUAGES:
                raise ValueError("unapproved SDK directory")
            sdk_export.safe_path("/".join(parts[2:]))
        if name.startswith(".github/workflows/"):
            text = path.read_text()
            if "pull_request_target" in text or re.search(r"uses:\s+[^\s@]+@(?![a-f0-9]{40}\b)", text):
                raise ValueError("unsafe workflow trigger or mutable action pin")
        raw = path.read_bytes()
        if any(re.search(pattern, raw) for pattern in sdk_export.PATTERNS):
            raise ValueError("content requires private security review")
    for sdk in sdk_export.LANGUAGES:
        meta = json.loads((Path("sdk") / sdk / "release.json").read_text())
        if meta["status"] == "ready":
            import check_sdk
            check_sdk.validate(Path.cwd(), sdk, meta["version"])
        elif meta["status"] != "planned":
            raise ValueError("unknown SDK readiness state")
except (OSError, ValueError, KeyError):
    sys.exit("Public source-boundary check failed. Inspect changes privately; no file contents printed.")

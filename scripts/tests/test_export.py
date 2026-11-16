import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("sdk_export", Path(__file__).resolve().parents[1] / "sdk_export.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ExportTests(unittest.TestCase):
    def fixture(self, root, extra=None):
        base = root / "sdk/go"
        base.mkdir(parents=True)
        files = {"README.md": b"SDK", "LICENSE": b"fixture-only license", "release.json": b'{"status":"planned"}'}
        files.update(extra or {})
        rows = []
        for name, raw in files.items():
            path = base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            rows.append(hashlib.sha256(raw).hexdigest() + "  " + name)
        (base / "export-files.txt").write_text("\n".join(rows) + "\n")
        return base

    def test_allowlist_excludes_private_neighbor_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            (root / "sdk/go/unreviewed.go").write_text("private neighbor")
            module.export(root, "go", root / "output")
            self.assertFalse((root / "output/sdk/go/unreviewed.go").exists())
            self.assertEqual((root / "output/sdk/go/README.md").read_bytes(), b"SDK")

    def test_tamper_and_symlink_rejected_atomically(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                base = self.fixture(root)
                (base / "README.md").unlink()
                if symlink:
                    (base / "README.md").symlink_to(base / "LICENSE")
                else:
                    (base / "README.md").write_text("changed")
                with self.assertRaises(ValueError):
                    module.export(root, "go", root / "output")
                self.assertFalse((root / "output").exists())

    def test_secrets_and_backend_imports_rejected(self):
        for raw in (b"-----BEGIN " + b"PRIVATE KEY-----", b"postgresql://" + b"user:" + b"password@host/db", b"github.com/indyzai-p/" + b"icreds.platform/internal/core"):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.fixture(root, {"client.go": raw})
                with self.assertRaises(ValueError):
                    module.export(root, "go", root / "output")

    def test_paths_rejected(self):
        for name in ("../secrets", "/tmp/secret", "foo/../bar", ".env", "x/.git/config", "keys/root.pem", "migrations/a.sql", "node_modules/a.js", "foo\\bar"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.safe_path(name)


if __name__ == "__main__":
    unittest.main()

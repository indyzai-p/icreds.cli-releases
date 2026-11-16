import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_artifacts
import check_sdk


class PublicationTests(unittest.TestCase):
    def test_planned_and_wrong_identity_cannot_publish(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / 'sdk/go'
            base.mkdir(parents=True)
            for status, package in [('planned', check_sdk.PACKAGES['go']), ('ready', 'wrong/module')]:
                (base / 'release.json').write_text(json.dumps({'status': status, 'package': package, 'version': '0.1.0', 'license': 'fixture'}))
                with self.assertRaises(ValueError):
                    check_sdk.validate(root, 'go', '0.1.0')

    def test_valid_ready_tree_and_unreviewed_neighbor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / 'sdk/go'
            base.mkdir(parents=True)
            files = {'README.md': b'fixture', 'LICENSE': b'fixture', 'go.mod': b'module github.com/indyzai-p/icreds.cli-releases/sdk/go\n', 'release.json': json.dumps({'status': 'ready', 'package': check_sdk.PACKAGES['go'], 'version': '0.1.0', 'license': 'fixture'}).encode()}
            for name, data in files.items():
                (base / name).write_bytes(data)
            (base / 'export-files.txt').write_text(''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in files.items()))
            check_sdk.validate(root, 'go', '0.1.0')
            (base / 'unreviewed.go').write_text('package fixture')
            with self.assertRaises(ValueError):
                check_sdk.validate(root, 'go', '0.1.0')

    def test_archive_traversal_credentials_and_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, data in [('../outside', b'fixture'), ('package/.env', b'fixture'), ('package/key.pem', b'fixture'), ('package/data', b'-----BEGIN '+b'PRIVATE KEY-----')]:
                path = root / 'package.zip'
                with zipfile.ZipFile(path,'w') as archive:
                    archive.writestr(name,data)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    audit_artifacts.audit(path)
            path = root / 'package.tar.gz'
            with tarfile.open(path,'w:gz') as archive:
                member=tarfile.TarInfo('package/link')
                member.type=tarfile.SYMTYPE
                member.linkname='/outside'
                archive.addfile(member)
            with self.assertRaises(ValueError):
                audit_artifacts.audit(path)


if __name__ == '__main__':
    unittest.main()

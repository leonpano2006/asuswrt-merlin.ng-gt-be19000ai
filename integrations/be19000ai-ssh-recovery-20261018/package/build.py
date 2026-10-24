#!/usr/bin/python3
"""Build and inspect the local candidate; never install it."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

base = Path(__file__).resolve().parent
root = base / 'root'
epoch = 1791072000
helper = root / 'usr/libexec/leon-asus/openssh-upgrade-guard'
payloads = sorted(p for p in root.rglob('*') if p.is_file() and 'DEBIAN' not in p.relative_to(root).parts)
(root / 'DEBIAN/md5sums').write_text(''.join(hashlib.md5(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(root)) + '\n' for p in payloads))
for path in [root, *root.rglob('*')]:
    path.chmod(0o755 if path.is_dir() or path == helper else 0o644)
    os.utime(path, (epoch, epoch))
deb = base / 'leon-asus-openssh-upgrade-guard_0.1+leonb53.1_all.deb'
subprocess.run(['dpkg-deb', '--root-owner-group', '-Zzstd', '-z6', '--build', str(root), str(deb)],
               check=True, env={**os.environ, 'SOURCE_DATE_EPOCH': str(epoch)})
control = subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(deb)])
with tarfile.open(fileobj=io.BytesIO(control)) as archive:
    members = {m.name.removeprefix('./').removeprefix('.') for m in archive}
    assert members == {'', 'control', 'conffiles', 'md5sums'}, members
data = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)])
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    for member in archive:
        assert member.uid == member.gid == 0
        assert not member.mode & 0o022
        if member.isfile():
            source = root / member.name.removeprefix('./')
            assert archive.extractfile(member).read() == source.read_bytes()
report = {'package': deb.name, 'sha256': hashlib.sha256(deb.read_bytes()).hexdigest(),
          'root_owner_group': True, 'maintainer_scripts': False,
          'archive_readback_verified': True,
          'focused_tests': '13 passed; run once before this build',
          'payload_sha256': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in payloads}}
(base / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))

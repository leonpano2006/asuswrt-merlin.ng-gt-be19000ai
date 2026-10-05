#!/usr/bin/env python3
"""Build an inert, no-maintainer-script native diagnostic Deb once."""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-trial-snapshot/package-v1'
SOURCE = R / 'scripts/asus-integration/trial-snapshot'
FILES = {
    'snapshot-v1.sh': 'usr/libexec/leon-asus/trial-runtime-snapshot',
    'leon-asus-trial-snapshot.service': 'usr/lib/systemd/system/leon-asus-trial-snapshot.service',
    'leon-asus-trial-snapshot.timer': 'usr/lib/systemd/system/leon-asus-trial-snapshot.timer',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    OUT.mkdir(parents=True, exist_ok=False)
    stage = OUT / 'payload'
    rows = []
    for name, target in FILES.items():
        source = SOURCE / name
        assert source.is_file() and not source.is_symlink()
        dest = stage / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        dest.chmod(0o644)
        rows.append({'source': source.relative_to(R).as_posix(),
                     'path': '/' + target, 'sha256': digest(dest), 'mode': '0644'})
    subprocess.run(['/bin/bash', '-n', str(SOURCE / 'snapshot-v1.sh')], check=True)
    control = stage / 'DEBIAN'
    control.mkdir()
    (control / 'control').write_text(
        'Package: leon-asus-trial-snapshot\n'
        'Version: 0.1+leonb53.1\n'
        'Architecture: all\n'
        'Maintainer: Leon firmware integration\n'
        'Section: admin\nPriority: optional\n'
        'Depends: bash, coreutils, iproute2, openssh-server, systemd\n'
        'Description: Bounded native network and SSH diagnostics for an explicit trial\n'
        ' Emits one non-secret runtime snapshot at 90 seconds after boot.\n'
        ' Installation has no maintainer scripts or automatic enablement.\n')
    assert sorted(x.name for x in control.iterdir()) == ['control']
    for path in stage.rglob('*'):
        if path.is_dir():
            path.chmod(0o755)
        os.utime(path, (1790195242, 1790195242), follow_symlinks=False)
    deb = OUT / 'leon-asus-trial-snapshot_0.1+leonb53.1_all.deb'
    env = os.environ.copy()
    env['SOURCE_DATE_EPOCH'] = '1790195242'
    subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(stage), str(deb)],
                   env=env, check=True, stdout=subprocess.PIPE)
    record = {'schema': 1, 'status': 'inert_diagnostic_deb_built',
              'deb': {'path': deb.relative_to(R).as_posix(), 'sha256': digest(deb)},
              'files': rows, 'builder_sha256': digest(Path(__file__)),
              'bash_syntax_passed': True, 'maintainer_scripts': [],
              'enabled': False, 'device_accessed': False,
              'hardware_behavior_proved': False, 'broad_tests_repeated': False,
              'scope': 'Read-only, once per boot when explicitly timer-enabled. No NVRAM, password, private-key or raw config dump.'}
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Package an inert, explicit boot target for the guarded Ubuntu trial.

No maintainer scripts, presets, enablement, credential material or device
operations are installed. Device provisioning must explicitly attach this
target to multi-user.target after all candidate gates have passed.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
NAME = 'leon-bcm-trial-activation'
VERSION = '0.3+leonb53.1'
EPOCH = 1791072000
FILES = {
    'usr/lib/systemd/system/leon-ubuntu-trial.target': '''[Unit]
Description=Guarded BE19000AI Ubuntu trial
Requires=leon-trial-runtime-ready.service leon-asus.target
After=leon-trial-runtime-ready.service leon-asus.target
# Deliberately no Install section or automatic enablement.
''',
    'usr/lib/systemd/system/leon-trial-runtime-ready.service': '''[Unit]
Description=Require the already armed immutable boot guardian
Before=leon-asus-prepare.service leon-asus-broker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/libexec/leon-asus/trial-health --assert-armed
TimeoutStartSec=5s
Restart=no
UMask=0077
# This query neither opens the watchdog nor starts or replaces its owner.
''',
    'usr/lib/systemd/system/leon-asus-prepare.service.d/20-trial-owner.conf': '''[Unit]
Requires=leon-trial-runtime-ready.service
After=leon-trial-runtime-ready.service
''',
    'usr/lib/systemd/system.conf.d/90-leon-trial-watchdog.conf': '''[Manager]
# The immutable pre-systemd guardian is the sole hardware watchdog owner.
RuntimeWatchdogSec=0
RebootWatchdogSec=0
KExecWatchdogSec=0
''',
    'usr/share/doc/leon-bcm-trial-activation/README': '''Inactive BE19000AI trial activation profile.

Installing the package does not enable or start the target, create an account,
generate host keys, change network settings, modify a disk or select a slot.
The device provisioning operation must explicitly attach leon-ubuntu-trial.target
to multi-user.target only after validating the exact candidate and backups.

The early SquashFS PID1 must already have armed its immutable guardian before
executing systemd. Native prerequisites refuse to run until trial-health obtains
an authenticated ownership response from that existing guardian. The helper
does not open the watchdog, feed it, start another guardian, or commit a slot.
Systemd watchdog settings are zero so they cannot compete for the hardware.
ASUS software watchdog remains managed by ASUS; its hardware owner is suppressed
only in the systemd rc build. Native SSH is independently socket-controlled.

An active trial additionally needs a real external LAN SSH observer. Stopping
that observer without completing the explicit trial workflow may expire its
lease and cause fallback. Healthy trial results never imply permanent boot
acceptance. The independent SL1680 AI-board OS is not changed.
''',
    'usr/share/doc/leon-bcm-trial-activation/copyright': '''Copyright Leon BCM Project
License: GPL-2.0-or-later
Full license: /usr/share/common-licenses/GPL-2.
'''
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', required=True)
    a = p.parse_args()
    assert re.fullmatch('[A-Za-z0-9_-]+', a.label)
    out = ROOT / 'build/ubuntu26-trial-activation' / a.label
    out.mkdir(parents=True, exist_ok=False)
    root = out / 'root'
    for name, text in FILES.items():
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    control = root / 'DEBIAN'
    control.mkdir()
    (control / 'control').write_text(f'''Package: {NAME}
Version: {VERSION}
Architecture: all
Section: admin
Priority: optional
Maintainer: Leon BCM Project <noreply@localhost>
Depends: systemd (>= 259), leon-bcm-boot-profile (= 0.1+leonb53.1), leon-asus-integration (= 0.7+asus3006.102.9), leon-asus-openssh-control (= 0.4+leonb53.1), leon-asus-trial-control (= 0.1+leonb53.1)
Description: Inactive boot activation profile for the guarded BCM Ubuntu trial
 Explicit target ordering requires an already armed immutable guardian before
 ASUS native preparation. No service activation or device writes on install.
''')
    (control / 'md5sums').write_text(''.join(
        hashlib.md5((root / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in sorted(FILES)))
    for path in [root, *root.rglob('*')]:
        path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (EPOCH, EPOCH))
    builds = []
    for number in [1, 2]:
        output = out / f'{NAME}_{VERSION}_all.build{number}.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zzstd', '-z6', '--build', str(root), str(output)],
                       check=True, stdout=subprocess.DEVNULL, env={**os.environ, 'SOURCE_DATE_EPOCH': str(EPOCH)})
        builds.append(output)
    assert sha(builds[0]) == sha(builds[1])
    package = out / f'{NAME}_{VERSION}_all.deb'
    shutil.copyfile(builds[0], package)
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(package)]))) as arc:
        members = {m.name.removeprefix('./') for m in arc}
        assert members == {'.', 'control', 'md5sums'}
    archive = []
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(package)]))) as arc:
        for entry in arc:
            name = entry.name.removeprefix('./')
            assert entry.uid == entry.gid == 0
            assert entry.isdir() or entry.isfile()
            assert entry.mode == (0o755 if entry.isdir() else 0o644)
            assert not name.startswith(('etc/', 'usr/lib/systemd/system-preset/'))
            row = {'path': '/' + name, 'mode': entry.mode, 'type': 'directory' if entry.isdir() else 'file'}
            if entry.isfile():
                assert name in FILES
                row['sha256'] = hashlib.sha256(arc.extractfile(entry).read()).hexdigest()
            archive.append(row)
    record = {'schema_version': 1, 'status': 'reproducible_inactive_package_pending_combined_validation',
              'package': {'name': NAME, 'version': VERSION, 'architecture': 'all',
                          'path': str(package.relative_to(ROOT)), 'sha256': sha(package)},
              'builder_sha256': sha(Path(__file__)), 'two_builds_identical': True,
              'control_members': sorted(members), 'archive': archive,
              'automatic_enablement': False, 'maintainer_scripts': False, 'device_modified': False,
              'flash_accepted': False,
              'remaining': ['Actual apt coinstallation with final runtime0.7 and native trial helper package',
                            'Kernel10 combined ordering and authenticated assert-armed tests',
                            'Explicit device identity provisioning and guarded trial activation']}
    (out / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'package': record['package']}, indent=2))


if __name__ == '__main__':
    main()

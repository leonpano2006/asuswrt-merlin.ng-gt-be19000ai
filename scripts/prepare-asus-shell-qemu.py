#!/usr/bin/env python3
"""Offline kernel10 proof of the matching private ASUS shell Debian package."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', required=True, type=Path)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    work = ROOT / 'build/asus-private-shell/qemu' / args.label
    work.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('cpio_fixture', ROOT / 'scripts/prepare-ubuntu26-openssh-qemu.py')
    cpio = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cpio)
    base_label = 'asus-shell-base-' + args.label
    subprocess.run(['python3', str(ROOT / 'scripts/prepare-ubuntu26-qemu.py'),
                    '--rootfs', str(args.rootfs), '--mode', 'systemd',
                    '--systemd-full-boot', '--output-label', base_label], check=True)
    base = ROOT / 'build/ubuntu26-rootfs' / ('ubuntu26-' + base_label + '.cpio.gz')
    rows = cpio.parse(gzip.decompress(base.read_bytes()))
    byname = {row[0]: row for row in rows}
    entry = byname['usr/libexec/leon-lab/full-boot-proof']
    marker = b'echo passed > /run/leon-full-boot-ok'
    assert entry[2].count(marker) == 1
    entry[2] = entry[2].replace(marker, b'/usr/libexec/leon-lab/private-shell-proof\n' + marker)
    service = byname['etc/systemd/system/leon-full-boot.service']
    service[2] = service[2].replace(b'TimeoutStartSec=90', b'TimeoutStartSec=150')
    ino = max(row[1][0] for row in rows) + 1
    inputs = []
    def add(name, data, mode, kind=stat.S_IFREG):
        nonlocal ino
        assert name not in byname
        fields = [ino, kind | mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name.encode()) + 1, 0]
        ino += 1
        row = [name, fields, data]
        rows.insert(-1, row)
        byname[name] = row
    add('usr/libexec/leon-lab/shell-src', b'', 0o755, stat.S_IFDIR)
    sources = ROOT / 'scripts/asus-integration'
    items = [
        (sources / 'private-shell-proof.sh', 'usr/libexec/leon-lab/private-shell-proof', 0o755),
        (sources / 'private-shell-probe.c', 'usr/libexec/leon-lab/shell-src/private-shell-probe.c', 0o644),
        (ROOT / 'build/asus-private-shell/packages/leon-asus-shell_0.2+asus3006.102.9_arm64.deb', 'root/leon-asus-shell.deb', 0o644),
    ]
    for name in ['rc-manager.c', 'rc-client.c', 'rc-bridge.h']:
        items.append((sources / 'src' / name, 'usr/libexec/leon-lab/shell-src/' + name, 0o644))
    for source, destination, mode in items:
        add(destination, source.read_bytes(), mode)
        inputs.append({'path': str(source.relative_to(ROOT)), 'sha256': sha(source), 'guest_path': '/' + destination})
    output = bytearray()
    for name, fields, data in rows:
        encoded = name.encode() + b'\0'
        fields[6] = len(data)
        fields[11] = len(encoded)
        output += b'070701' + ''.join(f'{value:08x}' for value in fields).encode() + encoded
        output += b'\0' * (-len(output) % 4)
        output += data
        output += b'\0' * (-len(output) % 4)
    path = work / 'initramfs.cpio.gz'
    path.write_bytes(gzip.compress(output, compresslevel=1, mtime=0))
    record = {
        'rootfs': str(args.rootfs), 'rootfs_sha256': sha(args.rootfs),
        'base_fixture': str(base.relative_to(ROOT)), 'base_fixture_sha256': sha(base),
        'initramfs': str(path.relative_to(ROOT)), 'initramfs_sha256': sha(path),
        'inputs': inputs, 'builder_sha256': sha(Path(__file__)),
        'scope': 'No-NIC kernel10 guest only. Package lifecycle, matching shell and safe applets; no vendor services or hardware.',
        'expected_markers': [
            'LAB_ASUS_SHELL_APPLETS_PASS', 'LAB_ASUS_SHELL_SEMANTICS_PASS',
            'LAB_ASUS_SHELL_SIGNAL_MASK_PASS', 'LAB_ASUS_SHELL_TIME64_OFF64_PASS',
            'LAB_ASUS_SHELL_FILE_APPLETS_PASS', 'LAB_ASUS_SHELL_APT_CYCLE_PASS',
            'LAB_ASUS_SHELL_KERNEL10_COMPLETE', 'QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE',
        ],
        'router_or_host_services_changed': False,
    }
    (work / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'initramfs': record['initramfs'], 'initramfs_sha256': record['initramfs_sha256']}, indent=2))

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Exercise the packaged signed local APT archive under the real kernel10."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
PROOF = r'''#!/bin/bash
set -euo pipefail
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
export DEBIAN_FRONTEND=noninteractive
stage=guard
trap 'rc=$?; echo LAB_LOCAL_APT_KERNEL10_EXIT_code=$rc stage=$stage' EXIT
for link in /sys/class/net/*; do test ! -e "$link/device"; done
test -z "$(ip -o address show scope global)"
test -z "$(ip route show default)"
# This no-RTC/no-NIC fixture has no NTP. Use the hash-bound repository's signing
# time, without relaxing APT signature or Release date/expiry verification.
date -u -s @__LAB_SIGNED_REPO_EPOCH__ > /dev/null
mkdir -m 0700 /run/leon-apt-proof
cd /run/leon-apt-proof
sha256sum /etc/passwd /etc/shadow /usr/bin/dash /usr/lib/systemd/systemd /usr/sbin/sshd /etc/apt/sources.list.d/ubuntu.sources > protected.sha256
dpkg-query -W '-f=${binary:Package}\t${Version}\n' > before.tsv
test "$(dpkg-query -W '-f=${db:Status-Status}' leon-bcm-archive)" = installed
test "$(dpkg-query -W '-f=${Version}' leon-gcc15-runtime:armel)" = 15.2.0-0leonb53.1
opts=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/leon-bcm.sources -o Dir::Etc::sourceparts=- -o APT::Update::Error-Mode=any)
stage=signature
apt-get "${opts[@]}" update
apt-cache "${opts[@]}" policy > origins.txt
grep -q 'o=Leon-BE19000AI-BCM' origins.txt
echo LAB_LOCAL_APT_KERNEL10_SIGNATURE_PASS
stage=fetch-reinstall
apt-get "${opts[@]}" -y --reinstall install leon-asus-shell
/usr/libexec/asus/ash -c '[[ "a b" == "a b" ]] && test "$(printf x)" = x'
echo LAB_LOCAL_APT_KERNEL10_SIGNED_REINSTALL_PASS
stage=release-policy
apt-cache "${opts[@]}" policy systemd:arm64 libc6:armel leon-gcc15-runtime:armel > policy.txt
grep -q 'Candidate: 259.5-0ubuntu3.4+leonb53.2' policy.txt
grep -q 'Candidate: 2.44-1ubuntu1+leonb53.1' policy.txt
grep -q 'Candidate: 15.2.0-0leonb53.1' policy.txt
apt-get "${opts[@]}" -s full-upgrade > upgrade.txt
if grep -Eq '^(Inst|Remv) ' upgrade.txt; then cat upgrade.txt; exit 1; fi
echo LAB_LOCAL_APT_KERNEL10_POLICY_PASS
stage=unchanged
sha256sum -c protected.sha256
dpkg-query -W '-f=${binary:Package}\t${Version}\n' > after.tsv
cmp before.tsv after.tsv
dpkg --audit > audit.txt
test ! -s audit.txt
echo LAB_LOCAL_APT_KERNEL10_COMPLETE
'''

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--candidate-manifest', type=Path,
                        default=ROOT / 'build/ubuntu26-local-repository/candidates/gnu-systemd-openssh-armel15-archive-b53-v1/result.json')
    parser.add_argument('--gcc15-runtime-version', default='15.2.0-0leonb53.1')
    args = parser.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    assert re.fullmatch(r'15\.2\.0-0leonb53\.[12]', args.gcc15_runtime_version)
    candidate = args.candidate_manifest
    record = json.loads(candidate.read_text())
    assert record['status'] == 'built_and_package_lifecycle_passed'
    rootfs = ROOT / record['rootfs']['path']
    assert sha(rootfs) == record['rootfs']['sha256']
    with tarfile.open(rootfs) as archive:
        member = next(m for m in archive if m.name.removeprefix('./') == 'usr/share/doc/leon-bcm-archive/release-manifest.json')
        data = archive.extractfile(member).read()
    assert hashlib.sha256(data).hexdigest() == record['archive_package']['repository_manifest_sha256']
    repository = json.loads(data)
    fixture_epoch = int(datetime.fromisoformat(repository['signed_at_utc']).timestamp()) + 60
    proof = PROOF.replace('15.2.0-0leonb53.1', args.gcc15_runtime_version).replace('__LAB_SIGNED_REPO_EPOCH__', str(fixture_epoch))
    work = ROOT / 'build/ubuntu26-local-repository/qemu' / args.label
    work.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('cpio_fixture', ROOT / 'scripts/prepare-ubuntu26-openssh-qemu.py')
    cpio = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cpio)
    base_label = 'local-apt-base-' + args.label
    subprocess.run(['python3', str(ROOT / 'scripts/prepare-ubuntu26-qemu.py'), '--rootfs', str(rootfs),
                    '--mode', 'systemd', '--systemd-full-boot', '--output-label', base_label], check=True)
    base = ROOT / 'build/ubuntu26-rootfs' / ('ubuntu26-' + base_label + '.cpio.gz')
    rows = cpio.parse(gzip.decompress(base.read_bytes()))
    byname = {row[0]: row for row in rows}
    entry = byname['usr/libexec/leon-lab/full-boot-proof']
    marker = b'echo passed > /run/leon-full-boot-ok'
    assert entry[2].count(marker) == 1
    entry[2] = entry[2].replace(marker, b'/usr/libexec/leon-lab/local-apt-proof\n' + marker)
    name = 'usr/libexec/leon-lab/local-apt-proof'
    assert name not in byname
    fields = [max(row[1][0] for row in rows)+1, stat.S_IFREG|0o755, 0, 0, 1, 0, len(proof.encode()), 0, 0, 0, 0, len(name)+1, 0]
    rows.insert(-1, [name, fields, proof.encode()])
    byname['etc/systemd/system/leon-full-boot.service'][2] = byname['etc/systemd/system/leon-full-boot.service'][2].replace(b'TimeoutStartSec=90', b'TimeoutStartSec=150')
    output = bytearray()
    for name, fields, data in rows:
        encoded = name.encode() + b'\0'
        fields[6], fields[11] = len(data), len(encoded)
        output += b'070701' + ''.join(f'{value:08x}' for value in fields).encode() + encoded
        output += b'\0' * (-len(output) % 4)
        output += data
        output += b'\0' * (-len(output) % 4)
    path = work / 'initramfs.cpio.gz'
    path.write_bytes(gzip.compress(output, compresslevel=1, mtime=0))
    (work / 'proof.sh').write_text(proof)
    result = {'rootfs': record['rootfs'], 'candidate_manifest_sha256': sha(candidate),
              'guest_clock_epoch': fixture_epoch, 'clock_scope': 'No-NIC guest only; signed Release time plus 60 seconds; APT time checks remain enabled',
              'initramfs': str(path.relative_to(ROOT)), 'initramfs_sha256': sha(path),
              'proof_sha256': sha(work / 'proof.sh'), 'builder_sha256': sha(Path(__file__)),
              'expected_markers': ['LAB_LOCAL_APT_KERNEL10_SIGNATURE_PASS', 'LAB_LOCAL_APT_KERNEL10_SIGNED_REINSTALL_PASS',
                                   'LAB_LOCAL_APT_KERNEL10_POLICY_PASS', 'LAB_LOCAL_APT_KERNEL10_COMPLETE',
                                   'QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE'],
              'scope': 'No-NIC guest only, actual candidate packaged repository and native APT signature verification. No ASUS daemon activation.'}
    (work / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'initramfs': result['initramfs'], 'initramfs_sha256': result['initramfs_sha256']}, indent=2))

if __name__ == '__main__':
    main()

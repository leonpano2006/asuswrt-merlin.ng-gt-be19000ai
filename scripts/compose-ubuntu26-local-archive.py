#!/usr/bin/env python3
"""Add the tested signed local APT archive and ASUS shell to a fresh candidate."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--archive-version', required=True)
    parser.add_argument('--base-manifest', type=Path,
                        default=ROOT / 'build/ubuntu26-armel-runtime-gcc15/validated-manifest.json',
                        help='Hash-bound candidate manifest containing a rootfs record')
    args = parser.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    assert re.fullmatch(r'[0-9][A-Za-z0-9.+~-]+', args.archive_version)
    base_manifest = args.base_manifest.resolve()
    assert base_manifest.is_relative_to(ROOT)
    base_record = json.loads(base_manifest.read_text())['rootfs']
    base = ROOT / base_record['path']
    assert sha(base) == base_record['sha256']
    package_manifest = ROOT / 'build/ubuntu26-local-repository/packages' / args.archive_version / 'manifest.json'
    package = json.loads(package_manifest.read_text())
    deb = ROOT / package['package_path']
    assert sha(deb) == package['sha256']
    work = ROOT / 'build/ubuntu26-local-repository/candidates' / args.label
    work.mkdir(parents=True, exist_ok=False)
    root = Path('/tmp/be19000ai-archive-candidate-' + args.label)
    assert not root.exists()
    inputs = Path(tempfile.mkdtemp(prefix='be19000ai-archive-input-'))
    inputs.chmod(0o755)
    for source, name in [(base, 'base.tar'), (deb, 'archive.deb')]:
        subprocess.run(['cp', '--reflink=auto', str(source), str(inputs / name)], check=True)
        (inputs / name).chmod(0o644)
    script = r'''set -euo pipefail
root="$1"; inputs="$2"
test "$(id -u)" = 0
mount --make-rprivate /
mkdir -m 0755 "$root"
tar --extract --numeric-owner --same-owner --same-permissions --acls --xattrs --xattrs-include='*' --exclude='./dev/*' --exclude='dev/*' -f "$inputs/base.tar" -C "$root"
for name in null zero full random urandom tty; do
    test ! -L "$root/dev/$name"
    touch "$root/dev/$name"
    mount --bind "/dev/$name" "$root/dev/$name"
done
mount -t proc proc "$root/proc"
mkdir -m 0755 "$root/work"
mkdir -m 0755 "$root/work/archive-proof"
cp "$inputs/archive.deb" "$root/tmp/leon-bcm-archive.deb"
printf '#!/bin/sh\nexit 101\n' > "$root/usr/sbin/policy-rc.d"
chmod 0755 "$root/usr/sbin/policy-rc.d"
unshare --net --uts chroot "$root" /bin/bash -s <<'INSTALL'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cd /work/archive-proof
sha256sum /etc/apt/sources.list.d/ubuntu.sources /usr/share/keyrings/ubuntu-archive-keyring.gpg /etc/passwd /etc/shadow /usr/bin/dash /usr/lib/systemd/systemd /usr/sbin/sshd > protected-before.sha256
dpkg-query -W '-f=${binary:Package}\t${Version}\n' > packages-before.tsv
apt-get -y install /tmp/leon-bcm-archive.deb > install-archive.txt 2>&1
opts=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/leon-bcm.sources -o Dir::Etc::sourceparts=- -o APT::Update::Error-Mode=any)
apt-get "${opts[@]}" update > update.txt 2>&1
apt-get "${opts[@]}" -y install leon-asus-shell > install-shell.txt 2>&1
/usr/libexec/asus/ash -c '[[ x == x ]]'
# Actual archive package lifecycle, including its conffiles, is tested here.
apt-get -y remove leon-bcm-archive > remove-archive.txt 2>&1
test ! -e /usr/share/keyrings/leon-bcm-archive-keyring.gpg
test ! -e /var/lib/leon-apt/repository/dists/bcm26-candidate/InRelease
apt-get -y install /tmp/leon-bcm-archive.deb > reinstall-archive.txt 2>&1
apt-get "${opts[@]}" update > update-reinstalled.txt 2>&1
apt-get "${opts[@]}" -s full-upgrade > upgrade-simulation.txt
if grep -Eq '^(Inst|Remv) ' upgrade-simulation.txt; then cat upgrade-simulation.txt; exit 1; fi
dpkg --audit > dpkg-audit.txt
test ! -s dpkg-audit.txt
apt-get check
sha256sum -c protected-before.sha256
dpkg-query -W '-f=${binary:Package}\t${Version}\n' > packages-final.tsv
# The base can already contain the tested shell/ASUS integration. Preserve
# every pre-existing package version except the explicitly replaced archive.
awk -F '\t' '$1 != "leon-bcm-archive" {print}' packages-before.tsv > preserved-before.tsv
while IFS= read -r row; do grep -Fx -- "$row" packages-final.tsv; done < preserved-before.tsv
awk -F '\t' 'NR==FNR {old[$1]=1; next} !old[$1] && $1!="leon-asus-shell" && $1!="leon-bcm-archive" {print; bad=1} END {exit bad}' packages-before.tsv packages-final.tsv
test ! -e /etc/systemd/system/multi-user.target.wants/ssh.service
test ! -e /etc/systemd/system/sockets.target.wants/ssh.socket
test ! -e /etc/ld.so.preload
mkdir -p /run/sshd
# The final candidate deliberately has no device identity yet. Check sshd with
# an ephemeral /run test key; never regenerate package-prototype /etc keys or
# accidentally bake a shared host identity into the sealed archive.
test_key=/run/leon-archive-sshd-test-key
test ! -e "$test_key"
ssh-keygen -q -t ed25519 -N '' -f "$test_key"
sshd -t -h "$test_key"
rm "$test_key" "$test_key.pub"
apt-cache "${opts[@]}" policy systemd libc6:arm64 libc6:armel libcrypt1:arm64 libcrypt1:armel libgcc-s1:arm64 leon-gcc15-runtime:armel > protected-policy.txt
echo LAB_ARCHIVE_CANDIDATE_INSTALL_REMOVE_REINSTALL_PASS
INSTALL
rm "$root/usr/sbin/policy-rc.d" "$root/tmp/leon-bcm-archive.deb"
unshare --net chroot "$root" apt-get clean
for name in tty urandom random full zero null; do umount "$root/dev/$name"; done
umount "$root/proc"
tar --create --numeric-owner --acls --xattrs --xattrs-include='*' --one-file-system --exclude=./dev --exclude=./work -f "$root/work/candidate-without-dev.tar" -C "$root" .
'''
    entry = inputs / 'compose.sh'
    entry.write_text(script)
    command = ['mmdebstrap', '--unshare-helper', '/bin/bash', str(entry), str(root), str(inputs)]
    start = time.monotonic()
    with (work / 'compose.log').open('w') as log:
        proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    evidence = root / 'work/archive-proof'
    if evidence.exists():
        for path in evidence.iterdir():
            if path.is_file(): shutil.copyfile(path, work / path.name)
    record = {'status': 'failed', 'returncode': proc.returncode,
              'elapsed_seconds': round(time.monotonic()-start, 2),
              'base': base_record, 'archive_package': package,
              'base_manifest': {'path': str(base_manifest.relative_to(ROOT)), 'sha256': sha(base_manifest)},
              'router_access': False, 'host_services_changed': False,
              'ASUS_services_activated': False, 'formal_login_identity_configured': False,
              'production_ready': False, 'builder_sha256': sha(Path(__file__))}
    if proc.returncode == 0:
        target = ROOT / 'build/ubuntu26-rootfs' / ('ubuntu26-bcm-' + args.label + '.tar')
        assert not target.exists()
        with target.open('wb') as stream:
            subprocess.run(['mmdebstrap', '--unshare-helper', 'cat', str(root / 'work/candidate-without-dev.tar')], stdout=stream, check=True)
        with tarfile.open(base) as original, tarfile.open(target, 'a') as output:
            for member in original:
                path = PurePosixPath(member.name)
                assert not path.is_absolute() and '..' not in path.parts
                name = str(path).removeprefix('./')
                if name == 'dev' or name.startswith('dev/'):
                    output.addfile(member, original.extractfile(member) if member.isfile() else None)
        record.update(status='built_and_package_lifecycle_passed', rootfs={'path': str(target.relative_to(ROOT)), 'sha256': sha(target), 'bytes': target.stat().st_size})
    record['evidence'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p)} for p in sorted(work.iterdir()) if p.is_file()]
    assert sha(base) == base_record['sha256']
    (work / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({key: record[key] for key in ['status', 'returncode', 'elapsed_seconds', 'rootfs'] if key in record}, indent=2))
    raise SystemExit(proc.returncode)

if __name__ == '__main__':
    main()

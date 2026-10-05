#!/usr/bin/env python3
"""Exercise candidate APT signature, scoped pins and package fetch in a clone."""
import argparse
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository-label', required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--with-armel-runtime', action='store_true')
    parser.add_argument('--base-manifest', type=Path, help='Hash-bound integrated candidate manifest with a rootfs object')
    args = parser.parse_args()
    assert all(re.fullmatch(r'[A-Za-z0-9_-]+', label) for label in [args.label, args.repository_label])
    base = ROOT / 'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-b53-v3.tar'
    expected = '303cafac152c86df9ac78a7c677e718ec411074dd7c73f33a3f0db26df59fda5'
    if args.base_manifest:
        runtime = json.loads(args.base_manifest.read_text())
        base = ROOT / runtime['rootfs']['path']
        expected = runtime['rootfs']['sha256']
    elif args.with_armel_runtime:
        runtime = json.loads((ROOT / 'build/ubuntu26-armel-runtime-gcc15/validated-manifest.json').read_text())
        base = ROOT / runtime['rootfs']['path']
        expected = runtime['rootfs']['sha256']
    assert sha(base) == expected
    source = ROOT / 'build/ubuntu26-local-repository' / args.repository_label
    manifest = json.loads((source / 'manifest.json').read_text())
    for item in manifest['artifacts']:
        assert sha(ROOT / item['path']) == item['sha256']
    work = ROOT / 'build/ubuntu26-local-repository/tests' / args.label
    work.mkdir(parents=True, exist_ok=False)
    target = Path('/tmp/be19000ai-repository-test-' + args.label)
    assert not target.exists()
    inputs = Path(tempfile.mkdtemp(prefix='be19000ai-repository-input-'))
    inputs.chmod(0o755)
    subprocess.run(['cp', '--reflink=auto', str(base), str(inputs / 'rootfs.tar')], check=True)
    (inputs / 'rootfs.tar').chmod(0o644)
    shutil.copytree(source / 'repository', inputs / 'repository')
    # Metadata-only future version: it deliberately has no installable payload.
    # Compare solver choice with and without the release pins, never install it.
    future = inputs / 'future-repository/dists/policy-test'
    index = future / 'main/binary-arm64/Packages'
    index.parent.mkdir(parents=True)
    index.write_text('Package: systemd\nVersion: 99:9999.0-1-policy-test\nArchitecture: arm64\n'
                     'Maintainer: Local policy fixture <root@localhost>\n'
                     'Description: Metadata-only negative policy fixture; never install\n'
                     'Filename: NO_INSTALLABLE_PAYLOAD.deb\nSize: 1\nSHA256: ' + '0' * 64 + '\n\n')
    armel_index = future / 'main/binary-armel/Packages'
    armel_index.parent.mkdir(parents=True)
    armel_index.write_text(''.join(
        f'Package: {name}\nVersion: {version}\nArchitecture: armel\n'
        'Maintainer: Local policy fixture <root@localhost>\n'
        'Description: Metadata-only ARM32 runtime policy fixture; never install\n'
        'Filename: NO_INSTALLABLE_PAYLOAD.deb\nSize: 1\nSHA256: ' + '0' * 64 + '\n\n'
        for name in ['libgcc-s1', 'libstdc++6']
        for version in ['16-20260322-1ubuntu1', '16.2.0-99-policy-test']))
    now = datetime.now(timezone.utc)
    release = future / 'Release'
    release.write_text('Origin: BCM-APT-Policy-Test\nSuite: policy-test\nCodename: policy-test\n'
                       'Architectures: arm64 armel\nComponents: main\nDate: ' + format_datetime(now, usegmt=True) +
                       '\nValid-Until: ' + format_datetime(now + timedelta(days=1), usegmt=True) +
                       '\nSHA256:\n' + ''.join(' ' + sha(item) + ' ' + str(item.stat().st_size) + ' ' + str(item.relative_to(future)) + '\n' for item in [index, armel_index]))
    subprocess.run(['gpg', '--homedir', str(ROOT / 'build/ubuntu26-local-repository/signing-private'),
                    '--batch', '--no-tty', '--local-user', manifest['signing_fingerprint'], '--digest-algo', 'SHA512',
                    '--clearsign', '--output', str(future / 'InRelease'), str(release)], check=True)
    for name in ['leon-bcm-archive-keyring.gpg', 'leon-bcm-release.pref', 'leon-bcm.sources']:
        shutil.copyfile(source / name, inputs / name)
        (inputs / name).chmod(0o644)
    expected_versions = ''.join(item['name'] + ':' + item['architecture'] + '\t' + item['version'] + '\n'
                                for item in manifest['packages'])
    (inputs / 'expected.tsv').write_text(expected_versions)
    (inputs / 'runtime-enabled').write_text('yes\n' if args.with_armel_runtime else 'no\n')
    script = r'''set -euo pipefail
root="$1"; inputs="$2"
test "$(id -u)" = 0
mount --make-rprivate /
mkdir -m 0755 "$root"
tar --extract --numeric-owner --same-owner --same-permissions --acls --xattrs --xattrs-include='*' --exclude='./dev/*' --exclude='dev/*' -f "$inputs/rootfs.tar" -C "$root"
for name in null zero full random urandom tty; do
    test ! -L "$root/dev/$name"
    touch "$root/dev/$name"
    mount --bind "/dev/$name" "$root/dev/$name"
done
mount -t proc proc "$root/proc"
mkdir -p "$root/var/lib/leon-apt" "$root/work/repo-test"
cp -a "$inputs/repository" "$root/var/lib/leon-apt/repository"
cp -a "$inputs/future-repository" "$root/work/repo-test/future-repository"
cp "$inputs/leon-bcm-archive-keyring.gpg" "$root/usr/share/keyrings/"
cp "$inputs/leon-bcm-release.pref" "$root/etc/apt/preferences.d/"
cp "$inputs/leon-bcm.sources" "$root/etc/apt/sources.list.d/"
cp "$inputs/expected.tsv" "$root/work/repo-test/"
cp "$inputs/runtime-enabled" "$root/work/repo-test/"
printf '#!/bin/sh\nexit 101\n' > "$root/usr/sbin/policy-rc.d"
chmod 0755 "$root/usr/sbin/policy-rc.d"
unshare --net --uts chroot "$root" /bin/bash -s <<'TEST'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cd /work/repo-test
sha256sum /etc/passwd /etc/shadow /usr/bin/dash /usr/lib/aarch64-linux-gnu/libc.so.6 /usr/lib/systemd/systemd /usr/sbin/sshd > protected-before.sha256
dpkg-query -W '-f=${binary:Package}\t${Version}\n' > packages-before.tsv
opts=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/leon-bcm.sources -o Dir::Etc::sourceparts=- -o APT::Update::Error-Mode=any)
apt-get "${opts[@]}" update > update-good.txt 2>&1
apt-cache "${opts[@]}" policy > policy-origins.txt
grep -q 'o=Leon-BE19000AI-BCM' policy-origins.txt
while IFS=$'\t' read -r package expected; do
    policy=$(apt-cache "${opts[@]}" policy "$package")
    printf '%s\n' "$policy" >> policy-packages.txt
    candidate=$(printf '%s\n' "$policy" | sed -n 's/^  Candidate: //p')
    test "$candidate" = "$expected"
    printf '%s\n' "$policy" | grep -q '1001'
done < expected.tsv
echo LAB_LOCAL_APT_SIGNED_UPDATE_AND_PINS_PASS
apt-get "${opts[@]}" -y install leon-asus-shell > install-shell.txt 2>&1
test "$(dpkg-query -W '-f=${db:Status-Status}' leon-asus-shell)" = installed
/usr/libexec/asus/ash -c '[[ "a b" == "a b" ]]'
apt-get "${opts[@]}" -y --reinstall install leon-asus-shell > reinstall-shell.txt 2>&1
if test "$(cat runtime-enabled)" = yes; then
    apt-get "${opts[@]}" -y --reinstall install libc6:armel libc-gconv-modules-extra:armel leon-gcc15-runtime:armel libcrypt1:arm64 libcrypt1:armel > reinstall-runtime.txt 2>&1
    echo LAB_LOCAL_APT_MULTIARCH_RUNTIME_FETCH_PASS
fi
echo LAB_LOCAL_APT_SIGNED_FETCH_INSTALL_PASS
apt-get "${opts[@]}" -s full-upgrade > upgrade-simulation.txt
if grep -Eq '^(Inst|Remv) ' upgrade-simulation.txt; then cat upgrade-simulation.txt; exit 1; fi
echo LAB_LOCAL_APT_UPGRADE_PRESERVES_RELEASE_PASS
mkdir -p policy-sources no-preferences
cp /etc/apt/sources.list.d/leon-bcm.sources policy-sources/
cat > policy-sources/future.sources <<'SOURCE'
Types: deb
URIs: file:/work/repo-test/future-repository
Suites: policy-test
Components: main
Architectures: arm64 armel
Signed-By: /usr/share/keyrings/leon-bcm-archive-keyring.gpg
SOURCE
policy_opts=(-o Dir::Etc::sourcelist=- -o Dir::Etc::sourceparts=/work/repo-test/policy-sources -o APT::Update::Error-Mode=any)
apt-get "${policy_opts[@]}" update > update-future.txt 2>&1
apt-cache "${policy_opts[@]}" policy systemd:arm64 > future-protected.txt
grep -q 'Candidate: 259.5-0ubuntu3.4+leonb53.2' future-protected.txt
grep -q '99:9999.0-1-policy-test -1' future-protected.txt
apt-cache "${policy_opts[@]}" -o Dir::Etc::preferences=- -o Dir::Etc::preferencesparts=/work/repo-test/no-preferences policy systemd:arm64 > future-unprotected.txt
grep -q 'Candidate: 99:9999.0-1-policy-test' future-unprotected.txt
if test "$(cat runtime-enabled)" = yes; then
    for package in libgcc-s1:armel libstdc++6:armel; do
        apt-cache "${policy_opts[@]}" policy "$package" > "future-${package}-protected.txt"
        grep -q 'Candidate: (none)' "future-${package}-protected.txt"
        grep -q '16-20260322-1ubuntu1 -1' "future-${package}-protected.txt"
        grep -q '16.2.0-99-policy-test -1' "future-${package}-protected.txt"
        apt-cache "${policy_opts[@]}" -o Dir::Etc::preferences=- -o Dir::Etc::preferencesparts=/work/repo-test/no-preferences policy "$package" > "future-${package}-unprotected.txt"
        grep -q 'Candidate: 16.2.0-99-policy-test' "future-${package}-unprotected.txt"
    done
    apt-get "${policy_opts[@]}" -s install libc6:armel leon-gcc15-runtime:armel > arm32-provider-solver.txt
    if grep -Eq '^(Inst|Remv) ' arm32-provider-solver.txt; then cat arm32-provider-solver.txt; exit 1; fi
    echo LAB_LOCAL_APT_ARM32_GCC15_PROVIDER_SNAPSHOT_AND_RELEASE_PROTECTED_PASS
fi
echo LAB_LOCAL_APT_FUTURE_UNVALIDATED_VERSION_BLOCKED
cp -a /var/lib/leon-apt/repository /work/repo-test/tampered
sed -i 's/^Origin: Leon/Origin: Fake/' /work/repo-test/tampered/dists/bcm26-candidate/InRelease
sed 's,file:/var/lib/leon-apt/repository,file:/work/repo-test/tampered,' /etc/apt/sources.list.d/leon-bcm.sources > tampered.sources
mkdir -m 0755 tampered-lists
mkdir -m 0700 tampered-lists/partial
if apt-get -o Dir::Etc::sourcelist=/work/repo-test/tampered.sources -o Dir::Etc::sourceparts=- -o Dir::State::Lists=/work/repo-test/tampered-lists -o APT::Update::Error-Mode=any update > update-tampered.txt 2>&1; then
    echo 'Tampered signed metadata was accepted'; exit 1
fi
grep -Eiq 'signature|verification|not signed' update-tampered.txt
echo LAB_LOCAL_APT_TAMPERED_SIGNATURE_REJECTED
sha256sum -c protected-before.sha256
dpkg-query -W '-f=${binary:Package}\t${Version}\n' > packages-after.tsv
while IFS= read -r row; do grep -Fx -- "$row" packages-after.tsv; done < packages-before.tsv
awk -F '\t' 'NR==FNR {old[$1]=1; next} !old[$1] && $1!="leon-asus-shell" {print; bad=1} END {exit bad}' packages-before.tsv packages-after.tsv
dpkg --audit > dpkg-audit.txt
test ! -s dpkg-audit.txt
echo LAB_LOCAL_APT_BASE_UNCHANGED_PASS
TEST
'''
    entry = inputs / 'test.sh'
    entry.write_text(script)
    command = ['mmdebstrap', '--unshare-helper', '/bin/bash', str(entry), str(target), str(inputs)]
    start = time.monotonic()
    with (work / 'test.log').open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    output = target / 'work/repo-test'
    if output.exists():
        for path in output.iterdir():
            if path.is_file(): shutil.copyfile(path, work / path.name)
    text = (work / 'test.log').read_text()
    markers = ['LAB_LOCAL_APT_SIGNED_UPDATE_AND_PINS_PASS', 'LAB_LOCAL_APT_SIGNED_FETCH_INSTALL_PASS',
               'LAB_LOCAL_APT_UPGRADE_PRESERVES_RELEASE_PASS', 'LAB_LOCAL_APT_FUTURE_UNVALIDATED_VERSION_BLOCKED', 'LAB_LOCAL_APT_TAMPERED_SIGNATURE_REJECTED',
               'LAB_LOCAL_APT_BASE_UNCHANGED_PASS']
    if args.with_armel_runtime:
        markers += ['LAB_LOCAL_APT_MULTIARCH_RUNTIME_FETCH_PASS',
                    'LAB_LOCAL_APT_ARM32_GCC15_PROVIDER_SNAPSHOT_AND_RELEASE_PROTECTED_PASS']
    record = {'status': 'passed' if result.returncode == 0 and all(text.count(marker) == 1 for marker in markers) else 'failed',
              'returncode': result.returncode, 'elapsed_seconds': round(time.monotonic()-start, 2),
              'repository_manifest': str((source / 'manifest.json').relative_to(ROOT)),
              'repository_manifest_sha256': sha(source / 'manifest.json'),
              'base_sha256': expected, 'base_unchanged': sha(base) == expected,
              'base_manifest_sha256': sha(args.base_manifest) if args.base_manifest else None,
              'markers': {marker: text.count(marker) for marker in markers},
              'scope': 'Actual native APT in isolated user/mount/PID/network/UTS namespaces; no host or router changes.',
              'evidence': [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p)} for p in sorted(work.iterdir()) if p.is_file()],
              'builder_sha256': sha(Path(__file__))}
    (work / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({key: record[key] for key in ['status', 'returncode', 'elapsed_seconds', 'markers']}, indent=2))
    raise SystemExit(0 if record['status'] == 'passed' else 1)

if __name__ == '__main__':
    main()

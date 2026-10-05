#!/usr/bin/env python3
"""Build a signed, offline candidate APT archive from hash-verified artifacts.

The private signing key remains on the build host, outside repository payloads.
Creating this candidate archive never publishes it or changes a running rootfs.
"""
import argparse
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / 'build/ubuntu26-local-repository'
ORIGIN = 'Leon-BE19000AI-BCM'
SUITE = 'bcm26-candidate'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def run(command, **kwargs):
    return subprocess.check_output(command, **kwargs)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--extra-packages', type=Path, action='append', default=[])
    args = parser.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    work = STORE / args.label
    work.mkdir(parents=True, exist_ok=False)
    repo = work / 'repository'
    pool = repo / 'pool/main'
    pool.mkdir(parents=True)
    base_record = ROOT / 'build/ubuntu26-rootfs/gnu-systemd-b53-v3-build.json'
    packages = json.loads(base_record.read_text())['local_packages']
    assert len(packages) == 41
    inputs = [{'path': str(base_record.relative_to(ROOT)), 'sha256': sha(base_record)}]
    for manifest in args.extra_packages:
        manifest = manifest.resolve()
        data = json.loads(manifest.read_text())
        rows = data.get('packages')
        if rows is None:
            if isinstance(data.get('package'), dict):
                rows = [data['package']]
            else:
                rows = [{'path': data['package_path'], 'sha256': data['sha256']}]
        packages.extend(rows)
        inputs.append({'path': str(manifest.relative_to(ROOT)), 'sha256': sha(manifest)})
    by_arch = {'arm64': [], 'armel': []}
    identities = set()
    records = []
    for row in packages:
        source = Path(row['path'])
        if not source.is_absolute(): source = ROOT / source
        assert source.resolve().is_relative_to(ROOT)
        assert sha(source) == row['sha256'], source
        control = run(['dpkg-deb', '-f', str(source)]).decode()
        fields = dict(re.findall(r'^([A-Za-z][A-Za-z0-9-]*): (.*)$', control, re.M))
        name, version, arch = (fields[k] for k in ['Package', 'Version', 'Architecture'])
        assert arch in ['arm64', 'armel', 'all']
        assert not re.search(r'(?:^|:)16-20\d{6}', version), (name, version)
        identity = (name, arch)
        assert identity not in identities, ('Duplicate package family member', identity)
        identities.add(identity)
        filename = name + '_' + version.replace(':', '%3a') + '_' + arch + '.deb'
        destination = pool / filename
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
        relative = str(destination.relative_to(repo))
        paragraph = control.rstrip() + '\nFilename: ' + relative + '\nSize: ' + str(destination.stat().st_size) + '\nSHA256: ' + sha(destination) + '\n\n'
        for index_arch in by_arch:
            if arch in [index_arch, 'all']: by_arch[index_arch].append((name, paragraph))
        records.append({'name': name, 'architecture': arch, 'version': version,
                        'source': str(source.relative_to(ROOT)), 'path': relative,
                        'sha256': row['sha256']})
    suite = repo / 'dists' / SUITE
    for arch, rows in by_arch.items():
        folder = suite / 'main' / ('binary-' + arch)
        folder.mkdir(parents=True)
        payload = ''.join(text for _, text in sorted(rows)).encode()
        (folder / 'Packages').write_bytes(payload)
        (folder / 'Packages.gz').write_bytes(gzip.compress(payload, mtime=0))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    metadata = ['Origin: ' + ORIGIN, 'Label: ' + ORIGIN, 'Suite: ' + SUITE,
                'Codename: ' + SUITE, 'Date: ' + format_datetime(now, usegmt=True),
                'Valid-Until: ' + format_datetime(now + timedelta(days=30), usegmt=True),
                'Architectures: arm64 armel', 'Components: main',
                'Description: Local staged BCM candidate; no automatic promotion',
                'NotAutomatic: yes', 'ButAutomaticUpgrades: yes', 'SHA256:']
    for path in sorted(suite.rglob('Packages*')):
        metadata.append(' ' + sha(path) + ' ' + str(path.stat().st_size) + ' ' + str(path.relative_to(suite)))
    release = suite / 'Release'
    release.write_text('\n'.join(metadata) + '\n')
    keyhome = STORE / 'signing-private'
    if not keyhome.exists():
        keyhome.mkdir(mode=0o700)
    assert keyhome.stat().st_uid == os.getuid() and keyhome.stat().st_mode & 0o777 == 0o700
    gpg = ['gpg', '--homedir', str(keyhome), '--batch', '--no-tty']
    keys = run(gpg + ['--with-colons', '--list-secret-keys'], stderr=subprocess.DEVNULL).decode()
    if not keys.strip():
        subprocess.run(gpg + ['--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                             'BE19000AI BCM local package archive', 'ed25519', 'sign', '1y'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        keys = run(gpg + ['--with-colons', '--list-secret-keys'], stderr=subprocess.DEVNULL).decode()
    fingerprints = [line.split(':')[9] for line in keys.splitlines() if line.startswith('fpr:')]
    assert len(fingerprints) == 1 and re.fullmatch(r'[A-F0-9]{40,64}', fingerprints[0])
    fingerprint = fingerprints[0]
    keyring = work / 'leon-bcm-archive-keyring.gpg'
    keyring.write_bytes(run(gpg + ['--export', fingerprint]))
    subprocess.run(gpg + ['--local-user', fingerprint, '--digest-algo', 'SHA512', '--clearsign',
                         '--output', str(suite / 'InRelease'), str(release)], check=True)
    subprocess.run(gpg + ['--local-user', fingerprint, '--digest-algo', 'SHA512', '--detach-sign',
                         '--output', str(suite / 'Release.gpg'), str(release)], check=True)
    with (work / 'signature-verification.txt').open('wb') as log:
        subprocess.run(['gpgv', '--keyring', str(keyring), str(suite / 'InRelease')],
                       check=True, stdout=log, stderr=subprocess.STDOUT)
    # Exact package-qualified pins form a tested release allowlist. The normal
    # signed Ubuntu sources retain their default priority for everything else.
    # Updating this allowlist is an explicit tested release transaction.
    preferences = []
    for item in sorted(records, key=lambda item: (item['name'], item['architecture'])):
        qualified = item['name'] + ':' + (item['architecture'] if item['architecture'] != 'all' else 'any')
        preferences.append(f"Package: {qualified}\nPin: version {item['version']}\nPin-Priority: 1001\n")
        preferences.append(f"Package: {qualified}\nPin: version *\nPin-Priority: -1\n")
    preferences.append('Package: gcc-16* libgcc-s1:any libstdc++6:any\nPin: version 16-20*\nPin-Priority: -1\n')
    # ARM32 libgcc/libstdc++ are supplied by the separately verified GCC15
    # provider. An official package with a newer major must not silently
    # replace that ABI boundary. ARMHF remains unavailable until its own
    # verified provider is included in a subsequent release.
    preferences.append('Package: libgcc-s1:armel libstdc++6:armel libgcc-s1:armhf libstdc++6:armhf\nPin: version *\nPin-Priority: -1\n')
    (work / 'leon-bcm-release.pref').write_text('\n'.join(preferences))
    (work / 'leon-bcm.sources').write_text(
        f'Types: deb\nURIs: file:/var/lib/leon-apt/repository\nSuites: {SUITE}\nComponents: main\n'
        'Architectures: arm64 armel\nSigned-By: /usr/share/keyrings/leon-bcm-archive-keyring.gpg\n')
    report = {'schema_version': 1, 'status': 'signed_local_staging_archive',
              'origin': ORIGIN, 'suite': SUITE, 'signing_fingerprint': fingerprint,
              'signed_at_utc': now.isoformat(), 'valid_until_utc': (now + timedelta(days=30)).isoformat(),
              'private_key_exported': False, 'published': False, 'rootfs_changed': False,
              'repo': str(repo.relative_to(ROOT)), 'inputs': inputs, 'packages': records,
              'artifacts': [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p)} for p in [
                  release, suite / 'InRelease', suite / 'Release.gpg', keyring,
                  work / 'leon-bcm-release.pref', work / 'leon-bcm.sources']],
              'apt_signature_and_solver_tested': False,
              'arm32_runtime_policy': 'Use the explicitly selected GCC15 provider; direct distribution libgcc-s1/libstdc++6 for armel/armhf are denied. ARMHF needs a separate verified provider before activation.',
              'security_maintenance': 'Exact pins prevent unintended replacement; they do not import upstream security fixes. Rebuild, test and sign a new coherent release before updating its allowlist.'}
    (work / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ['status', 'repo', 'signing_fingerprint']}, indent=2))

if __name__ == '__main__':
    main()

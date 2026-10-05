#!/usr/bin/env python3
"""Build a fixed, guarded BSP helper replacement; never runs on a device."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
S = R / 'scripts/asus-integration/bsp-update'
OLD_SHA = 'f51beb4faf20bac73df894a7752b385a06436967d782e3c264e48416e24ddbc9'
HARDWARE_MANIFEST_SHA = '5747dbf9a9387d7ea9ad95450ca6ab63c086d29ea787ef27fe80f7929a8ead52'


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def ref(path):
    return {'path': str(path.resolve().relative_to(R)), 'sha256': sha(path)}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--new-binary', required=True, type=Path)
    parser.add_argument('--new-sha256', required=True)
    parser.add_argument('--new-manifest', required=True, type=Path)
    parser.add_argument('--new-manifest-sha256', required=True)
    parser.add_argument('--reuse-transaction-manifest', required=True, type=Path)
    args = parser.parse_args()
    assert re.fullmatch('[a-z0-9-]+', args.label)
    assert re.fullmatch('[0-9a-f]{64}', args.new_sha256) and args.new_sha256 != OLD_SHA
    assert sha(args.new_binary) == args.new_sha256 and sha(args.new_manifest) == args.new_manifest_sha256
    policy = json.loads(args.new_manifest.read_text())
    assert policy['binary']['sha256'] == args.new_sha256 and policy['old_binary']['sha256'] == OLD_SHA
    payload = args.new_binary.read_bytes()
    assert 64 <= len(payload) <= 16 * 1024 * 1024
    assert payload[:6] == b'\x7fELF\x02\x01' and payload[18:20] == b'\xb7\x00'
    old_binary = R / 'build/asus-bsp-resources/native-v4/bsp-ownership'
    assert sha(old_binary) == OLD_SHA
    # Check the actual root07 member, not only a filename or version claim.
    root07_receipt = R / 'build/ubuntu26-local-repository/candidates/asus-runtime07-archive-sealed-v1/result.json'
    root07 = json.loads(root07_receipt.read_text())['rootfs']
    assert root07['sha256'] == '2f0eafc638180019bb44b230e71877e200886e9c6afc9895bb299b0d6e4ca688'
    archive = R / root07['path']
    resources_manifest = R / 'build/asus-native-integration/v4/manifest.json'
    assert sha(resources_manifest) == 'aeafe353cd9f422d4a15b3548d89e9f5b988bd4847e72615885c59e54bfae107'
    resources_archive = {row['path'].lstrip('/'): row for row in json.loads(resources_manifest.read_text())['archive']}
    wanted = {prefix + '/' + name for prefix in ('usr/share/asus/integration/etc-seed/init.d', 'usr/share/asus/integration/rom/etc/init.d')
              for name in ('hndmfg.sh', 'hndnvram.sh', 'mount-data.inc', 'mount-fs.sh')}
    resource_bytes, resource_receipt = {}, []
    with tarfile.open(archive, 'r:') as tar:
        all_members = list(tar)
        rows = [member for member in all_members if member.name.removeprefix('./') == 'usr/libexec/asus/bsp-ownership']
        assert len(rows) == 1
        member = rows[0]
        assert member.isfile() and member.uid == member.gid == 0 and member.mode == 0o755
        assert hashlib.sha256(tar.extractfile(member).read()).hexdigest() == OLD_SHA
        for item in all_members:
            name = item.name.removeprefix('./')
            if name not in wanted:
                continue
            expected_resource = resources_archive[name]
            assert item.isfile() and item.uid == item.gid == 0 and item.mode == 0o755
            data = tar.extractfile(item).read()
            assert hashlib.sha256(data).hexdigest() == expected_resource['sha256']
            short = Path(name).name
            assert short not in resource_bytes or resource_bytes[short] == data
            resource_bytes[short] = data
            resource_receipt.append({'path': '/' + name, 'sha256': expected_resource['sha256'], 'mode': '0755', 'uid': 0, 'gid': 0})
    assert len(resource_receipt) == 8 and {row['path'].lstrip('/') for row in resource_receipt} == wanted
    # Reuse only the unchanged transaction function and its already passed cases.
    prior_path = args.reuse_transaction_manifest.resolve()
    assert sha(prior_path) == 'bdf091c7f854e070b2a19fc16adf3c63db77e2ff178c5f3a6372b2e80854a57f'
    prior = json.loads(prior_path.read_text())
    assert prior['status'] == 'guarded_static_updater_focused_transaction_passed' and prior['focused_cases'] == 15
    assert prior['new_binary'] == ref(args.new_binary) and prior['old_binary'] == ref(old_binary)
    prior_source_hashes = {row['path']: row['sha256'] for row in prior['sources']}
    for name in ('provision.c', 'fixture.c'):
        assert sha(prior_path.parent / 'source' / name) == prior_source_hashes['scripts/asus-integration/bsp-update/' + name]
    previous_source = (prior_path.parent / 'source/provision.c').read_text()
    current_source = (S / 'provision.c').read_text()
    for function in ('bsp_parent', 'bsp_file', 'bsp_update'):
        pattern = r'static int ' + function + r'\([^\n]*\) \{.*?\n\}'
        before = re.findall(pattern, previous_source, re.S)
        after = re.findall(pattern, current_source, re.S)
        assert len(before) == len(after) == 1 and before == after
    previous_fixture = (prior_path.parent / 'source/fixture.c').read_text()
    assert previous_fixture.split('    int oldfd=', 1)[1] == (S / 'fixture.c').read_text().split('    int oldfd=', 1)[1]
    prior_outputs = {Path(row['path']).name: row for row in prior['outputs']}
    assert sha(R / prior_outputs['fixture.log']['path']) == prior_outputs['fixture.log']['sha256']
    assert (R / prior_outputs['fixture.log']['path']).read_text().splitlines()[-1] == 'CASES 15'
    baseline = R / 'build/ubuntu26-hardware-order/native-v1/manifest.json'
    assert sha(baseline) == HARDWARE_MANIFEST_SHA
    accepted = json.loads(baseline.read_text())
    expected = {Path(row['path']).name: row['sha256'] for row in accepted['sources'] + accepted['generated_headers']}
    out = R / 'build/ubuntu26-bsp-update' / args.label
    out.mkdir(parents=True, exist_ok=False)
    snap = out / 'source'
    snap.mkdir(mode=0o755)
    inputs = Path(tempfile.mkdtemp(prefix='leon-bsp-update-'))
    inputs.chmod(0o755)
    for target in (snap, inputs):
        (target / 'resources').mkdir(mode=0o755)
        for name, data in resource_bytes.items():
            (target / 'resources' / name).write_bytes(data)
            (target / 'resources' / name).chmod(0o755)
    sources = []
    for name in ('slot-device.c', 'slot-proof.c', 'slot-proof.h', 'slot-device-policy.h', 'p11-clear-view.h',
                 'sha256-compat.h', 'sha256.c', 'boot-diagnostics.h', 'hardware-payload.h', 'resolver-payload.h', 'provision.c'):
        source = baseline.parent / 'source' / name
        expected_name = 'device.c' if name == 'slot-device.c' else name
        assert sha(source) == expected[expected_name]
        sources.append(ref(source))
        target_name = 'hardware-provision.c' if name == 'provision.c' else name
        for target in (snap, inputs):
            shutil.copyfile(source, target / target_name)
    for name in ('provision.c', 'fixture.c'):
        sources.append(ref(S / name))
        for target in (snap, inputs):
            shutil.copyfile(S / name, target / name)
    header = '#define BSP_NEW_SHA ' + json.dumps(args.new_sha256) + '\nstatic const unsigned char bsp_payload[]={\n'
    header += '\n'.join(','.join('0x%02x' % byte for byte in payload[i:i+16]) + ',' for i in range(0, len(payload), 16))
    header += '\n};\n'
    for target in (snap, inputs):
        (target / 'bsp-payload.h').write_text(header)
    shutil.copyfile(old_binary, inputs / 'old-bsp')
    env_receipt = R / 'build/asus-native-build/v2/result.json'
    root = Path(json.loads(env_receipt.read_text())['root'])
    worker = r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/bsp-update-$label"
cp -r "$inputs"/. "$root/work/bsp-update-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/bsp-update-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" provision.c slot-proof.c sha256.c -o provision-bsp-update
ccache gcc-16 "${flags[@]}" fixture.c slot-proof.c sha256.c -o fixture
./fixture --resources-only resources > fixture.log
./provision-bsp-update --invalid >badargs.stdout 2>badargs.stderr && exit 1 || test "$?" = 64
test ! -s badargs.stdout && test ! -s badargs.stderr
./provision-bsp-update --update-bsp-ownership aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 11111111-2222-3333-4444-555555555555 >nondevice.stdout 2>nondevice.stderr && exit 1 || test "$?" = 1
test ! -s nondevice.stdout
grep -Fx 'LEON_BSP_UPDATE_REFUSED stage=stock-root-and-native-namespace temporary_created=0 published=0 retained_for_review=true' nondevice.stderr
readelf -h -l -d provision-bsp-update > elf.txt
gcc-16 --version > compiler.txt
BUILD
'''
    (inputs / 'build.sh').write_text(worker)
    with (out / 'build.log').open('w') as log:
        subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'), str(root), str(inputs), args.label],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    stage = root / f'work/bsp-update-{args.label}'
    names = ['provision-bsp-update', 'fixture', 'fixture.log', 'badargs.stdout', 'badargs.stderr', 'nondevice.stdout', 'nondevice.stderr', 'elf.txt', 'compiler.txt']
    for name in names:
        shutil.copyfile(stage / name, out / name)
        (out / name).chmod(0o755 if name in ('provision-bsp-update', 'fixture') else 0o644)
    assert 'INTERP' not in (out / 'elf.txt').read_text() and 'AArch64' in (out / 'elf.txt').read_text()
    lines = (out / 'fixture.log').read_text().splitlines()
    assert lines[-1] == 'RESOURCE_CASES 5' and len([line for line in lines if line.startswith('PASS ')]) == 5
    shutil.copyfile(R / prior_outputs['fixture.log']['path'], out / 'transaction-fixture-reused.log')
    report = {'schema': 1, 'status': 'guarded_static_updater_focused_transaction_passed',
        'builder': ref(Path(__file__)), 'sources': sources, 'embedded_payload_header': ref(snap / 'bsp-payload.h'),
        'new_binary': ref(args.new_binary), 'new_binary_manifest': ref(args.new_manifest), 'old_binary': ref(old_binary),
        'root07_old_binary_evidence': {'receipt': ref(root07_receipt), 'archive': root07, 'member': 'usr/libexec/asus/bsp-ownership',
            'member_sha256': OLD_SHA, 'member_uid': member.uid, 'member_gid': member.gid, 'member_mode': '0755',
            'scope': 'Actual member bytes and metadata re-read; other root07 files and baseline tests not repeated.'},
        'reused_guard_and_preservation': ref(baseline), 'native_build_environment': ref(env_receipt),
        'reviewed_bsp_resource_manifest': ref(resources_manifest), 'required_bsp_resources': resource_receipt,
        'resource_scope': 'All eight exact transformed script bytes and root0755 metadata from reviewed integration and actual root07 archive; enforced before and after replacement using no-follow same-volume parents.',
        'outputs': [ref(out / name) for name in names], 'provisioner': ref(out / 'provision-bsp-update'),
        'focused_cases': 5, 'transaction_cases_reused': 15, 'transaction_evidence_reused': ref(prior_path),
        'transaction_log_reused': ref(out / 'transaction-fixture-reused.log'),
        'bad_arguments_exit': 64, 'nondevice_refusal_exit': 1,
        'usage': 'provision-bsp-update --update-bsp-ownership <fresh metadata SHA256> <current stock2 boot UUID>',
        'transaction': 'Fixed root0755 old-hash target only; exact new target is idempotent. Root0600 O_EXCL/no-follow staging, complete write/fsync/hash readback, chmod0755/fsync, old inode/hash recheck, atomic same-directory rename, directory fsync and new inode/hash readback.',
        'preservation': 'Unmodified frozen device guards and existing generation/token, diagnostic bytes/inode/FIEMAP, resolver, hardware-order configuration bytes/inode, private insmod target/inode and exact BusyBox provider.',
        'new_root_payload_writes': ['/usr/libexec/asus/bsp-ownership.leon-update (exclusive staging)', '/usr/libexec/asus/bsp-ownership (atomic replacement only)'],
        'device_operated': False, 'boot_metadata_changed': False, 'firmware_changed': False, 'rebooted': False, 'boot_committed': False,
        'limits': ['Five new BSP-resource prerequisite cases ran. The byte-identical replacement transaction and its fifteen passed cases were reused, as were device/format/preservation proofs.',
            'Private RW ext4 mounting and syncing can update filesystem metadata. Clean p11 is required; no fsck or journal repair.',
            'Failure before rename retains the old target and staging file; failure after rename reports published=1 and retains the new target. No automatic rollback or removal.',
            'The advisory lock excludes cooperating tools only; exclusive maintenance remains required.',
            '300-second alarm cannot interrupt uninterruptible storage I/O; stuck process retains its lock until exit.',
            'Updater does not run the replacement helper or update dpkg/guardian identity. Parent separately owns those changes before another trial.']}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(out / 'manifest.json'), 'provisioner': report['provisioner'], 'new_resource_cases': 5, 'transaction_cases_reused': 15}))


if __name__ == '__main__':
    main()

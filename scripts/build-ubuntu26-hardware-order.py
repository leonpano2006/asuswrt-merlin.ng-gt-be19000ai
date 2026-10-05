#!/usr/bin/env python3
"""Build fixed stock-side modprobe config and private insmod alias provisioner; no device access."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
S = R / 'scripts/asus-integration/hardware-order'
GUARD_SHA = '2a3db1ff59671dcd39089ec6fe7af67e45b8304047113ff756e9476d7e51c567'
HEADER_SHA = '6db67153c5e05327afb92d42bb20765a98e96667fad1b5af66157931bdadb1af'
PAYLOAD_SHA = '27d8aec699f3e8c44288d1a02b3a02e2e8f05a324496413ae76ebde8d46705b4'
RESOLVER_SHA = '2a51b2b2ad2dc3393dcf6557824683548d1d0118d9416e7d4f0470ba5f63a7d4'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    assert re.fullmatch('[a-z0-9-]+', args.label)
    baseline = R / 'build/ubuntu26-slot-proof/v7/manifest.json'
    assert sha(baseline) == GUARD_SHA
    guard_receipt = R / 'build/ubuntu26-slot-proof/v7/validated-manifest.json'
    assert sha(guard_receipt) == '546d19137c01d4118b7cfd77adee93380bf8371e4b13d86b4c97cbc27a2de6c5'
    old = json.loads(baseline.read_text())
    expected = {Path(row['path']).name: row['sha256'] for row in old['sources']}
    common = R / 'scripts/asus-integration/boot-diagnostics/boot-diagnostics.h'
    assert sha(common) == HEADER_SHA
    payload = R / 'configs/ubuntu26/asus-hardware-order/90-leon-asus-hardware-order.conf'
    resolver = R / 'configs/ubuntu26/asus-resolver-ordering/10-leon-ordering.conf'
    assert sha(payload) == PAYLOAD_SHA and sha(resolver) == RESOLVER_SHA
    busybox = R / 'build/asus-private-shell/native-v4/busybox-native'
    assert sha(busybox) == '686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6'
    directives = [line.split() for line in payload.read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith('#')]
    assert directives == [['blacklist', name] for name in
                          ('bcm_bca_usb', 'bcm_pcie_hcd', 'bcmflex', 'bcmspu', 'dhd', 'hs_uart_drv', 'rdpa_cmd', 'rdpa_gpl')]
    # Reuse the accepted header/format evidence; do not repeat the format suite.
    foundation = R / 'reports/ubuntu26/boot-diagnostics-foundation.json'
    foundation_data = json.loads(foundation.read_text())
    assert HEADER_SHA in json.dumps(foundation_data)
    out = R / 'build/ubuntu26-hardware-order' / args.label
    out.mkdir(parents=True, exist_ok=False)
    snap = out / 'source'
    snap.mkdir(mode=0o755)
    inputs = Path(tempfile.mkdtemp(prefix='leon-hardware-order-'))
    inputs.chmod(0o755)
    shutil.copyfile(busybox, inputs / 'busybox-reference')
    sources = []
    for name in ('device.c', 'slot-proof.c', 'slot-proof.h', 'slot-device-policy.h', 'p11-clear-view.h', 'sha256-compat.h', 'sha256.c'):
        source = baseline.parent / 'source-snapshot' / name
        assert sha(source) == expected[name]
        sources.append(ref(source))
        destination = 'slot-device.c' if name == 'device.c' else name
        for target in (snap, inputs):
            shutil.copyfile(source, target / destination)
    for source in (common, S / 'provision.c', S / 'fixture.c'):
        sources.append(ref(source))
        for target in (snap, inputs):
            shutil.copyfile(source, target / source.name)
    for name, source, macro, symbol in (
            ('hardware-payload.h', payload, 'HARDWARE_PAYLOAD_SHA', 'hardware_payload'),
            ('resolver-payload.h', resolver, 'RESOLVER_PAYLOAD_SHA', 'resolver_payload')):
        header = '#define ' + macro + ' ' + json.dumps(sha(source)) + '\nstatic const char ' + symbol + '[]=' + json.dumps(source.read_text()) + ';\n'
        for target in (snap, inputs):
            (target / name).write_text(header)
    env_receipt = R / 'build/asus-native-build/v2/result.json'
    root = Path(json.loads(env_receipt.read_text())['root'])
    worker = r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/hardware-order-$label"
cp "$inputs"/* "$root/work/hardware-order-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/hardware-order-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" provision.c slot-proof.c sha256.c -o provision-hardware-order
ccache gcc-16 "${flags[@]}" fixture.c slot-proof.c sha256.c -o fixture
./fixture busybox-reference > fixture.log
./provision-hardware-order --invalid >badargs.stdout 2>badargs.stderr && exit 1 || test "$?" = 64
test ! -s badargs.stdout && test ! -s badargs.stderr
./provision-hardware-order --install-hardware-order aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 11111111-2222-3333-4444-555555555555 >nondevice.stdout 2>nondevice.stderr && exit 1 || test "$?" = 1
test ! -s nondevice.stdout
grep -Fx 'LEON_HARDWARE_ORDER_REFUSED stage=stock-root-and-native-namespace payload_created=0 alias_created=0 retained_for_review=true' nondevice.stderr
readelf -h -l -d provision-hardware-order > elf.txt
gcc-16 --version > compiler.txt
BUILD
'''
    (inputs / 'build.sh').write_text(worker)
    with (out / 'build.log').open('w') as log:
        subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'), str(root), str(inputs), args.label],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    stage = root / f'work/hardware-order-{args.label}'
    outputs = ['provision-hardware-order', 'fixture', 'fixture.log', 'badargs.stdout', 'badargs.stderr',
               'nondevice.stdout', 'nondevice.stderr', 'elf.txt', 'compiler.txt']
    for name in outputs:
        shutil.copyfile(stage / name, out / name)
        (out / name).chmod(0o755 if name in ('provision-hardware-order', 'fixture') else 0o644)
    assert 'INTERP' not in (out / 'elf.txt').read_text() and 'AArch64' in (out / 'elf.txt').read_text()
    cases = (out / 'fixture.log').read_text().splitlines()
    assert cases[-1] == 'CASES 25' and len([line for line in cases if line.startswith('PASS ')]) == 25
    report = {
        'schema': 1, 'status': 'static_provisioner_focused_file_safety_passed',
        'builder': ref(Path(__file__)), 'sources': sources,
        'generated_headers': [ref(snap / name) for name in ('hardware-payload.h', 'resolver-payload.h')],
        'payload': ref(payload), 'preserved_resolver': ref(resolver), 'exact_busybox_provider': ref(busybox), 'native_build_environment': ref(env_receipt),
        'frozen_guard_manifest': ref(baseline), 'guard_evidence_reused': ref(guard_receipt),
        'diagnostic_format_evidence_reused': ref(foundation),
        'outputs': [ref(out / name) for name in outputs], 'provisioner': ref(out / 'provision-hardware-order'),
        'focused_cases': 25, 'bad_arguments_exit': 64, 'nondevice_refusal_exit': 1,
        'usage': 'provision-hardware-order --install-hardware-order <fresh metadata SHA256> <current stock2 boot UUID>',
        'guard_scope': 'Unmodified hash-pinned slot-proof v7 stock p6/CID/GPT/11 extents/full p5+p6/metadata/UUID/clean ext4/all-process mounts/holders/swaps checks; shared identity flock.',
        'mount_identity': 'Fresh UUID verified on enrolled 179:11 descriptor; private CLONE_NEWNS/MS_PRIVATE; mount /proc/self/fd/N ext4 nodev,nosuid,noexec. No unchecked path fallback.',
        'new_root_payload_writes': ['/etc/modprobe.d (root0755 directory only if missing)', '/etc/modprobe.d/90-leon-asus-hardware-order.conf (exact approved root0644 file only if missing)', '/usr/share/asus/commands/sbin/insmod -> /usr/libexec/asus/busybox (root-owned symlink only if missing; exact existing BusyBox bytes required)'],
        'preservation': 'Exact generation and slot token before/after; initialized fixed diagnostics opened O_RDONLY and all16384bytes/inode/FIEMAP unchanged; resolver drop-in bytes/inode and resolv.conf symlink unchanged.',
        'idempotence': 'Both config and private alias are preflighted before any payload write. Safe exact config and root-owned exact symlink are accepted without rewrite. Partial/foreign/unsafe/FIFO/hardlink files and unexpected symlinks are rejected, retained, never truncated or removed.',
        'forbidden_operations_performed': {'device_access': False, 'firmware_writes': False, 'gpt_writes': False,
            'boot_metadata_writes': False, 'diagnostic_reset': False, 'resolver_changes': False, 'reboot': False, 'boot_commit': False},
        'limits': ['Focused fixture only exercises new file/directory handling on isolated temporary regular directories; actual device guards and ext4 FIEMAP proofs reused, not rerun.',
            'Production requires an already clean p11, existing valid slot proof, existing initialized diagnostic file and exact resolver override; it does not repair or manufacture prerequisites.',
            'Normal ext4 mount/fsync update filesystem metadata. Failure after creation leaves the new file or partial file for review; there is no rollback overwrite.',
            'The shared flock excludes cooperating tools only; caller must keep other privileged storage maintenance stopped.',
            '300-second process alarm bounds normal execution but cannot interrupt uninterruptible kernel I/O; a stuck process retains its lock until exit.',
            'This admin configuration does not disable explicit ASUS insmod and is not itself a dpkg transaction. No physical execution was performed.']}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(out / 'manifest.json'), 'provisioner': report['provisioner'], 'focused_cases': 25}))


if __name__ == '__main__':
    main()

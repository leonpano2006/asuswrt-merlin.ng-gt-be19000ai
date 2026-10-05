#!/usr/bin/env python3
"""Execute the staged SquashFS PID1, plus an explicitly adapted loop handoff.

exact-entry runs the production image/binary unchanged. Only the ASUS rc entry
is bind-mounted to a RAM test sink, so failed checks cannot launch hardware
services. QEMU virt has no BCM eMMC: success is reaching the identity gate.
loop-handoff changes exactly three regular files in a separate derived image:
PID1's loop policy, the fsck device policy, and a protocol-only guardian. Every
directory and all remaining vendor contents are preserved from the real image.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def load_module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

STAGER = load_module('bootstrap_stage', 'stage-ubuntu26-bootstrap.py')
INV = load_module('bootstrap_inventory', 'kernel9_ui1.py').inventory

FALLBACK = r'''#!/tmp/busybox sh
set -eu
B=/tmp/busybox
test "$$" = 1
test "$($B stat -f -c %t /)" = 73717368
echo LAB_EXACT_BOOTSTRAP_VENDOR_SINK
echo LAB_EXACT_BOOTSTRAP_KMSG_BEGIN
$B dmesg | $B grep LEON_ROOT_ || true
echo LAB_EXACT_BOOTSTRAP_KMSG_END
echo QEMU_EXACT_BOOTSTRAP_COMPLETE
$B poweroff -f
'''

EARLY = r'''#!/busybox sh
set -eu
B=/busybox
exec </dev/console >/dev/console 2>&1
trap 'rc=$?; echo LAB_BOOTSTRAP_SETUP_FAILED_code=$rc; $B poweroff -f' EXIT
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
$B mount -t tmpfs -o mode=0755,size=1536m tmpfs /store
$B mount --make-rprivate /
echo QEMU_LAB_INIT_REACHED
$B mv /firmware.sqfs /store/firmware.sqfs
$B cp /busybox /store/busybox
$B cp /fallback /store/fallback
$B losetup /dev/loop0 /store/firmware.sqfs
$B mount -t squashfs -o ro /dev/loop0 /firmware
$B mount --bind /store/fallback /firmware/sbin/rc
# This is an existing vendor /tmp directory; never manufacture /run in the
# tested image. The production PID1 must validate and mount /run itself.
@HANDOFF@
$B mount --move /store /firmware/tmp
for name in proc sys dev; do $B mount --move /$name /firmware/$name; done
echo LAB_EXACT_BOOTSTRAP_PID1_EXEC
exec $B switch_root /firmware /sbin/init
'''

UBUNTU_INIT = r'''#!/usr/libexec/leon-lab/busybox sh
set -eu
B=/usr/libexec/leon-lab/busybox
if [ "${1:-}" = --version ]; then exec /usr/lib/systemd/systemd --version; fi
test "$$" = 1
$B grep -q ' / ext4 rw,' /proc/mounts
$B grep -q ' /mnt/leon-vendor-root squashfs ro,' /proc/mounts
echo LAB_BOOTSTRAP_REAL_SQUASHFS_EXT4_HANDOFF
($B sleep 35
 if [ -s /run/leon-bootstrap-proof ]; then
  $B cat /run/leon-bootstrap-proof
  echo QEMU_BOOTSTRAP_HANDOFF_COMPLETE
 else
  echo LAB_BOOTSTRAP_SYSTEMD_PROOF_MISSING
 fi
 $B poweroff -f) &
exec /usr/lib/systemd/systemd --system --unit=leon-pivot.target --log-target=console --log-level=info
'''

PROOF = r'''#!/bin/sh
set -eu
test "$(cat /proc/1/comm)" = systemd
grep -q ' / ext4 rw,' /proc/mounts
grep -q ' /mnt/leon-vendor-root squashfs ro,' /proc/mounts
grep -q '/system.slice/leon-pivot.service' /proc/self/cgroup
for n in dev proc sys run; do test -d /mnt/leon-vendor-root/$n; done
count=0
while [ ! -f /run/leon-guardian-exec-survived ]; do
 count=$((count+1)); test "$count" -lt 100; sleep 0.1
done
test "$(cat /run/leon-guardian-exec-survived)" = private-cloexec-parent1-systemd
echo LAB_BOOTSTRAP_GUARDIAN_HANDOFF_SYSTEMD_PASS
if (echo forbidden > /mnt/leon-vendor-root/run/forbidden) 2>/dev/null; then exit 1; fi
echo LAB_BOOTSTRAP_OLDROOT_READONLY_PASS
dmesg | grep 'LEON_ROOT_ENTER stage=mounts code=0'
dmesg | grep 'LEON_ROOT_ENTER stage=identity code=0'
dmesg | grep 'LEON_ROOT_UBUNTU_EXEC stage=ubuntu-exec code=0'
trace=/etc/leon/boot-diagnostics
reader=/usr/libexec/leon-lab/boot-diagnostics-read
boot=$(cat /proc/sys/kernel/random/boot_id)
build=@ROOT_DIAG_BUILD_ID@
test "$(stat -c '%a:%u:%g:%h:%s' "$trace")" = 600:0:0:1:16384
for expected in 'event=ENTER stage=mounts code=0' 'event=GUARDIAN_PREPARED_UNARMED' 'event=GUARDIAN_ARM_REQUEST' 'event=GUARDIAN_ARMED stage=guardian-handoff code=40' 'event=UBUNTU_EXEC stage=ubuntu-exec code=0'; do
 "$reader" --check "$trace" 0 "$boot" "$build" "$expected"
done
"$reader" --empty "$trace" 1
echo LAB_BOOTSTRAP_FIXED_TRACE_CRC_BUILD_SEQUENCE_PASS
echo LAB_BOOTSTRAP_PERSISTENT_TRACE_PASS
printf 'LAB_BOOTSTRAP_SYSTEMD_KMSG_PASS\n' > /run/leon-bootstrap-proof
cat /run/leon-bootstrap-proof
'''

def record(path):
    return {'path': str(path.relative_to(ROOT)), 'sha256': sha(path)}

def cpio(output, entries):
    offset = 0
    with output.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', compresslevel=1, mtime=0) as gz:
        for ino, (name, mode, data, major, minor) in enumerate(entries, 1):
            size = data.stat().st_size if isinstance(data, Path) else len(data)
            encoded = name.encode() + b'\0'
            fields = [ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0, size, 0, 0, major, minor, len(encoded), 0]
            header = b'070701' + ''.join(f'{v:08x}' for v in fields).encode() + encoded
            gz.write(header); offset += len(header)
            pad = -offset % 4; gz.write(b'\0' * pad); offset += pad
            if isinstance(data, Path):
                with data.open('rb') as source: shutil.copyfileobj(source, gz, 1024*1024)
            else: gz.write(data)
            offset += size
            pad = -offset % 4; gz.write(b'\0' * pad); offset += pad

def main():
    if not __debug__: raise RuntimeError('Python optimization is not supported')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', required=True)
    p.add_argument('--stage-manifest', type=Path, required=True)
    p.add_argument('--mode', choices=['exact-entry', 'loop-handoff'], required=True)
    p.add_argument('--helper-label', default='bootstrap-loop-kmsg-v1')
    a = p.parse_args()
    assert re.fullmatch('[A-Za-z0-9_-]+', a.label)
    stage = json.loads(a.stage_manifest.read_text())
    original = ROOT / stage['rootfs']['path']
    assert sha(original) == stage['rootfs']['sha256']
    assert stage['kernel_sha256'] == sha(ROOT / 'build/Image-v10')
    out = ROOT / 'build/ubuntu26-bootstrap-qemu' / a.label
    out.mkdir(parents=True, exist_ok=False)
    image = original
    differences = []
    image_ext4 = None
    extra = []
    early = EARLY.replace('@HANDOFF@', '')
    helper = None
    if a.mode == 'loop-handoff':
        STAGER.verify_packed_mountpoints(original)
        helperdir = ROOT / 'build/ubuntu26-root-init' / a.helper_label
        helper = json.loads((helperdir / 'manifest.json').read_text())
        assert helper['source_sha256'] == sha(ROOT / 'scripts/asus-integration/ubuntu-root-init.c')
        assert helper['policy']['scope'] == 'offline-qemu-fixture'
        assert helper['guardian_required'] and helper['emergency_fault_sink']
        assert helper['policy']['device'] == '/dev/loop1'
        assert helper['policy']['fsck'] == '/usr/libexec/leon-boot/fsck'
        fw = out / 'firmware'
        subprocess.run(['unsquashfs', '-no-progress', '-d', str(fw), str(original)], check=True, stdout=subprocess.DEVNULL)
        before = INV(fw)
        assert before == stage['inventory']
        replacements = {'sbin/init': helperdir / 'ubuntu-root-init',
                        'usr/libexec/leon-boot/trial-guardian': helperdir / 'root-guardian-mock',
                        'usr/libexec/leon-boot/fsck': ROOT / 'build/ubuntu26-boot-fsck/qemu-v1/stage/usr/libexec/leon-boot/fsck'}
        fsck = json.loads((ROOT / 'build/ubuntu26-boot-fsck/qemu-v1/manifest.json').read_text())
        for name, row in fsck['payload'].items():
            source = ROOT / 'build/ubuntu26-boot-fsck/qemu-v1/stage' / name
            assert sha(source) == row['sha256']
            if name not in replacements: assert sha(fw / name) == row['sha256']
        for name, source in replacements.items():
            if name == 'sbin/init': assert sha(source) == helper['outputs']['ubuntu-root-init']
            if name.endswith('trial-guardian'): assert sha(source) == helper['outputs']['root-guardian-mock']
            shutil.copyfile(source, fw / name); (fw / name).chmod(0o755)
        after = INV(fw)
        differences = [n for n in sorted(set(before) | set(after)) if before.get(n) != after.get(n)]
        assert set(differences) == set(replacements), differences
        image = out / 'loop-adapted.squashfs'
        subprocess.run(['mksquashfs', str(fw), str(image), '-all-root', '-noappend', '-comp', 'zstd', '-b', '524288', '-processors', '4', '-no-progress'], check=True, stdout=subprocess.DEVNULL)
        STAGER.verify_packed_mountpoints(image)
        base = ROOT / 'build/ubuntu26-pivot-qemu/guardian-emergency-v1'
        baseline = json.loads((base / 'manifest.json').read_text())
        assert sha(base / 'ubuntu.ext4') == baseline['image_sha256']
        image_ext4 = out / 'ubuntu.ext4'
        subprocess.run(['cp', '--reflink=auto', '--sparse=always', str(base / 'ubuntu.ext4'), str(image_ext4)], check=True)
        reader = helperdir / 'boot-diagnostics-read'
        assert sha(reader) == helper['outputs']['boot-diagnostics-read']
        common_header = ROOT / 'scripts/asus-integration/boot-diagnostics/boot-diagnostics.h'
        common_reader = common_header.with_name('reader.c')
        assert helper['boot_diagnostics_sha256'] == sha(common_header)
        assert helper['diagnostic_reader_sha256'] == sha(common_reader)
        zero_file = out / 'boot-diagnostics.zero'
        zero_file.write_bytes(bytes(16384))
        commands = [f'write {reader} /usr/libexec/leon-lab/boot-diagnostics-read',
                    'set_inode_field /usr/libexec/leon-lab/boot-diagnostics-read mode 0100755',
                    'set_inode_field /usr/libexec/leon-lab/boot-diagnostics-read uid 0',
                    'set_inode_field /usr/libexec/leon-lab/boot-diagnostics-read gid 0',
                    f'write {zero_file} /etc/leon/boot-diagnostics',
                    'set_inode_field /etc/leon/boot-diagnostics mode 0100600',
                    'set_inode_field /etc/leon/boot-diagnostics uid 0',
                    'set_inode_field /etc/leon/boot-diagnostics gid 0']
        for name, target, content in [('ubuntu-init', '/usr/libexec/leon-lab/ubuntu-init', UBUNTU_INIT),
                                       ('proof', '/usr/libexec/leon-lab/pivot-proof', PROOF.replace('@ROOT_DIAG_BUILD_ID@', helper['diagnostic_build_id']))]:
            src = out / name; src.write_text(content)
            commands += [f'rm {target}', f'write {src} {target}', f'set_inode_field {target} mode 0100755', f'set_inode_field {target} uid 0', f'set_inode_field {target} gid 0']
        script = out / 'populate.debugfs'; script.write_text('\n'.join(commands) + '\n')
        with (out / 'debugfs.log').open('w') as log:
            subprocess.run(['debugfs', '-w', '-f', str(script), str(image_ext4)], stdout=log, stderr=subprocess.STDOUT, check=True)
        for name, target in [('ubuntu-init', '/usr/libexec/leon-lab/ubuntu-init'), ('proof', '/usr/libexec/leon-lab/pivot-proof')]:
            restored = out / (name + '.readback')
            subprocess.run(['debugfs', '-R', f'dump {target} {restored}', str(image_ext4)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            assert sha(restored) == sha(out / name)
        for name, target, expected in [('reader', '/usr/libexec/leon-lab/boot-diagnostics-read', reader),
                                       ('zero', '/etc/leon/boot-diagnostics', zero_file)]:
            restored = out / (name + '.readback')
            subprocess.run(['debugfs', '-R', f'dump {target} {restored}', str(image_ext4)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            assert sha(restored) == sha(expected)
        with (out / 'e2fsck.log').open('w') as log:
            subprocess.run(['e2fsck', '-f', '-n', str(image_ext4)], stdout=log, stderr=subprocess.STDOUT, check=True)
        early = EARLY.replace('@HANDOFF@', '''$B mv /ubuntu.ext4 /store/ubuntu.ext4
$B losetup /dev/loop1 /store/ubuntu.ext4
# Initialize every byte before the writer exists; debugfs can store zeros sparsely.
# This guest-only preparation is not a production boot-time allocation path.
$B mount -t ext4 /dev/loop1 /diag-root
test "$($B stat -c '%a:%u:%g:%h:%s' /diag-root/etc/leon/boot-diagnostics)" = 600:0:0:1:16384
$B dd if=/dev/zero of=/diag-root/etc/leon/boot-diagnostics bs=4096 count=4 conv=notrunc
$B sync
/diag-root/usr/libexec/leon-lab/boot-diagnostics-read --empty /diag-root/etc/leon/boot-diagnostics 0
/diag-root/usr/libexec/leon-lab/boot-diagnostics-read --empty /diag-root/etc/leon/boot-diagnostics 1
echo LAB_BOOTSTRAP_DIAGNOSTIC_PREALLOCATED_ZERO_PASS
$B umount /diag-root
$B mount -t tmpfs -o mode=0755 tmpfs /run
echo positive > /run/scenario
$B mount --move /run /firmware/run''')
        extra = [('ubuntu.ext4', stat.S_IFREG | 0o600, image_ext4, 0, 0)]
    (out / 'early-init').write_text(early)
    (out / 'fallback').write_text(FALLBACK)
    entries = [(n, stat.S_IFDIR | 0o755, b'', 0, 0) for n in ['dev', 'proc', 'sys', 'run', 'store', 'firmware', 'diag-root']]
    entries += [('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1),
                ('busybox', stat.S_IFREG | 0o755, ROOT / 'build/busybox', 0, 0),
                ('init', stat.S_IFREG | 0o755, early.encode(), 0, 0),
                ('fallback', stat.S_IFREG | 0o755, FALLBACK.encode(), 0, 0),
                ('firmware.sqfs', stat.S_IFREG | 0o600, image, 0, 0), *extra,
                ('TRAILER!!!', 0, b'', 0, 0)]
    initrd = out / 'initramfs.cpio.gz'; cpio(initrd, entries)
    manifest = {'schema_version': 1, 'mode': a.mode, 'stage_manifest': record(a.stage_manifest.resolve()),
                'production_squashfs': record(original), 'executed_squashfs': record(image),
                'initramfs': record(initrd), 'builder': record(Path(__file__).resolve()),
                'kernel_sha256': stage['kernel_sha256'], 'firmware_changed_paths': differences,
                'loop_helper_manifest': record(helperdir / 'manifest.json') if helper else None,
                'ubuntu_fixture': record(image_ext4) if image_ext4 else None,
                'runtime_bind_overlays': ['/sbin/rc -> RAM failure sink'],
                'directory_inodes_preserved': True, 'firmware_run_manufactured_by_fixture': False,
                'hardware_emulated': False, 'physical_trial_accepted': False,
                'diagnostic_fixed_slots': ({'path': '/etc/leon/boot-diagnostics', 'bytes': 16384,
                    'mode': 0o600, 'uid': 0, 'gid': 0, 'producer': 0,
                    'preinitialized_zero': True, 'payload_crc_reader': record(reader),
                    'common_header_sha256': helper['boot_diagnostics_sha256'],
                    'reader_source_sha256': helper['diagnostic_reader_sha256'],
                    'build_id': helper['diagnostic_build_id'],
                    'producer1_must_remain_empty': True} if helper else None),
                'limits': ['QEMU virt cannot model BCM eMMC; exact production PID1 must refuse the absent device.',
                           'Positive handoff adapts exactly the three listed regular files to loop storage and a guardian protocol mock.']}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'mode': a.mode, 'manifest': str((out / 'manifest.json').relative_to(ROOT)), 'initramfs': manifest['initramfs']}, indent=2))

if __name__ == '__main__': main()

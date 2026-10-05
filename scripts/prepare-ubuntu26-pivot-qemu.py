#!/usr/bin/env python3
"""Prepare a real readonly SquashFS to ext4 PID1 handoff/recovery fixture.

All disks are regular files embedded in a no-NIC QEMU initramfs. Firmware rc is
an explicit test double. The helper under test is the production C source with
a separate loop-device policy. Successful handoff starts real Ubuntu systemd.
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
GENERATION = 'squashfs-pivot-qemu-v1\n'
# Optional explicit inputs from the separate production-loop fixture composer.
# Default invocations retain the original fixture and never load extra files.
EXTRA_FIXTURE_FILES = []
EXTRA_FIXTURE_DIRECTORIES = []
GUARDIAN_FIXTURE_ROLE = None
FIXTURE_SCENARIOS = None

EARLY = r'''#!/busybox sh
set -eu
B=/busybox
exec </dev/console >/dev/console 2>&1
trap 'rc=$?; echo LAB_PIVOT_FIXTURE_EXIT_code=$rc; $B poweroff -f' EXIT
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
$B mount -t tmpfs -o size=1536m,mode=0755 tmpfs /run
$B mount --make-rprivate /
echo QEMU_LAB_INIT_REACHED
scenario=positive
for arg in $($B cat /proc/cmdline); do
 case "$arg" in lab_pivot=*) scenario=${arg#lab_pivot=};; esac
done
case "$scenario" in positive|bad-uuid|bad-size|bad-generation|bad-root-mode|bad-init-parent|symlink-init-parent|owned-mounts|fsck-reboot|fsck-error|fsck-timeout|mount-error|loader-error|exec-error) ;; *) exit 1;; esac
echo "$scenario" > /run/scenario
$B mv /firmware.sqfs /run/firmware.sqfs
$B mv /ubuntu.ext4 /run/ubuntu.ext4
case "$scenario" in
 bad-uuid|owned-mounts) printf 'wrong-uuid-16byte' | $B dd of=/run/ubuntu.ext4 bs=1 seek=1128 conv=notrunc 2>/dev/null;;
 bad-size) $B truncate -s 536870912 /run/ubuntu.ext4;;
esac
$B losetup /dev/loop0 /run/firmware.sqfs
$B losetup /dev/loop1 /run/ubuntu.ext4
case "$scenario" in
 bad-generation)
  $B mount -t ext4 /dev/loop1 /scratch
  echo invalid-generation > /scratch/etc/leon/root-generation
  $B umount /scratch;;
esac
$B mount -t squashfs -o ro /dev/loop0 /firmware
if [ "$scenario" = owned-mounts ]; then
 for name in proc sys dev; do $B umount /$name; done
 $B mount --move /run /firmware/lab-store
else
 for name in proc sys dev run; do $B mount --move /$name /firmware/$name; done
fi
echo LAB_REAL_SQUASHFS_PID1_START
exec $B switch_root /firmware /sbin/init
'''

FSCK = r'''#!/busybox sh
set -eu
case "$(/busybox cat /run/scenario)" in
 fsck-reboot) exit 2;;
 fsck-error) exit 4;;
 fsck-timeout) /busybox sleep 30; exit 0;;
esac
/usr/sbin/e2fsck "$@"
code=$?
if [ "$(/busybox cat /run/scenario)" = mount-error ]; then
 /busybox dd if=/dev/zero of=/dev/loop1 bs=1 seek=1080 count=2 conv=notrunc 2>/dev/null
fi
exit "$code"
'''

FALLBACK = r'''#!/busybox sh
set -eu
B=/busybox
trap 'echo LAB_VENDOR_FIXTURE_FAILED; $B poweroff -f' EXIT
test "$$" = 1
if [ -f /lab-store/scenario ]; then
 for name in proc sys dev run; do test "$($B stat -f -c %t /$name)" = 73717368; done
 echo LAB_ALL_OWNED_PSEUDO_MOUNTS_REMOVED_PASS
 $B mount -t proc proc /proc
 $B mount -t sysfs sysfs /sys
 $B mount -t devtmpfs devtmpfs /dev
 $B mount -t tmpfs -o mode=0755 tmpfs /run
 $B cp /lab-store/scenario /run/scenario
fi
$B grep -q ' / squashfs ro,' /proc/mounts
if $B grep -q ' /leon-newroot ' /proc/mounts; then exit 1; fi
for name in proc sys dev run; do $B grep -q " /$name " /proc/mounts; done
test "$(/busybox cat /etc/vendor-marker)" = untouched-vendor-root
test "$(/busybox cat /run/scenario)" != positive
echo LAB_VENDOR_FALLBACK_PID1_SQUASHFS_PASS
echo QEMU_UBUNTU26_PIVOT_COMPLETE
$B poweroff -f
'''

UBUNTU_INIT = r'''#!/usr/libexec/leon-lab/busybox sh
set -eu
B=/usr/libexec/leon-lab/busybox
if [ "${1:-}" = --version ]; then
 # This runs inside an unmounted-namespace chroot before pivot. /run has not
 # moved yet, so the fixture injector leaves a root-owned marker in the image.
 if [ -f /etc/leon/loader-error ]; then exit 42; fi
 /usr/lib/systemd/systemd --version
 if [ -f /etc/leon/exec-error ]; then $B rm /usr/libexec/leon-lab/ubuntu-init; fi
 exit 0
fi
test "$$" = 1
$B grep -q ' / ext4 rw,' /proc/mounts
$B grep -q ' /mnt/leon-vendor-root squashfs ro,' /proc/mounts
test "$($B cat /etc/leon/root-generation)" = squashfs-pivot-qemu-v1
test "$($B cat /mnt/leon-vendor-root/etc/vendor-marker)" = untouched-vendor-root
echo LAB_SQUASHFS_TO_EXT4_PID1_PASS
($B sleep 30
 if [ -s /run/leon-pivot-service-ok ]; then
  $B cat /run/leon-pivot-service-ok
  echo QEMU_UBUNTU26_PIVOT_COMPLETE
 else
  echo LAB_PIVOT_SYSTEMD_SERVICE_MISSING
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
printf writable-root > /etc/leon/pivot-proof
test "$(cat /etc/leon/pivot-proof)" = writable-root
apt-get -y install /root/leon-writable-probe.deb
test "$(dpkg-query -W '-f=${Status}' leon-writable-probe)" = 'install ok installed'
dpkg --audit > /run/pivot-dpkg-audit
test ! -s /run/pivot-dpkg-audit
if (echo must-fail > /mnt/leon-vendor-root/etc/forbidden-write) 2>/dev/null; then exit 1; fi
printf 'LAB_PIVOT_SYSTEMD_APT_WRITABLE_OLDROOT_READONLY_PASS\n' > /run/leon-pivot-service-ok
cat /run/leon-pivot-service-ok
'''

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def put(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)

def copy_elf_closure(source, dest, executable):
    todo = [executable]
    copied = {}
    while todo:
        name = todo.pop()
        if name in copied: continue
        original = source / name.lstrip('/')
        assert original.is_file(), original
        target = dest / name.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        target.chmod(0o755)
        copied[name] = sha(original)
        elf = subprocess.run(['readelf', '-l', '-d', str(original)], capture_output=True, text=True, check=True).stdout
        for interp in re.findall(r'Requesting program interpreter: (.*?)\]', elf):
            todo.append(interp)
        for library in re.findall(r'\(NEEDED\).*?\[(.*?)\]', elf):
            candidates = ['/lib/aarch64-linux-gnu/' + library, '/usr/lib/aarch64-linux-gnu/' + library]
            found = next((candidate for candidate in candidates if (source / candidate[1:]).is_file()), None)
            assert found, library
            todo.append(found)
    return copied

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--helper-label', default='qemu-v1')
    parser.add_argument('--boot-fsck-label', help='Use the isolated native closure while retaining a stock-loader sentinel')
    parser.add_argument('--partition-start-sector', type=int, help='Regular-file GPT loop fixture only; requires a partition policy')
    parser.add_argument('--base-label', default='gnu-systemd-b53-v3', help='Previously verified writable-root fixture suffix')
    parser.add_argument('--guardian-candidate-label', help='Use a separately built, deployment-gate-closed real guardian for refusal only')
    args = parser.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
    output = ROOT / 'build/ubuntu26-pivot-qemu' / args.label
    output.mkdir(parents=True, exist_ok=False)
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.base_label)
    base = ROOT / ('build/ubuntu26-writable-root-' + args.base_label)
    base_report = json.loads((ROOT / ('reports/ubuntu26/writable-root-test-' + args.base_label + '.json')).read_text())
    assert base_report['passed'] and sha(base / 'ubuntu-root.ext4') == base_report['image_sha256']
    helperdir = ROOT / 'build/ubuntu26-root-init' / args.helper_label
    helper = json.loads((helperdir / 'manifest.json').read_text())
    assert helper['status'] == 'built' and sha(helperdir / 'ubuntu-root-init') == helper['outputs']['ubuntu-root-init']
    assert helper['policy']['scope'] == 'offline-qemu-fixture'
    guardian_required = helper['policy'].get('guardian', {}).get('required', False)
    if guardian_required:
        assert helper['emergency_fault_sink'], 'Guarded QEMU must never execute the production emergency-reset path'
    assert helper['policy']['generation'] == GENERATION
    assert helper['policy']['uuid'] == base_report['filesystem']['uuid']
    assert helper['policy']['sectors'] * 512 == base_report['filesystem']['image_bytes']
    partitioned = bool(helper['policy']['start_sysfs'])
    partition_start = args.partition_start_sector or helper['policy']['start_sector']
    if partitioned:
        assert helper['policy']['device'] == '/dev/loop1p11'
        assert helper['policy']['start_sysfs'] == '/sys/dev/block/7:27/start'
        assert (helper['policy']['major'], helper['policy']['minor']) == (7, 27)
        assert 2048 <= partition_start <= 65536 and partition_start % 2048 == 0
    else:
        assert args.partition_start_sector is None
    image = output / 'ubuntu.ext4'
    subprocess.run(['cp', '--reflink=auto', '--sparse=always', str(base / 'ubuntu-root.ext4'), str(image)], check=True)
    proof = PROOF
    if guardian_required:
        proof = proof.replace('printf writable-root', '''count=0
while [ ! -f /run/leon-guardian-exec-survived ]; do
 count=$((count + 1)); test "$count" -lt 50; sleep 0.1
done
test "$(cat /run/leon-guardian-exec-survived)" = private-cloexec-parent1-systemd
echo LAB_PIVOT_GUARDIAN_REAL_SYSTEMD_PROOF_PASS
printf writable-root''')
    files = {'generation': GENERATION, 'ubuntu-init': UBUNTU_INIT, 'proof': proof,
             'target': '[Unit]\nDefaultDependencies=no\nRequires=leon-pivot.service\nAfter=leon-pivot.service\n',
             'service': '[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/libexec/leon-lab/pivot-proof\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n'}
    for name, content in files.items(): put(output / name, content)
    if helper.get('health_identity_fixture'):
        files['proof']=files['proof'].replace('printf writable-root', '''/usr/libexec/leon-asus/trial-health --assert-armed
echo LAB_GUARDIAN_HEALTH_IMMUTABLE_PID1_CHILD_PASS
set +e
/usr/libexec/leon-asus/trial-health --assert-armed
status=$?
set -e
test "$status" = 125
echo LAB_GUARDIAN_HEALTH_WRONG_BOOT_REJECTED_PASS
mv /run/leon-trial/control /run/leon-trial/real-control
systemctl start leon-forged-guardian.service
count=0
while [ ! -S /run/leon-trial/control ]; do count=$((count+1)); test "$count" -lt 30; sleep 0.1; done
pid=$(systemctl show leon-forged-guardian.service -p MainPID --value)
test "$pid" -gt 1
test "$(awk '{print $4}' /proc/$pid/stat)" = 1
test "$(stat -c %u /proc/$pid)" = 0
test "$(stat -Lc %d:%i /proc/$pid/ns/mnt)" = "$(stat -Lc %d:%i /proc/1/ns/mnt)"
set +e
/usr/libexec/leon-asus/trial-health --assert-armed
status=$?
set -e
test "$status" = 125
echo LAB_GUARDIAN_HEALTH_FORGED_ROOT_SERVER_REJECTED_PASS
systemctl stop leon-forged-guardian.service
rm /run/leon-trial/control
mv /run/leon-trial/real-control /run/leon-trial/control
/usr/libexec/leon-asus/trial-health --assert-armed
echo LAB_GUARDIAN_HEALTH_RESTORED_TRUSTED_SERVER_PASS
printf writable-root''')
        files['forged-service']='[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\nExecStart=/usr/libexec/leon-lab/forged-guardian --forged-server\n'
        for name in ['proof','forged-service']:put(output/name,files[name])
    cmds = ['mkdir /etc/leon', 'mkdir /mnt/leon-vendor-root',
            'set_inode_field /usr/libexec/leon-lab mode 040755']
    if helper.get('health_identity_fixture'):
        for name in ['root-guardian-mock','trial-health']:assert sha(helperdir/name)==helper['outputs'][name]
        cmds += ['mkdir /usr/libexec/leon-asus', 'set_inode_field /usr/libexec/leon-asus mode 040755']
        for source,target in [(helperdir/'root-guardian-mock','/usr/libexec/leon-lab/forged-guardian'),(helperdir/'trial-health','/usr/libexec/leon-asus/trial-health'),(output/'forged-service','/etc/systemd/system/leon-forged-guardian.service')]:
            cmds += [f'write "{source}" "{target}"',f'set_inode_field "{target}" mode '+('0100644' if target.endswith('.service') else '0100755')]
    for name, target, mode in [('generation', '/etc/leon/root-generation', '0100644'),
                                ('ubuntu-init', '/usr/libexec/leon-lab/ubuntu-init', '0100755'),
                                ('proof', '/usr/libexec/leon-lab/pivot-proof', '0100755'),
                                ('target', '/etc/systemd/system/leon-pivot.target', '0100644'),
                                ('service', '/etc/systemd/system/leon-pivot.service', '0100644')]:
        cmds += [f'write "{output/name}" "{target}"', f'set_inode_field "{target}" mode {mode}']
    put(output / 'populate.debugfs', '\n'.join(cmds) + '\n')
    with (output / 'debugfs.log').open('w') as log:
        subprocess.run(['debugfs', '-w', '-f', str(output / 'populate.debugfs'), str(image)], stdout=log, stderr=subprocess.STDOUT, check=True)
    extra_sources=[]
    for directory in EXTRA_FIXTURE_DIRECTORIES:
        assert re.fullmatch(r'/[A-Za-z0-9_./:-]+',directory) and '..' not in Path(directory).parts
        commands=[]
        for parent in [*reversed(list(Path(directory).parents)[:-1]),Path(directory)]:
            commands += [f'mkdir "{parent}"',f'set_inode_field "{parent}" mode 040755',f'set_inode_field "{parent}" uid 0',f'set_inode_field "{parent}" gid 0']
        script=output/'extra-directories.debugfs';put(script,'\n'.join(commands)+'\n')
        with (output/'extra-directories.log').open('a') as log:
            subprocess.run(['debugfs','-w','-f',str(script),str(image)],stdout=log,stderr=subprocess.STDOUT,check=True)
    for number,row in enumerate(EXTRA_FIXTURE_FILES):
        source=Path(row['source']);target=row['target'];mode=row['mode']
        assert source.is_file() and not source.is_symlink() and sha(source)==row['sha256']
        assert re.fullmatch(r'/[A-Za-z0-9_./:-]+',target) and '..' not in Path(target).parts
        assert isinstance(mode,int) and mode in [0o600,0o644,0o755]
        assert row['placement'] in ['ubuntu','firmware']
        forbidden = {'/sbin/init','/usr/lib/systemd/systemd','/etc/leon/root-generation',
                     '/usr/libexec/leon-lab/ubuntu-init','/usr/libexec/leon-boot/trial-guardian'}
        assert target not in forbidden,target
        extra_sources.append(dict(row))
        if row['placement']!='ubuntu':continue
        parents=list(Path(target).parents)[:-1]
        commands=[]
        for parent in reversed(parents):
            commands += [f'mkdir "{parent}"',f'set_inode_field "{parent}" mode 040755']
        commands += [f'rm "{target}"',f'write "{source.resolve()}" "{target}"',f'set_inode_field "{target}" mode {oct(stat.S_IFREG|mode)[2:]}',f'set_inode_field "{target}" uid 0',f'set_inode_field "{target}" gid 0']
        script=output/f'extra-{number}.debugfs';put(script,'\n'.join(commands)+'\n')
        with (output/f'extra-{number}.log').open('w') as log:
            subprocess.run(['debugfs','-w','-f',str(script),str(image)],stdout=log,stderr=subprocess.STDOUT,check=True)
        restored=output/f'extra-{number}.readback'
        subprocess.run(['debugfs','-R',f'dump "{target}" "{restored}"',str(image)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        assert sha(restored)==row['sha256'],target
    with (output / 'e2fsck.log').open('w') as log:
        subprocess.run(['e2fsck', '-f', '-n', str(image)], stdout=log, stderr=subprocess.STDOUT, check=True)
    if partitioned:
        filesystem = image
        image = output / 'ubuntu-disk.img'
        sectors = filesystem.stat().st_size // 512
        with image.open('xb') as stream:
            stream.truncate((partition_start + sectors + 2048) * 512)
        layout = f'label: gpt\nunit: sectors\n11 : start={partition_start}, size={sectors}, type=L, name="ubuntu-lab"\n'
        with (output / 'sfdisk.log').open('w') as log:
            subprocess.run(['sfdisk', '--no-reread', '--no-tell-kernel', str(image)], input=layout, text=True, stdout=log, stderr=subprocess.STDOUT, check=True)
        table = json.loads(subprocess.check_output(['sfdisk', '--json', str(image)], text=True))
        partitions = table['partitiontable']['partitions']
        assert len(partitions) == 1 and partitions[0]['node'].endswith('11')
        assert (partitions[0]['start'], partitions[0]['size']) == (partition_start, sectors)
        with image.open('r+b') as target, filesystem.open('rb') as source:
            target.seek(partition_start * 512)
            shutil.copyfileobj(source, target, 1024 * 1024)
        put(output / 'sfdisk.json', json.dumps(table, indent=2) + '\n')
    fw = output / 'firmware'
    for name in ['dev', 'proc', 'sys', 'run', 'leon-newroot', 'etc', 'sbin', 'lab-store']:
        (fw / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'build/busybox', fw / 'busybox')
    (fw / 'busybox').chmod(0o755)
    shutil.copyfile(helperdir / 'ubuntu-root-init', fw / 'sbin/init')
    (fw / 'sbin/init').chmod(0o755)
    fallback = FALLBACK
    if guardian_required:
        fallback = fallback.replace('echo LAB_VENDOR_FALLBACK_PID1_SQUASHFS_PASS',
                                    'echo fixture > /run/leon-vendor-executed\necho LAB_VENDOR_FALLBACK_PID1_SQUASHFS_PASS')
    put(fw / 'sbin/rc', fallback, 0o755)
    put(fw / 'etc/vendor-marker', 'untouched-vendor-root\n')
    fsck = FSCK
    private_manifest = None
    if args.boot_fsck_label:
        assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.boot_fsck_label)
        private_dir = ROOT / 'build/ubuntu26-boot-fsck' / args.boot_fsck_label
        private_manifest = json.loads((private_dir / 'manifest.json').read_text())
        assert private_manifest['status'] == 'built' and private_manifest['device'] == helper['policy']['device']
        for name, identity in private_manifest['payload'].items():
            assert sha(private_dir / 'stage' / name) == identity['sha256']
            assert (private_dir / 'stage' / name).stat().st_mode & 0o777 == int(identity['mode'], 8)
        shutil.copytree(private_dir / 'stage', fw, dirs_exist_ok=True)
        # Deliberately unusable old-loader sentinel: the native e2fsck must not
        # use PT_INTERP, ld.so.cache or any stock root library/config path.
        put(fw / 'lib/ld-linux-aarch64.so.1', 'ORIGINAL_STOCK_LOADER_SENTINEL\n', 0o755)
        put(fw / 'etc/e2fsck.conf', 'INVALID_STOCK_CONFIG_MUST_NOT_BE_READ\n')
        closure = private_manifest['closure']
        invoke = r'''set +e
/usr/libexec/leon-boot/fsck --version
test "$?" = 64 || exit 90
/usr/libexec/leon-boot/fsck -p /dev/loop0
test "$?" = 64 || exit 91
set -e
if [ "$(/busybox cat /run/scenario)" = fsck-private-missing ]; then
 /busybox mount -t tmpfs -o mode=0755 tmpfs /usr/libexec/leon-boot/lib
fi
LD_PRELOAD=/invalid/must-not-load.so LD_LIBRARY_PATH=/invalid E2FSCK_CONFIG=/etc/e2fsck.conf /usr/libexec/leon-boot/fsck "$@"
test "$(/busybox cat /lib/ld-linux-aarch64.so.1)" = ORIGINAL_STOCK_LOADER_SENTINEL
echo LAB_PRIVATE_FSCK_CLOSURE_PASS'''
        fsck = fsck.replace('/usr/sbin/e2fsck "$@"', invoke)
    else:
        closure = copy_elf_closure(base / 'stage', fw, '/usr/sbin/e2fsck')
    if partitioned:
        fsck = fsck.replace('/dev/loop1', '/dev/loop1p11')
    put(fw / 'usr/libexec/leon-lab/fsck', fsck, 0o755)
    guardian_input = None
    if guardian_required:
        if args.guardian_candidate_label:
            assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.guardian_candidate_label)
            guarddir = ROOT / 'build/asus-trial-guard' / args.guardian_candidate_label
            guardbinary = guarddir / 'guardian-candidate'
            guardmeta = json.loads((guarddir / 'manifest.json').read_text())
            assert guardmeta['status'] == 'built_mock_process_tests_passed'
            assert guardmeta['production_gate_enabled'] is False
            assert sha(guardbinary) == guardmeta['outputs']['guardian-candidate']
            guardian_input = {'role': 'real_gate_closed_guardian', 'manifest_sha256': sha(guarddir / 'manifest.json')}
        else:
            guardbinary = helperdir / 'root-guardian-mock'
            assert sha(guardbinary) == helper['outputs']['root-guardian-mock']
            guardian_input = {'role': 'protocol_mock_without_hardware'}
        assert 'INTERP' not in subprocess.check_output(['readelf', '-l', str(guardbinary)], text=True)
        guardian_input.update(path=str(guardbinary.relative_to(ROOT)), sha256=sha(guardbinary))
        destination = fw / 'usr/libexec/leon-boot/trial-guardian'
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(guardbinary, destination)
        destination.chmod(0o755)
    for row in extra_sources:
        if row['placement']!='firmware':continue
        target=fw/row['target'].lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
        assert not target.is_symlink()
        shutil.copyfile(row['source'],target);target.chmod(row['mode'])
    # Builder umask may be 0002; every immutable trusted parent must be 0755.
    for directory in [fw, *[path for path in fw.rglob('*') if path.is_dir()]]:
        directory.chmod(0o755)
    squash = output / 'firmware.sqfs'
    with (output / 'mksquashfs.log').open('w') as log:
        subprocess.run(['mksquashfs', str(fw), str(squash), '-noappend', '-all-root', '-comp', 'zstd', '-Xcompression-level', '8', '-no-progress'], stdout=log, stderr=subprocess.STDOUT, check=True)
    # Marker mutation is guest-only before the bootstrap mounts the volume.
    early = EARLY.replace(' bad-generation)\n', ' bad-generation|bad-root-mode|bad-init-parent|symlink-init-parent|loader-error|exec-error)\n').replace(
        '  echo invalid-generation > /scratch/etc/leon/root-generation\n',
        '  case "$scenario" in\n   bad-generation) echo invalid-generation > /scratch/etc/leon/root-generation;;\n   bad-root-mode) $B chmod 0777 /scratch;;\n   bad-init-parent) $B chmod 0777 /scratch/usr/libexec;;\n   symlink-init-parent) $B mv /scratch/usr/libexec/leon-lab /scratch/usr/libexec/leon-pivot-alt; $B ln -s /usr/libexec/leon-pivot-alt /scratch/usr/libexec/leon-lab;;\n   *) echo fixture > "/scratch/etc/leon/$scenario";;\n  esac\n')
    if private_manifest:
        early = early.replace('case "$scenario" in positive|', 'case "$scenario" in fsck-private-missing|positive|')
    guardian_scenarios = ['guardian-refused', 'guardian-prearm-hang', 'guardian-postarm-hang',
                          'guardian-postarm-dies', 'guardian-bad-nonce', 'guardian-abort-failure', 'guardian-aborted-alive']
    if guardian_required:
        early = early.replace('case "$scenario" in positive|', 'case "$scenario" in ' + '|'.join(guardian_scenarios) + '|positive|')
        # Abort failures must occur after a successful loader preflight and pivot.
        early = early.replace(' bad-generation|bad-root-mode|', ' guardian-abort-failure|guardian-aborted-alive|bad-generation|bad-root-mode|')
        early = early.replace('   *) echo fixture >', '   guardian-abort-failure|guardian-aborted-alive) echo fixture > /scratch/etc/leon/exec-error;;\n   *) echo fixture >')
    if partitioned:
        early = early.replace('/dev/loop1', '/dev/loop1p11').replace('losetup /dev/loop1p11 ', 'losetup /dev/loop1 ')
        early = early.replace('seek=1128 ', 'seek=' + str(partition_start * 512 + 1128) + ' ')
        early = early.replace('case "$scenario" in fsck-private-missing|', 'case "$scenario" in bad-start|fsck-private-missing|') if private_manifest else early.replace('case "$scenario" in positive|', 'case "$scenario" in bad-start|positive|')
        early = early.replace('case "$scenario" in\n bad-generation', 'echo LAB_REAL_GPT_PARTITION_START_$(/busybox cat /sys/dev/block/7:27/start)\ncase "$scenario" in\n bad-generation')
    tmpfs_mib = max(1536, (image.stat().st_size + 1024*1024-1) // (1024*1024) + 256)
    early = early.replace('size=1536m', f'size={tmpfs_mib}m')
    probe = helperdir / 'root-emergency-probe'
    if probe.exists():
        assert sha(probe) == helper['outputs']['root-emergency-probe']
        early = early.replace('echo "$scenario" > /run/scenario', '/root-emergency-probe\necho "$scenario" > /run/scenario')
    put(output / 'early-init', early, 0o755)
    entries = [(n, stat.S_IFDIR | 0o755, b'', 0, 0) for n in ['dev', 'proc', 'sys', 'run', 'firmware', 'scratch']]
    entries += [('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1),
                ('busybox', stat.S_IFREG | 0o755, ROOT / 'build/busybox', 0, 0),
                ('init', stat.S_IFREG | 0o755, early.encode(), 0, 0),
                ('firmware.sqfs', stat.S_IFREG | 0o600, squash, 0, 0),
                ('ubuntu.ext4', stat.S_IFREG | 0o600, image, 0, 0), ('TRAILER!!!', 0, b'', 0, 0)]
    if probe.exists(): entries.insert(-1, ('root-emergency-probe', stat.S_IFREG | 0o755, probe, 0, 0))
    initrd = output / 'initramfs.cpio.gz'
    offset = 0
    with initrd.open('wb') as file, gzip.GzipFile(fileobj=file, mode='wb', compresslevel=1, mtime=0) as gz:
        for ino, (name, mode, data, major, minor) in enumerate(entries, 1):
            size = data.stat().st_size if isinstance(data, Path) else len(data)
            name = name.encode() + b'\0'
            fields = [ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0, size, 0, 0, major, minor, len(name), 0]
            head = b'070701' + ''.join(f'{v:08x}' for v in fields).encode() + name
            gz.write(head); offset += len(head)
            pad = -offset % 4; gz.write(b'\0' * pad); offset += pad
            if isinstance(data, Path):
                with data.open('rb') as source: shutil.copyfileobj(source, gz, 1024*1024)
            else: gz.write(data)
            offset += size
            pad = -offset % 4; gz.write(b'\0' * pad); offset += pad
    record = {'status': 'prepared', 'helper_manifest_sha256': sha(helperdir / 'manifest.json'),
              'helper_source_sha256': helper['source_sha256'], 'helper_sha256': sha(helperdir / 'ubuntu-root-init'),
              'base_image_sha256': base_report['image_sha256'], 'image_sha256': sha(image), 'image_filename': image.name,
              'base_label': args.base_label, 'base_rootfs_tar_sha256': base_report['rootfs_tar_sha256'],
              'partitioned_loop': partitioned, 'partition_start_sector': partition_start if partitioned else None,
              'required_extra_kernel_arguments': 'loop.max_part=15' if partitioned else '',
              'squashfs_sha256': sha(squash), 'initramfs_sha256': sha(initrd),
              'e2fsck_closure': closure, 'builder_sha256': sha(Path(__file__)),
              'private_fsck_manifest_sha256': sha(private_dir / 'manifest.json') if private_manifest else None,
              'vendor_rc_is_test_double': True, 'board_trial_or_flash_accepted': False,
              'scenarios': ['positive', 'bad-uuid', 'bad-size', 'bad-generation', 'bad-root-mode', 'bad-init-parent', 'symlink-init-parent', 'owned-mounts', 'fsck-reboot', 'fsck-error', 'fsck-timeout', 'mount-error', 'loader-error', 'exec-error']}
    if private_manifest:
        record['scenarios'].append('fsck-private-missing')
    record['guardian_required'] = guardian_required
    record['guardian_input'] = guardian_input
    if GUARDIAN_FIXTURE_ROLE:
        assert guardian_required and not args.guardian_candidate_label
        record['guardian_input']['role']=GUARDIAN_FIXTURE_ROLE
    record['extra_fixture_sources']=extra_sources
    record['extra_fixture_directories']=EXTRA_FIXTURE_DIRECTORIES
    record['health_identity_fixture'] = helper.get('health_identity_fixture')
    record['emergency_route_probe_sha256'] = sha(probe) if probe.exists() else None
    if guardian_required:
        record['scenarios'] = ['positive', 'exec-error', *guardian_scenarios]
        if args.guardian_candidate_label:
            record['scenarios'] = ['guardian-refused']
        if helper.get('guardian_exec_failure_fixture'):
            record['scenarios'] = ['guardian-refused']
            record['guardian_exec_failure_fixture'] = True
    if partitioned and partition_start != helper['policy']['start_sector']:
        record['scenarios'] = ['bad-start']
    if FIXTURE_SCENARIOS is not None:record['scenarios']=list(FIXTURE_SCENARIOS)
    (output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': 'prepared', 'initramfs': str(initrd), 'sha256': record['initramfs_sha256']}, indent=2))

if __name__ == '__main__':
    main()

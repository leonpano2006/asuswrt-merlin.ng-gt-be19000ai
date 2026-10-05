#!/usr/bin/env python3
"""Stage an immutable Ubuntu boot shim over the reviewed ASUS fallback root.

This only writes a new local SquashFS and an unapplied JFFS hook candidate.
It does not sign a firmware, select a boot slot, or contact a device. Final
QEMU and physical recovery gates are deliberately separate from staging.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

from kernel9_ui1 import inventory
import ubuntu26_bootstrap_reuse as reuse_gate

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/rootfs-kernel9-ui1.zstd.squashfs'
BASE_SHA = 'beac450ebc9d71192a421cf6c2cb8e06ef6997b6e11b2ea854c3ef49e20dc766'
KERNEL_SHA = '4a15601eada042576aed2a3680dcc48e9228eea70f70c478840767aaa89a9f8e'
RELEASE = 'kernel10-ubuntu26-trial'
PREFIX = 'usr/libexec/leon-boot'
OLD_START_SHA = 'f54313162e5a4ff518e92500e646da56fd4c0600bbb8a7866c88048fc6146408'
POLICY = ROOT / 'configs/ubuntu26/root-init-device-policy.json'
BOOT_MOUNTPOINTS = ('dev', 'proc', 'sys', 'run', 'leon-newroot')


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def read(path):
    return json.loads(path.read_text())


def verified(path, digest):
    assert path.is_file() and not path.is_symlink(), path
    assert re.fullmatch('[0-9a-f]{64}', digest) and sha(path) == digest, path
    return path


def static_arm64(path):
    elf = subprocess.check_output(['readelf', '-h', '-l', '-d', str(path)], text=True)
    assert 'AArch64' in elf and 'ELF64' in elf
    assert 'INTERP' not in elf and '(NEEDED)' not in elf


def relative_input(row):
    path = Path(row['path'])
    assert not path.is_absolute() and '..' not in path.parts
    return verified(ROOT / path, row['sha256'])


def verify_packed_mountpoints(image):
    """Check the actual packed inode table, not only an extracted build tree."""
    listing = subprocess.check_output(['unsquashfs', '-lln', str(image)], text=True)
    result = {}
    for name in BOOT_MOUNTPOINTS:
        lines = [line for line in listing.splitlines()
                 if line.endswith(' squashfs-root/' + name)]
        assert len(lines) == 1, f'Missing/ambiguous boot mountpoint: /{name}'
        fields = lines[0].split()
        assert fields[:2] == ['drwxr-xr-x', '0/0'], (name, lines[0])
        result['/' + name] = {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755'}
    return result


def main():
    if not __debug__:
        raise RuntimeError('Python optimization is not supported')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--root-init-manifest', type=Path, required=True)
    parser.add_argument('--guardian-manifest', type=Path, required=True)
    parser.add_argument('--fsck-manifest', type=Path, required=True)
    parser.add_argument('--bootstrap-reuse-receipt', type=Path,
                        help='Narrow explicit UUID/diagnostic PID1 successor reuse; does not skip new handoff proof')
    parser.add_argument('--guardian-gate', choices=['closed', 'enabled'], default='closed',
                        help='Require the explicit guardian build gate; enabling staging is not flash acceptance')
    args = parser.parse_args()
    assert re.fullmatch('[A-Za-z0-9_-]+', args.label)
    verified(BASE, BASE_SHA)
    verified(ROOT / 'build/Image-v10', KERNEL_SHA)
    policy = read(POLICY)
    assert policy['scope'] == 'candidate-device-policy' and not policy['flash_accepted']
    assert policy['guardian']['required'] and not policy['emergency_fault_sink']

    init = read(args.root_init_manifest)
    assert init['status'] == 'built' and init['policy'] == policy
    assert init['policy_file_sha256'] == sha(POLICY)
    assert init['guardian_required'] and init['static_no_interpreter']
    assert not init['emergency_fault_sink'] and not init['guardian_exec_failure_fixture']
    assert not init['mock_guardian_source_sha256']
    assert init['source_sha256'] == sha(ROOT / 'scripts/asus-integration/ubuntu-root-init.c')
    assert init['trial_handoff_sha256'] == sha(ROOT / 'scripts/asus-integration/trial-guard/trial-handoff.h')
    init_program = verified(args.root_init_manifest.parent / 'ubuntu-root-init', init['outputs']['ubuntu-root-init'])
    static_arm64(init_program)

    # Production build receipts must explicitly distinguish the real adapter
    # from mock watchdog and fault-sink binaries. A closed deployment gate is
    # expected at this stage and is not permission to flash the output.
    guardian = read(args.guardian_manifest)
    assert guardian['status'] == 'built'
    assert guardian['scope'] == 'candidate-device-policy'
    assert guardian['hardware_adapter'] is True and guardian['fixture'] is False
    assert guardian['deployment_gate_enabled'] is (args.guardian_gate == 'enabled')
    reuse = None
    if args.bootstrap_reuse_receipt:
        reuse = reuse_gate.validate_stager(args.bootstrap_reuse_receipt.resolve(),
                                          args.root_init_manifest.resolve(), args.guardian_manifest.resolve())
    else:
        assert guardian['root_init_policy_sha256'] == sha(POLICY)
    assert guardian['trial_handoff_sha256'] == init['trial_handoff_sha256']
    guard_program = relative_input(guardian['executable'])
    static_arm64(guard_program)

    fsck = read(args.fsck_manifest)
    assert fsck['status'] == 'built' and fsck['scope'] == 'candidate-device-policy'
    assert fsck['device'] == policy['device'] and fsck['static_wrapper_no_interpreter']
    assert fsck['preserves_stock_arm64_loader'] and not fsck['flash_accepted']
    assert fsck['source_sha256'] == sha(ROOT / 'scripts/asus-integration/boot-fsck.c')
    for name, row in fsck['payload'].items():
        assert name.startswith(PREFIX + '/') and '..' not in Path(name).parts
        verified(args.fsck_manifest.parent / 'stage' / name, row['sha256'])

    modules_path = ROOT / 'reports/kernel10/modules-stage.json'
    modules = read(modules_path)
    assert modules['module_count'] == 181
    module_root = ROOT / modules['root'] / 'lib/modules/4.19.294'
    for name, digest in modules['file_sha256'].items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        verified(module_root / name, digest)

    out = ROOT / 'build/ubuntu26-bootstrap' / args.label
    out.mkdir(parents=True, exist_ok=False)
    stage = out / 'root'
    subprocess.run(['unsquashfs', '-no-progress', '-processors', '4', '-d', str(stage), str(BASE)], check=True)
    before = inventory(stage)
    base_modules = {n.removeprefix('lib/modules/4.19.294/'): r['sha256'] for n, r in before.items()
                    if n.startswith('lib/modules/4.19.294/') and 'sha256' in r}
    assert base_modules.keys() == modules['file_sha256'].keys()
    assert before['sbin/init']['target'] == 'rc'
    assert before['sbin/rc']['sha256'] == '9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814'
    assert before['usr/libexec/be19000ai-candidate/start-services.sh']['sha256'] == OLD_START_SHA
    assert PREFIX not in before and 'leon-newroot' not in before
    allowed = {'sbin/init', 'usr/libexec', 'usr/libexec/be19000ai-candidate/manifest.json',
               'usr/libexec/be19000ai-candidate/start-services.sh', 'leon-newroot', 'run'}

    def copy(source, target, mode):
        destination = stage / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        assert not destination.is_symlink(), target
        shutil.copyfile(source, destination)
        destination.chmod(mode)
        allowed.add(target)

    # Existing vendor /usr/libexec was0775. The immutable helpers deliberately
    # reject group-writable parents, even on SquashFS. Only this known parent
    # changes mode; vendor ELF, stock loader and all Web resources stay exact.
    assert before['usr/libexec']['mode'] == 0o775
    (stage / 'usr/libexec').chmod(0o755)
    (stage / 'sbin/init').unlink()
    copy(init_program, 'sbin/init', 0o755)
    (stage / 'leon-newroot').mkdir(mode=0o755)
    # The vendor root has no /run. PID1 must mount tmpfs before it can write
    # there, and cannot create this directory on an immutable SquashFS root.
    # Never replace a vendor symlink/non-directory with a guessed mountpoint.
    if 'run' not in before:
        (stage / 'run').mkdir(mode=0o755)
    for name in BOOT_MOUNTPOINTS:
        path = stage / name
        assert path.is_dir() and not path.is_symlink(), name
        assert stat.S_IMODE(path.stat().st_mode) == 0o755, name
    for name, row in fsck['payload'].items():
        copy(args.fsck_manifest.parent / 'stage' / name, name, int(row['mode'], 8))
    copy(guard_program, PREFIX + '/trial-guardian', 0o755)
    for path in (stage / PREFIX).rglob('*'):
        if path.is_dir():
            path.chmod(0o755)
            allowed.add(str(path.relative_to(stage)))
    (stage / PREFIX).chmod(0o755)
    allowed.add(PREFIX)

    meta_path = stage / 'usr/libexec/be19000ai-candidate/manifest.json'
    meta = read(meta_path)
    assert meta['release'] == 'kernel9-ui1' and meta['kernel'] == '4.19.294 #9'
    meta.update(release=RELEASE, kernel='4.19.294 #10',
                fallback_userspace='reviewed ASUS kernel9-ui1 payload; rc and original loader retained',
                ubuntu_generation=policy['generation'].rstrip('\n'))
    meta['features'] += ['pidfd-process-handles', 'pcan-usb-fd-new-mcu', 'guarded-ubuntu26-root-pivot']
    meta_path.write_text(json.dumps(meta, indent=2) + '\n')
    meta_path.chmod(0o644)
    start = stage / 'usr/libexec/be19000ai-candidate/start-services.sh'
    content = start.read_text()
    assert content.count('kernel9-ui1') == 1
    start.write_text(content.replace('kernel9-ui1', RELEASE))
    start.chmod(0o755)
    subprocess.run(['sh', '-n', str(start)], check=True)

    boot_receipt = {'schema_version': 1, 'release': RELEASE,
                    'root_policy': policy, 'kernel_sha256': KERNEL_SHA,
                    'root_init_sha256': sha(init_program), 'guardian_sha256': sha(guard_program),
                    'root_init_manifest_sha256': sha(args.root_init_manifest),
                    'guardian_manifest_sha256': sha(args.guardian_manifest),
                    'private_fsck_manifest_sha256': sha(args.fsck_manifest),
                    'guardian_deployment_gate_enabled': guardian['deployment_gate_enabled'],
                    'trial_only': True, 'automatic_boot_commit': False}
    if reuse:
        boot_receipt['bootstrap_evidence_reuse_sha256'] = sha(args.bootstrap_reuse_receipt)
    (stage / PREFIX / 'manifest.json').write_text(json.dumps(boot_receipt, indent=2) + '\n')
    (stage / PREFIX / 'manifest.json').chmod(0o644)
    allowed.add(PREFIX + '/manifest.json')
    for name, digest in modules['file_sha256'].items():
        rel = 'lib/modules/4.19.294/' + name
        if base_modules[name] != digest:
            copy(module_root / name, rel, before[rel]['mode'])
    after = inventory(stage)
    changes = [{'path': n, 'before': before.get(n), 'after': after.get(n)}
               for n in sorted(before.keys() | after.keys()) if before.get(n) != after.get(n)]
    assert {r['path'] for r in changes} <= allowed
    assert not (before.keys() - after.keys())
    assert before['sbin/rc'] == after['sbin/rc']
    assert before['lib/ld-linux-aarch64.so.1'] == after['lib/ld-linux-aarch64.so.1']
    assert all(before[n] == after[n] for n in before if n.startswith('www/'))
    assert all(after['lib/modules/4.19.294/' + n]['sha256'] == digest
               for n, digest in modules['file_sha256'].items())
    for path in [stage, stage / 'usr', stage / 'usr/libexec', stage / PREFIX, stage / PREFIX / 'lib']:
        assert path.is_dir() and not path.is_symlink() and not stat.S_IMODE(path.stat().st_mode) & 0o022

    # Exact old and new start entry hashes coexist so stock slot2/JFFS repairs
    # and earlier kernel trials remain usable. This file is only staged here.
    old_hook = ROOT / 'build/kernel9-ui1-services-start'
    hook = old_hook.read_text()
    assert hook.count(OLD_START_SHA) == 1
    hook = hook.replace('the three exact reviewed candidates', 'the exact reviewed candidates')
    hook = hook.replace(OLD_START_SHA, OLD_START_SHA + '|' + sha(start))
    hook_path = out / 'services-start.candidate'
    hook_path.write_text(hook)
    hook_path.chmod(0o755)
    subprocess.run(['sh', '-n', str(hook_path)], check=True)

    image = out / 'bootstrap.zstd.squashfs'
    subprocess.run(['mksquashfs', str(stage), str(image), '-noappend', '-all-root', '-comp', 'zstd',
                    '-Xcompression-level', '22', '-b', '524288', '-processors', '12', '-no-progress'], check=True)
    assert image.stat().st_size < 200 * 1024**2
    packed_mountpoints = verify_packed_mountpoints(image)
    report = {'schema_version': 1, 'status': 'staged_local_only', 'release': RELEASE,
              'builder_sha256': sha(Path(__file__)), 'base_rootfs_sha256': BASE_SHA,
              'kernel_sha256': KERNEL_SHA, 'root_policy_sha256': sha(POLICY),
              'inputs': boot_receipt, 'changed_entries': changes,
              'module_count': 181, 'module_inventory_sha256': sha(modules_path),
              'stock_rc_unchanged': True, 'stock_arm64_loader_unchanged': True,
              'reviewed_web_resources_unchanged': True,
              'rootfs': {'path': str(image.relative_to(ROOT)), 'sha256': sha(image), 'bytes': image.stat().st_size},
              'inventory': after,
              'packed_boot_mountpoints': packed_mountpoints,
              'unapplied_jffs_hook': {'path': str(hook_path.relative_to(ROOT)), 'sha256': sha(hook_path)},
              'qemu_validated': False, 'hardware_validated': False, 'flash_accepted': False,
              'device_modified': False, 'automatic_boot_commit': False,
              'limits': ['The retained ASUS root is only an early pre-systemd fallback.',
                         'Later failures rely on the guardian and stock slot2 bootloader fallback, still requiring board proof.',
                         'The final writable Ubuntu tar, deployment backup and exact firmware QEMU bindings remain separate gates.']}
    if reuse:
        report['bootstrap_evidence_reuse'] = reuse_gate.record(args.bootstrap_reuse_receipt)
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    if reuse:
        reuse_gate.validate_stage(args.bootstrap_reuse_receipt.resolve(), out / 'manifest.json',
                                  args.guardian_manifest.resolve())
    print(json.dumps({'status': report['status'], 'rootfs': report['rootfs'],
                      'changed_entries': len(changes), 'flash_accepted': False}, indent=2))


if __name__ == '__main__':
    main()

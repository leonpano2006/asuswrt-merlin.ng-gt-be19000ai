#!/usr/bin/env python3
"""Bind a final bootstrap to executed PID1 and real systemd handoff evidence."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def record(path):
    return {'path': str(path.resolve().relative_to(ROOT)), 'sha256': sha(path)}

def read(path): return json.loads(path.read_text())

def pinned(row):
    rel = Path(row['path'])
    assert not rel.is_absolute() and '..' not in rel.parts
    path = ROOT / rel
    assert path.is_file() and not path.is_symlink() and sha(path) == row['sha256'], path
    return path

def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    obj = importlib.util.module_from_spec(spec); spec.loader.exec_module(obj); return obj

def cpio_hashes(path):
    """Stream the actual compressed archive, including its embedded image."""
    rows = {}; offset = 0
    with gzip.open(path, 'rb') as f:
        while True:
            header = f.read(110); offset += len(header)
            assert len(header) == 110 and header[:6] == b'070701'
            fields = [int(header[6+i*8:14+i*8], 16) for i in range(13)]
            mode, size, namesize = fields[1], fields[6], fields[11]
            assert 1 < namesize < 512 and size < 3 * 1024**3
            raw = f.read(namesize); offset += namesize
            assert len(raw) == namesize and raw[-1:] == b'\0' and b'\0' not in raw[:-1]
            name = raw[:-1].decode()
            assert name not in rows and not name.startswith('/') and '..' not in Path(name).parts
            pad = -offset % 4; assert f.read(pad) == b'\0' * pad; offset += pad
            digest = hashlib.sha256(); remaining = size
            while remaining:
                block = f.read(min(1024**2, remaining)); assert block
                digest.update(block); remaining -= len(block)
            offset += size
            pad = -offset % 4; assert f.read(pad) == b'\0' * pad; offset += pad
            if name == 'TRAILER!!!':
                assert size == 0 and not f.read(1)
                return rows
            rows[name] = {'sha256': digest.hexdigest(), 'mode': mode, 'bytes': size}
            assert len(rows) <= 32

def qemu(fixture_path, result_path, mode, frozen_regression=False):
    f = read(fixture_path); r = read(result_path)
    assert f['mode'] == mode and f['schema_version'] == 1
    if frozen_regression:
        # Reuse only the already validated missing-/run regression. Its builder
        # predates the new positive trace assertion; do not rewrite old receipts.
        baseline = ROOT / 'reports/ubuntu26/bootstrap-pid1-handoff-device-v3.json'
        assert sha(baseline) == '293baa22b62014831fb23ee20937320dae2421bf8547763b6072133ae9bed635'
        previous = read(baseline)['regression']
        assert record(fixture_path) == previous['fixture']
        assert record(result_path) == previous['result']
        assert mode == 'exact-entry'
    else:
        assert pinned(f['builder']) == ROOT / 'scripts/prepare-ubuntu26-bootstrap-handoff-qemu.py'
    stage_path = pinned(f['stage_manifest']); stage = read(stage_path)
    image = pinned(f['executed_squashfs']); production = pinned(f['production_squashfs'])
    assert production == ROOT / stage['rootfs']['path'] and sha(production) == stage['rootfs']['sha256']
    assert f['directory_inodes_preserved'] and not f['firmware_run_manufactured_by_fixture']
    assert not f['hardware_emulated'] and not f['physical_trial_accepted']
    assert f['runtime_bind_overlays'] == ['/sbin/rc -> RAM failure sink']
    assert r['guest_complete'] and r['init_reached'] and not r['panic']
    assert r['stop_reason'] in ['qemu_exit', 'complete'] and r['exit_code'] in [0, -15]
    assert r['kernel_sha256'] == f['kernel_sha256'] == stage['kernel_sha256'] == sha(ROOT / 'build/Image-v10')
    cmd = r['command']; assert cmd[cmd.index('-nic')+1] == 'none'
    assert '-drive' not in cmd and '-device' not in cmd
    assert Path(cmd[cmd.index('-kernel')+1]).resolve() == ROOT / 'build/Image-v10'
    initrd = pinned(f['initramfs'])
    assert Path(cmd[cmd.index('-initrd')+1]).resolve() == initrd
    assert r['initramfs_sha256'] == sha(initrd)
    entries = cpio_hashes(initrd)
    assert entries['firmware.sqfs']['sha256'] == sha(image)
    assert entries['firmware.sqfs']['bytes'] == image.stat().st_size
    assert entries['init']['sha256'] == sha(fixture_path.parent / 'early-init')
    assert entries['fallback']['sha256'] == sha(fixture_path.parent / 'fallback')
    assert stat.S_ISREG(entries['firmware.sqfs']['mode'])
    log = result_path.with_name('serial.log'); assert sha(log) == r['log_sha256']
    text = log.read_text(errors='replace')
    assert not re.search(r'BUG:|WARNING: CPU:|Oops:|kernel BUG|Unable to handle kernel|Bad page state|LAB_BOOTSTRAP_.*(?:FAILED|MISSING)', text)
    if mode == 'exact-entry':
        assert image == production and not f['firmware_changed_paths']
        assert 'QEMU_EXACT_BOOTSTRAP_COMPLETE' in text
        assert 'LAB_EXACT_BOOTSTRAP_PID1_EXEC' in text and 'LAB_EXACT_BOOTSTRAP_VENDOR_SINK' in text
    else:
        assert set(f['firmware_changed_paths']) == {'sbin/init', 'usr/libexec/leon-boot/fsck', 'usr/libexec/leon-boot/trial-guardian'}
        helper_path = pinned(f['loop_helper_manifest']); helper = read(helper_path)
        assert helper['source_sha256'] == sha(ROOT / 'scripts/asus-integration/ubuntu-root-init.c')
        assert helper['boot_diagnostics_sha256'] == sha(ROOT / 'scripts/asus-integration/boot-diagnostics/boot-diagnostics.h')
        assert helper['diagnostic_reader_sha256'] == sha(ROOT / 'scripts/asus-integration/boot-diagnostics/reader.c')
        assert helper['policy_file_sha256'] == sha(ROOT / 'configs/ubuntu26/root-init-qemu-bootstrap-policy.json')
        diagnostic = f['diagnostic_fixed_slots']
        assert diagnostic['path'] == '/etc/leon/boot-diagnostics' and diagnostic['bytes'] == 16384
        assert diagnostic['mode'] == 0o600 and diagnostic['uid'] == diagnostic['gid'] == 0
        assert diagnostic['producer'] == 0 and diagnostic['preinitialized_zero'] and diagnostic['producer1_must_remain_empty']
        assert diagnostic['build_id'] == helper['diagnostic_build_id']
        assert diagnostic['common_header_sha256'] == helper['boot_diagnostics_sha256']
        assert diagnostic['reader_source_sha256'] == helper['diagnostic_reader_sha256']
        pinned(diagnostic['payload_crc_reader'])
        assert helper['guardian_required'] and helper['emergency_fault_sink']
        assert helper['policy']['scope'] == 'offline-qemu-fixture'
        assert helper['policy']['device'] == '/dev/loop1'
        assert entries['ubuntu.ext4']['sha256'] == sha(pinned(f['ubuntu_fixture']))
        inv = module('handoff_inventory', 'kernel9_ui1.py').inventory(fixture_path.parent / 'firmware')
        changes = {name for name in inv.keys() | stage['inventory'].keys() if inv.get(name) != stage['inventory'].get(name)}
        assert changes == set(f['firmware_changed_paths'])
        assert inv['sbin/init']['sha256'] == helper['outputs']['ubuntu-root-init']
        assert inv['usr/libexec/leon-boot/trial-guardian']['sha256'] == helper['outputs']['root-guardian-mock']
        assert 'LEON_ROOT_FALLBACK' not in text and 'LAB_EXACT_BOOTSTRAP_VENDOR_SINK' not in text
        for marker in ['LAB_BOOTSTRAP_REAL_SQUASHFS_EXT4_HANDOFF', 'LAB_GUARDIAN_ARM_PERMISSION_RECEIVED',
                       'LAB_GUARDIAN_CLOEXEC_REAL_SYSTEMD_SURVIVAL_PASS', 'LAB_BOOTSTRAP_GUARDIAN_HANDOFF_SYSTEMD_PASS',
                       'LAB_BOOTSTRAP_OLDROOT_READONLY_PASS', 'LAB_BOOTSTRAP_SYSTEMD_KMSG_PASS',
                       'LAB_BOOTSTRAP_PERSISTENT_TRACE_PASS', 'QEMU_BOOTSTRAP_HANDOFF_COMPLETE']:
            assert marker in text, marker
        assert 'LAB_BOOTSTRAP_FIXED_TRACE_CRC_BUILD_SEQUENCE_PASS' in text
    return f, stage_path, text, {'fixture': record(fixture_path), 'result': record(result_path), 'log': record(log),
                               'elapsed_seconds': r['elapsed_seconds'], 'initramfs': record(initrd)}

def evaluate(stage_path, entry_fixture, entry_result, handoff_fixture, handoff_result, regression_fixture, regression_result):
    if not __debug__: raise RuntimeError('Python optimization is not supported')
    stage = read(stage_path)
    assert stage['status'] == 'staged_local_only'
    assert stage['builder_sha256'] == sha(ROOT / 'scripts/stage-ubuntu26-bootstrap.py')
    stager = module('handoff_stager', 'stage-ubuntu26-bootstrap.py')
    mountpoints = stager.verify_packed_mountpoints(ROOT / stage['rootfs']['path'])
    assert stage['packed_boot_mountpoints'] == mountpoints
    e, es, et, er = qemu(entry_fixture, entry_result, 'exact-entry')
    h, hs, ht, hr = qemu(handoff_fixture, handoff_result, 'loop-handoff')
    n, ns, nt, nr = qemu(regression_fixture, regression_result, 'exact-entry', frozen_regression=True)
    assert es == stage_path.resolve()
    rebase = None
    if hs != es:
        # The positive fixture replaces these executables with exact loop-policy
        # init/fsck/protocol-mock bytes. A new guardian is tested independently.
        # Compare every remaining payload byte; only the non-executed generated
        # receipt may differ. Retain the actual fixture's original image scope.
        old = read(hs)
        allowed = {'sbin/init', 'usr/libexec/leon-boot/trial-guardian', 'usr/libexec/leon-boot/manifest.json'}
        differences = {name for name in old['inventory'].keys() | stage['inventory'].keys()
                       if old['inventory'].get(name) != stage['inventory'].get(name)}
        assert differences <= allowed and differences
        for key in ['kernel_sha256', 'module_inventory_sha256', 'module_count', 'base_rootfs_sha256']:
            assert stage[key] == old[key], key
        for key in ['private_fsck_manifest_sha256', 'kernel_sha256', 'trial_only', 'automatic_boot_commit']:
            assert stage['inputs'][key] == old['inputs'][key], key
        assert stage['root_policy_sha256'] == old['root_policy_sha256']
        reuse = module('handoff_rebase_reuse', 'ubuntu26_bootstrap_reuse.py')
        reuse.validate_stage(pinned(stage['bootstrap_evidence_reuse']), es,
                             pinned(read(pinned(stage['bootstrap_evidence_reuse']))['guardian']))
        rebase = {'actual_fixture_stage': record(hs), 'candidate_stage': record(es),
                  'inventory_differences': sorted(differences),
                  'scope': 'Exact current root-init source/fixed-slot writer handoff; guardian bytes replaced by protocol mock, separately covered by new full-loop proof. Only generated boot receipt remains different in executed fixture.'}
    assert ns != es and read(ns)['inventory'].get('run') is None
    assert 'LEON_ROOT_FALLBACK stage=mounts code=22' in nt
    assert 'LEON_ROOT_UBUNTU_EXEC' not in nt
    assert 'LEON_ROOT_FALLBACK stage=identity code=22' in et
    assert 'LEON_ROOT_FALLBACK stage=mounts' not in et
    kernel_ring = et.split('LAB_EXACT_BOOTSTRAP_KMSG_BEGIN', 1)[1].split('LAB_EXACT_BOOTSTRAP_KMSG_END', 1)[0]
    for marker in ['LEON_ROOT_ENTER stage=mounts code=0', 'LEON_ROOT_ENTER stage=identity code=0',
                   'LEON_ROOT_FALLBACK stage=identity code=22']:
        assert marker in kernel_ring
    return {'schema_version': 1, 'status': 'bootstrap_pid1_and_handoff_validated', 'passed': True,
            'stage_manifest': record(stage_path), 'production_squashfs': e['production_squashfs'],
            'kernel_sha256': stage['kernel_sha256'], 'packed_mountpoints': mountpoints,
            'exact_production_pid1_passed_mounts': True, 'fallback_kernel_log_retained': True,
            'missing_run_regression_reproduced': True, 'real_systemd_handoff_passed': True,
            'exact_entry': er, 'loop_handoff': hr, 'regression': nr,
            'handoff_inventory_rebase': rebase,
            'validator': record(Path(__file__).resolve()), 'physical_trial_accepted': False,
            'hardware_watchdog_tested': False, 'automatic_boot_commit': False,
            'limits': ['Exact production image executes PID1 and refuses the absent BCM eMMC in QEMU virt.',
                       'Positive systemd handoff keeps all image directories and other payload bytes; exactly three regular files adapt PID1/fsck to loop storage and use a protocol-only guardian.',
                       'This proves the missing-mountpoint fix and boot packaging path; physical board and watchdog acceptance remain separate.']}

def revalidate_report(report_path, stage_path):
    saved = read(report_path)
    assert saved['stage_manifest'] == record(stage_path)
    f = saved['exact_entry']; h = saved['loop_handoff']; n = saved['regression']
    fresh = evaluate(stage_path, pinned(f['fixture']), pinned(f['result']), pinned(h['fixture']), pinned(h['result']),
                     pinned(n['fixture']), pinned(n['result']))
    assert fresh == saved, 'Bootstrap acceptance report differs from freshly validated evidence'
    return fresh

def main():
    if not __debug__: raise RuntimeError('Python optimization is not supported')
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['stage-manifest', 'entry-fixture', 'entry-result', 'handoff-fixture', 'handoff-result', 'regression-fixture', 'regression-result', 'output']:
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args(); assert not a.output.exists()
    r = evaluate(a.stage_manifest.resolve(), a.entry_fixture.resolve(), a.entry_result.resolve(), a.handoff_fixture.resolve(),
                 a.handoff_result.resolve(), a.regression_fixture.resolve(), a.regression_result.resolve())
    a.output.write_text(json.dumps(r, indent=2) + '\n')
    print(json.dumps({'passed': r['passed'], 'report': record(a.output)}, indent=2))

if __name__ == '__main__': main()

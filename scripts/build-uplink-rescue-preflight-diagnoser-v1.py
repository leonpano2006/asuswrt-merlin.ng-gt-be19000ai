#!/usr/bin/env python3
"""Source-bound fixed rescue metadata diagnoser; default is a read-only plan.

One future static compile requires the exact reviewed plan digest. No helper,
fixture, version probe, service, device or inherited installer is executed.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-uplink-rescue/install-v2'
BASE_SHA = '96d7ee155a4b6070d893aa47570dd2b971907c72fb9a60773b8bb3eded852406'
C = R / 'scripts/asus-integration/uplink-rescue/preflight-diagnoser-v1.c'
C_SHA = '3c7259612c521bc8b37251ed3cf61ae80a0587ccec7d2a32ff95f8f8844c42a5'
CLEAN = R / 'scripts/asus-integration/root-forensics/clean-only-v7/clean-superblock.h'
CLEAN_SHA = '651f5f73f1346c5dcb3f9da4b926b8984cede0da3c5de8afc1cdff174c67d527'
ENV = R / 'build/asus-native-build/v2/result.json'
ENV_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
OUT = R / 'build/asus-uplink-rescue/preflight-diagnoser-v1'
WORK = 'uplink-rescue-preflight-diagnoser-v1'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    assert path.is_file() and not path.is_symlink()
    return digest(path.read_bytes())


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def inventory(path):
    assert not any(p.is_symlink() for p in path.rglob('*'))
    return {p.relative_to(path).as_posix(): sha(p) for p in sorted(path.rglob('*')) if p.is_file()}


def once(value, before, after):
    assert value.count(before) == 1
    return value.replace(before, after, 1)


def prepare():
    for path, pin in [(BASE / 'manifest.json', BASE_SHA), (C, C_SHA), (CLEAN, CLEAN_SHA), (ENV, ENV_SHA)]:
        assert sha(path) == pin
    base = json.loads((BASE / 'manifest.json').read_text())
    assert base['compile_count'] == 1 and not base['installer_executed']
    assert len(base['source_inventory']) == 21 and inventory(BASE / 'source') == base['source_inventory']
    files = {p.relative_to(BASE / 'source').as_posix(): p.read_bytes()
             for p in sorted((BASE / 'source').rglob('*')) if p.is_file()}
    original = files['slot-device.c'].decode()
    before = ('if(!own || !allow_p11 || ++p11!=1 || strcmp(root,"/") || strcmp(target,mountpoint) ||\n'
              '               strcmp(type,"ext4") || !has_flag(flags,"rw") || !has_flag(super,"rw"))goto done;')
    after = before.replace('has_flag(flags,"rw")', 'has_flag(flags,"ro")').replace('has_flag(super,"rw")', 'has_flag(super,"ro")')
    # This exact full line appears only in the own-p11 branch. The separate
    # stock p7..p10 rw predicate and stock squashfs-root ro check are retained.
    readonly = once(original, before, after)
    assert once(readonly, after, before) == original
    files['slot-device.c'] = readonly.encode()
    files['preflight-diagnoser.c'] = C.read_bytes()
    files['clean-superblock.h'] = CLEAN.read_bytes()
    sources = {name: digest(raw) for name, raw in sorted(files.items())}
    assert set(name for name in base['source_inventory'] if sources[name] != base['source_inventory'][name]) == {'slot-device.c'}
    delta = ''.join(difflib.unified_diff(original.splitlines(True), readonly.splitlines(True),
                                        fromfile='frozen-install-v2/slot-device.c', tofile='readonly-diagnoser/slot-device.c'))
    worker = (BASE / 'build.sh').read_text()
    assert digest(worker.encode()) == base['compile_worker_sha256']
    assert worker.count(base['native_work_label']) == 3
    worker = worker.replace(base['native_work_label'], WORK)
    worker = once(worker, 'install.c slot-proof.c sha256.c -o install-additions',
                  'preflight-diagnoser.c slot-proof.c sha256.c -o preflight-diagnoser')
    worker = once(worker, 'readelf -h -l -d install-additions >elf.txt',
                  'readelf -h -l -d preflight-diagnoser >elf.txt')
    plan = {'schema': 1, 'status': 'fixed_rescue_readonly_preflight_diagnoser_compile_plan',
            'builder': ref(Path(__file__)), 'baseline_manifest': ref(BASE / 'manifest.json'),
            'baseline_installer': base['installer'], 'native_environment': ref(ENV),
            'diagnoser_source': ref(C), 'clean_predicate_source': ref(CLEAN),
            'output': OUT.relative_to(R).as_posix(), 'native_work_label': WORK,
            'source_inventory': sources, 'frozen_source_count': 21,
            'frozen_sources_unchanged': {name: pin for name, pin in base['source_inventory'].items() if name != 'slot-device.c'},
            'sole_frozen_source_delta': {'path': 'slot-device.c', 'before': before, 'after': after,
                'reverse_equals_frozen_source': True, 'scope': 'own p11 mount flags and super flags rw->ro only'},
            'source_delta_sha256': digest(delta.encode()), 'compile_worker_sha256': digest(worker.encode()),
            'compiler_and_flags_inherited_exactly': True, 'compiler_version_probes': 0,
            'cli': '--inspect-fixed-uplink-rescue-preflights', 'payload_count': 7, 'link_count': 1,
            'actual_preflight_functions': ['target_preflight', 'candidate_link_check'],
            'included_installer_entrypoint_never_called': True,
            'preserve_identity_provision_publication_functions_never_called': True,
            'two_full1024_clean_byte_equal_checks_before_mount': True,
            'readonly_mount': 'MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC; ext4 noload',
            'full_recheck_before_and_after_mount_and_unmount': True,
            'full1024_clean_byte_equal_checks_before_and_after_unmount': True,
            'metadata_scope': 'Fixed nofollow prefixes, leaf and exclusive temporary metadata; actual exact preflight outcomes. No content, unexpected link target or directory listing output.',
            'return_contract': '0 only after metadata inspection, guards and unmount complete; failed_preflights may be0..8. Other failure returns1 with stderr; invalidargs64.',
            'final_json': {'schema': 1, 'status': 'fixed_rescue_preflight_metadata_inspected',
                'boot_id': 'argv[3]', 'metadata_sha256': 'argv[2]', 'payload_count': 7, 'link_count': 1,
                'failed_preflights': '0..8', 'writes_to_p11': False, 'armed': False,
                'rebooted': False, 'boot_committed': False},
            'diagnoser_executed': False, 'device_accessed': False, 'tests_or_fixtures_run': False,
            'limits': ['Metadata diagnosis is not installer acceptance; native identity/prerequisite preserve routines are not called.',
                'Actual preflights hash existing fixed payload leaves privately without exporting contents.',
                'Inherited shared flock excludes cooperating writers only; no block-level write barrier is introduced.',
                'Some predicate failures do not assign errno; errno is explicitly qualified in each actual-preflight row.',
                'Creating the shared lock if absent and a private mountpoint affects stock/tmp only; no writes to p11 are requested.']}
    return plan, files, delta, worker


def compile_once(plan, files, delta, worker, approved):
    if OUT.exists():
        raise RuntimeError('Immutable output already exists; no retry')
    root = Path(json.loads(ENV.read_text())['root'])
    assert root.as_posix() == '/tmp/be19000ai-asus-native-build-v2'
    if (root / 'work' / WORK).exists():
        raise RuntimeError('Immutable native work label already exists')
    OUT.mkdir(parents=True, exist_ok=False)
    for name, raw in files.items():
        path = OUT / 'source' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw); path.chmod(0o644)
    assert inventory(OUT / 'source') == plan['source_inventory']
    (OUT / 'compile-plan.json').write_bytes(canonical(plan))
    (OUT / 'source-delta.patch').write_text(delta)
    (OUT / 'build.sh').write_text(worker)
    inputs = Path(tempfile.mkdtemp(prefix='leon-rescue-preflight-build-')); inputs.chmod(0o755)
    shutil.copytree(OUT / 'source', inputs / 'source')
    shutil.copyfile(OUT / 'build.sh', inputs / 'build.sh')
    with (OUT / 'build.log').open('wb') as log:
        run = subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'),
                              str(root), str(inputs)], stdout=log, stderr=subprocess.STDOUT)
    (OUT / 'native-returncode.json').write_text(json.dumps({'native_returncode': run.returncode, 'compile_dispatch_count': 1}) + '\n')
    if run.returncode:
        raise RuntimeError('Sole build failed; output retained, no retry')
    work = root / 'work' / WORK
    assert inventory(work) == {**plan['source_inventory'], 'preflight-diagnoser': sha(work / 'preflight-diagnoser'),
                              'elf.txt': sha(work / 'elf.txt')}
    for name in ['preflight-diagnoser', 'elf.txt']:
        shutil.copyfile(work / name, OUT / name)
        (OUT / name).chmod(0o755 if name == 'preflight-diagnoser' else 0o644)
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'DYN (Position-Independent Executable file)' in elf
    assert 'INTERP' not in elf and 'NEEDED' not in elf
    manifest = dict(plan, status='source_bound_static_rescue_preflight_diagnoser_built',
                    approved_compile_plan_sha256=approved, compile_count=1, native_returncode=0,
                    binary=ref(OUT / 'preflight-diagnoser'), elf=ref(OUT / 'elf.txt'),
                    compiled_input_inventory_matches=True, static_pie_aarch64_no_interp_no_needed=True,
                    build_log=ref(OUT / 'build.log'))
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return {'manifest': ref(OUT / 'manifest.json'), 'binary': manifest['binary']}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true')
    group.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan, files, delta, worker = prepare()
    gate = digest(canonical(plan))
    if args.execute_plan_sha256 is None:
        result = {'plan_sha256': gate, 'plan': plan}
    else:
        if not re.fullmatch('[0-9a-f]{64}', args.execute_plan_sha256) or args.execute_plan_sha256 != gate:
            raise RuntimeError('Exact reviewed plan SHA required; no compile started')
        result = compile_once(plan, files, delta, worker, gate)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

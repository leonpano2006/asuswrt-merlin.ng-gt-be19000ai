#!/usr/bin/env python3
"""Fixed rescue additive installer: default plan is read-only; source may be frozen.

A future sole compile requires the exact reviewed --execute-plan-sha256.
Never run the installer, old fixtures, native packages, services or device commands.
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-candidate-v15/install-v1'
BASE_SHA = '18c2470a65afa9d2aad2e5e9676b810f6a1757ab4f89bb9b1a1196987a2ff984'
BASE_BUILDER = R / 'scripts/build-trial-candidate-v15-installer-v1.py'
BASE_BUILDER_SHA = 'd7f229565906938e7ed6bc9b6c3a642336a02e1fa2b60c5dd127053e2dcb6025'
PACKAGE = R / 'build/asus-uplink-rescue/package-v2/manifest.json'
PACKAGE_SHA = 'a74d36081f61bde3be2c81a3109067df1679b9a4322ab687f2471e16dc3c0e37'
FIXTURE = R / 'reports/ubuntu26/trial-candidate-v15-focused-fixture-result-v1.json'
FIXTURE_SHA = 'c3af062c40673e710991c061be101d58a8e6fdfa0d4db2e5e2f2e01cd7835104'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
ENVIRONMENT_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
LAYOUT = R / 'build/asus-trial-candidate-v15/source-plan-v1/payload-layout.h'
LAYOUT_SHA = 'a1e183d2db345affb6b00a6fbe9d0f76149cca3dba207bc517b062fd6437de25'
SOURCE_OUT = R / 'build/asus-uplink-rescue/install-source-v2'
OUT = R / 'build/asus-uplink-rescue/install-v2'
WORK_LABEL = 'uplink-rescue-installer-v2'
CLI = '--install-native-uplink-rescue'
STATUS = 'native_uplink_rescue_staged'
OLD_CLI = '--install-native-trial-candidate-v15'
OLD_STATUS = 'native_trial_candidate_v15_staged'


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    return sha_bytes(path.read_bytes())


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}


def canonical(record):
    return (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()


def pinned(row):
    name = Path(row['path'])
    assert not name.is_absolute() and '..' not in name.parts
    path = R / name
    assert path.is_file() and not path.is_symlink() and sha(path) == row['sha256']
    if 'bytes' in row:
        assert path.stat().st_size == row['bytes']
    return path


def inventory(root):
    assert not any(p.is_symlink() for p in root.rglob('*'))
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def once(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after, 1)


def header(rows, checks, base):
    text = LAYOUT.read_text() + '\n'
    for i, row in enumerate(rows):
        raw = pinned(row).read_bytes()
        assert 1 <= len(raw) <= 256 * 1024
        text += f'static const unsigned char recovery_data_{i}[]={{\n'
        text += '\n'.join(','.join(f'0x{b:02x}' for b in raw[n:n+16]) + ','
                          for n in range(0, len(raw), 16)) + '\n};\n'
    text += 'static const struct recovery_payload recovery_payloads[]={\n'
    for i, row in enumerate(rows):
        text += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        text += f',recovery_data_{i},sizeof(recovery_data_{i}),' + row['mode'] + ',NULL,0},\n'
    text += '};\n#define RECOVERY_PAYLOAD_COUNT (sizeof(recovery_payloads)/sizeof(recovery_payloads[0]))\n'
    native = checks[0]
    text += 'static const struct recovery_payload recovery_original_rule={'
    text += json.dumps(native['target'].lstrip('/')) + ',' + json.dumps(native['sha256'])
    text += ',NULL,' + str(native['bytes']) + ',0644,NULL,0};\n'
    text += 'static const struct recovery_payload recovery_checks[]={\n'
    for row in checks[1:]:
        text += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        text += ',NULL,' + str(row['bytes']) + ',' + row['mode'] + ',NULL,0},\n'
    text += '};\n#define RECOVERY_CHECK_COUNT (sizeof(recovery_checks)/sizeof(recovery_checks[0]))\n'
    text += 'static const struct candidate_link recovery_links[]={\n'
    text += '{"etc/systemd/system/sockets.target.wants/leon-asus-ssh-uplink-rescue.socket",'
    text += '"/usr/lib/systemd/system/leon-asus-ssh-uplink-rescue.socket"},\n};\n'
    text += '#define RECOVERY_LINK_COUNT (sizeof(recovery_links)/sizeof(recovery_links[0]))\n'
    timer = base['old90_timer_preserved']
    text += 'static const struct candidate_link recovery_old_timer={'
    text += json.dumps(timer['path'].lstrip('/')) + ',' + json.dumps(timer['target']) + '};\n'
    public = re.findall(r'static const char recovery_host_public\[\]=[^\n]+;',
                        (BASE / 'source/recovery-payload.h').read_text())
    assert len(public) == 1
    return (text + public[0] + '\n').encode()


def prepare():
    if PACKAGE_SHA is None:
        raise RuntimeError('New package manifest pin pending; no source output or compile permitted')
    for path, expected in [(BASE / 'manifest.json', BASE_SHA), (BASE_BUILDER, BASE_BUILDER_SHA),
                           (PACKAGE, PACKAGE_SHA), (FIXTURE, FIXTURE_SHA),
                           (ENVIRONMENT, ENVIRONMENT_SHA), (LAYOUT, LAYOUT_SHA)]:
        assert sha(path) == expected
    base = json.loads((BASE / 'manifest.json').read_text())
    assert base['compile_count'] == 1 and not base['installer_executed']
    assert inventory(BASE / 'source') == base['source_inventory']
    fixture = json.loads(FIXTURE.read_text())
    assert fixture['status'] == 'one_focused_native_fixture_compile_and_run_passed'
    assert fixture['compile_count'] == fixture['fixture_run_count'] == 1 and fixture['native_returncode'] == 0
    assert len(fixture['variants']) == 4 and all(row['pass'] for row in fixture['variants'])
    assert not fixture['physical_hardware_guards_entered'] and not fixture['device_accessed']
    package = json.loads(PACKAGE.read_text())
    assert package['status'] == 'built_inert_native_uplink_rescue_package'
    assert package['build']['count'] == 1 and len(package['files']) == 6
    assert package['no_maintainer_scripts_triggers_presets_activation'] and not package['helper_executed']
    rows = []
    for row in package['files']:
        item = {'path': row['source'], 'target': row['path'], 'sha256': row['sha256'],
                'bytes': row['bytes'], 'mode': row['mode'], 'uid': row['uid'], 'gid': row['gid'],
                'role': 'add', 'absent_or_identical_only': True}
        pinned(item); rows.append(item)
    deb = dict(package['deb'], target=package['staged_deb_install_target'], mode='0644',
               uid=0, gid=0, role='add', absent_or_identical_only=True)
    pinned(deb); rows.append(deb)
    assert len(rows) == 7 and len({row['target'] for row in rows}) == 7
    for row in rows:
        assert row['uid'] == row['gid'] == 0 and row['mode'] in ('0644', '0755')
        assert row['target'].startswith('/') and '..' not in Path(row['target']).parts
    checks = [dict(row) for row in base['check_only_preserve']]
    assert len(checks) == 7
    for row in checks[1:]:
        pinned(row)
    original_rule = R / 'build/asus-udev-dummy0-policy/package-v1/original-99-systemd.rules'
    assert sha(original_rule) == checks[0]['sha256'] and original_rule.stat().st_size == checks[0]['bytes']
    old_rc = base['regular_payloads'][1]['old']
    pinned(old_rc)
    assert old_rc['sha256'] == '7e00ff39b48ff4b5efcba7829b1d4849343c88232af3090038bd53b1e9791355'
    assert old_rc['bytes'] == 7709628 and old_rc['mode'] == '0755'
    rc_check = dict(old_rc, target='/usr/libexec/asus/rc', role='preserve', inode_unchanged_required=True)
    checks.append(rc_check)
    assert len(checks) == 8
    files = {p.relative_to(BASE / 'source').as_posix(): p.read_bytes()
             for p in sorted((BASE / 'source').rglob('*')) if p.is_file()}
    old = files['install.c'].decode()
    substitutions = [(OLD_CLI, CLI), (OLD_STATUS, STATUS),
                     ('LEON_TRIAL_CANDIDATE_INSTALL_REFUSED', 'LEON_UPLINK_RESCUE_INSTALL_REFUSED'),
                     ('publish-fixed-inactive-v15-candidate', 'publish-fixed-inactive-uplink-rescue')]
    generated = old
    for before, after in substitutions:
        generated = once(generated, before, after)
    reverse = generated
    for before, after in reversed(substitutions):
        reverse = once(reverse, after, before)
    assert reverse == old
    # Import only the pinned parser definitions; never call its old prepare/main.
    spec = importlib.util.spec_from_file_location('frozen_v15_source_parser', BASE_BUILDER)
    parser = importlib.util.module_from_spec(spec); spec.loader.exec_module(parser)
    unchanged = [name for name in ['state_dir', 'recovery_parent', 'identity_save', 'identity_equal',
        'identity_all', 'enrolled_identity', 'recovery_file', 'dummy0_original_rule_matches',
        'candidate_temp_name', 'candidate_same_inode', 'candidate_old_file',
        'candidate_replace_preflight', 'candidate_replace', 'candidate_stat_unchanged',
        'candidate_checks', 'candidate_link_check', 'candidate_link_publish',
        'target_preflight', 'install_target', 'enable_dir', 'enable_link', 'install_recovery']]
    for name in unchanged:
        assert parser.function(old, name) == parser.function(generated, name)
    # Actual preserve guard excludes RC: protect RCv6 through the check-only table.
    preserve = parser.function(files['bsp-provision.c'].decode(), 'update_preserve')
    assert 'rc' not in re.findall(r'"([^"\n]*)"', preserve)
    assert 'guardian' not in preserve
    files['install.c'] = generated.encode()
    files['recovery-payload.h'] = header(rows, checks, base)
    hashes = {name: sha_bytes(data) for name, data in sorted(files.items())}
    changed = [name for name in hashes if hashes[name] != base['source_inventory'][name]]
    assert changed == ['install.c', 'recovery-payload.h']
    delta = ''.join(difflib.unified_diff(old.splitlines(True), generated.splitlines(True),
                                       fromfile='frozen-v15/install.c', tofile='uplink-rescue/install.c'))
    worker = (BASE / 'build.sh').read_text()
    assert sha_bytes(worker.encode()) == base['compile_worker_sha256']
    assert worker.count(base['native_work_label']) == 3
    worker = worker.replace(base['native_work_label'], WORK_LABEL)
    record = {'schema': 1, 'status': 'source_bound_additive_uplink_rescue_compile_plan_only',
              'builder': ref(Path(__file__)), 'baseline': ref(BASE / 'manifest.json'),
              'baseline_installer': base['installer'], 'baseline_builder': ref(BASE_BUILDER),
              'package_manifest': ref(PACKAGE), 'focused_transaction_fixture': ref(FIXTURE),
              'native_environment': ref(ENVIRONMENT), 'output': OUT.relative_to(R).as_posix(),
              'source_output': SOURCE_OUT.relative_to(R).as_posix(), 'native_work_label': WORK_LABEL,
              'cli': CLI, 'result_status': STATUS, 'source_inventory': hashes,
              'changed_source_files': changed, 'literal_substitutions': substitutions,
              'reverse_literal_transform_equals_frozen_install_c': True,
              'unchanged_function_sha256': {name: sha_bytes(parser.function(old, name).encode()) for name in unchanged},
              'frozen_guard_and_transaction_sources_unchanged': {name: value for name, value in hashes.items() if name not in changed},
              'regular_payloads': rows, 'replacement_count': 0,
              'all_regular_descriptors_have_old_sha_null_and_old_size_zero': True,
              'links': [package['socket_alias_separate_from_package']],
              'check_only_preserve': checks, 'original_seven_checks_unchanged': True,
              'current_rc_v6_before_after_inode_hash_mode_preserved': rc_check,
              'old90_timer_preserved': base['old90_timer_preserved'],
              'existing_parent_policy': 'All file/link parent traversals create=0; missing parent refuses before any candidate write.',
              'required_new_parent_already_exists': '/etc/systemd/system/sockets.target.wants',
              'shared_lock': '/tmp/leon-device-identity.lock', 'native_identity_files': 16,
              'native_account_state_mode': '0755; existing, no chmod/recreation',
              'source_delta_sha256': sha_bytes(delta.encode()), 'source_delta_bytes': len(delta.encode()),
              'header_bytes': len(files['recovery-payload.h']), 'compile_worker_sha256': sha_bytes(worker.encode()),
              'worker_flags_inherited_exactly': True, 'source_or_installer_compiled': False,
              'fixtures_autoexecuted': False, 'new_fixture_requested': False,
              'old_guards_fixtures_QEMU_reused_not_rerun': True,
              'must_stage_before_v15_candidate_rc_replacement': True,
              'update_preserve_ignores_rc_source_verified': True,
              'guardian_on_p11_written_or_replaced': False,
              'guardian_snapshot_preservation_scope': 'Seven additive regular leaves and one socket alias cannot rewrite existing snapshot leaves; frozen prerequisite and identity guards retained. External original-SquashFS guardian unchanged. No claim of re-running the full213-entry verifier.',
              'future_device_result_path': 'evidence/ubuntu26/device-uplink-rescue-live/install-v2/result.json',
              'expected_fresh_installer_stdout': {'schema': 1, 'status': STATUS,
                  'additions_published': 7, 'replacements_published': 0, 'temporary_created': 7,
                  'links_created': 1, 'mode_changed': False, 'native_identity_unchanged': True,
                  'known_preserved_leaf_inodes_unchanged': True, 'prerequisites_unchanged': True,
                  'package_database_updated': False, 'armed': False, 'rebooted': False, 'boot_committed': False},
              'limits': ['Source-only: no native installer ELF or physical guard execution yet.',
                         'Routine clean-p11 preen remains a separate root-owned prerequisite; no recovery relaxation.',
                         'Clean frozen storage guard does not add a new explicit s_last_orphan check.',
                         'Sequential publication may retain owned temp/partial additions on failure; no rollback, retry or ARM.',
                         'Shared flock excludes cooperating writers only.',
                         'Offline socket enable alias is for the future candidate boot; no running service activation/native apt/account/key/boot metadata change.']}
    return record, files, delta, worker


def freeze_sources(record, files, delta, worker):
    if SOURCE_OUT.exists():
        raise RuntimeError('Immutable source output already exists')
    SOURCE_OUT.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = SOURCE_OUT / 'source' / name
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(0o644)
    assert inventory(SOURCE_OUT / 'source') == record['source_inventory']
    (SOURCE_OUT / 'compile-plan.json').write_bytes(canonical(record))
    (SOURCE_OUT / 'source-delta.patch').write_text(delta)
    (SOURCE_OUT / 'build.sh').write_text(worker)
    (SOURCE_OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    return {'manifest': ref(SOURCE_OUT / 'manifest.json'), 'plan_sha256': sha_bytes(canonical(record)),
            'source_only': True, 'compiled': False, 'executed': False}


def compile_once(record, approved):
    if OUT.exists():
        raise RuntimeError('Immutable native output already exists')
    assert (SOURCE_OUT / 'compile-plan.json').read_bytes() == canonical(record)
    assert inventory(SOURCE_OUT / 'source') == record['source_inventory']
    assert sha(SOURCE_OUT / 'build.sh') == record['compile_worker_sha256']
    root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    assert root.as_posix() == '/tmp/be19000ai-asus-native-build-v2'
    if (root / 'work' / WORK_LABEL).exists():
        raise RuntimeError('Immutable native work label already exists')
    OUT.mkdir(parents=True, exist_ok=False)
    shutil.copytree(SOURCE_OUT / 'source', OUT / 'source')
    for name in ['compile-plan.json', 'source-delta.patch', 'build.sh']:
        shutil.copyfile(SOURCE_OUT / name, OUT / name)
    inputs = Path(tempfile.mkdtemp(prefix='leon-uplink-rescue-install-')); inputs.chmod(0o755)
    shutil.copytree(OUT / 'source', inputs / 'source')
    shutil.copyfile(OUT / 'build.sh', inputs / 'build.sh')
    with (OUT / 'build.log').open('wb') as log:
        subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'),
                        str(root), str(inputs)], stdout=log, stderr=subprocess.STDOUT, check=True)
    work = root / 'work' / WORK_LABEL
    assert inventory(work) == {**record['source_inventory'],
        'install-additions': sha(work / 'install-additions'), 'elf.txt': sha(work / 'elf.txt')}
    for name in ['install-additions', 'elf.txt']:
        shutil.copyfile(work / name, OUT / name); (OUT / name).chmod(0o755 if name == 'install-additions' else 0o644)
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    result = dict(record, status='source_bound_static_additive_uplink_rescue_installer_built',
                  approved_compile_plan_sha256=approved, compile_count=1,
                  installer=ref(OUT / 'install-additions'), elf=ref(OUT / 'elf.txt'),
                  compiled_input_inventory_matches=True, static_elf_passed=True,
                  installer_executed=False, device_accessed=False, fixtures_oldtests_QEMU_run=False,
                  build_log=ref(OUT / 'build.log'))
    (OUT / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    return {'manifest': ref(OUT / 'manifest.json'), 'installer': result['installer']}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--plan-only', action='store_true')
    mode.add_argument('--write-source', action='store_true')
    mode.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    record, files, delta, worker = prepare()
    plan = sha_bytes(canonical(record))
    if args.write_source:
        result = freeze_sources(record, files, delta, worker)
    elif args.execute_plan_sha256 is not None:
        if not re.fullmatch('[0-9a-f]{64}', args.execute_plan_sha256) or args.execute_plan_sha256 != plan:
            raise RuntimeError('Exact reviewed source-plan SHA required; no build started')
        result = compile_once(record, plan)
    else:
        result = {'plan_sha256': plan, 'plan': record}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

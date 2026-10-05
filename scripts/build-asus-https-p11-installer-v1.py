#!/usr/bin/env python3
"""Plan/build one inert fixed HTTPS helper, cached Deb and alias on clean inactive p11."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-network-v21/install-v1'
BASE_SHA = '1ea1ce0152723a6130295bc83107794e36cd844fd3786bbcfd33e0fa7fb340ed'
ENV = R / 'build/asus-native-build/v2/result.json'
ENV_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
C = ('scripts/asus-integration/https-staging/install-v1.c', '2cab747ea8227c929a169abe397737b0591f19f29b0a7fe7f46b97ceced6ef99')
DELTA = ('reports/ubuntu26/https-helper-installer-source-v1.json', '3f16e3a486e0daf3cae7138303659dc489a1fe26a79d9c2330b4be8bcc13c55c')
PACKAGE = ('build/asus-web-telemetry-fixes/package-v2/manifest.json', 'd728e7b3bc16379f5c23b74a3fcafd4b5dd5434e7cdeaeec362c633d8121656e')
TELEMETRY = ('build/asus-web-telemetry-fixes/package-v3/manifest.json', 'f2f3604e88a362be7dac0a9a2cb425343a93b8962b8d3ee41cd432a26fca13d3')
HELPER = ('build/stock-rootfs/usr/sbin/gencert.sh', 'a52a57a1af92407bbf57c6e624a2c5c2f67f59163c9fab0d751d7693514ee517')
RC_MARKER = ('build/asus-web-telemetry-fixes/package-v3/telemetry-root/usr/share/asus/integration/rc.sha256', 'b0bf8ee66fdd11544be62edf5e54e5f0337b4470e920929247ef6d0d5e4ccb2b')
OUT = R / 'build/asus-https-helper/install-v1'
WORK = 'https-helper-installer-v1'
CLI = '--install-native-https-helper-v1'
STATUS = 'native_https_helper_v1_staged'

def sha(path):
    assert path.is_file() and not path.is_symlink(), str(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}


def pin(row):
    assert row[1] is not None, 'Pending input blocks compilation: ' + row[0]
    p = R / row[0]
    assert sha(p) == row[1], row[0]
    return p


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def inventory(root):
    assert not any(p.is_symlink() for p in root.rglob('*'))
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def once(s, old, new):
    assert s.count(old) == 1, old
    return s.replace(old, new, 1)


def prepare():
    if not __debug__: raise RuntimeError('Python -O forbidden')
    assert not OUT.exists() and not OUT.is_symlink()
    assert sha(BASE / 'manifest.json') == BASE_SHA and sha(ENV) == ENV_SHA
    base = json.loads((BASE / 'manifest.json').read_text())
    assert base['status'] == 'fixed_trial_network_v21_installer_built'
    assert base['compile_count'] == 1 and base['returncode'] == 0 and not base['installer_executed']
    assert inventory(BASE / 'source') == base['source_inventory'] and len(base['source_inventory']) == 21
    files = {p.relative_to(BASE / 'source').as_posix(): p.read_bytes()
             for p in sorted((BASE / 'source').rglob('*')) if p.is_file()}
    original = files['install.c'].decode()
    code = pin(C).read_text()
    delta = json.loads(pin(DELTA).read_text())
    assert delta['baseline']['sha256'] == hashlib.sha256(original.encode()).hexdigest()
    assert delta['source'] == ref(pin(C))
    old_parent = pin((delta['parent_primitive_baseline']['path'], delta['parent_primitive_baseline']['sha256'])).read_text()
    a = old_parent.index('/* The one proven missing parent.')
    b = old_parent.index('#ifndef RECOVERY_INSTALL_MAIN', a)
    helper_region = old_parent[a:b]
    for before, after in delta['parent_primitive_literal_substitutions']:
        assert before in helper_region
        helper_region = helper_region.replace(before, after)
    assert code.count(helper_region) == 1
    reverse = code.replace(helper_region, '', 1)
    for before, after in reversed(delta['literal_substitutions']):
        reverse = once(reverse, after, before)
    assert reverse == original
    files['install.c'] = code.encode()
    package = json.loads(pin(PACKAGE).read_text())
    assert package['status'] == 'built_inert_not_installed'
    assert package['no_target_script_run'] and package['no_enablement_hooks_triggers'] and not package['device_accessed']
    artifact = next(row for row in package['packages'] if row['name'] == 'leon-asus-https-helper')
    assert artifact['control_members'] == ['control', 'md5sums'] and len(artifact['inventory']) == 3
    deb = ref(R / artifact['path'])
    assert deb == {key: artifact[key] for key in ('path', 'sha256', 'bytes')}
    assert deb['sha256'] == '08167f716ffb11bc905a391c968e22a66403eeb1d81958b42dc40d0d1e6937f2' and deb['bytes'] == 4292
    helper = ref(pin(HELPER))
    expected_helper = next(row for row in artifact['inventory'] if row['path'] == '/usr/libexec/asus/scripts/gencert.sh')
    assert expected_helper['type'] == 'regular' and expected_helper['mode'] == 0o755 and expected_helper['sha256'] == helper['sha256']
    expected_link = next(row for row in artifact['inventory'] if row['type'] == 'symlink')
    assert expected_link == {'path': '/usr/share/asus/commands/sbin/gencert.sh', 'mode': 0o777, 'type': 'symlink', 'target': '/usr/libexec/asus/scripts/gencert.sh'}
    rows = [dict(helper, target=expected_helper['path'], mode='0755', old=None),
            dict(deb, target='/usr/share/asus/trial-additions/' + Path(deb['path']).name, mode='0644', old=None)]
    checks = [dict(row) for row in base['checks']]
    for row in base['regular_payloads']:
        check = {key: value for key, value in row.items() if key != 'old'}
        checks.append(check)
    assert any(row['target'] == '/usr/libexec/leon-asus/rescue-link' and row['sha256'] == '98e4d025fd79e5969a038fa1a141767358996941bf940c720110f6aee1e51028' and row['bytes'] == 73768 for row in checks)
    assert any(row['target'] == '/usr/libexec/asus/startup-prepare' and row['sha256'] == '69994d0dbaf4db84c3ea9207ec3d03ff27a3c2d05edaf2571a23f30a76b9c6d7' and row['bytes'] == 87488 for row in checks)
    marker = ref(pin(RC_MARKER))
    assert marker['bytes'] == 87 and pin(RC_MARKER).read_bytes() == b'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2  /usr/libexec/asus/rc\n'
    telemetry = json.loads(pin(TELEMETRY).read_text())
    assert telemetry['no_target_script_run'] and not telemetry['device_accessed']
    marker_row = next(row for row in telemetry['packages'][0]['inventory'] if row['path'] == '/usr/share/asus/integration/rc.sha256')
    assert marker_row == {'path': '/usr/share/asus/integration/rc.sha256', 'mode': 0o644, 'type': 'regular', 'sha256': marker['sha256']}
    checks.append(dict(marker, target=marker_row['path'], mode='0644'))
    assert len({row['target'] for row in checks}) == len(checks)
    for row in checks[1:]:
        assert sha(R / row['path']) == row['sha256'] and (R / row['path']).stat().st_size == row['bytes']
    original_rule = R / 'build/asus-udev-dummy0-policy/package-v1/original-99-systemd.rules'
    assert sha(original_rule) == checks[0]['sha256'] and original_rule.stat().st_size == checks[0]['bytes']
    header = files['recovery-payload.h'].decode()
    h = header[:header.index('static const unsigned char recovery_data_0[]')]
    for i, row in enumerate(rows):
        raw = (R / row['path']).read_bytes()
        assert 1 <= len(raw) <= 256 * 1024
        h += f'static const unsigned char recovery_data_{i}[]={{\n'
        h += '\n'.join(','.join(f'0x{x:02x}' for x in raw[n:n+16]) + ',' for n in range(0, len(raw), 16)) + '\n};\n'
    h += 'static const struct recovery_payload recovery_payloads[]={\n'
    for i, row in enumerate(rows):
        h += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        h += f',recovery_data_{i},sizeof(recovery_data_{i}),' + row['mode'] + ',NULL,0},\n'
    h += '};\n#define RECOVERY_PAYLOAD_COUNT (sizeof(recovery_payloads)/sizeof(recovery_payloads[0]))\n'
    declarations = re.findall(r'static const struct recovery_payload recovery_original_rule=\{[^\n]+;', header)
    assert len(declarations) == 1
    h += declarations[0] + '\nstatic const struct recovery_payload recovery_checks[]={\n'
    for row in checks[1:]:
        h += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        h += ',NULL,' + str(row['bytes']) + ',' + row['mode'] + ',NULL,0},\n'
    h += '};\n#define RECOVERY_CHECK_COUNT (sizeof(recovery_checks)/sizeof(recovery_checks[0]))\n'
    tail = header[header.index('static const struct candidate_link recovery_links[]='):]
    link_line = '{"etc/systemd/system/sockets.target.wants/leon-asus-ssh-uplink-rescue.socket","/usr/lib/systemd/system/leon-asus-ssh-uplink-rescue.socket"},\n'
    new_link = '{"usr/share/asus/commands/sbin/gencert.sh","/usr/libexec/asus/scripts/gencert.sh"},\n'
    h += once(tail, link_line, link_line + new_link)
    files['recovery-payload.h'] = h.encode()
    worker = (BASE / 'build.sh').read_text()
    assert hashlib.sha256(worker.encode()).hexdigest() == base['worker_sha256']
    assert worker.count(base['work']) == 3
    worker = worker.replace(base['work'], WORK)
    sources = {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())}
    assert [name for name in sources if sources[name] != base['source_inventory'][name]] == ['install.c', 'recovery-payload.h']
    plan = {'schema': 1, 'status': 'fixed_https_helper_v1_source_plan', 'builder': ref(Path(__file__)),
            'base': ref(BASE / 'manifest.json'), 'baseline_installer': base['installer'], 'environment': ref(ENV),
            'https_package_manifest': ref(pin(PACKAGE)), 'telemetry_package_manifest': ref(pin(TELEMETRY)),
            'source_delta': ref(pin(DELTA)), 'installer_source': ref(pin(C)), 'link_source': base['link_source'],
            'source_inventory': sources, 'regular_payloads': rows, 'checks': checks,
            'source_changes': ['install.c', 'recovery-payload.h'], 'unchanged_source_files': 19,
            'reverse_literal_and_parent_transform_equals_frozen_install_c': True,
            'parent_primitive_transplanted_with_fixed_paths_and_counts_only': True,
            'worker_sha256': hashlib.sha256(worker.encode()).hexdigest(),
            'output': OUT.relative_to(R).as_posix(), 'work': WORK, 'cli': CLI, 'result_status': STATUS,
            'expected_counts': {'additions_published': 2, 'replacements_published': 0, 'links_created': 1,
                                'private_sh_links_replaced': 0, 'temporary_created': 2, 'directories_created': 1},
            'counts_apply_to_previously_absent_https_leaves_and_parent': True,
            'all_existing_checks_and_current_rescue_startup_rc_retained': True,
            'current_telemetry_rc_marker_verified_before_after_inode_unchanged': True,
            'only_fixed_scripts_parent_created_missing_or_existing_root0755': True,
            'all_other_parents_strict_existing_nofollow_root0755': True,
            'existing_rescue_socket_alias_required_and_inode_preserved': True,
            'only_fixed_gencert_command_alias_absent_or_identical': True,
            'private_sh_inherited_verified_readonly_noop': True,
            'no_account_key_boot_firmware_service_or_package_database_changes': True,
            'compiler_version_probes': 0, 'old_fixtures_reexecuted': False}
    return plan, files, worker


def main():
    p = argparse.ArgumentParser(); p.add_argument('--execute-plan-sha256'); a = p.parse_args()
    plan, files, worker = prepare(); gate = hashlib.sha256(canonical(plan)).hexdigest()
    if a.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2)); return
    assert a.execute_plan_sha256 == gate
    root = Path(json.loads(ENV.read_text())['root']); assert not (root / 'work' / WORK).exists()
    OUT.mkdir(parents=True)
    for name, raw in files.items():
        path = OUT / 'source' / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    (OUT / 'build.sh').write_text(worker); (OUT / 'compile-plan.json').write_bytes(canonical(plan))
    inp = Path(tempfile.mkdtemp(prefix='leon-https-helper-build-')); inp.chmod(0o755)
    shutil.copytree(OUT / 'source', inp / 'source'); shutil.copyfile(OUT / 'build.sh', inp / 'build.sh')
    with (OUT / 'build.log').open('wb') as log:
        run = subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inp / 'build.sh'), str(root), str(inp)], stdout=log, stderr=subprocess.STDOUT)
    (OUT / 'returncode.json').write_text(json.dumps({'returncode': run.returncode, 'compile_count': 1}) + '\n')
    assert run.returncode == 0, 'One compile failed; retained evidence, no retry'
    work = root / 'work' / WORK
    assert inventory(work) == {**plan['source_inventory'], 'install-additions': sha(work / 'install-additions'), 'elf.txt': sha(work / 'elf.txt')}
    for name in ('install-additions', 'elf.txt'): shutil.copyfile(work / name, OUT / name)
    (OUT / 'install-additions').chmod(0o755)
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    report = {**plan, 'status': 'fixed_https_helper_v1_installer_built', 'approved_plan_sha256': gate,
              'installer': ref(OUT / 'install-additions'), 'compile_count': 1, 'returncode': 0,
              'installer_executed': False, 'device_accessed': False}
    (OUT / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'installer': report['installer']}))


if __name__ == '__main__':
    main()

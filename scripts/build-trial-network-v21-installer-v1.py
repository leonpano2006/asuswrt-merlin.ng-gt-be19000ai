#!/usr/bin/env python3
"""Plan/compile one fixed rescue-v6 replacement and inert Deb addition, retaining V18 guards."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-network-v20/install-v1'
BASE_SHA = 'afcba06d5ff140c6672a51d6d803684ab2271d430cccad437b1d1aaa51a7fcec'
ENV = R / 'build/asus-native-build/v2/result.json'
ENV_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
NATIVE = ('build/asus-uplink-rescue/native-v8/manifest.json', '5577ec95befc9414847f3c0b366d876825906ab5e22ad5ff853bf7b652b99491')
PACKAGE = ('build/asus-uplink-rescue/package-v6/manifest.json', 'd2d122daf42f00c05cdbe4e8cbaeb97e808d38ca22feff025d6dd88998af492a')
FIXTURE = ('build/asus-uplink-rescue/compat8437-rule-fixture-v1/result.json', '11ff601eca517b7cbbf912a10c3090c13cc7a07417d8e2356788ae8522a342b9')
OLD = ('build/asus-uplink-rescue/native-v7/rescue-link', 'a68f9637bb753f1cafc4804f5b8f01be7601e619b2baed546762e41c8485ece8')
OUT = R / 'build/asus-trial-network-v21/install-v1'
WORK = 'trial-network-v21-installer-v1'
CLI = '--install-native-trial-network-v21'
STATUS = 'native_trial_network_v21_staged'


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
    assert all(row[1] is not None for row in (NATIVE, PACKAGE, FIXTURE)), 'Pending successor artifacts block even the default plan'
    assert not OUT.exists() and not OUT.is_symlink()
    assert sha(BASE / 'manifest.json') == BASE_SHA and sha(ENV) == ENV_SHA
    native = json.loads(pin(NATIVE).read_text())
    package = json.loads(pin(PACKAGE).read_text())
    assert native['status'] == 'built_not_executed' and native['returncode'] == 0
    assert native['source_compile_invocations'] == 1 and not native['target_binary_executed']
    fixture = json.loads(pin(FIXTURE).read_text())
    assert fixture['status'] == 'pure_production_compat8437_rule_fixture_passed' and fixture['returncode'] == 0
    assert fixture['compile_count'] == fixture['fixture_run_count'] == 1 and fixture['expected_case_count'] == 17
    assert len(fixture['cases']) == 17 and all(row['pass'] is True for row in fixture['cases'])
    assert fixture['inputs']['production_source'] == ref(R / native['sources']['new']['path'])
    assert package['no_maintainer_scripts_triggers_presets_activation'] is True
    assert package['helper_executed'] is False
    old = ref(pin(OLD)); assert old['bytes'] == 73768
    base = json.loads((BASE / 'manifest.json').read_text())
    assert base['status'] == 'fixed_trial_network_v20_installer_built'
    assert inventory(BASE / 'source') == base['source_inventory'] and len(base['source_inventory']) == 21
    files = {p.relative_to(BASE / 'source').as_posix(): p.read_bytes()
             for p in sorted((BASE / 'source').rglob('*')) if p.is_file()}
    code = files['install.c'].decode()
    for a, b in [('--install-native-trial-network-v20', CLI), ('native_trial_network_v20_staged', STATUS),
                 ('LEON_TRIAL_NETWORK_V20_INSTALL_REFUSED', 'LEON_TRIAL_NETWORK_V21_INSTALL_REFUSED'),
                 ('publish-fixed-inactive-uplink-rescue', 'publish-fixed-inactive-uplink-rescue-rule')]:
        code = once(code, a, b)
    files['install.c'] = code.encode()
    helper = ref(R / native['binary']['path'])
    assert all(helper[k] == native['binary'][k] for k in ('path', 'sha256'))
    assert 1 <= helper['bytes'] <= 256 * 1024
    deb = package['deb']
    assert ref(R / deb['path']) == deb
    assert len(package['files']) == 6
    asset = next(row for row in package['files'] if row['path'] == '/usr/libexec/leon-asus/rescue-link')
    assert asset['sha256'] == helper['sha256'] and asset['bytes'] == helper['bytes'] and asset['mode'] == '0755'
    rows = [dict(helper, target=asset['path'], mode='0755', old=old),
            dict(deb, target='/usr/share/asus/trial-additions/' + Path(deb['path']).name, mode='0644', old=None)]
    checks = [dict(row) for row in base['checks'] if row['target'] != '/usr/libexec/leon-asus/rescue-link']
    replaced_check = [row for row in [*base['checks'], *base['regular_payloads']] if row['target'] == '/usr/libexec/leon-asus/rescue-link']
    assert len(replaced_check) == 1 and replaced_check[0]['sha256'] == old['sha256'] and replaced_check[0]['bytes'] == old['bytes']
    for row in base['regular_payloads']:
        if row['target'] == '/usr/libexec/leon-asus/rescue-link':
            continue
        check = {k: v for k, v in row.items() if k != 'old'}
        assert ref(R / check['path']) == {k: check[k] for k in ('path', 'sha256', 'bytes')}
        checks.append(check)
    assert not any(row['target'] == '/usr/libexec/leon-asus/rescue-link' for row in checks)
    assert any(row['target'] == '/usr/share/asus/trial-additions/leon-asus-uplink-rescue_0.1+leonb53.5_arm64.deb'
               and row['sha256'] == '0adb92aaf7268ded253d45c6ba6a18c1c53f9c8ae580563ea73d5f00331fced0'
               and row['bytes'] == 16836 for row in checks)
    assert any(row['target'] == '/usr/libexec/asus/startup-prepare'
               and row['sha256'] == '69994d0dbaf4db84c3ea9207ec3d03ff27a3c2d05edaf2571a23f30a76b9c6d7' and row['bytes'] == 87488 for row in checks)
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
        old_row = row['old']
        h += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        h += f',recovery_data_{i},sizeof(recovery_data_{i}),' + row['mode'] + ','
        h += ('NULL,0' if old_row is None else json.dumps(old_row['sha256']) + ',' + str(old_row['bytes'])) + '},\n'
    h += '};\n#define RECOVERY_PAYLOAD_COUNT (sizeof(recovery_payloads)/sizeof(recovery_payloads[0]))\n'
    declarations = re.findall(r'static const struct recovery_payload recovery_original_rule=\{[^\n]+;', header)
    assert len(declarations) == 1
    h += declarations[0] + '\nstatic const struct recovery_payload recovery_checks[]={\n'
    for row in checks[1:]:
        h += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        h += ',NULL,' + str(row['bytes']) + ',' + row['mode'] + ',NULL,0},\n'
    h += '};\n#define RECOVERY_CHECK_COUNT (sizeof(recovery_checks)/sizeof(recovery_checks[0]))\n'
    h += header[header.index('static const struct candidate_link recovery_links[]='):]
    files['recovery-payload.h'] = h.encode()
    worker = (BASE / 'build.sh').read_text()
    assert worker.count(base['work']) == 3
    worker = worker.replace(base['work'], WORK)
    sources = {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())}
    assert [name for name in sources if sources[name] != base['source_inventory'][name]] == ['install.c', 'recovery-payload.h']
    plan = {'schema': 1, 'status': 'fixed_trial_network_v21_source_plan', 'builder': ref(Path(__file__)),
            'base': ref(BASE / 'manifest.json'), 'environment': ref(ENV), 'new_native': ref(pin(NATIVE)),
            'rescue_package': ref(pin(PACKAGE)), 'raw_header_fixture': ref(pin(FIXTURE)), 'link_source': base['link_source'],
            'source_inventory': sources, 'regular_payloads': rows, 'checks': checks,
            'source_changes': ['install.c', 'recovery-payload.h'], 'unchanged_source_files': 19,
            'worker_sha256': hashlib.sha256(worker.encode()).hexdigest(),
            'output': OUT.relative_to(R).as_posix(), 'work': WORK, 'cli': CLI, 'result_status': STATUS,
            'expected_counts': {'additions_published': 1, 'replacements_published': 1, 'links_created': 0,
                                'private_sh_links_replaced': 0, 'temporary_created': 2},
            'private_sh_inherited_verified_readonly_noop': True,
            'scoped_startup_v18_helper_and_package_preserved': True,
            'no_account_key_boot_firmware_service_or_package_database_changes': True}
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
    inp = Path(tempfile.mkdtemp(prefix='leon-v21-rescue-build-')); inp.chmod(0o755)
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
    report = {**plan, 'status': 'fixed_trial_network_v21_installer_built', 'approved_plan_sha256': gate,
              'installer': ref(OUT / 'install-additions'), 'compile_count': 1, 'returncode': 0,
              'installer_executed': False, 'device_accessed': False}
    (OUT / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'installer': report['installer']}))


if __name__ == '__main__':
    main()

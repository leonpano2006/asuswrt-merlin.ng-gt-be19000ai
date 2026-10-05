#!/usr/bin/env python3
"""Compile one fixed inactive-p11 startup helper update, retaining V17 guards."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-network-v17/install-v1'
BASE_SHA = '861fa327f5556cb1bac8d6a2c48a8f8b5230b43246d7efdaa61b5f0f90721be8'
ENV = R / 'build/asus-native-build/v2/result.json'
ENV_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
NATIVE = ('build/asus-startup/scoped-udev-native-v1/validated-manifest.json', 'dbef69abeb91de3becf2a19f5b30d86ce30a60362201b43a8cbaf135f29d3559')
PACKAGE = ('build/asus-startup/scoped-udev-package-v1/manifest.json', '9d370749c8200a8670dccecb6ecbeb746700ff15429e0a6062109aa5a65ad1b5')
OLD = ('build/asus-startup/native-v7/startup-prepare', '27c226d22963fe37a674c0975a5426b88eefd3607dce3cb966334df033bb119c')
OUT = R / 'build/asus-trial-startup-v18/install-v1'
WORK = 'trial-startup-v18-installer-v1'
CLI = '--install-native-trial-startup-v18'
STATUS = 'native_trial_startup_v18_staged'


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
    assert __debug__ and not OUT.exists() and not OUT.is_symlink()
    assert sha(BASE / 'manifest.json') == BASE_SHA and sha(ENV) == ENV_SHA
    native = json.loads(pin(NATIVE).read_text())
    package = json.loads(pin(PACKAGE).read_text())
    assert native['status'] == 'built_not_executed' and native['returncode'] == 0
    assert native['source_compile_invocations'] == 1 and native['compile_count'] == 1
    assert package['no_maintainer_scripts_triggers_presets_activation'] is True
    assert package['helper_executed'] is False
    old = ref(pin(OLD)); assert old['bytes'] == 87544
    base = json.loads((BASE / 'manifest.json').read_text())
    assert base['status'] == 'fixed_trial_network_v17_installer_built'
    assert inventory(BASE / 'source') == base['source_inventory'] and len(base['source_inventory']) == 21
    files = {p.relative_to(BASE / 'source').as_posix(): p.read_bytes()
             for p in sorted((BASE / 'source').rglob('*')) if p.is_file()}
    code = files['install.c'].decode()
    for a, b in [('--install-native-trial-network-v17', CLI), ('native_trial_network_v17_staged', STATUS),
                 ('LEON_TRIAL_NETWORK_V17_INSTALL_REFUSED', 'LEON_TRIAL_STARTUP_V18_INSTALL_REFUSED'),
                 ('publish-fixed-inactive-uplink-rescue', 'publish-fixed-inactive-startup-prepare')]:
        code = once(code, a, b)
    files['install.c'] = code.encode()
    helper = native['binary']
    assert ref(R / helper['path']) == helper
    assert 1 <= helper['bytes'] <= 256 * 1024
    deb = package['deb']
    assert ref(R / deb['path']) == deb
    assert len(package['files']) == 1
    asset = package['files'][0]
    assert asset['path'] == '/usr/libexec/asus/startup-prepare' and asset['sha256'] == helper['sha256']
    rows = [dict(helper, target=asset['path'], mode='0755', old=old),
            dict(deb, target='/usr/share/asus/trial-additions/' + Path(deb['path']).name, mode='0644', old=None)]
    checks = [dict(row) for row in base['checks']]
    for row in base['regular_payloads']:
        check = {k: v for k, v in row.items() if k != 'old'}
        assert ref(R / check['path']) == {k: check[k] for k in ('path', 'sha256', 'bytes')}
        checks.append(check)
    assert not any(row['target'] == '/usr/libexec/asus/startup-prepare' for row in checks)
    assert any(row['target'] == '/usr/libexec/leon-asus/rescue-link'
               and row['sha256'] == 'bc4a5a7cdc368dafebd0ac172abed57bd3352436def9303bba656ed6f7a3a590' for row in checks)
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
    plan = {'schema': 1, 'status': 'fixed_trial_startup_v18_source_plan', 'builder': ref(Path(__file__)),
            'base': ref(BASE / 'manifest.json'), 'environment': ref(ENV), 'new_native': ref(pin(NATIVE)),
            'startup_package': ref(pin(PACKAGE)), 'link_source': base['link_source'],
            'source_inventory': sources, 'regular_payloads': rows, 'checks': checks,
            'source_changes': ['install.c', 'recovery-payload.h'], 'unchanged_source_files': 19,
            'worker_sha256': hashlib.sha256(worker.encode()).hexdigest(),
            'output': OUT.relative_to(R).as_posix(), 'work': WORK, 'cli': CLI, 'result_status': STATUS,
            'expected_counts': {'additions_published': 1, 'replacements_published': 1, 'links_created': 0,
                                'private_sh_links_replaced': 0, 'temporary_created': 2},
            'private_sh_inherited_verified_readonly_noop': True,
            'rescue_v17_helper_and_package_preserved': True,
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
    inp = Path(tempfile.mkdtemp(prefix='leon-v18-startup-build-')); inp.chmod(0o755)
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
    report = {**plan, 'status': 'fixed_trial_startup_v18_installer_built', 'approved_plan_sha256': gate,
              'installer': ref(OUT / 'install-additions'), 'compile_count': 1, 'returncode': 0,
              'installer_executed': False, 'device_accessed': False}
    (OUT / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'installer': report['installer']}))


if __name__ == '__main__':
    main()

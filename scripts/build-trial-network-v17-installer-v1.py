#!/usr/bin/env python3
"""Prepare/compile one fixed inactive-p11 update, retaining the proven guards."""
import argparse
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
ENV = R / 'build/asus-native-build/v2/result.json'
ENV_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
OUT = R / 'build/asus-trial-network-v17/install-v1'
WORK = 'trial-network-v17-installer-v1'
LINK_SOURCE = R / 'scripts/asus-integration/uplink-rescue/private-sh-link-update-v1.c.inc'
LINK_SHA = '08a349b255366f46d76bbfe50a7d304485dc0216a383a8ac5ed8b80bac47f9f2'
NEW_NATIVE = ('build/asus-uplink-rescue/native-v6/manifest.json', '83a31ea94c48bd55c1e103e0300424ab13da754c57918df7ad40b9d3bac97c1c')
NEW_RESCUE_PACKAGE = ('build/asus-uplink-rescue/package-v4/manifest.json', 'f8711704584a711f602f1213163e62d5ed7a7aa6039a95b7bdbe4bac086bc425')
NEW_SH_PACKAGE = ('build/asus-private-shell-dispatch-policy/package-v1/manifest.json', '0a12dda3bd369bd234229b23c1c1d1208d8460884252ae268abc0f3be36d4b87')
OLD_RESCUE = ('build/asus-uplink-rescue/package-v3/manifest.json', '82e3012cd335ce9f8df22f53d2113095a0fa7b1c25e8bdee17cde8f0c8209c53')
OLDER_RESCUE = ('build/asus-uplink-rescue/package-v2/manifest.json', 'a74d36081f61bde3be2c81a3109067df1679b9a4322ab687f2471e16dc3c0e37')
RC = ('build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-lan-ssh-policy-v7/linked/rc', 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2')
CLI = '--install-native-trial-network-v17'
STATUS = 'native_trial_network_v17_staged'


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
    assert __debug__ and not OUT.exists()
    assert sha(BASE / 'manifest.json') == BASE_SHA and sha(ENV) == ENV_SHA
    assert LINK_SHA is not None and sha(LINK_SOURCE) == LINK_SHA
    native = json.loads(pin(NEW_NATIVE).read_text())
    rescue = json.loads(pin(NEW_RESCUE_PACKAGE).read_text())
    shell = json.loads(pin(NEW_SH_PACKAGE).read_text())
    old_rescue = json.loads(pin(OLD_RESCUE).read_text())
    assert native['status'] == 'built_not_executed' and native['returncode'] == 0
    assert rescue['no_maintainer_scripts_triggers_presets_activation']
    assert not rescue['helper_executed'] and shell['automatic_activation'] is False
    assert pin(RC).stat().st_size == 7714412
    base = json.loads((BASE / 'manifest.json').read_text())
    assert inventory(BASE / 'source') == base['source_inventory'] and len(base['source_inventory']) == 21
    files = {p.relative_to(BASE / 'source').as_posix(): p.read_bytes()
             for p in sorted((BASE / 'source').rglob('*')) if p.is_file()}
    original = files['install.c'].decode()
    code = original
    for old, new in [('--install-native-uplink-rescue', CLI), ('native_uplink_rescue_staged', STATUS),
                     ('LEON_UPLINK_RESCUE_INSTALL_REFUSED', 'LEON_TRIAL_NETWORK_V17_INSTALL_REFUSED')]:
        code = once(code, old, new)
    code = once(code, 'static int target_preflight(', LINK_SOURCE.read_text() + '\nstatic int target_preflight(')
    code = once(code, 'candidate_link_check(root,&recovery_links[i],1,&links[i].present,&links[i].before)',
                'candidate_link_check(root,&recovery_links[i],0,&links[i].present,&links[i].before)')
    code = once(code, '    unsigned enabled=0,replaced=0;\n',
                '    unsigned enabled=0,replaced=0,sh_replaced=0;\n')
    code = once(code, '    struct candidate_link_state links[RECOVERY_LINK_COUNT]={0};\n',
                '    struct candidate_link_state links[RECOVERY_LINK_COUNT]={0};\n    struct private_sh_state sh={0};\n')
    code = once(code, '    /* Same immutable physical recheck under the same lock, before publication. */',
                '    if(private_sh_preflight(root,&sh)||!sh.already_new)goto done;\n    /* Same immutable physical recheck under the same lock, before publication. */')
    code = once(code, '    stage="sync-readback-and-preservation";\n',
                '    if(private_sh_publish(root,&sh,&sh_replaced,&temporary))goto done;\n    stage="sync-readback-and-preservation";\n')
    code = once(code, '    close(root);root=-1;\n',
                '    if(private_sh_preserved(root,&sh))goto done;\n    close(root);root=-1;\n')
    code = once(code, 'mode_changed=%d links=%u retained_for_review=',
                'mode_changed=%d links=%u sh_replaced=%u retained_for_review=')
    code = once(code, 'stage,temporary,published,replaced,mode_changed,enabled);',
                'stage,temporary,published,replaced,mode_changed,enabled,sh_replaced);')
    code = once(code, '\\"links_created\\":%u,\\"mode_changed\\":false',
                '\\"links_created\\":%u,\\"private_sh_links_replaced\\":%u,\\"mode_changed\\":false')
    code = once(code, 'argv[3],argv[2],published,replaced,temporary,enabled);',
                'argv[3],argv[2],published,replaced,temporary,enabled,sh_replaced);')
    files['install.c'] = code.encode()
    old_helper = next(row for row in old_rescue['files'] if row['path'] == '/usr/libexec/leon-asus/rescue-link')
    new_helper = next(row for row in rescue['files'] if row['path'] == old_helper['path'])
    assert new_helper['sha256'] == native['binary']['sha256']
    assert old_helper['sha256'] == '3f7a7949d7740c3c6f8f27f114a81c1a7d8698d49161049d5f9cd164c5e7fd97'
    assert old_helper['bytes'] == 73720
    assert sha(R / new_helper['source']) == new_helper['sha256']
    assert (R / new_helper['source']).stat().st_size == new_helper['bytes']
    rows = [dict(ref(R / new_helper['source']), target=new_helper['path'], mode='0755', old=old_helper)]
    for package in (rescue,):
        deb = package.get('deb', package['package'])
        assert sha(R / deb['path']) == deb['sha256']
        assert (R / deb['path']).stat().st_size == deb['bytes']
        rows.append(dict(ref(R / deb['path']), target='/usr/share/asus/trial-additions/' + Path(deb['path']).name,
                         mode='0644', old=None))
    checks = [dict(row) for row in base['check_only_preserve']]
    rc = checks[-1]
    assert rc['target'] == '/usr/libexec/asus/rc'
    rc.update(ref(pin(RC)), mode='0755')
    for row in old_rescue['files']:
        if row['path'] != old_helper['path']:
            assert sha(R / row['source']) == row['sha256']
            assert (R / row['source']).stat().st_size == row['bytes']
            checks.append(dict(ref(R / row['source']), target=row['path'], mode=row['mode']))
    assert sha(R / old_rescue['deb']['path']) == old_rescue['deb']['sha256']
    checks.append(dict(ref(R / old_rescue['deb']['path']), target=old_rescue['staged_deb_install_target'], mode='0644'))
    older_rescue=json.loads(pin(OLDER_RESCUE).read_text())
    for prior in (older_rescue,shell):
        deb=prior.get('deb',prior['package'])
        assert sha(R/deb['path'])==deb['sha256'] and (R/deb['path']).stat().st_size==deb['bytes']
        checks.append(dict(ref(R/deb['path']),target='/usr/share/asus/trial-additions/'+Path(deb['path']).name,mode='0644'))
    for name, digest in [('ash','9ef57c1e25b49471e581e35994603fd7ac8b8096d0862f9e7cc0dcc9012df80a'),
                         ('busybox','686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6')]:
        path = R / ('build/asus-native-helpers/v3/ash' if name == 'ash' else 'build/asus-private-shell/native-v4/busybox-native')
        assert sha(path) == digest
        checks.append(dict(ref(path), target='/usr/libexec/asus/' + name, mode='0755'))
    original_rule_path = R / 'build/asus-udev-dummy0-policy/package-v1/original-99-systemd.rules'
    assert sha(original_rule_path) == checks[0]['sha256']
    assert original_rule_path.stat().st_size == checks[0]['bytes']
    for row in [*rows, *checks[1:]]:
        assert sha(R / row['path']) == row['sha256'] and (R / row['path']).stat().st_size == row['bytes']
    # Preserve the layout and fixed native/original-rule, socket/timer, public-key
    # declarations. Generate only the reviewed regular descriptor tables.
    old_header = files['recovery-payload.h'].decode()
    layout = old_header[:old_header.index('static const unsigned char recovery_data_0[]')]
    h = layout
    for i, row in enumerate(rows):
        raw = (R / row['path']).read_bytes()
        assert 1 <= len(raw) <= 256 * 1024
        h += f'static const unsigned char recovery_data_{i}[]={{\n'
        h += '\n'.join(','.join(f'0x{x:02x}' for x in raw[n:n+16]) + ',' for n in range(0,len(raw),16)) + '\n};\n'
    h += 'static const struct recovery_payload recovery_payloads[]={\n'
    for i,row in enumerate(rows):
        old = row['old']
        h += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        h += f',recovery_data_{i},sizeof(recovery_data_{i}),' + row['mode'] + ','
        h += ('NULL,0' if old is None else json.dumps(old['sha256']) + ',' + str(old['bytes'])) + '},\n'
    h += '};\n#define RECOVERY_PAYLOAD_COUNT (sizeof(recovery_payloads)/sizeof(recovery_payloads[0]))\n'
    original_rule = re.findall(r'static const struct recovery_payload recovery_original_rule=\{[^\n]+;', old_header)
    assert len(original_rule) == 1
    h += original_rule[0] + '\nstatic const struct recovery_payload recovery_checks[]={\n'
    for row in checks[1:]:
        h += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        h += ',NULL,' + str(row['bytes']) + ',' + row['mode'] + ',NULL,0},\n'
    h += '};\n#define RECOVERY_CHECK_COUNT (sizeof(recovery_checks)/sizeof(recovery_checks[0]))\n'
    h += old_header[old_header.index('static const struct candidate_link recovery_links[]='):]
    files['recovery-payload.h'] = h.encode()
    worker = (BASE / 'build.sh').read_text()
    assert worker.count(base['native_work_label']) == 3
    worker = worker.replace(base['native_work_label'], WORK)
    sources = {name: hashlib.sha256(raw).hexdigest() for name,raw in sorted(files.items())}
    assert [name for name in sources if sources[name] != base['source_inventory'][name]] == ['install.c','recovery-payload.h']
    plan = {'schema':1,'status':'fixed_trial_network_v17_source_plan','builder':ref(Path(__file__)),
            'base':ref(BASE / 'manifest.json'),'environment':ref(ENV),'new_native':ref(pin(NEW_NATIVE)),
            'rescue_package':ref(pin(NEW_RESCUE_PACKAGE)),'private_sh_package':ref(pin(NEW_SH_PACKAGE)),
            'link_source':ref(LINK_SOURCE),'source_inventory':sources,'regular_payloads':rows,
            'checks':checks,'source_changes':['install.c','recovery-payload.h'],
            'unchanged_source_files':19,'worker_sha256':hashlib.sha256(worker.encode()).hexdigest(),
            'output':OUT.relative_to(R).as_posix(),'work':WORK,'cli':CLI,'result_status':STATUS,
            'expected_counts':{'additions_published':1,'replacements_published':1,'links_created':0,
                               'private_sh_links_replaced':0,'temporary_created':2},
            'private_sh_inherited_verified_readonly_noop':True,
            'no_account_key_boot_firmware_service_or_package_database_changes':True}
    return plan,files,worker


def main():
    p=argparse.ArgumentParser();p.add_argument('--execute-plan-sha256');a=p.parse_args()
    plan,files,worker=prepare();gate=hashlib.sha256(canonical(plan)).hexdigest()
    if a.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256':gate,'plan':plan},indent=2));return
    assert a.execute_plan_sha256 == gate
    root=Path(json.loads(ENV.read_text())['root']);assert not (root / 'work' / WORK).exists()
    OUT.mkdir(parents=True)
    for name,raw in files.items():
        path=OUT / 'source' / name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    (OUT / 'build.sh').write_text(worker);(OUT / 'compile-plan.json').write_bytes(canonical(plan))
    inp=Path(tempfile.mkdtemp(prefix='leon-v17-network-build-'));inp.chmod(0o755)
    shutil.copytree(OUT / 'source',inp / 'source');shutil.copyfile(OUT / 'build.sh',inp / 'build.sh')
    with (OUT / 'build.log').open('wb') as log:
        run=subprocess.run(['mmdebstrap','--unshare-helper','bash',str(inp / 'build.sh'),str(root),str(inp)],stdout=log,stderr=subprocess.STDOUT)
    (OUT / 'returncode.json').write_text(json.dumps({'returncode':run.returncode,'compile_count':1})+'\n')
    assert run.returncode == 0, 'One compile failed; retained evidence, no retry'
    work=root / 'work' / WORK
    assert inventory(work) == {**plan['source_inventory'],'install-additions':sha(work / 'install-additions'),'elf.txt':sha(work / 'elf.txt')}
    for name in ('install-additions','elf.txt'):shutil.copyfile(work / name,OUT / name)
    (OUT / 'install-additions').chmod(0o755)
    elf=(OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    report={**plan,'status':'fixed_trial_network_v17_installer_built','approved_plan_sha256':gate,
            'installer':ref(OUT / 'install-additions'),'compile_count':1,'returncode':0,
            'installer_executed':False,'device_accessed':False}
    (OUT / 'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'manifest':ref(OUT / 'manifest.json'),'installer':report['installer']}))


if __name__ == '__main__':
    main()

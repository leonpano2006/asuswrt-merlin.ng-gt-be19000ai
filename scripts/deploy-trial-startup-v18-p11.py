#!/usr/bin/env python3
"""One clean-only inactive-p11 network fix; default is a local plan."""
import argparse, ast, hashlib, json, shlex, struct, subprocess
from pathlib import Path
R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000032'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py', 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
MANIFEST = ('build/asus-trial-startup-v18/install-v1/manifest.json', 'fe8ce24d157c2b22625003a8ac3a7366b09182ab8500ef19c2814f82f4c107f0')
INSTALLER = ('build/asus-trial-startup-v18/install-v1/install-additions', 'f5fd8d28521fef0eeb12ff2ba923e8ca9369806b01b31d4a09b60a8fe5f6d96b')
FIXTURE = ('build/asus-uplink-rescue/rule-route-focused-fixture-v1/result.json', '436358fe5485a92d89b13efcb56ceb088172834dae340d0880151e2fa5623277')
SH_FIXTURE = ('build/asus-private-shell-dispatch-policy/focused-fixture-v1/result.json', '99985e8c1282efbaf0bd11624d055d820ecd7ff089908659b50413254de3e044')
RESCUE_NATIVE = ('build/asus-uplink-rescue/native-v6/manifest.json', '83a31ea94c48bd55c1e103e0300424ab13da754c57918df7ad40b9d3bac97c1c')
NATIVE = ('build/asus-startup/scoped-udev-native-v1/validated-manifest.json', 'dbef69abeb91de3becf2a19f5b30d86ce30a60362201b43a8cbaf135f29d3559')
REMOTE = '/tmp/leon-trial-startup-v18-f5fd8d28521fef0e'
OUT = R / 'evidence/ubuntu26/device-trial-startup-v18-live/install-v1'
FLAG = '--install-native-trial-startup-v18'
OUTER_STATUS = 'fixed_trial_startup_v18_p11_staged_no_boot_selection'
GUARD = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT)
         + '; grep -Eq \'(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)\' /proc/cmdline; ')
def require(value, message):
    if not value:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def ref(path):
    require(path.is_file() and not path.is_symlink(), 'Pinned regular file required: ' + str(path))
    return {'path': str(path.relative_to(R)), 'sha256': sha(path), 'bytes': path.stat().st_size}

def pinned(row):
    value = ref(R / row[0])
    require(row[1] is not None and value['sha256'] == row[1], 'Pinned file differs: ' + row[0])
    return value

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def transport_node():
    pinned(TRANSPORT)
    source = (R / TRANSPORT[0]).read_text()
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    require(len(nodes) == 1 and not nodes[0].decorator_list, 'One frozen transport function required')
    return nodes[0], hashlib.sha256(ast.get_source_segment(source, nodes[0]).encode()).hexdigest()

def transport_only():
    node, _ = transport_node()
    namespace = {'__builtins__': {}, 'shlex': shlex}
    exec(compile(ast.Module(body=[node], type_ignores=[]), TRANSPORT[0] + ':transport-only', 'exec'), namespace)
    return namespace['transport']

def prepare():
    require(__debug__, 'Python -O forbidden')
    m,i = pinned(MANIFEST),pinned(INSTALLER)
    require(REMOTE == '/tmp/leon-trial-startup-v18-' + i['sha256'][:16], 'Fixed unique transfer required')
    data=json.loads((R / MANIFEST[0]).read_text())
    fixture_ref=pinned(FIXTURE);fixture=json.loads((R/FIXTURE[0]).read_text())
    rescue_native_ref=pinned(RESCUE_NATIVE);rescue_native=json.loads((R/RESCUE_NATIVE[0]).read_text())
    require(fixture['status']=='pure_production_rule_route_fixture_passed'
            and fixture['returncode']==0 and fixture['expected_case_count']==29
            and len(fixture['cases'])==29 and all(x['pass'] is True for x in fixture['cases'])
            and fixture['inputs']['production_source']==ref(R/rescue_native['sources']['new']['path']),
            'Previously completed unchanged rescue policy proof required')
    sh_fixture_ref=pinned(SH_FIXTURE);sh_fixture=json.loads((R/SH_FIXTURE[0]).read_text())
    require(sh_fixture['status']=='isolated_three_case_private_sh_fixture_passed'
            and sh_fixture['link']==data['link_source'],'Prior unchanged private shell proof retained')
    native_ref=pinned(NATIVE);native=json.loads((R/NATIVE[0]).read_text())
    require(data['new_native']==native_ref and native['status']=='built_not_executed'
            and native['returncode']==0 and native['compile_count']==native['source_compile_invocations']==1,
            'Exactly one completed scoped startup helper compile required')
    require(data['status']=='fixed_trial_startup_v18_installer_built' and data['installer']==i
            and data['compile_count']==1 and data['returncode']==0 and not data['installer_executed']
            and not data['device_accessed'] and data['unchanged_source_files']==19,
            'Source-bound frozen-guard static installer required')
    require(data['private_sh_inherited_verified_readonly_noop'] is True
            and data['rescue_v17_helper_and_package_preserved'] is True,'Inherited networking preserved')
    require(data['cli']==FLAG and data['expected_counts']=={
        'additions_published':1,'replacements_published':1,'links_created':0,
        'private_sh_links_replaced':0,'temporary_created':2},'Exact fixed update required')
    helper=data['regular_payloads'][0]
    require(helper['target']=='/usr/libexec/asus/startup-prepare'
            and {k:helper[k] for k in ('path','sha256','bytes')}==native['binary']
            and helper['old']['sha256']=='27c226d22963fe37a674c0975a5426b88eefd3607dce3cb966334df033bb119c'
            and helper['old']['bytes']==87544,'Only original startup helper replacement required')
    for row in data['regular_payloads']:
        require(ref(R/row['path'])=={k:row[k] for k in ('path','sha256','bytes')},'Payload binding')
    require(any(row['target']=='/usr/libexec/leon-asus/rescue-link'
                and row['sha256']=='bc4a5a7cdc368dafebd0ac172abed57bd3352436def9303bba656ed6f7a3a590'
                for row in data['checks']),'Actual V17 rescue retained')
    pinned(TRANSPORT)
    return {'schema':1,'status':'fixed_trial_startup_v18_p11_source_plan','wrapper':ref(Path(__file__)),
            'manifest':m,'installer':i,'reused_rescue_fixture':fixture_ref,'reused_shell_fixture':sh_fixture_ref,
            'rescue_native_manifest':rescue_native_ref,'native_manifest':native_ref,'boot_id':BOOT,'metadata_sha256':META,
            'expected_counts':data['expected_counts'],'helper_sha256':helper['sha256'],
            'outer_success_status':OUTER_STATUS,'evidence_output':str(OUT.relative_to(R)),
            'ready_for_execution':True,'clean_only':True,'recovery_permitted':False,
            'firmware_flashing':False,'boot_selected':False,'rebooted':False,'boot_committed':False}


def execute(plan, approved):
    require(hashlib.sha256(canonical(plan)).hexdigest() == approved, 'Exact reviewed execution plan SHA required')
    require(plan['ready_for_execution'] is True, 'Reviewed local network update build prerequisites required before any output/transport')
    OUT.mkdir(parents=True, exist_ok=False)
    transport = transport_only()
    result_plan = {**plan, 'approved_execution_plan_sha256': approved, 'installer_started': False,
                   'published': False, 'status': 'started_fixed_trial_startup_v18_stage'}

    def call(label, command, timeout, binary=None):
        try:
            if binary is None:
                run = subprocess.run(transport(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=timeout)
            else:
                with binary.open('rb') as stream:
                    run = subprocess.run(transport(command), stdin=stream, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            (OUT / (label + '.stdout')).write_bytes(exc.stdout or b'')
            (OUT / (label + '.stderr')).write_bytes(exc.stderr or b'')
            raise
        (OUT / (label + '.stdout')).write_bytes(run.stdout)
        (OUT / (label + '.stderr')).write_bytes(run.stderr)
        result_plan[label + '_returncode'] = run.returncode
        require(run.returncode == 0, 'Step refused: ' + label + '; evidence retained, no retry')
        return run.stdout

    try:
        fixed = ('test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; '
                 'test "$(cat /sys/class/block/mmcblk0p11/dev)" = 179:11; '
                 'test "$(cat /sys/class/block/mmcblk0p11/start)" = 26849280; '
                 'test "$(cat /sys/class/block/mmcblk0p11/size)" = 25165824; ')
        sb = call('superblock-before', GUARD + fixed + 'exec /bin/busybox dd if=/dev/mmcblk0p11 bs=1024 skip=1 count=1', 20)
        require(len(sb) == 1024 and sb[56:58] == b'\x53\xef'
                and sb[104:120].hex() == 'ea8e47b8c606406cb931d2244d26ec55', 'Fixed p11 superblock required')
        fields = {'state': struct.unpack_from('<H', sb, 58)[0], 'needs_recovery': bool(struct.unpack_from('<I', sb, 96)[0] & 4),
                  'error_count': struct.unpack_from('<I', sb, 404)[0], 'last_orphan': struct.unpack_from('<I', sb, 232)[0]}
        result_plan['superblock_before'] = fields
        require(fields == {'state': 1, 'needs_recovery': False, 'error_count': 0, 'last_orphan': 0},
                'p11 is not clean; stop without recovery or mount')
        command = (GUARD + 'umask 077; test ! -e ' + shlex.quote(REMOTE) + '; test ! -L '
                   + shlex.quote(REMOTE) + '; set -C; cat > ' + shlex.quote(REMOTE)
                   + '; set +C; set -- $(sha256sum ' + shlex.quote(REMOTE) + '); test "$1" = '
                   + INSTALLER[1] + '; chmod 700 ' + shlex.quote(REMOTE))
        call('installer-transfer', command, 180, R / INSTALLER[0])
        result_plan['installer_dispatched'] = True
        result_plan['installer_started'], result_plan['published'] = None, None
        installed = json.loads(call('installer', GUARD + 'exec ' + shlex.join([REMOTE, FLAG, META, BOOT]), 330))
        require(installed['schema'] == 1 and installed['status'] == 'native_trial_startup_v18_staged'
                and installed['boot_id'] == BOOT and installed['metadata_sha256'] == META,
                'Exact network update receipt required')
        for key, value in plan['expected_counts'].items():
            require(installed[key] == value, 'First network update count: ' + key)
        for key in ('native_identity_unchanged', 'known_preserved_leaf_inodes_unchanged', 'prerequisites_unchanged'):
            require(installed[key] is True, 'Network update preservation receipt: ' + key)
        for key in ('mode_changed', 'package_database_updated', 'armed', 'rebooted', 'boot_committed'):
            require(installed[key] is False, 'Network update must not change: ' + key)
        result_plan.update(status=OUTER_STATUS,
                           installer_started=True, published=True, installer_result=installed)
    except Exception as exc:
        result_plan.update(status='failed_evidence_preserved_no_repeat', error=str(exc))
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(result_plan, indent=2) + '\n')
        print(json.dumps(result_plan), flush=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true')
    group.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan = prepare()
    gate = hashlib.sha256(canonical(plan)).hexdigest()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)

if __name__ == '__main__':
    main()

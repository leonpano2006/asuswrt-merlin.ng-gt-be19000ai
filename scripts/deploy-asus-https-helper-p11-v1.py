#!/usr/bin/env python3
"""One clean-only inactive-p11 inert HTTPS staging; default is a local plan."""
import argparse, ast, hashlib, json, shlex, struct, subprocess
from pathlib import Path
R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000035'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py', 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
BASE_WRAPPER = ('scripts/deploy-trial-network-v21-p11.py', 'fbdb37f04a6fd150633598af320eb15dbbb85296186629ef9dfabd968a2e0a48')
BASE = ('build/asus-trial-network-v21/install-v1/manifest.json', '1ea1ce0152723a6130295bc83107794e36cd844fd3786bbcfd33e0fa7fb340ed')
MANIFEST = ('build/asus-https-helper/install-v1/manifest.json', '8909ffaa23f6046a7ffa18e85584d7debefaa5a826036e62e2e38b804601a796')
INSTALLER = ('build/asus-https-helper/install-v1/install-additions', 'fa2564f1ec98217135230bf923c55b90bc9b7f70959e6b43b6c5a4b8fcb93909')
BUILD_RECEIPT = ('reports/ubuntu26/https-helper-installer-build-v1.json', '98abbc4628024953aa76f391af62c6c995da70307ee7c9eed407e8987aa8fd0b')
SOURCE_PEER = ('reports/ubuntu26/https-helper-installer-source-peer-v1.json', '532a43457cf4b1dcf2527809b98c8c2c420853f983f46630a7b186b9603ac17b')
REUSED_FIXTURE = ('build/asus-uplink-rescue/rule-route-focused-fixture-v1/result.json', '436358fe5485a92d89b13efcb56ceb088172834dae340d0880151e2fa5623277')
SH_FIXTURE = ('build/asus-private-shell-dispatch-policy/focused-fixture-v1/result.json', '99985e8c1282efbaf0bd11624d055d820ecd7ff089908659b50413254de3e044')
RESCUE_NATIVE = ('build/asus-uplink-rescue/native-v6/manifest.json', '83a31ea94c48bd55c1e103e0300424ab13da754c57918df7ad40b9d3bac97c1c')
NATIVE = ('build/asus-uplink-rescue/native-v8/manifest.json', '5577ec95befc9414847f3c0b366d876825906ab5e22ad5ff853bf7b652b99491')
STARTUP_NATIVE = ('build/asus-startup/scoped-udev-native-v1/validated-manifest.json', 'dbef69abeb91de3becf2a19f5b30d86ce30a60362201b43a8cbaf135f29d3559')
FIXTURE = ('build/asus-uplink-rescue/compat8437-rule-fixture-v1/result.json', '11ff601eca517b7cbbf912a10c3090c13cc7a07417d8e2356788ae8522a342b9')
STOCK = ('evidence/ubuntu26/trial-live/twentyfirst-stock2-return-v1/stock-result.json', 'aebb807e3539fe69b717b6423c839e28d291015dcdb257243b188d5dba8d5691')
REMOTE = '/tmp/leon-https-helper-v1-fa2564f1ec982171'
OUT = R / 'evidence/ubuntu26/device-https-helper-live/install-v1'
FLAG = '--install-native-https-helper-v1'
OUTER_STATUS = 'fixed_https_helper_v1_p11_staged_no_boot_selection'
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
    require(all(row[1] is not None for row in (MANIFEST, INSTALLER, BUILD_RECEIPT, SOURCE_PEER)),
            'Pending HTTPS proof blocks before output or transport')
    m,i = pinned(MANIFEST),pinned(INSTALLER)
    require(REMOTE == '/tmp/leon-https-helper-v1-' + i['sha256'][:16], 'Fixed unique transfer required')
    data=json.loads((R/MANIFEST[0]).read_text())
    baseline_ref=pinned(BASE);baseline=json.loads((R/BASE[0]).read_text())
    require(data['base']==baseline_ref and baseline['status']=='fixed_trial_network_v21_installer_built'
            and baseline['compile_count']==1 and baseline['returncode']==0 and not baseline['installer_executed'],
            'Completed V21 frozen baseline required')
    require(data['status']=='fixed_https_helper_v1_installer_built' and data['installer']==i
            and data['compile_count']==1 and data['returncode']==0 and not data['installer_executed']
            and not data['device_accessed'] and data['unchanged_source_files']==19
            and data['source_changes']==['install.c','recovery-payload.h'], 'One source-bound static HTTPS installer required')
    base_source=R/BASE[0];base_source=base_source.parent/'source'
    new_source=(R/MANIFEST[0]).parent/'source'
    for name, digest in data['source_inventory'].items():
        require(ref(new_source/name)['sha256']==digest, 'Actual compiled source inventory differs: '+name)
        if name not in data['source_changes']:
            require(digest==baseline['source_inventory'][name] and ref(base_source/name)['sha256']==digest,
                    'Frozen device/identity/transaction source differs: '+name)
    for key in ('private_sh_inherited_verified_readonly_noop', 'all_existing_checks_and_current_rescue_startup_rc_retained',
                'current_telemetry_rc_marker_verified_before_after_inode_unchanged',
                'only_fixed_scripts_parent_created_missing_or_existing_root0755',
                'all_other_parents_strict_existing_nofollow_root0755',
                'existing_rescue_socket_alias_required_and_inode_preserved', 'only_fixed_gencert_command_alias_absent_or_identical',
                'reverse_literal_and_parent_transform_equals_frozen_install_c',
                'no_account_key_boot_firmware_service_or_package_database_changes'):
        require(data[key] is True, 'Fixed HTTPS source scope: '+key)
    require(data['cli']==FLAG and data['result_status']=='native_https_helper_v1_staged'
            and data['expected_counts']=={'additions_published':2,'replacements_published':0,'links_created':1,
                'private_sh_links_replaced':0,'temporary_created':2,'directories_created':1}, 'Exact inert HTTPS publication required')
    receipt_ref=pinned(BUILD_RECEIPT);receipt=json.loads((R/BUILD_RECEIPT[0]).read_text())
    require(receipt['manifest']==m and receipt['installer']==i and receipt['builder']==data['builder']
            and receipt['source_delta']==data['source_delta'] and receipt['returncode']==0 and receipt['compile_count']==1
            and receipt['source_compile_invocations']==1 and receipt['compiled_input_inventory_matches'] is True
            and receipt['static_pie_aarch64_no_interp_no_needed'] is True
            and receipt['installer_executed'] is False and receipt['device_accessed'] is False,
            'One actual compile and static ELF/source inventory inspection required')
    require(pinned((receipt['elf']['path'],receipt['elf']['sha256']))==receipt['elf'], 'ELF inspection receipt differs')
    for key in ('builder','source_delta','installer_source','https_package_manifest','telemetry_package_manifest'):
        require(pinned((data[key]['path'],data[key]['sha256']))==data[key], 'Artifact closure differs: '+key)
    peer_ref=pinned(SOURCE_PEER);peer=json.loads((R/SOURCE_PEER[0]).read_text())
    require(peer['status']=='source_go' and peer['builder']==data['builder']
            and peer['source_delta']==data['source_delta'] and peer['installer_source']==data['installer_source']
            and not peer['execution_performed'], 'Independent source GO required')
    package=json.loads((R/data['https_package_manifest']['path']).read_text())
    require(package['status']=='built_inert_not_installed' and package['no_target_script_run'] is True
            and package['no_enablement_hooks_triggers'] is True and not package['device_accessed'], 'Existing inert HTTPS Deb only')
    pkg=next(row for row in package['packages'] if row['name']=='leon-asus-https-helper')
    require(pkg['control_members']==['control','md5sums'] and len(pkg['inventory'])==3, 'No package hooks or unexpected leaves')
    require(len(data['regular_payloads'])==2, 'Only helper and cached Deb may be published')
    helper,deb=data['regular_payloads']
    require(helper['target']=='/usr/libexec/asus/scripts/gencert.sh' and helper['mode']=='0755'
            and helper['sha256']=='a52a57a1af92407bbf57c6e624a2c5c2f67f59163c9fab0d751d7693514ee517'
            and helper['bytes']==10430 and helper['old'] is None, 'Byte-exact original helper addition only')
    require(deb['target']=='/usr/share/asus/trial-additions/leon-asus-https-helper_0.1+leonb53.1_all.deb'
            and deb['mode']=='0644' and deb['sha256']=='08167f716ffb11bc905a391c968e22a66403eeb1d81958b42dc40d0d1e6937f2'
            and deb['bytes']==4292 and deb['old'] is None
            and {k:deb[k] for k in ('path','sha256','bytes')}=={k:pkg[k] for k in ('path','sha256','bytes')}, 'Existing cached Deb addition only')
    for row in data['regular_payloads']:
        require(ref(R/row['path'])=={k:row[k] for k in ('path','sha256','bytes')}, 'Payload binding')
    old_checks=[dict(row) for row in baseline['checks']]
    old_checks.extend({k:v for k,v in row.items() if k!='old'} for row in baseline['regular_payloads'])
    require(data['checks'][:-1]==old_checks and len(data['checks'])==25, 'Every V21 current preserved leaf remains strict')
    marker=data['checks'][-1]
    require(marker['target']=='/usr/share/asus/integration/rc.sha256' and marker['mode']=='0644'
            and marker['sha256']=='b0bf8ee66fdd11544be62edf5e54e5f0337b4470e920929247ef6d0d5e4ccb2b'
            and marker['bytes']==87 and ref(R/marker['path'])=={k:marker[k] for k in ('path','sha256','bytes')},
            'Current telemetry RC marker preserved instead of stale stock marker')
    fixture_ref=pinned(REUSED_FIXTURE);fixture=json.loads((R/REUSED_FIXTURE[0]).read_text())
    rescue_native_ref=pinned(RESCUE_NATIVE);rescue_native=json.loads((R/RESCUE_NATIVE[0]).read_text())
    require(fixture['status']=='pure_production_rule_route_fixture_passed' and fixture['returncode']==0
            and fixture['expected_case_count']==29 and len(fixture['cases'])==29 and all(x['pass'] is True for x in fixture['cases'])
            and fixture['inputs']['production_source']==ref(R/rescue_native['sources']['new']['path']), 'Previously completed unchanged rescue policy proof retained')
    sh_fixture_ref=pinned(SH_FIXTURE);sh_fixture=json.loads((R/SH_FIXTURE[0]).read_text())
    require(sh_fixture['status']=='isolated_three_case_private_sh_fixture_passed'
            and sh_fixture['link']==data['link_source'], 'Prior unchanged private shell proof retained')
    native_ref=pinned(NATIVE);native=json.loads((R/NATIVE[0]).read_text())
    require(baseline['new_native']==native_ref and native['status']=='built_not_executed' and native['returncode']==0
            and native['source_compile_invocations']==1 and any(row['target']=='/usr/libexec/leon-asus/rescue-link'
                and {k:row[k] for k in ('path','sha256','bytes')}=={**native['binary'],'bytes':73768} for row in data['checks']),
            'Current rescue98e check-only retained')
    startup_ref=pinned(STARTUP_NATIVE);startup=json.loads((R/STARTUP_NATIVE[0]).read_text())
    require(any(row['target']=='/usr/libexec/asus/startup-prepare'
                and {k:row[k] for k in ('path','sha256','bytes')}==startup['binary'] for row in data['checks']), 'Scoped startup699 retained')
    new_fixture_ref=pinned(FIXTURE);new_fixture=json.loads((R/FIXTURE[0]).read_text())
    require(baseline['raw_header_fixture']==new_fixture_ref and new_fixture['status']=='pure_production_compat8437_rule_fixture_passed'
            and new_fixture['returncode']==0 and new_fixture['compile_count']==new_fixture['fixture_run_count']==1
            and new_fixture['expected_case_count']==17 and len(new_fixture['cases'])==17 and all(row['pass'] is True for row in new_fixture['cases'])
            and new_fixture['inputs']['production_source']==ref(R/native['sources']['new']['path'])
            and not new_fixture['device_accessed'] and not new_fixture['service_netlink_or_write_functions_executed'], 'Current rescue canonical-rule proof retained')
    stock_ref=pinned(STOCK);stock=json.loads((R/STOCK[0]).read_text())
    require(stock['status']=='authenticated_new_stock2_return' and stock['boot_id']==BOOT and stock['metadata_sha256']==META
            and stock['reset_reason']=='34', 'Actual current stock2 lineage required')
    pinned(TRANSPORT);pinned(BASE_WRAPPER)
    return {'schema':1,'status':'fixed_https_helper_v1_p11_source_plan','wrapper':ref(Path(__file__)),
            'manifest':m,'installer':i,'build_receipt':receipt_ref,'source_peer':peer_ref,'v21_baseline':baseline_ref,
            'reused_rescue_fixture':fixture_ref,'reused_shell_fixture':sh_fixture_ref,'rescue_native_manifest':rescue_native_ref,
            'native_manifest':native_ref,'raw_header_fixture':new_fixture_ref,'scoped_startup_native_manifest':startup_ref,
            'current_stock_receipt':stock_ref,'boot_id':BOOT,'metadata_sha256':META,'expected_counts':data['expected_counts'],
            'helper_sha256':helper['sha256'],'outer_success_status':OUTER_STATUS,'evidence_output':str(OUT.relative_to(R)),
            'ready_for_execution':True,'clean_only':True,'recovery_permitted':False,'firmware_flashing':False,
            'boot_selected':False,'rebooted':False,'boot_committed':False}


def execute(plan, approved):
    require(hashlib.sha256(canonical(plan)).hexdigest() == approved, 'Exact reviewed execution plan SHA required')
    require(plan['ready_for_execution'] is True, 'Reviewed local HTTPS staging build prerequisites required before any output/transport')
    OUT.mkdir(parents=True, exist_ok=False)
    transport = transport_only()
    result_plan = {**plan, 'approved_execution_plan_sha256': approved, 'installer_started': False,
                   'published': False, 'status': 'started_fixed_https_helper_v1_stage'}

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
        require(installed['schema'] == 1 and installed['status'] == 'native_https_helper_v1_staged'
                and installed['boot_id'] == BOOT and installed['metadata_sha256'] == META,
                'Exact HTTPS staging receipt required')
        for key, value in plan['expected_counts'].items():
            require(installed[key] == value, 'First HTTPS staging count: ' + key)
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

#!/usr/bin/env python3
"""One V20 selector and separate reboot; saved full metadata plus fresh hashes.

Default is a local plan. Pending actual V20 p11-stage pins block device access.
Reuses historical V19 firmware/guardian with fresh component readback.
No raw metadata transport, flash, ACK, permanent commit, tests or target build.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess

R = Path(__file__).resolve().parents[1]
BASE = ('scripts/trial-startup-v18.py', 'd0df3c1f96cf870d0d3e54bcb98707ee9207e37fc9b027aa378f7b124fb07aa8')
FLASH_SOURCE = ('scripts/flash-scoped-udev-guardian30-v19.py', 'f9e2185b95bd6ccb1aece4de7efc956e7b63a00716f879f36f5805c395f7461f')
FLASH_RECEIPT = ('evidence/ubuntu26/flash-live/nineteenth-inactive-flash-v1/result.json', '3b6a734f828d70604b5db1c1b6d8bdb5120879a0e71cf025e17efacece9eacb1')
BOOT = '00000000-0000-4000-8000-000000000033'
OLD_BOOT = '00000000-0000-4000-8000-000000000032'
V19_TEMPLATE = ('scripts/trial-guardian30-v19.py', '44412e719ab659fbc1f01f5e7d35967f7b5a495f4c59dbbc6d2131c11beac45f')
HISTORICAL_FLASH_BOOT = '00000000-0000-4000-8000-000000000017'
NATIVE_V19_BOOT = '00000000-0000-4000-8000-000000000030'
STOCK = ('evidence/ubuntu26/trial-live/nineteenth-return-forensics-v1/stock-result.json', 'd4c0ae8f60bcee6330d71edfc2a83aeecd7c08c6219930475ab19e7ea289f94f')
CLEAN_EXPORT = ('evidence/ubuntu26/trial-live/nineteenth-return-forensics-v1/result.json', 'b2e6ddc3b31e1d4ccd7f2b0dca8c57c9d363f28d7d5b15f1e3d44e0b9e9a80a8')
EXPORT = ('evidence/ubuntu26/trial-live/nineteenth-return-forensics-v1/export.stdout', '61450fbc376ef664d3d68ec4ff976a5e63ab5f080f8d4017179e0dff80e375fc')
NATIVE_PROOF = ('reports/ubuntu26/v19-native-and-rescue-diagnosis.json', '92bcde3b75673ef40138b3f5a384b52e4a339411f10d960eb53e1c99b8f712ab')
STAGE_SOURCE = ('scripts/deploy-trial-network-v20-p11.py', 'f28fa52b66a0dfddd03463502dafede3063b719160293502bb4b015a5971dbb0')
STAGE_RECEIPT = ('evidence/ubuntu26/device-trial-network-v20-live/install-v1/result.json', 'd584ac8c5dd210930b25d28c5b10f590cfa27b101e4d66e5e37dfaeeaa1b342c')
COUNTS = {'additions_published':1, 'replacements_published':1, 'links_created':0,
          'private_sh_links_replaced':0, 'temporary_created':2}
SAVED_DIRECTORY = R / 'evidence/ubuntu26/trial-live/post-selection-v18'
SAVED_VERIFIED = ('evidence/ubuntu26/trial-live/post-selection-v18/verified.json', '50ffe39798d39d5ae2978830499ae2122b92ca2b47c69f0d1aef75e2dfaa720b')
SAVED_FINISH = ('evidence/ubuntu26/trial-live/eighteenth-selection-finish-v2/finish-result.json', 'dc8fee282c110b3ace8adb9eadda0c82f9a35bf890dc5aecdc385b3516b9b22f')
LIVE = R / 'evidence/ubuntu26/trial-live'
DIRECTORY = LIVE / 'twentieth-selection-capture-v1'
SELECT_ATTEMPT = LIVE / 'twentieth-selection-attempt-v1.json'
SELECT_RESULT = LIVE / 'twentieth-selection-result-v1.json'
REBOOT_ATTEMPT = LIVE / 'twentieth-reboot-attempt-v1.json'
REBOOT_RESULT = LIVE / 'twentieth-reboot-result-v1.json'
METHOD = 'saved_full_metadata_plus_fresh_device_hashes'


def frozen(row, name):
    path = R / row[0]
    if not __debug__ or not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != row[1]:
        raise RuntimeError('Exact frozen source required; Python -O forbidden')
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # Never invoke any imported CLI main/execute.
    return mod


def guard(mod, reason, report=False):
    command = mod.guard(reason)
    if report:
        for part in (1, 2):
            old = 'set -- $(/bin/busybox sha256sum /dev/mmcblk0p' + str(part) + '); test "$1" = ' + mod.META
            mod.require(command.count(old) == 1, 'Exact frozen full metadata hash clause')
            new = old + '; /bin/busybox printf "METADATA' + str(part) + '_SHA256=%s\\n" "$1"'
            command = command.replace(old, new)
    command += 'test "$(uname -r)" = 4.19.294; case "$(uname -v)" in "#1 "*) ;; *) exit 1 ;; esac; '
    return command


def current_evidence(mod):
    stock_ref=mod.pinned(STOCK,64*1024);stock=json.loads((R/STOCK[0]).read_text())
    mod.exact(stock,{'status':'authenticated_new_stock2_return','boot_id':BOOT,'metadata_sha256':mod.META,
                     'reset_reason':'34','manual_powercycle_requested':False,'manual_powercycle_performed':False},'Actual current stock2 return')
    for value in stock['originals'].values():
        mod.require(mod.pinned((value['path'],value['sha256']),8192)==value,'Hash-bound actual stock source proof')
    original=json.loads((R/stock['originals']['result.json']['path']).read_text())
    mod.exact(original,{'returncode':0,'ACK_sent':False,'settings_changed':False,'manual_powercycle_performed':False},'Actual authenticated return capture')
    raw=(R/stock['originals']['stdout']['path']).read_text()
    mod.require(raw.startswith('boot='+BOOT+'\nreason=34\n4.19.294\n#1 ')
                and raw.count('root=/dev/mmcblk0p6')==1 and 'root=/dev/mmcblk0p4' not in raw,
                'Current authenticated stock2 root/kernel context')
    clean_ref=mod.pinned(CLEAN_EXPORT,64*1024);clean=json.loads((R/CLEAN_EXPORT[0]).read_text())
    mod.exact(clean,{'status':'clean_only_export_complete','boot_id':BOOT,'metadata_sha256':mod.META,
                     'export_sha256':EXPORT[1],'rebooted':False,'boot_selected':False,'git_commit_or_push':False},'Actual current clean export')
    mod.exact(clean['recovery'],{'status':'p11_preen_completed_and_frozen_clean_gates_passed','boot_id':BOOT,
                                'metadata_sha256':mod.META,'e2fsck_exit':0,'child_starts':1,'retries':0,
                                'mounted':False,'provisioned':False,'armed':False,'rebooted':False,'boot_committed':False},'Actual single completed preen proof')
    export_ref=mod.pinned(EXPORT,256*1024*1024)
    mod.require(export_ref['bytes']==clean['export_bytes'],'Actual bounded export bytes')
    native_ref=mod.pinned(NATIVE_PROOF,64*1024);native=json.loads((R/NATIVE_PROOF[0]).read_text())
    mod.exact(native,{'status':'v19_native_success_backup_route_parser_failure_and_actual_automatic_stock2_return',
                      'native_boot_id':NATIVE_V19_BOOT,'native_primary_login_passed':True,'backup_login_passed':False,
                      'guardian_preflight_passed_and_ARMED':True,'UBUNTU_EXEC_proved':True,
                      'actual_current_stock2_boot_id':BOOT,'metadata_sha256':mod.META,'ACK_sent':False,
                      'manual_powercycle_performed':False,'permanent_acceptance':False,'git_commit_or_push':False},'Actual native V19 evidence kept separate from current stock boot')
    for value in native['evidence'].values():
        mod.require(mod.pinned((value['path'],value['sha256']),256*1024)==value,'Hash-bound actual V19 native analysis proof')
    return {'receipt':stock_ref,'originals':stock['originals']},clean_ref,export_ref,native_ref


def staged_proof(mod):
    ready=STAGE_SOURCE[1] is not None and STAGE_RECEIPT[1] is not None
    if not ready:return False,{'path':STAGE_RECEIPT[0],'sha256':STAGE_RECEIPT[1],'ready':False}
    deploy=frozen(STAGE_SOURCE,'frozen_v20_p11_deploy_source_for_selection')
    stage_plan=deploy.prepare()  # Pure pins only; never its execute/main.
    mod.require(stage_plan['boot_id']==BOOT and stage_plan['metadata_sha256']==mod.META
                and stage_plan['expected_counts']==COUNTS,'Reviewed same-boot p11-only source plan')
    stage_ref=mod.pinned(STAGE_RECEIPT,256*1024);data=json.loads((R/STAGE_RECEIPT[0]).read_text())
    mod.exact(data,{'schema':1,'status':'fixed_trial_network_v20_p11_staged_no_boot_selection','boot_id':BOOT,
                   'metadata_sha256':mod.META,'installer_returncode':0,'installer_started':True,'published':True,
                   'superblock-before_returncode':0,'installer-transfer_returncode':0,'clean_only':True,
                   'recovery_permitted':False,'firmware_flashing':False,'boot_selected':False,
                   'rebooted':False,'boot_committed':False},'Actual V20 p11-stage PASS required')
    for key,value in stage_plan.items():
        if key!='status':mod.require(data.get(key)==value,'Actual stage source/artifact binding: '+key)
    mod.exact(data['superblock_before'],{'state':1,'needs_recovery':False,'error_count':0,'last_orphan':0},'Actual preinstall clean-only gate')
    native=data['installer_result']
    mod.exact(native,{'schema':1,'status':'native_trial_network_v20_staged','boot_id':BOOT,'metadata_sha256':mod.META,
                      **COUNTS,'mode_changed':False,'native_identity_unchanged':True,
                      'known_preserved_leaf_inodes_unchanged':True,'prerequisites_unchanged':True,
                      'package_database_updated':False,'armed':False,'rebooted':False,'boot_committed':False},'Actual p11 one-helper/one-Deb publication and preservation')
    return True,stage_ref


def reuse_readback_guard(mod,flash_plan):
    # Fixed old writer prefix lengths/readback shape; no p11 full-device hash.
    firmware=json.loads((R/flash_plan['artifacts']['firmware']['path']).read_text())
    expected={'V19_BOOTFS1_PREFIX_SHA256':firmware['outer']['bootfs_sha256'],
              'V19_ROOTFS1_PREFIX_SHA256':firmware['outer']['rootfs_sha256'],
              'ORIGINAL_BOOTFS2_SHA256':flash_plan['original_stock2_hashes']['bootfs2'],
              'ORIGINAL_ROOTFS2_SHA256':flash_plan['original_stock2_hashes']['rootfs2']}
    mod.require(firmware['image']['sha256']=='50bcd2c42179a7f6b835d650adf9cc292225263e41e5ac58f5954426b0ce978c'
                and firmware['repack_record']['/images/bootfs_6813_a0+']['bytes']==12493580
                and firmware['outer']['rootfs_bytes']==76570624,'Exact reused V19 component bounds')
    commands=[]
    for name,part,sectors in [('bootfs1',3,102400),('rootfs1',4,409600),('bootfs2',5,102400),('rootfs2',6,409600)]:
        path='/dev/mmcblk0p'+str(part);sys='/sys/class/block/mmcblk0p'+str(part)
        commands+=['test "$(/bin/busybox readlink /dev/'+name+')" = '+path,
                   'test -b '+path,'test ! -L '+path,
                   'test "$(/bin/busybox cat '+sys+'/dev)" = 179:'+str(part),
                   'test "$(/bin/busybox cat '+sys+'/size)" = '+str(sectors)]
    for label,device,count in [('V19_BOOTFS1_PREFIX_SHA256','bootfs1',12493580),('V19_ROOTFS1_PREFIX_SHA256','rootfs1',76570624),
                               ('ORIGINAL_BOOTFS2_SHA256','bootfs2',None),('ORIGINAL_ROOTFS2_SHA256','rootfs2',None)]:
        command='/bin/busybox head -c '+str(count)+' /dev/'+device+' | /bin/busybox sha256sum' if count else '/bin/busybox sha256sum /dev/'+device
        commands+=['set -- $('+command+'); test "$1" = '+expected[label],
                   '/bin/busybox printf "'+label+'=%s\\n" "$1"']
    return '; '.join(commands)+'; ',expected


def verify_reuse_stdout(mod,raw,expected):
    lines=raw.decode('utf-8',errors='strict').splitlines()
    mod.require(all(lines.count(label+'='+digest)==1 for label,digest in expected.items()),
                'Actual same-command reused V19 prefixes and complete original stock2 readback required')


def prepare(action):
    mod = frozen(BASE, 'frozen_v18_helpers_for_v20')
    mod.BOOT = BOOT  # New imported namespace only; frozen source remains exact.
    flasher = frozen(FLASH_SOURCE, 'frozen_v20_flash_source_for_selection')
    mod.require(flasher.BOOT == HISTORICAL_FLASH_BOOT and flasher.META == mod.META, 'Historical V19 flash identity stays historical')
    flash_plan = flasher.prepare()  # Pure fixed file/receipt validation; no device actions.
    check = mod.checker()
    mod.pinned(V19_TEMPLATE)
    current_stock,clean_export,export,native_v19=current_evidence(mod)
    ready,stage=staged_proof(mod)
    readback_command,readback_expected=reuse_readback_guard(mod,flash_plan)
    old_proof = mod.pinned(SAVED_VERIFIED, 64 * 1024)
    old_finish = mod.pinned(SAVED_FINISH, 256 * 1024)
    saved_inputs = check.read_inputs(SAVED_DIRECTORY)
    old_verified = check.verify(saved_inputs, OLD_BOOT)  # Same complete CRC/canonical parser, no commands.
    mod.require(json.loads((R / SAVED_VERIFIED[0]).read_text()) == old_verified, 'Actual old complete metadata proof')
    finish = json.loads((R / SAVED_FINISH[0]).read_text())
    mod.require(finish['status'] == 'v18_saved_dd_and_fresh_state_verified_no_reboot' and finish['verified'] == old_verified
                and finish['verified_receipt'] == old_proof and finish['guard_returncode'] == 0,
                'Actual completed V18 full-byte corroboration')
    saved = []
    for part in (1, 2):
        path = SAVED_DIRECTORY / ('metadata' + str(part) + '.bin')
        item = mod.pinned((str(path.relative_to(R)), mod.META), 262144)
        mod.require(item['bytes'] == 262144 and item['sha256'] == old_verified['metadata_sha256'] == mod.META,
                    'Previously verified complete raw metadata bytes')
        saved.append(item)
    sources = {'frozen_helpers': mod.pinned(BASE), 'flash_wrapper': mod.pinned(FLASH_SOURCE),
               'checker': mod.pinned(mod.CHECK_SOURCE), 'gpt': mod.pinned(mod.GPT_SOURCE),
               'transport': mod.pinned(mod.TRANSPORT)}
    flashed = {'path': FLASH_RECEIPT[0], 'sha256': FLASH_RECEIPT[1], 'ready': False}
    if FLASH_RECEIPT[1] is not None:
        flashed = mod.pinned(FLASH_RECEIPT, 256 * 1024)
        data = json.loads((R / FLASH_RECEIPT[0]).read_text())
        mod.exact(data, {'schema': 1, 'status': 'fixed_v19_inactive_slot1_readback_passed_no_boot_selection',
                        'boot_id': HISTORICAL_FLASH_BOOT, 'metadata_sha256': mod.META, 'flash_returncode': 0,
                        'only_inactive_slot1_written': True, 'boot_selected': False, 'rebooted': False,
                        'boot_committed': False, 'ACK_sent': False}, 'Historical actual V19 flash required, never relabelled current')
        mod.require(data['wrapper'] == sources['flash_wrapper'] and data['artifacts'] == flash_plan['artifacts']
                    and data['current_stock2_identity'] == flash_plan['current_stock2_identity']
                    and data['actual_startup_stage'] == flash_plan['actual_startup_stage']
                    and data['current_clean_export'] == flash_plan['current_clean_export'], 'Historical V19 flash/old stock2/startup bindings preserved')
        for label in ('stdout', 'stderr'):
            mod.require(data[label] == mod.ref((R / FLASH_RECEIPT[0]).with_name('flash.' + label)), 'Actual flash transcript binding')
        mod.require((R / FLASH_RECEIPT[0]).with_name('flash.stdout').read_text().splitlines().count(
                    'KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS') == 1, 'One actual complete firmware write/readback proof')
    plan = {'schema': 1, 'status': 'fixed_v20_selection_reboot_source_plan', 'action': action,
            'source': mod.ref(Path(__file__)), 'sources': sources, 'boot_id': BOOT, 'metadata_sha256': mod.META,
            'ready_for_execution': ready, 'historical_v19_flash': flashed,
            'historical_v19_flash_boot_id':HISTORICAL_FLASH_BOOT,
            'current_stock2_identity':current_stock,'current_clean_export':clean_export,'actual_native_v19':native_v19,
            'current_export':export,'actual_v20_p11_stage':stage,
            'historical_startup_stage':flash_plan['actual_startup_stage'],
            'reused_v19_component_hashes':readback_expected,
            'reuse_readback_command_sha256':hashlib.sha256(readback_command.encode()).hexdigest(),
            'saved_metadata_proof': old_proof, 'saved_metadata_finish': old_finish, 'saved_full_metadata': saved,
            'saved_metadata_boot_id': OLD_BOOT, 'capture_method': METHOD,
            'current_raw_metadata_transferred': False, 'local_full_CRC_canonical_checks_preserved': True,
            'selection_guard_sha256': hashlib.sha256(guard(mod, '34').encode()).hexdigest(),
            'fresh_hash_guard_sha256': hashlib.sha256(guard(mod, '1', True).encode()).hexdigest(),
            'reboot_guard_sha256': hashlib.sha256(guard(mod, '1').encode()).hexdigest(),
            'selection_output': str(DIRECTORY.relative_to(R)), 'selector_calls': 1 if action == 'select-and-capture' else 0,
            'flash_ACK_accept_commit_or_token_actions': False}
    if action == 'reboot' and ready:
        verified = check.verify(check.read_inputs(DIRECTORY), BOOT)
        selected = json.loads(SELECT_RESULT.read_text())
        mod.exact(selected, {'schema': 1, 'status': 'one_v20_selector_saved_metadata_capture_verified_no_reboot',
                            'boot_id': BOOT, 'metadata_sha256': mod.META, 'selector_call_dispatched': True,
                            'selector_returncode': 0, 'fresh-guard_returncode': 0, 'rebooted': False,
                            'context-before_returncode': 0, 'state-before_returncode': 0,
                            'state-after_returncode': 0, 'context-after_returncode': 0,
                            'permanent_commit': False, 'capture_method': METHOD, 'current_raw_metadata_transferred': False}, 'Actual V20 selection')
        for key in ('source', 'sources', 'historical_v19_flash', 'current_stock2_identity', 'current_clean_export', 'actual_native_v19', 'actual_v20_p11_stage', 'reused_v19_component_hashes', 'reuse_readback_command_sha256', 'historical_startup_stage',
                    'saved_metadata_proof', 'saved_metadata_finish', 'saved_full_metadata', 'fresh_hash_guard_sha256'):
            mod.require(selected[key] == plan[key], 'Same frozen selector source/receipt: ' + key)
        mod.require(selected['verified'] == verified and selected['verified_receipt'] == mod.ref(DIRECTORY / 'verified.json', 64 * 1024)
                    and json.loads((DIRECTORY / 'verified.json').read_text()) == verified, 'Exact current full-byte/CRC/state proof')
        mod.require(selected['inactive_v19_and_original_stock2_readback_verified'] is True
                    and selected['stdout']==mod.ref(LIVE/'twentieth-single-selection-v1.stdout'), 'Actual fresh firmware reuse receipt')
        verify_reuse_stdout(mod,(LIVE/'twentieth-single-selection-v1.stdout').read_bytes(),readback_expected)
        provenance = json.loads((DIRECTORY / 'capture-provenance.json').read_text())
        mod.require(provenance['capture_method'] == METHOD and provenance['saved_full_metadata'] == saved
                    and provenance['fresh_guard_returncode'] == 0 and provenance['raw_device_read_returncodes'] is None
                    and provenance['saved_metadata_boot_id'] == OLD_BOOT
                    and provenance['fresh_guard_command_sha256'] == plan['fresh_hash_guard_sha256']
                    and provenance['current_raw_metadata_transferred'] is False
                    and provenance['fresh_guard_stdout'] == mod.ref(DIRECTORY / 'fresh-guard.stdout'), 'Saved-byte versus fresh-hash provenance')
        mod.require((DIRECTORY / 'fresh-guard.stdout').read_bytes() ==
                    ('METADATA1_SHA256=' + mod.META + '\nMETADATA2_SHA256=' + mod.META + '\n').encode(), 'Actual fresh full-device hash transcript')
        marker = json.loads(SELECT_ATTEMPT.read_text())
        mod.require(marker['plan_sha256'] == selected['plan_sha256'] and marker['boot_id'] == BOOT
                    and marker['one_selector_call'] == 6, 'One exclusive actual selection marker')
        plan['saved_selection'] = {'result': mod.ref(SELECT_RESULT, 256 * 1024), 'verified': verified,
                                   'provenance': mod.ref(DIRECTORY / 'capture-provenance.json', 64 * 1024)}
    return plan, mod, check


def execute(plan, mod, check, approved):
    mod.require(plan['action'] in ('select-and-capture', 'reboot') and plan['ready_for_execution'] is True
                and hashlib.sha256(mod.canonical(plan)).hexdigest() == approved, 'Actual p11-stage PASS, reused V19 proof and exact reviewed action plan required')
    select = plan['action'] == 'select-and-capture'
    attempt, output = (SELECT_ATTEMPT, SELECT_RESULT) if select else (REBOOT_ATTEMPT, REBOOT_RESULT)
    prefix = 'twentieth-single-selection-v1' if select else 'twentieth-reboot-v1'
    paths = [attempt, output, LIVE / (prefix + '.stdout'), LIVE / (prefix + '.stderr')]
    mod.require(LIVE.is_dir() and not LIVE.is_symlink() and all(not p.exists() and not p.is_symlink() for p in paths), 'Exclusive evidence required; no retry')
    mod.require(not select or (not DIRECTORY.exists() and not DIRECTORY.is_symlink()), 'Exclusive selection capture required')
    mod.durable_json(attempt, {'boot_id': BOOT, 'plan_sha256': approved, 'one_selector_call': 6 if select else 0,
                             'issued_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'historical_v19_flash':plan['historical_v19_flash'],'actual_v20_p11_stage':plan['actual_v20_p11_stage']})
    result = {**plan, 'plan_sha256': approved, 'status': 'v20_action_dispatched_outcome_unknown',
              'permanent_commit': False, 'rebooted': False if select else None}
    stdout = stderr = b''
    try:
        historical=frozen(FLASH_SOURCE,'frozen_v19_flash_for_v20_component_bounds')
        readback_command,expected=reuse_readback_guard(mod,historical.prepare())
        mod.require(hashlib.sha256(readback_command.encode()).hexdigest()==plan['reuse_readback_command_sha256']
                    and expected==plan['reused_v19_component_hashes'],'Same source-bound fresh component readback')
        command = guard(mod, '34') + readback_command + 'exec /bin/bcm_bootstate 6' if select else guard(mod, '1') + '/bin/busybox sync; exec /sbin/reboot'
        result['selector_call_dispatched' if select else 'reboot_call_dispatched'] = True
        run = mod.remote('/bin/busybox ash -c ' + shlex.quote(command), 25)
        stdout, stderr = run.stdout, run.stderr
        result['selector_returncode' if select else 'reboot_returncode'] = run.returncode
        mod.require(run.returncode == 0, 'Action refused or uncertain; no retry')
        if select:
            verify_reuse_stdout(mod,stdout,plan['reused_v19_component_hashes'])
            result['inactive_v19_and_original_stock2_readback_verified']=True
            DIRECTORY.mkdir(mode=0o700, parents=False, exist_ok=False)
            queries = [('fresh-guard', '/bin/busybox ash -c ' + shlex.quote(guard(mod, '1', True)), 25, 8192),
                       ('context-before', check.CONTEXT, 15, 8192), ('state-before', check.STATE, 15, 32768),
                       ('state-after', check.STATE, 15, 32768), ('context-after', check.CONTEXT, 15, 8192)]
            for label, command, timeout, cap in queries:
                try:
                    read = mod.remote(command, timeout)
                except subprocess.TimeoutExpired as exc:
                    mod.durable_bytes(DIRECTORY / (label + '.stdout'), exc.stdout or b'')
                    mod.durable_bytes(DIRECTORY / (label + '.stderr'), exc.stderr or b'')
                    raise
                mod.durable_bytes(DIRECTORY / (label + '.stdout'), read.stdout)
                mod.durable_bytes(DIRECTORY / (label + '.stderr'), read.stderr)
                result[label + '_returncode'] = read.returncode
                mod.require(read.returncode == 0 and 0 < len(read.stdout) <= cap, 'Fresh guarded snapshot refused; no retry')
                if label == 'fresh-guard':
                    mod.require(read.stdout == ('METADATA1_SHA256=' + mod.META + '\nMETADATA2_SHA256=' + mod.META + '\n').encode(), 'Exact actual full-device metadata hashes')
                    for item in plan['saved_full_metadata']:
                        mod.require(mod.pinned((item['path'], item['sha256']), 262144) == item, 'Saved metadata bytes unchanged')
                        mod.durable_bytes(DIRECTORY / Path(item['path']).name, (R / item['path']).read_bytes())
                    mod.durable_json(DIRECTORY / 'capture-provenance.json', {'capture_method': METHOD,
                                     'saved_full_metadata': plan['saved_full_metadata'], 'saved_metadata_boot_id': OLD_BOOT,
                                     'fresh_guard_returncode': 0, 'fresh_guard_stdout': mod.ref(DIRECTORY / 'fresh-guard.stdout'),
                                     'fresh_guard_command_sha256': plan['fresh_hash_guard_sha256'],
                                     'raw_device_read_returncodes': None, 'current_raw_metadata_transferred': False})
                else:
                    mod.durable_bytes(DIRECTORY / (label + '.txt'), read.stdout)
            verified = check.verify(check.read_inputs(DIRECTORY), BOOT)
            mod.require(verified['metadata_sha256'] == mod.META, 'Complete CRC/canonical fields and current context/state required')
            mod.durable_json(DIRECTORY / 'verified.json', verified)
            result.update(status='one_v20_selector_saved_metadata_capture_verified_no_reboot', verified=verified,
                          verified_receipt=mod.ref(DIRECTORY / 'verified.json', 64 * 1024), rebooted=False)
        else:
            result.update(status='one_v20_guarded_reboot_requested')
    except subprocess.TimeoutExpired as exc:
        # Snapshot timeout bytes were saved separately; retain action stdout unchanged.
        if 'selector_returncode' not in result and 'reboot_returncode' not in result:
            stdout, stderr = exc.stdout or b'', exc.stderr or b''
        result.update(status='v20_action_timeout_retained_no_retry', error='remote_timeout')
        raise
    except Exception as exc:
        result.update(status='v20_action_failed_retained_no_retry', error=str(exc))
        raise
    finally:
        mod.durable_bytes(paths[2], stdout)
        mod.durable_bytes(paths[3], stderr)
        result.update(stdout=mod.ref(paths[2]), stderr=mod.ref(paths[3]))
        mod.durable_json(output, result)
        print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='plan', choices=['plan', 'select-and-capture', 'reboot'])
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan, mod, check = prepare(args.action)
    gate = hashlib.sha256(mod.canonical(plan)).hexdigest()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2))
    else:
        execute(plan, mod, check, args.execute_plan_sha256)


if __name__ == '__main__':
    main()

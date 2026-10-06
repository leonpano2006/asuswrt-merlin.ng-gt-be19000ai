#!/usr/bin/env python3
"""One V24 selector and separate reboot; saved full metadata plus fresh hashes.

Default is a local plan. Pending actual V24 flash pins block device access.
Binds current native33/kernel11/HTTPS stage and fresh component readback; COMMITTED2.
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
import struct

R = Path(__file__).resolve().parents[1]
BASE = ('scripts/trial-startup-v18.py', 'd0df3c1f96cf870d0d3e54bcb98707ee9207e37fc9b027aa378f7b124fb07aa8')
FLASH_SOURCE = ('scripts/flash-device-bpf-guardian33-v24.py', '2d72e5ef1cca702e4dd055aa5f907c048a9811c9bfd743c1d0049f2b5b86868e')
FLASH_RECEIPT = ('evidence/ubuntu26/flash-live/twentyfourth-kernel11-inactive-flash-v1/result.json', '0fed6a12ecf98b02ac20b17ee2aafa217e79a297ae18bf33b160936fed78c178')
BOOT = '00000000-0000-4000-8000-000000000004'
OLD_BOOT = '00000000-0000-4000-8000-000000000032'
ANCESTOR = ('scripts/trial-pid1-zero-guardian32-v23.py', '486f40b0a58159fc8a9ff7a78477a6647e1884169c639a3b3f6d9d988b907db2')
STOCK = ('evidence/ubuntu26/trial-live/docker-kernel11-v24-stock2-return-v1/stock-result.json', 'fd2d88aa1c1a50ec017be321e1b7e15a674eed80c16084eef0788dc656762759')
STOCK_CONTEXT = ('evidence/ubuntu26/trial-live/docker-kernel11-v24-stock2-return-v1/stock-context.stdout', '223a1cee9bb4b64efd7fbe4b8e2c61b2d36fc75c512476dffb6d9d515144e175')
CURRENT_CLEAN_SB = ('evidence/ubuntu26/trial-live/docker-kernel11-v24-p11-recovery-v1/post-recovery-superblock.stdout', '54b2ff41a448db0c679bf3026e0e0e13509dce40393458f0807f63f550c2c4e6')
PACK_SOURCE = ('scripts/pack-ubuntu26-kernel11-guardian33-v24.py', '866d08380ee06eafd3eb429139360e4cc5560ad91aeabf8262de4409d5e1f02f')
FW_IMAGE_SHA = 'a6dd363892b5d9871432b3edcfd4e0db7795b7e603063c83a92e0a2cef730650'
NATIVE_BUILD_SOURCE = ('scripts/build-asus-guardian33-kernel11-native.py', '7a572af945fb47a07ea931c4d5f5d60a2d8969f1433d4c0ae1e28fd9c203431b')
NATIVE_MANIFEST = ('build/asus-trial-runtime/native-v33-kernel11-identity/manifest.json', 'a1d034cb56444162c24debc905a61fadf59d4a1072e0c1f0718d98151b41d155')
NATIVE_RECEIPT = ('build/asus-trial-runtime/native-v33-kernel11-identity/guardian-receipt.json', 'ffebfcc7c4338742a56624fd2af35fa0319a17e21742ff707e8f5dd4521cc90b')
FOCUSED = ('reports/ubuntu26/guardian-v31-focused-validation-v1.json', '3990ccc55feb827195d968bc2534c25b352c46677a9a97c9fae6be502382c2be')
PID1_FOCUSED = ('build/asus-accepted-runtime/pid1-zero-time-fixture-v1/result.json', '9b3d89f11dce2b7d5189d0e773cfb3a68b65a98915aa1efc08a2150c2d7f018b')
HTTPS_BOOT = '00000000-0000-4000-8000-000000000035'  # Historical installation only.
IDENTITY_HEADER_SHA = '5fdc4366c0f7ea248e35ef175351f73de9c00745f7b0947d65cbfd8ee21fe42c'
FW_KERNEL_SHA = '7d0be9c9c719291e52cf8994221d3c6267185a27e9b5bd4079f40d9bf21a21ed'
FW_NOTES_SHA = 'bb2994742f8f681f7046672cdf59b38e2e259480b59d368134c2fbd25e67721c'

STAGE_SOURCE = ('scripts/deploy-asus-https-helper-p11-v1.py', 'd112bb8676d7049e6a8ee287c735dd5c66059dfd15aed861f4fac496617e1af2')
STAGE_RECEIPT = ('evidence/ubuntu26/device-https-helper-live/install-v1/result.json', '978ca08968b393bdfe9b153a27b48a8a44a477e479909337a7b77652a81a54b1')
COUNTS = {'additions_published':2, 'replacements_published':0, 'links_created':1,
          'private_sh_links_replaced':0, 'temporary_created':2, 'directories_created':1}
SAVED_DIRECTORY = R / 'evidence/ubuntu26/trial-live/post-selection-v18'
SAVED_VERIFIED = ('evidence/ubuntu26/trial-live/post-selection-v18/verified.json', '50ffe39798d39d5ae2978830499ae2122b92ca2b47c69f0d1aef75e2dfaa720b')
SAVED_FINISH = ('evidence/ubuntu26/trial-live/eighteenth-selection-finish-v2/finish-result.json', 'dc8fee282c110b3ace8adb9eadda0c82f9a35bf890dc5aecdc385b3516b9b22f')
LIVE = R / 'evidence/ubuntu26/trial-live'
DIRECTORY = LIVE / 'twentyfourth-kernel11-selection-capture-v1'
SELECT_ATTEMPT = LIVE / 'twentyfourth-kernel11-selection-attempt-v1.json'
SELECT_RESULT = LIVE / 'twentyfourth-kernel11-selection-result-v1.json'
REBOOT_ATTEMPT = LIVE / 'twentyfourth-kernel11-reboot-attempt-v1.json'
REBOOT_RESULT = LIVE / 'twentyfourth-kernel11-reboot-result-v1.json'
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
                     'reset_reason':'34','manual_powercycle_requested':False,'ACK_sent':False},'Actual current stock2 monitor capture')
    context_ref=mod.pinned(STOCK_CONTEXT,8192)
    mod.require(context_ref['sha256']==stock['context_sha256'],'Authenticated return context binding')
    raw=(R/STOCK_CONTEXT[0]).read_text()
    mod.require(raw.startswith('boot='+BOOT+'\nreason=34\n4.19.294\n#1 ')
                and raw.count('root=/dev/mmcblk0p6')==1 and 'root=/dev/mmcblk0p4' not in raw
                and raw.splitlines().count(mod.META+'  /dev/mmcblk0p1')==1
                and raw.splitlines().count(mod.META+'  /dev/mmcblk0p2')==1,'Actual stock2 root/kernel/full metadata context')
    sb_ref=mod.pinned(CURRENT_CLEAN_SB,1024);sb=(R/CURRENT_CLEAN_SB[0]).read_bytes()
    mod.require(len(sb)==1024 and sb[56:58]==b'\x53\xef'
                and sb[104:120].hex()=='ea8e47b8c606406cb931d2244d26ec55'
                and struct.unpack_from('<H',sb,58)[0]==1 and not(sb[96]&4)
                and struct.unpack_from('<I',sb,404)[0]==0 and struct.unpack_from('<I',sb,232)[0]==0,
                'Actual current-stock2 post-recovery clean full1024 p11 UUID proof')
    build=frozen(NATIVE_BUILD_SOURCE,'frozen_guardian33_build_for_v24_trial')
    manifest_ref=mod.pinned(NATIVE_MANIFEST,128*1024);receipt_ref=mod.pinned(NATIVE_RECEIPT,64*1024)
    native=build.verify_successor(R/NATIVE_MANIFEST[0])  # Pure36/213/two-literal kernel11 identity/old39+21/client-reuse/ELF verifier.
    mod.require(native['identity_delta']['changed_rows']==0 and native['identity_delta']['unchanged_rows']==213
                and native['identity_delta']['files']==[] and native['identity_header_sha256']==IDENTITY_HEADER_SHA
                and native['metadata_committed']==2 and native['focused_validation']=={'path':FOCUSED[0],'sha256':FOCUSED[1]}
                and native['pid1_focused_validation']=={'path':PID1_FOCUSED[0],'sha256':PID1_FOCUSED[1]}
                and native['guardian_compile_count']==1 and native['accept_client_compile_count']==0
                and native['accept_client_reused'] is True and native['focused_new_case_count']==0 and native['reused_pid1_case_count']==21
                and native['identity_only_successor'] is True
                and native['kernel_identity']['image_sha256']==FW_KERNEL_SHA
                and native['kernel_identity']['notes_sha256']==FW_NOTES_SHA
                and native['reused_focused_case_count']==39 and native['full_production_loop_validation_passed'] is False,
                'Current-boot-only native33 one-compile/client-reuse scope')
    focused_ref=mod.pinned(FOCUSED,64*1024);focused=json.loads((R/FOCUSED[0]).read_text())
    mod.require(focused['passed_case_count']==39 and focused['repeated_case_count']==0
                and focused['full_production_loop_validated'] is False and focused['physical_boot_validated'] is False,
                'Original source-bound39 focused cases reused; no current full-loop or physical claim')
    pid1_ref=mod.pinned(PID1_FOCUSED,64*1024)
    pid1=json.loads((R/PID1_FOCUSED[0]).read_text())
    mod.require(pid1['status']=='pure_production_pid1_zero_start_parser_fixture_passed' and pid1['returncode']==0
                and pid1['compile_count']==pid1['fixture_run_count']==1 and pid1['expected_case_count']==21,
                'Actual old21 PID1-only fixture proof retained; not rerun')
    mod.pinned(PACK_SOURCE)
    return {'receipt':stock_ref,'authenticated_context':context_ref},sb_ref,{'manifest':manifest_ref,'receipt':receipt_ref,
            'focused_validation':focused_ref,'pid1_focused_validation':pid1_ref,'client_reused_unchanged':True}

def staged_proof(mod):
    ready=STAGE_SOURCE[1] is not None and STAGE_RECEIPT[1] is not None
    if not ready:return False,{'path':STAGE_RECEIPT[0],'sha256':STAGE_RECEIPT[1],'ready':False}
    deploy=frozen(STAGE_SOURCE,'frozen_v24_p11_deploy_source_for_selection')
    stage_plan=deploy.prepare()  # Pure pins only; never its execute/main.
    mod.require(stage_plan['boot_id']==HTTPS_BOOT and stage_plan['metadata_sha256']==mod.META
                and stage_plan['expected_counts']==COUNTS,'Historical HTTPS p11-only source plan retains original boot')
    stage_ref=mod.pinned(STAGE_RECEIPT,256*1024);data=json.loads((R/STAGE_RECEIPT[0]).read_text())
    mod.exact(data,{'schema':1,'status':'fixed_https_helper_v1_p11_staged_no_boot_selection','boot_id':HTTPS_BOOT,
                   'metadata_sha256':mod.META,'installer_returncode':0,'installer_started':True,'published':True,
                   'superblock-before_returncode':0,'installer-transfer_returncode':0,'clean_only':True,
                   'recovery_permitted':False,'firmware_flashing':False,'boot_selected':False,
                   'rebooted':False,'boot_committed':False},'Historical actual HTTPS p11-stage PASS under its original boot required')
    for key,value in stage_plan.items():
        if key!='status':mod.require(data.get(key)==value,'Actual stage source/artifact binding: '+key)
    mod.exact(data['superblock_before'],{'state':1,'needs_recovery':False,'error_count':0,'last_orphan':0},'Actual preinstall clean-only gate')
    native=data['installer_result']
    mod.exact(native,{'schema':1,'status':'native_https_helper_v1_staged','boot_id':HTTPS_BOOT,'metadata_sha256':mod.META,
                      **COUNTS,'mode_changed':False,'native_identity_unchanged':True,
                      'known_preserved_leaf_inodes_unchanged':True,'prerequisites_unchanged':True,
                      'package_database_updated':False,'armed':False,'rebooted':False,'boot_committed':False},'Actual HTTPS two-addition/alias publication and preservation')
    return True,stage_ref


def reuse_readback_guard(mod,flash_plan):
    # Preserve fixed writer readback shape with actual V24 rootfs length; no p11 full-device hash.
    firmware=json.loads((R/flash_plan['artifacts']['firmware']['path']).read_text())
    expected={'V24_BOOTFS1_PREFIX_SHA256':firmware['outer']['bootfs_sha256'],
              'V24_ROOTFS1_PREFIX_SHA256':firmware['outer']['rootfs_sha256'],
              'ORIGINAL_BOOTFS2_SHA256':flash_plan['original_stock2_hashes']['bootfs2'],
              'ORIGINAL_ROOTFS2_SHA256':flash_plan['original_stock2_hashes']['rootfs2']}
    mod.require(firmware['image']['sha256']==FW_IMAGE_SHA
                and firmware['outer']['repack_record']['/images/bootfs_6813_a0+']['bytes']==12584732
                and firmware['kernel_sha256']==FW_KERNEL_SHA
                and firmware['outer']['rootfs_bytes']==76578816,'Exact V24 component bounds')
    commands=[]
    for name,part,sectors in [('bootfs1',3,102400),('rootfs1',4,409600),('bootfs2',5,102400),('rootfs2',6,409600)]:
        path='/dev/mmcblk0p'+str(part);sys='/sys/class/block/mmcblk0p'+str(part)
        commands+=['test "$(/bin/busybox readlink /dev/'+name+')" = '+path,
                   'test -b '+path,'test ! -L '+path,
                   'test "$(/bin/busybox cat '+sys+'/dev)" = 179:'+str(part),
                   'test "$(/bin/busybox cat '+sys+'/size)" = '+str(sectors)]
    for label,device,count in [('V24_BOOTFS1_PREFIX_SHA256','bootfs1',12584732),('V24_ROOTFS1_PREFIX_SHA256','rootfs1',76578816),
                               ('ORIGINAL_BOOTFS2_SHA256','bootfs2',None),('ORIGINAL_ROOTFS2_SHA256','rootfs2',None)]:
        command='/bin/busybox head -c '+str(count)+' /dev/'+device+' | /bin/busybox sha256sum' if count else '/bin/busybox sha256sum /dev/'+device
        commands+=['set -- $('+command+'); test "$1" = '+expected[label],
                   '/bin/busybox printf "'+label+'=%s\\n" "$1"']
    return '; '.join(commands)+'; ',expected


def verify_reuse_stdout(mod,raw,expected):
    lines=raw.decode('utf-8',errors='strict').splitlines()
    mod.require(all(lines.count(label+'='+digest)==1 for label,digest in expected.items()),
                'Actual same-command V24 prefixes and complete original stock2 readback required')


def prepare(action):
    if BOOT is None or FLASH_SOURCE[1] is None or FLASH_RECEIPT[1] is None or STOCK[1] is None or STOCK_CONTEXT[1] is None or CURRENT_CLEAN_SB[1] is None:
        raise RuntimeError('Pending actual stock2/cleanSB/V24flash proof blocks before any output or transport')
    mod = frozen(BASE, 'frozen_v18_helpers_for_v24')
    mod.BOOT = BOOT  # New imported namespace only; frozen source remains exact.
    flasher = frozen(FLASH_SOURCE, 'frozen_v24_flash_source_for_selection')
    mod.require(flasher.BOOT == BOOT and flasher.META == mod.META, 'Actual same-boot V24 flash identity')
    flash_plan = flasher.prepare()  # Pure fixed file/receipt validation; no device actions.
    check = mod.checker()
    mod.pinned(ANCESTOR)
    current_stock,current_clean_sb,native33=current_evidence(mod)
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
        mod.exact(data, {'schema': 1, 'status': 'fixed_v24_kernel11_inactive_slot1_readback_passed_no_boot_selection',
                        'boot_id': BOOT, 'metadata_sha256': mod.META, 'flash_returncode': 0,
                        'only_inactive_slot1_written': True, 'boot_selected': False, 'rebooted': False,
                        'boot_committed': False, 'ACK_sent': False}, 'Actual same-boot V24 flash PASS required')
        mod.require(data['wrapper'] == sources['flash_wrapper'] and data['artifacts'] == flash_plan['artifacts']
                    and data['current_stock2_identity'] == flash_plan['current_stock2_identity']
                    and data['actual_startup_stage'] == flash_plan['actual_startup_stage']
                    and data['actual_https_stage'] == flash_plan['actual_https_stage']
                    and data['current_p11_recovery'] == flash_plan['current_p11_recovery']
                    and data['clean_superblock'] == flash_plan['clean_superblock'],
                    'Actual V24 flash/current stock2/startup/HTTPS/clean recovery bindings preserved')
        for label in ('stdout', 'stderr'):
            mod.require(data[label] == mod.ref((R / FLASH_RECEIPT[0]).with_name('flash.' + label)), 'Actual flash transcript binding')
        mod.require((R / FLASH_RECEIPT[0]).with_name('flash.stdout').read_text().splitlines().count(
                    'KERNEL11_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS') == 1, 'One actual complete firmware write/readback proof')
    plan = {'schema': 1, 'status': 'fixed_v24_selection_reboot_source_plan', 'action': action,
            'source': mod.ref(Path(__file__)), 'sources': sources, 'boot_id': BOOT, 'metadata_sha256': mod.META,
            'ready_for_execution': ready and FLASH_RECEIPT[1] is not None, 'actual_v24_flash': flashed,
            'current_stock2_identity':current_stock,'current_clean_superblock':current_clean_sb,'actual_native33_build':native33,
            'actual_https_stage':stage, 'historical_https_boot_id':HTTPS_BOOT, 'flash_https_stage':flash_plan['actual_https_stage'],
            'flash_current_stock2_identity':flash_plan['current_stock2_identity'],
            'current_p11_recovery':flash_plan['current_p11_recovery'], 'clean_superblock':flash_plan['clean_superblock'],
            'historical_startup_stage':flash_plan['actual_startup_stage'],
            'v24_component_hashes':readback_expected,
            'reuse_readback_command_sha256':hashlib.sha256(readback_command.encode()).hexdigest(),
            'saved_metadata_proof': old_proof, 'saved_metadata_finish': old_finish, 'saved_full_metadata': saved,
            'saved_metadata_boot_id': OLD_BOOT, 'capture_method': METHOD,
            'current_raw_metadata_transferred': False, 'local_full_CRC_canonical_checks_preserved': True,
            'selection_guard_sha256': hashlib.sha256(guard(mod, '34').encode()).hexdigest(),
            'fresh_hash_guard_sha256': hashlib.sha256(guard(mod, '1', True).encode()).hexdigest(),
            'reboot_guard_sha256': hashlib.sha256(guard(mod, '1').encode()).hexdigest(),
            'selection_output': str(DIRECTORY.relative_to(R)), 'selector_calls': 1 if action == 'select-and-capture' else 0,
            'flash_ACK_accept_commit_or_token_actions': False}
    if action == 'reboot' and plan['ready_for_execution']:
        verified = check.verify(check.read_inputs(DIRECTORY), BOOT)
        selected = json.loads(SELECT_RESULT.read_text())
        mod.exact(selected, {'schema': 1, 'status': 'one_v24_selector_saved_metadata_capture_verified_no_reboot',
                            'boot_id': BOOT, 'metadata_sha256': mod.META, 'selector_call_dispatched': True,
                            'selector_returncode': 0, 'fresh-guard_returncode': 0, 'rebooted': False,
                            'context-before_returncode': 0, 'state-before_returncode': 0,
                            'state-after_returncode': 0, 'context-after_returncode': 0,
                            'permanent_commit': False, 'capture_method': METHOD, 'current_raw_metadata_transferred': False}, 'Actual V24 selection')
        for key in ('source', 'sources', 'actual_v24_flash', 'current_stock2_identity', 'current_clean_superblock', 'actual_native33_build', 'actual_https_stage', 'flash_https_stage', 'flash_current_stock2_identity', 'current_p11_recovery', 'clean_superblock', 'v24_component_hashes', 'reuse_readback_command_sha256', 'historical_startup_stage',
                    'saved_metadata_proof', 'saved_metadata_finish', 'saved_full_metadata', 'fresh_hash_guard_sha256'):
            mod.require(selected[key] == plan[key], 'Same frozen selector source/receipt: ' + key)
        mod.require(selected['verified'] == verified and selected['verified_receipt'] == mod.ref(DIRECTORY / 'verified.json', 64 * 1024)
                    and json.loads((DIRECTORY / 'verified.json').read_text()) == verified, 'Exact current full-byte/CRC/state proof')
        mod.require(selected['inactive_v24_and_original_stock2_readback_verified'] is True
                    and selected['stdout']==mod.ref(LIVE/'twentyfourth-kernel11-single-selection-v1.stdout'), 'Actual fresh firmware reuse receipt')
        verify_reuse_stdout(mod,(LIVE/'twentyfourth-kernel11-single-selection-v1.stdout').read_bytes(),readback_expected)
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
                and hashlib.sha256(mod.canonical(plan)).hexdigest() == approved, 'Historical HTTPS PASS, actual current-stock V24 flash proof and exact reviewed action plan required')
    select = plan['action'] == 'select-and-capture'
    attempt, output = (SELECT_ATTEMPT, SELECT_RESULT) if select else (REBOOT_ATTEMPT, REBOOT_RESULT)
    prefix = 'twentyfourth-kernel11-single-selection-v1' if select else 'twentyfourth-kernel11-reboot-v1'
    paths = [attempt, output, LIVE / (prefix + '.stdout'), LIVE / (prefix + '.stderr')]
    mod.require(LIVE.is_dir() and not LIVE.is_symlink() and all(not p.exists() and not p.is_symlink() for p in paths), 'Exclusive evidence required; no retry')
    mod.require(not select or (not DIRECTORY.exists() and not DIRECTORY.is_symlink()), 'Exclusive selection capture required')
    mod.durable_json(attempt, {'boot_id': BOOT, 'plan_sha256': approved, 'one_selector_call': 6 if select else 0,
                             'issued_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'actual_v24_flash':plan['actual_v24_flash'],'actual_https_stage':plan['actual_https_stage']})
    result = {**plan, 'plan_sha256': approved, 'status': 'v24_action_dispatched_outcome_unknown',
              'permanent_commit': False, 'rebooted': False if select else None}
    stdout = stderr = b''
    try:
        flasher=frozen(FLASH_SOURCE,'frozen_v24_flash_for_component_bounds')
        readback_command,expected=reuse_readback_guard(mod,flasher.prepare())
        mod.require(hashlib.sha256(readback_command.encode()).hexdigest()==plan['reuse_readback_command_sha256']
                    and expected==plan['v24_component_hashes'],'Same source-bound fresh component readback')
        command = guard(mod, '34') + readback_command + 'exec /bin/bcm_bootstate 6' if select else guard(mod, '1') + '/bin/busybox sync; exec /sbin/reboot'
        result['selector_call_dispatched' if select else 'reboot_call_dispatched'] = True
        run = mod.remote('/bin/busybox ash -c ' + shlex.quote(command), 25)
        stdout, stderr = run.stdout, run.stderr
        result['selector_returncode' if select else 'reboot_returncode'] = run.returncode
        mod.require(run.returncode == 0, 'Action refused or uncertain; no retry')
        if select:
            verify_reuse_stdout(mod,stdout,plan['v24_component_hashes'])
            result['inactive_v24_and_original_stock2_readback_verified']=True
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
            result.update(status='one_v24_selector_saved_metadata_capture_verified_no_reboot', verified=verified,
                          verified_receipt=mod.ref(DIRECTORY / 'verified.json', 64 * 1024), rebooted=False)
        else:
            result.update(status='one_v24_guarded_reboot_requested')
    except subprocess.TimeoutExpired as exc:
        # Snapshot timeout bytes were saved separately; retain action stdout unchanged.
        if 'selector_returncode' not in result and 'reboot_returncode' not in result:
            stdout, stderr = exc.stdout or b'', exc.stderr or b''
        result.update(status='v24_action_timeout_retained_no_retry', error='remote_timeout')
        raise
    except Exception as exc:
        result.update(status='v24_action_failed_retained_no_retry', error=str(exc))
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

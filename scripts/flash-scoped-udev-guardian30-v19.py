#!/usr/bin/env python3
"""Plan V19 inactive-slot1 flash, preserving the actual V15 guard/writer.

Default reads local files only. Pending firmware pins block all transport.
Historical V15 staging is separate from the actual V18 update/current stock2
and clean-export proof. No selector, reboot, ACK, commit or package changes.
"""
import argparse
import ast
import datetime
import hashlib
import json
import shlex
import subprocess
import struct
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000017'
HISTORICAL_BOOT = '00000000-0000-4000-8000-000000000024'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py', 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
OLD_LAUNCHER = ('scripts/flash-cfe-factory-v11.py', '74615c25691949f9578a7c110028425f5f27a1b53b3b0e42d959ef25852e17f4')
FW = ('build/ubuntu26-firmware/kernel10-ubuntu26-trial-v19-scoped-udev-guardian30/manifest.json', '88f28651167112b46a384a96fc851df333c54574406f71f903cea086da17aaff')
IMAGE = ('build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v19-scoped-udev-guardian30_TRIAL.pkgtb', '50bcd2c42179a7f6b835d650adf9cc292225263e41e5ac58f5954426b0ce978c')
WRAPPER_MANIFEST = ('build/ubuntu26-flash/kernel10-ubuntu26-nineteenth-scoped-udev-guardian30-v1/manifest.json', '108dba1ee88c01e55bea47a01a9faafbc6180cc74659156cd7490d944559dead')
SCRIPT = ('build/ubuntu26-flash/kernel10-ubuntu26-nineteenth-scoped-udev-guardian30-v1/flash-inactive-slot1.sh', 'cae12b5c1b43790414346ba9ac17982b20f3b145ecb242143861b000b8b0b3ce')
STAGE = ('build/ubuntu26-bootstrap/device-scoped-udev-guardian30-v19/manifest.json', 'e6321d7c4f8a190f9b1f7652bb4242464890ad5d9ae52e8c78bad0847610967b')
GUARDIAN_MANIFEST = ('build/asus-trial-runtime/native-v30-scoped-udev-identity/manifest.json', 'e50e65513820de6de5d529c547ec2653bed4192e59c7f0334a342a49ef2e47bd')
GUARDIAN_RECEIPT = ('build/asus-trial-runtime/native-v30-scoped-udev-identity/guardian-receipt.json', 'ec4a12a9c6d0f4364676a8369ff8533a9abe197a628ca8ea93200950bc0b5439')
GUARDIAN_SHA = '9aa7baeb30774346e4a60924ba78697c5f70ce3d7c8c6756185555d6914e702f'
BASE_OUTER = ('scripts/flash-lan-ssh-policy-v15.py', 'd800cf4dbab82d2f35777caea9db32ca527e5b880825f5496b5abc05815371dc')
BASE_SCRIPT = ('build/ubuntu26-flash/kernel10-ubuntu26-fifteenth-lan-ssh-policy-v1/flash-inactive-slot1.sh', '228fd9dcbf2c710672d766c410e31e364592b0d927f2507b7bc2596a35e04e1a')
BASE_WRAPPER = ('build/ubuntu26-flash/kernel10-ubuntu26-fifteenth-lan-ssh-policy-v1/manifest.json', 'e6aaa4ffcbba083d6afbfff19eed3722ba7c82f6a32602b122016379c4466bbc')
BASE_FW = ('build/ubuntu26-firmware/kernel10-ubuntu26-trial-v15-lan-ssh-policy/manifest.json', 'cb2f3ae9657ae92e563be14187fcddf7ec6456f0a0edcf48b94f9b4291ec5295')
BASE_IMAGE = ('build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v15-lan-ssh-policy_TRIAL.pkgtb', '0ca0e99f11c5c6711a3d0cbf8ffcee18eed3bdc1d5d5b35c49a0d63b364b9916')
BASE_FLASH = ('evidence/ubuntu26/flash-live/fifteenth-lan-ssh-policy-v1/result.json', '3d20ae5cb6b0f38fac996141eee6b4d27735d5a32f8c07559ebc008d3bb368e7')
BASE_FINISH = ('reports/ubuntu26/guardian29-firmware-finish-v2.json', '4eb502cc295c69bad84e300249f42276c4e1acf6d07bfa9f0ebd45ca6ab5fa2c')
STOCK = ('evidence/ubuntu26/trial-live/eighteenth-return-forensics-v2/stock-result.json', '822368c5b038dbc84af4e5e8a31548f0150c5caf4c32bb81b9ad4c89133879bb')
AUTH_RESULT = ('evidence/ubuntu26/trial-live/eighteenth-stock2-identity-v2/result.json', '30debcccc5e5c5f0ec940912f0dd4fd3520a390dad808dbda3fb3a1d3ae45f9c')
AUTH_COMMAND = ('evidence/ubuntu26/trial-live/eighteenth-stock2-identity-v2/command.txt', '3107baaad684e125c82546c12ff1247dc9fd32253067b413fc62bfb493177305')
AUTH_STDOUT = ('evidence/ubuntu26/trial-live/eighteenth-stock2-identity-v2/stdout', '47d47a100648a31761aed9664095238e769f46f91337495ea0708c51ead4d916')
AUTH_STDERR = ('evidence/ubuntu26/trial-live/eighteenth-stock2-identity-v2/stderr', '3cd1f6118d42c24158bbe30d2bcf2d629860c93910bf4311de898a5703e3a1d9')
STARTUP_RECEIPT = ('evidence/ubuntu26/device-trial-startup-v18-live/install-v1/result.json', '7751a47ea672819c47b41cec9e85da4799b0214a2a005aff4963d61afacc36ef')
STARTUP_MANIFEST = ('build/asus-trial-startup-v18/install-v1/manifest.json', 'fe8ce24d157c2b22625003a8ac3a7366b09182ab8500ef19c2814f82f4c107f0')
STARTUP_SHA = '69994d0dbaf4db84c3ea9207ec3d03ff27a3c2d05edaf2571a23f30a76b9c6d7'
CURRENT_RESCUE_SHA = 'bc4a5a7cdc368dafebd0ac172abed57bd3352436def9303bba656ed6f7a3a590'
CURRENT_EXPORT = ('evidence/ubuntu26/trial-live/eighteenth-return-forensics-v2/result.json', 'f62741f2ef719785f9811d09981228b6ce2f64163ccd2519b36563f67f963e40')
CLEAN_SB = ('evidence/ubuntu26/trial-live/eighteenth-return-forensics-v2/superblock-before.stdout', 'b4c8cf517ce9754ebb4c1e9970fc2fab2efdd819373cb478536d3fdb5ce990bd')
CANDIDATE_MANIFEST = ('build/asus-trial-candidate-v15/install-v1/manifest.json', '18c2470a65afa9d2aad2e5e9676b810f6a1757ab4f89bb9b1a1196987a2ff984')
CANDIDATE_INSTALLER_SHA = '3ee1c2a1e8b1e78bf03501bb84bb61e549bbd28c75761501ebb1e57a78c11b65'
RC_SHA = 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2'
RESCUE_SHA = '55f6953743d6e0420d4d04d2ad95505fcf0ba340da9c84ce91ee375be622a133'
# Deferred paths are visible in a source-only plan, never accepted for execution.
CANDIDATE_RECEIPT = ('evidence/ubuntu26/device-trial-candidate-v15-live/install-v1/result.json', '65a5e4e8bf9766bdd86def92f5f78491d299f03181568270ba2ff096e76c4898')
RESCUE_RECEIPT = ('evidence/ubuntu26/device-uplink-rescue-live/install-v3/result.json', '7d9968b458f1076e333517794857072f77bf53867345d9050b509ec056b5c643')
RESCUE_STATUS = 'fixed_native_uplink_rescue_p11_staged_no_boot_selection'
REMOTE_IMAGE = '/tmp/kernel10-ubuntu26-v19-candidate.pkgtb'
REMOTE_SCRIPT = '/tmp/leon-flash-v19-scoped-udev-guardian30.sh'
REMOTE_LOCK = '/tmp/kernel10-ubuntu26-v19-flash.lock'
REMOTE_LOG = '/tmp/kernel10-ubuntu26-v19-flash.log'
OUT = R / 'evidence/ubuntu26/flash-live/nineteenth-inactive-flash-v1'
GUARD = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT)
         + '; test "$(readlink /proc/1/exe)" = /sbin/rc; '
         + 'test "$(uname -r)" = 4.19.294; case "$(uname -v)" in "#1 "*) ;; *) exit 1 ;; esac; '
         + 'test "$(cat /proc/bootstate/reset_reason)" = 34; '
         + 'test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; '
         + 'grep -Eq \'(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)\' /proc/cmdline; '
         + 'test ! -e /dev/nvram; test ! -L /dev/nvram; '
         + 'set -- $(sha256sum /bin/bcm_bootstate); test "$1" = 2b01eb80604ef66aa21a99178c70501eeb8a2c458132d133051a241373c5c845; '
         + 'set -- $(sha256sum /lib/libbcm_flashutil.so); test "$1" = 18c98a3c45d78b7ccc26e82a94ea225ac3b422d123b6b783f71691f5639fb0d0; '
         + 'for part in 1 2; do test -b /dev/mmcblk0p$part; test ! -L /dev/mmcblk0p$part; '
         + 'test "$(cat /sys/class/block/mmcblk0p$part/size)" = 512; '
         + 'test "$(cat /sys/class/block/mmcblk0p$part/dev)" = 179:$part; '
         + 'set -- $(sha256sum /dev/mmcblk0p$part); test "$1" = ' + META + '; done; ')
SB_GUARD = ('set -- $(/bin/busybox dd if=/dev/mmcblk0p11 bs=1024 skip=1 count=1 2>/dev/null | sha256sum); '
            + 'test "$1" = ' + CLEAN_SB[1] + '; ')


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


def declared(row):
    if row[1] is None:
        return {'path': row[0], 'sha256': None, 'bytes': None, 'status': 'pending_actual_root_verified_artifact'}
    return pinned(row)


def clean_superblock(data):
    require(len(data) == 1024 and data[56:58] == b'\x53\xef'
            and data[104:120].hex() == 'ea8e47b8c606406cb931d2244d26ec55', 'Full1024 p11 ext4/UUID required')
    require(struct.unpack_from('<H', data, 58)[0] == 1 and not (data[96] & 4)
            and struct.unpack_from('<I', data, 404)[0] == 0 and struct.unpack_from('<I', data, 232)[0] == 0,
            'P11 must be clean, error0, no journal recovery and orphan0 before firmware write')


def current_provenance():
    stock_ref = pinned(STOCK)
    originals = {key: pinned(row) for key, row in [('result', AUTH_RESULT), ('command', AUTH_COMMAND),
                                                  ('stdout', AUTH_STDOUT), ('stderr', AUTH_STDERR)]}
    stock = json.loads((R / STOCK[0]).read_text())
    auth = json.loads((R / AUTH_RESULT[0]).read_text())
    require(stock['status'] == 'authenticated_new_stock2_return' and stock['boot_id'] == BOOT
            and stock['metadata_sha256'] == META and stock['reset_reason'] == '34'
            and stock['capture_method'] == 'reuse_saved_authenticated_stock2_identity'
            and stock['forensics_capture_branch_executed'] is False
            and stock['source'] == originals['command'] and stock['actual_authentication_result'] == originals['result']
            and stock['original_stdout'] == originals['stdout'] and stock['original_stderr'] == originals['stderr']
            and stock['context_sha256'] == AUTH_STDOUT[1]
            and stock['uid_not_proved_by_unsupported_id_query'] is True,
            'Actual saved authenticated stock2 provenance required; no fabricated UID/capture claim')
    require(auth['returncode'] == 0 and auth['read_only'] is True and auth['selector_calls'] == 0
            and auth['rebooted'] is False, 'Successful saved read-only stock2 authentication required')
    lines = (R / AUTH_STDOUT[0]).read_text().splitlines()
    require(lines[:5] == ['uid=', 'boot=' + BOOT, 'pid1=/sbin/rc', 'reason_raw=34', '4.19.294']
            and lines[5].startswith('#1 ') and [word for word in lines[6].split() if word.startswith('root=')] == ['root=/dev/mmcblk0p6']
            and lines[-2:] == [META + '  /dev/mmcblk0p1', META + '  /dev/mmcblk0p2'], 'Exact saved stock2 context required')
    stage_ref = pinned(STARTUP_RECEIPT)
    data = json.loads((R / STARTUP_RECEIPT[0]).read_text())
    manifest_ref = pinned(STARTUP_MANIFEST)
    manifest = json.loads((R / STARTUP_MANIFEST[0]).read_text())
    require(data['schema'] == 1 and data['status'] == 'fixed_trial_startup_v18_p11_staged_no_boot_selection'
            and data['boot_id'] == '00000000-0000-4000-8000-000000000032' and data['metadata_sha256'] == META
            and data['helper_sha256'] == STARTUP_SHA and data['manifest'] == manifest_ref
            and data['installer'] == manifest['installer'] and data['published'] is True
            and data['installer_returncode'] == 0 and manifest['rescue_v17_helper_and_package_preserved'] is True,
            'Actual V18 startup-only update/native preservation required')
    native = data['installer_result']
    require(native['status'] == 'native_trial_startup_v18_staged' and native['boot_id'] == data['boot_id']
            and native['metadata_sha256'] == META, 'Exact native V18 update identity required')
    for key, value in {'additions_published': 1, 'replacements_published': 1, 'temporary_created': 2,
                       'links_created': 0, 'private_sh_links_replaced': 0}.items():
        require(native[key] == value, 'Actual startup-only count required: ' + key)
    for key in ('native_identity_unchanged', 'known_preserved_leaf_inodes_unchanged', 'prerequisites_unchanged'):
        require(native[key] is True, 'Actual startup preservation required: ' + key)
    for key in ('mode_changed', 'package_database_updated', 'armed', 'rebooted', 'boot_committed'):
        require(native[key] is False, 'Actual startup no other changes required: ' + key)
    require(any(row['target'] == '/usr/libexec/leon-asus/rescue-link' and row['sha256'] == CURRENT_RESCUE_SHA
                for row in manifest['checks']), 'V17 rescue helper preserved by the actual startup installer')
    clean_ref = pinned(CURRENT_EXPORT)
    exported = json.loads((R / CURRENT_EXPORT[0]).read_text())
    require(exported['status'] == 'clean_only_export_complete' and exported['boot_id'] == BOOT
            and exported['metadata_sha256'] == META and exported['stock_receipt'] == stock_ref
            and exported['recovery_started'] is False and exported['export_started'] is True
            and exported['superblock_before'] == {'state': 1, 'error_count': 0, 'needs_recovery': False, 'last_orphan': 0}
            and exported['boot_selected'] is False and exported['rebooted'] is False,
            'Actual current-boot clean exporter/native stock2 guards required')
    pinned(CLEAN_SB)
    clean_superblock((R / CLEAN_SB[0]).read_bytes())
    return {**stock_ref, 'originals': originals}, stage_ref, clean_ref


def expected_writer(firmware, image):
    """Prove every original guard/one writer call/readback byte survives."""
    pinned(BASE_SCRIPT)
    old = (R / BASE_SCRIPT[0]).read_text()
    changes = [('# Guardian29 root successor; unchanged signed bootfs inherits prior QEMU evidence.',
                '# Guardian30 startup-identity successor; unchanged signed bootfs inherits prior QEMU evidence.'),
               ('image=/tmp/kernel10-ubuntu26-v15-candidate.pkgtb', 'image=' + REMOTE_IMAGE),
               ('lock=/tmp/kernel10-ubuntu26-v15-flash.lock', 'lock=' + REMOTE_LOCK),
               (BASE_IMAGE[1], image['sha256']),
               ('= 89065172 ] || fail package_length', '= ' + str(image['bytes']) + ' ] || fail package_length'),
               ('> /tmp/kernel10-ubuntu26-v15-flash.log 2>&1', '> ' + REMOTE_LOG + ' 2>&1'),
               ('prefix_hash /dev/rootfs1 76570624', 'prefix_hash /dev/rootfs1 ' + str(firmware['outer']['rootfs_bytes'])),
               ('9982c9ee897658e347adcf293593cbffe954fb7224281de23e3743c7edb585e4', firmware['outer']['rootfs_sha256'])]
    expected = old
    for before, after in changes:
        require(expected.count(before) == 1, 'Unique fixed writer substitution required')
        expected = expected.replace(before, after, 1)
    require((R / SCRIPT[0]).read_text() == expected, 'Any original writer/guard/readback change refused')
    reverse = expected
    for before, after in reversed(changes):
        require(reverse.count(after) == 1, 'Unique fixed writer reverse substitution required')
        reverse = reverse.replace(after, before, 1)
    require(reverse == old, 'Every original inactive-write/readback/preservation guard must remain exact')


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


def install_receipt(row, rescue):
    if row[1] is None or (rescue and RESCUE_STATUS is None):
        return {'path': row[0], 'sha256': row[1], 'status': 'deferred_actual_install_receipt_required', 'ready': False}
    value = pinned(row)
    data = json.loads((R / row[0]).read_text())
    status = RESCUE_STATUS if rescue else 'fixed_v15_p11_candidate_staged_no_boot_selection'
    require(data['schema'] == 1 and data['status'] == status and data['boot_id'] == HISTORICAL_BOOT
            and data['metadata_sha256'] == META and data['published'] is True,
            'Exact historical V15 same-boot completed install receipt required')
    native = data['installer_result']
    require(native['schema'] == 1 and native['boot_id'] == HISTORICAL_BOOT and native['metadata_sha256'] == META,
            'Native install receipt identity required')
    expected = {'status': 'native_uplink_rescue_staged' if rescue else 'native_trial_candidate_v15_staged',
                'additions_published': 7 if rescue else 8, 'replacements_published': 0 if rescue else 2,
                'temporary_created': 7 if rescue else 10, 'links_created': 1 if rescue else 2}
    for key, expected_value in expected.items():
        require(native[key] == expected_value, 'Exact native install field: ' + key)
    for key in ('native_identity_unchanged', 'known_preserved_leaf_inodes_unchanged', 'prerequisites_unchanged'):
        require(native[key] is True, 'Preservation receipt: ' + key)
    for key in ('mode_changed', 'package_database_updated', 'armed', 'rebooted', 'boot_committed'):
        require(native[key] is False, 'Installer must not change: ' + key)
    if rescue:
        require(data['helper_sha256'] == RESCUE_SHA, 'Exact rescue helper required')
    else:
        require(data['expected_new_rc_sha256'] == RC_SHA and data['installer']['sha256'] == CANDIDATE_INSTALLER_SHA
                and data['manifest'] == pinned(CANDIDATE_MANIFEST), 'Exact candidate installer/RC required')
        require(data['prior_rescue_stage']['sha256'] == RESCUE_RECEIPT[1]
                and data['prior_rescue_stage']['path'] == RESCUE_RECEIPT[0]
                and data['prior_rescue_stage']['ready'] is True, 'Rescue must precede candidate staging')
    return {**value, 'status': status, 'ready': True, 'scope': 'historical_v15_provisioning', 'boot_id': HISTORICAL_BOOT}


def prepare():
    require(__debug__, 'Python -O forbidden')
    history = {key: pinned(row) for key, row in [('outer_wrapper', BASE_OUTER), ('writer', BASE_SCRIPT),
               ('wrapper_manifest', BASE_WRAPPER), ('firmware', BASE_FW), ('image', BASE_IMAGE),
               ('actual_flash_receipt', BASE_FLASH), ('finish_receipt', BASE_FINISH), ('old_launcher', OLD_LAUNCHER)]}
    flashed = json.loads((R / BASE_FLASH[0]).read_text())
    require(flashed['status'] == 'fixed_v15_inactive_slot1_readback_passed_no_boot_selection'
            and flashed['flash_returncode'] == 0 and flashed['wrapper'] == history['outer_wrapper']
            and flashed['artifacts']['script'] == history['writer'] and flashed['artifacts']['image'] == history['image'],
            'Actual successful original V15 writer/readback proof retained')
    finish = json.loads((R / BASE_FINISH[0]).read_text())
    require(finish['status'] == 'existing_sole_pack_outputs_verified_after_failed_finish_sidecar'
            and finish['first_complete_readonly_verification']['exit_code'] == 0
            and finish['outputs']['image'] == history['image'] and finish['outputs']['firmware_manifest'] == history['firmware'],
            'Original actual V15 complete verification proof retained')
    stock, startup, clean = current_provenance()
    rescue = install_receipt(RESCUE_RECEIPT, True)
    candidate = install_receipt(CANDIDATE_RECEIPT, False)
    refs = {key: declared(row) for key, row in [('firmware', FW), ('image', IMAGE), ('wrapper_manifest', WRAPPER_MANIFEST),
            ('script', SCRIPT), ('stage', STAGE), ('guardian_manifest', GUARDIAN_MANIFEST), ('guardian_receipt', GUARDIAN_RECEIPT)]}
    ready = all(refs[key]['sha256'] is not None for key in ('firmware', 'image', 'wrapper_manifest', 'script', 'stage'))
    if ready:
        firmware = json.loads((R / FW[0]).read_text())
        wrapper = json.loads((R / WRAPPER_MANIFEST[0]).read_text())
        stage = json.loads((R / STAGE[0]).read_text())
        require(firmware['status'] == 'guardian30_v19_repacked_with_byte_identical_signed_bootfs_not_flash_accepted'
                and firmware['image'] == refs['image'] and firmware['stage_manifest'] == refs['stage']
                and firmware['guardian_manifest']['sha256'] == GUARDIAN_MANIFEST[1]
                and firmware['guardian_receipt']['sha256'] == GUARDIAN_RECEIPT[1]
                and firmware['outer']['entire_signed_bootfs_byte_identical'] is True
                and firmware['outer']['original_outer_timestamp_preserved'] is True, 'Exact V19 firmware/new guardian chain')
        require(stage['inputs']['guardian_sha256'] == GUARDIAN_SHA
                and stage['inputs']['guardian_manifest_sha256'] == GUARDIAN_RECEIPT[1], 'Trusted SquashFS guardian30 required')
        require(wrapper['script'] == refs['script'] and wrapper['image'] == refs['image']
                and wrapper['firmware_manifest'] == refs['firmware'] and wrapper['guard_and_writer_bytes_preserved'] is True
                and wrapper['remote_image'] == REMOTE_IMAGE and wrapper['remote_lock'] == REMOTE_LOCK
                and wrapper['remote_log'] == REMOTE_LOG, 'Exact guarded V19 generated writer')
        expected_writer(firmware, refs['image'])
    _, function_sha = transport_node()
    return {'schema': 1, 'status': 'fixed_v19_inactive_slot1_flash_source_plan', 'wrapper': ref(Path(__file__)),
            'boot_id': BOOT, 'metadata_sha256': META, 'artifacts': refs, 'historical_v15_proof': history,
            'historical_rescue_stage': rescue, 'historical_candidate_stage': candidate,
            'actual_startup_stage': startup, 'current_stock2_identity': stock, 'current_clean_export': clean,
            'transport_source': pinned(TRANSPORT), 'transport_function_sha256': function_sha,
            'remote_image': REMOTE_IMAGE, 'remote_script': REMOTE_SCRIPT, 'remote_lock': REMOTE_LOCK, 'remote_log': REMOTE_LOG,
            'evidence_output': str(OUT.relative_to(R)), 'expected_rc_sha256': RC_SHA,
            'expected_current_rescue_helper_sha256': CURRENT_RESCUE_SHA, 'expected_startup_sha256': STARTUP_SHA,
            'original_stock2_hashes': {'bootfs2': 'ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256',
                                       'rootfs2': '51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465'},
            'clean_superblock': pinned(CLEAN_SB), 'full1024_clean_gate_before_transfer_and_immediate_preflash': True,
            'ready_for_execution': ready and rescue['ready'] and candidate['ready'], 'only_inactive_slot1_written': True,
            'boot_selected': False, 'rebooted': False, 'boot_committed': False, 'ACK_sent': False,
            'limits': ['V15 rescue/candidate staging receipts are historical evidence, not new same-boot staging claims.',
                       'Actual V18 startup update/current stock2/clean exporter receipts are separate exact dependencies.',
                       'Full1024 clean UUID/state/error/orphan/recovery gate is fresh before transfer and hash-bound again immediately before the original writer.',
                       'Frozen writer retains stock2 state/code, complete stock2/GPT/full p11 before/after and inactive readback guards.',
                       'Unique V19 output/files/lock/log are retained on failure; no automatic retry, selector, reboot or acceptance.',
                       'No new exact-image QEMU or physical native acceptance is claimed.']}


def execute(plan, approved):
    require(hashlib.sha256(canonical(plan)).hexdigest() == approved, 'Exact reviewed execution plan SHA required')
    require(plan['ready_for_execution'] is True, 'All firmware and actual/historical evidence pins required before any output/transport')
    OUT.mkdir(parents=True, exist_ok=False)
    transport = transport_only()
    result = {**plan, 'approved_execution_plan_sha256': approved, 'flash_started': False,
              'status': 'started_fixed_v19_inactive_flash'}

    def transfer(local_row, remote, mode, label):
        command = (GUARD + 'umask 077; test ! -e ' + shlex.quote(remote) + '; test ! -L ' + shlex.quote(remote)
                   + '; set -C; cat > ' + shlex.quote(remote) + '; set +C; set -- $(sha256sum '
                   + shlex.quote(remote) + '); test "$1" = ' + local_row[1] + '; chmod ' + mode + ' ' + shlex.quote(remote))
        try:
            with (R / local_row[0]).open('rb') as stream:
                run = subprocess.run(transport(command), stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        except subprocess.TimeoutExpired as exc:
            (OUT / (label + '.stdout')).write_bytes(exc.stdout or b'')
            (OUT / (label + '.stderr')).write_bytes(exc.stderr or b'')
            raise
        (OUT / (label + '.stdout')).write_bytes(run.stdout)
        (OUT / (label + '.stderr')).write_bytes(run.stderr)
        result[label + '_returncode'] = run.returncode
        require(run.returncode == 0, 'Exclusive transfer refused; retain evidence, no retry')

    try:
        command = GUARD + 'exec /bin/busybox dd if=/dev/mmcblk0p11 bs=1024 skip=1 count=1'
        run = subprocess.run(transport(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        (OUT / 'superblock-before.stdout').write_bytes(run.stdout)
        (OUT / 'superblock-before.stderr').write_bytes(run.stderr)
        require(run.returncode == 0, 'Fresh clean superblock read refused; no transfer/write')
        clean_superblock(run.stdout)
        require(hashlib.sha256(run.stdout).hexdigest() == CLEAN_SB[1], 'Fresh full1024 must equal the pinned observed clean superblock')
        result['superblock_before'] = ref(OUT / 'superblock-before.stdout')
        transfer(IMAGE, REMOTE_IMAGE, '600', 'image-transfer')
        transfer(SCRIPT, REMOTE_SCRIPT, '700', 'script-transfer')
        # Recheck exact stock boot/code/metadata immediately before the frozen
        # writer; unique lock/log must not have been preplaced. The writer owns
        # the exclusive lock and repeats its original before/after guards.
        command = GUARD + SB_GUARD
        for path in (REMOTE_LOCK, REMOTE_LOG):
            command += 'test ! -e ' + shlex.quote(path) + '; test ! -L ' + shlex.quote(path) + '; '
        command += ('set -- $(sha256sum ' + shlex.quote(REMOTE_SCRIPT) + '); test "$1" = ' + SCRIPT[1]
                    + '; exec /bin/sh ' + shlex.quote(REMOTE_SCRIPT))
        result['flash_call_dispatched'] = True
        result['flash_started'] = None  # Remote progress is unknown until verified receipt.
        result['flash_started_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT / 'attempt.json').write_text(json.dumps(result, indent=2) + '\n')
        with (OUT / 'flash.stdout').open('wb') as stdout, (OUT / 'flash.stderr').open('wb') as stderr:
            run = subprocess.run(transport(command), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=600)
        result.update(flash_returncode=run.returncode, stdout=ref(OUT / 'flash.stdout'), stderr=ref(OUT / 'flash.stderr'))
        require(run.returncode == 0, 'Flash refused or incomplete; no selection/reboot, retain evidence, no retry')
        lines = (OUT / 'flash.stdout').read_text().splitlines()
        require(lines.count('KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS') == 1,
                'One complete frozen-writer success marker required')
        result.update(status='fixed_v19_inactive_slot1_readback_passed_no_boot_selection', flash_started=True)
    except Exception as exc:
        result.update(status='failed_evidence_preserved_no_repeat', error=str(exc))
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)


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

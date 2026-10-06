#!/usr/bin/env python3
"""Plan V24 kernel11 inactive-slot1 flash, preserving the actual V23 guard/writer.

Default reads local files only. Historical provisioning and V18 startup are
separate from current stock2, journal preen, HTTPS stage and post-stage clean
proof. No selector, reboot, ACK, commit or package changes.
"""
import argparse
import ast
import datetime
import hashlib
import importlib.util
import json
import shlex
import subprocess
import struct
import sys

sys.dont_write_bytecode = True
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000004'
HISTORICAL_BOOT = '00000000-0000-4000-8000-000000000024'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py', 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
OLD_LAUNCHER = ('scripts/flash-cfe-factory-v11.py', '74615c25691949f9578a7c110028425f5f27a1b53b3b0e42d959ef25852e17f4')
FW = ('build/ubuntu26-firmware/kernel11-ubuntu26-trial-v24-device-bpf-guardian33/manifest.json', 'd8438184cfa126df5849b36d9e86faf161af466581b87d4396c4dbbe9f28e8da')
IMAGE = ('build/GT-BE19000AI_3006_102.9_leon-kernel11-ubuntu26-trial-v24-device-bpf-guardian33_TRIAL.pkgtb', 'a6dd363892b5d9871432b3edcfd4e0db7795b7e603063c83a92e0a2cef730650')
WRAPPER_MANIFEST = ('build/ubuntu26-flash/kernel11-ubuntu26-twentyfourth-device-bpf-guardian33-v1/manifest.json', '76c9050f24a3bcf470d91436f5f19e4aa8793994ca70d82289e5243e3c6dfff4')
SCRIPT = ('build/ubuntu26-flash/kernel11-ubuntu26-twentyfourth-device-bpf-guardian33-v1/flash-inactive-slot1.sh', 'aff4bca49eced0dbb637fdb67625dc5415c1bec19f73bb4cbbe9a261a5b53997')
STAGE = ('build/ubuntu26-bootstrap/device-kernel11-guardian33-v24/manifest.json', 'f9291e0ee9dd0fcf2ce5885ba0b8d094bfed698ef2ef6fd85e6c16df321a538e')
GUARDIAN_MANIFEST = ('build/asus-trial-runtime/native-v33-kernel11-identity/manifest.json', 'a1d034cb56444162c24debc905a61fadf59d4a1072e0c1f0718d98151b41d155')
GUARDIAN_RECEIPT = ('build/asus-trial-runtime/native-v33-kernel11-identity/guardian-receipt.json', 'ffebfcc7c4338742a56624fd2af35fa0319a17e21742ff707e8f5dd4521cc90b')
GUARDIAN_SHA = '24d5743457e3fb9717b3acca783ecf314121f6a5191a7dc61a44afc586f063b4'
BASE_OUTER = ('scripts/flash-lan-ssh-policy-v15.py', 'd800cf4dbab82d2f35777caea9db32ca527e5b880825f5496b5abc05815371dc')
BASE_SCRIPT = ('build/ubuntu26-flash/kernel10-ubuntu26-fifteenth-lan-ssh-policy-v1/flash-inactive-slot1.sh', '228fd9dcbf2c710672d766c410e31e364592b0d927f2507b7bc2596a35e04e1a')
BASE_WRAPPER = ('build/ubuntu26-flash/kernel10-ubuntu26-fifteenth-lan-ssh-policy-v1/manifest.json', 'e6aaa4ffcbba083d6afbfff19eed3722ba7c82f6a32602b122016379c4466bbc')
BASE_FW = ('build/ubuntu26-firmware/kernel10-ubuntu26-trial-v15-lan-ssh-policy/manifest.json', 'cb2f3ae9657ae92e563be14187fcddf7ec6456f0a0edcf48b94f9b4291ec5295')
BASE_IMAGE = ('build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v15-lan-ssh-policy_TRIAL.pkgtb', '0ca0e99f11c5c6711a3d0cbf8ffcee18eed3bdc1d5d5b35c49a0d63b364b9916')
BASE_FLASH = ('evidence/ubuntu26/flash-live/fifteenth-lan-ssh-policy-v1/result.json', '3d20ae5cb6b0f38fac996141eee6b4d27735d5a32f8c07559ebc008d3bb368e7')
BASE_FINISH = ('reports/ubuntu26/guardian29-firmware-finish-v2.json', '4eb502cc295c69bad84e300249f42276c4e1acf6d07bfa9f0ebd45ca6ab5fa2c')
STOCK = ('evidence/ubuntu26/trial-live/docker-kernel11-v24-stock2-return-v1/stock-result.json', 'fd2d88aa1c1a50ec017be321e1b7e15a674eed80c16084eef0788dc656762759')
STOCK_SOURCE = ('scripts/observe-kernel11-v24-stock2-return-v1.py', 'fd5a9c8b9aab0b70074444bc2104308161cb87df354195a28767b89e78b8a516')
AUTH_COMMAND = ('evidence/ubuntu26/trial-live/docker-kernel11-v24-stock2-return-v1/command.txt', 'f215b572368d82753606ab15e8929c81a58179df71e14ac851994b1fb98b709b')
AUTH_STDOUT = ('evidence/ubuntu26/trial-live/docker-kernel11-v24-stock2-return-v1/stock-context.stdout', '223a1cee9bb4b64efd7fbe4b8e2c61b2d36fc75c512476dffb6d9d515144e175')
AUTH_ATTEMPTS = ('evidence/ubuntu26/trial-live/docker-kernel11-v24-stock2-return-v1/attempts.jsonl', '2166439d4ef9d1aac80eb35a0aee221f05869cb6ba185e8641bed7bfecf6b5e4')
RECOVERY_SOURCE = ('scripts/recover-kernel11-v24-p11-once.py', 'ee27ad0b7375a4d5473b553d1babf5a49fedf67bdceea65c8dc46b663b3103b4')
CURRENT_RECOVERY = ('evidence/ubuntu26/trial-live/docker-kernel11-v24-p11-recovery-v1/result.json', '4031b81c513e9ef3ae54904ac9493cec2ffe28b87634bf423bd2150afe3c2f92')
HTTPS_RECEIPT = ('evidence/ubuntu26/device-https-helper-live/install-v1/result.json', '978ca08968b393bdfe9b153a27b48a8a44a477e479909337a7b77652a81a54b1')
HTTPS_MANIFEST = ('build/asus-https-helper/install-v1/manifest.json', '8909ffaa23f6046a7ffa18e85584d7debefaa5a826036e62e2e38b804601a796')
PACKER = ('scripts/pack-ubuntu26-kernel11-guardian33-v24.py', '866d08380ee06eafd3eb429139360e4cc5560ad91aeabf8262de4409d5e1f02f')
GUARDIAN_SOURCE_REPORT = ('reports/ubuntu26/guardian33-kernel11-identity-source-v1.json', '54de51e7e2b045d4d32792b253a4cb6265aa73d9f2aa0db0854b2b7586c474d6')
GUARDIAN_FOCUSED = ('reports/ubuntu26/guardian-v31-focused-validation-v1.json', '3990ccc55feb827195d968bc2534c25b352c46677a9a97c9fae6be502382c2be')
STARTUP_RECEIPT = ('evidence/ubuntu26/device-trial-startup-v18-live/install-v1/result.json', '7751a47ea672819c47b41cec9e85da4799b0214a2a005aff4963d61afacc36ef')
STARTUP_MANIFEST = ('build/asus-trial-startup-v18/install-v1/manifest.json', 'fe8ce24d157c2b22625003a8ac3a7366b09182ab8500ef19c2814f82f4c107f0')
STARTUP_SHA = '69994d0dbaf4db84c3ea9207ec3d03ff27a3c2d05edaf2571a23f30a76b9c6d7'
HISTORICAL_V18_RESCUE_SHA = 'bc4a5a7cdc368dafebd0ac172abed57bd3352436def9303bba656ed6f7a3a590'
CURRENT_RESCUE_SHA = '98e4d025fd79e5969a038fa1a141767358996941bf940c720110f6aee1e51028'
CLEAN_SB = ('evidence/ubuntu26/trial-live/docker-kernel11-v24-p11-recovery-v1/post-recovery-superblock.stdout', '54b2ff41a448db0c679bf3026e0e0e13509dce40393458f0807f63f550c2c4e6')
CANDIDATE_MANIFEST = ('build/asus-trial-candidate-v15/install-v1/manifest.json', '18c2470a65afa9d2aad2e5e9676b810f6a1757ab4f89bb9b1a1196987a2ff984')
CANDIDATE_INSTALLER_SHA = '3ee1c2a1e8b1e78bf03501bb84bb61e549bbd28c75761501ebb1e57a78c11b65'
RC_SHA = 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2'
RESCUE_SHA = '55f6953743d6e0420d4d04d2ad95505fcf0ba340da9c84ce91ee375be622a133'
BASE_V22 = ('scripts/flash-accepted-guardian31-v22.py', '533860e820ad0b1c3cdc48b3871e5aa8ab2cc01d0f384edabfaf19fddc939fc6')
GUARDIAN_PID1_FOCUSED = ('build/asus-accepted-runtime/pid1-zero-time-fixture-v1/result.json', '9b3d89f11dce2b7d5189d0e773cfb3a68b65a98915aa1efc08a2150c2d7f018b')
CLIENT_SHA = '0ae4d35580e43297ba2a78978d12ce656aad8325ef2ad16d169d4525b7553fc3'
# Deferred paths are visible in a source-only plan, never accepted for execution.
CANDIDATE_RECEIPT = ('evidence/ubuntu26/device-trial-candidate-v15-live/install-v1/result.json', '65a5e4e8bf9766bdd86def92f5f78491d299f03181568270ba2ff096e76c4898')
RESCUE_RECEIPT = ('evidence/ubuntu26/device-uplink-rescue-live/install-v3/result.json', '7d9968b458f1076e333517794857072f77bf53867345d9050b509ec056b5c643')
RESCUE_STATUS = 'fixed_native_uplink_rescue_p11_staged_no_boot_selection'
REMOTE_IMAGE = '/tmp/kernel11-ubuntu26-v24-candidate.pkgtb'
REMOTE_SCRIPT = '/tmp/leon-flash-v24-kernel11-guardian33.sh'
REMOTE_LOCK = '/tmp/kernel11-ubuntu26-v24-flash.lock'
REMOTE_LOG = '/tmp/kernel11-ubuntu26-v24-flash.log'
OUT = R / 'evidence/ubuntu26/flash-live/twentyfourth-kernel11-inactive-flash-v1'
V23_OUTER = ('scripts/flash-pid1-zero-guardian32-v23.py', '6fac921a8c44eaac3b0469331bdfbba95332fae311d74998f3442a56e2d0f9c3')
V23_SCRIPT = ('build/ubuntu26-flash/kernel10-ubuntu26-twentythird-pid1-zero-guardian32-v1/flash-inactive-slot1.sh', '46e142a27752d70e89901f19872172a1501ee93294e005442fb9818e8fe7b324')
V23_FIRMWARE = ('build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v23-accepted-this-boot-guardian32_TRIAL.pkgtb', '5a9233f2aa13a473daebc612f4d29654cf06fed90638e25266f38331e1e47fbd')
KERNEL_SHA = '7d0be9c9c719291e52cf8994221d3c6267185a27e9b5bd4079f40d9bf21a21ed'
KERNEL_NOTES_SHA = 'bb2994742f8f681f7046672cdf59b38e2e259480b59d368134c2fbd25e67721c'
TARGETED_QEMU = ('build/qemu/kernel11-device-bpf-docker-v2/result.json', 'd01bee2acf64ecdd2a64c33adbc1ef9bbc844981fc17d0c6203ebfc3710954fc')

GUARD = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT or '__PENDING_STOCK_BOOT__')
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
            + 'test "$1" = ' + (CLEAN_SB[1] or '__PENDING_CLEAN_SB_SHA__') + '; ')


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


def historical_v22_provenance():
    # Pure historical validator; its main/prepare/execute are never called here.
    pinned(BASE_V22)
    spec = importlib.util.spec_from_file_location('frozen_v22_https_ancestry', R / BASE_V22[0])
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    stock, startup, recovered, https = base.current_provenance()
    return {'wrapper': pinned(BASE_V22), 'boot_id': '00000000-0000-4000-8000-000000000035',
            'stock2_identity': stock, 'actual_startup_stage': startup, 'p11_recovery': recovered,
            'actual_https_stage': https, 'post_https_clean_superblock': pinned(base.CLEAN_SB),
            'scope': 'historical_v22_ancestry_not_current_stock_or_recovery'}


def current_provenance(historical):
    rows = (STOCK, AUTH_COMMAND, AUTH_STDOUT, AUTH_ATTEMPTS, CURRENT_RECOVERY, CLEAN_SB)
    if BOOT is None or any(row[1] is None for row in rows):
        return ({**declared(STOCK), 'ready': False, 'originals': {k: declared(row) for k, row in
                 [('source', STOCK_SOURCE), ('command', AUTH_COMMAND), ('stdout', AUTH_STDOUT), ('attempts', AUTH_ATTEMPTS)]}},
                historical['actual_startup_stage'], {**declared(CURRENT_RECOVERY), 'ready': False}, historical['actual_https_stage'])
    stock_ref = pinned(STOCK)
    originals = {key: pinned(row) for key, row in [('source', STOCK_SOURCE), ('command', AUTH_COMMAND),
                                                  ('stdout', AUTH_STDOUT), ('attempts', AUTH_ATTEMPTS)]}
    stock = json.loads((R / STOCK[0]).read_text())
    require(stock['status'] == 'authenticated_new_stock2_return' and stock['boot_id'] == BOOT
            and BOOT not in ('00000000-0000-4000-8000-000000000035', '00000000-0000-4000-8000-000000000027')
            and stock['metadata_sha256'] == META and stock['reset_reason'] == '34'
            and stock['context_sha256'] == AUTH_STDOUT[1] and stock['source_sha256'] == STOCK_SOURCE[1]
            and stock['manual_powercycle_requested'] is False and stock['ACK_sent'] is False
            and stock['intentional_sysrq_reset_after_root_ro'] is True,
            'Actual newly authenticated stock2 context required; historical V22 stays separate')
    attempts = [json.loads(line) for line in (R / AUTH_ATTEMPTS[0]).read_text().splitlines()]
    require(len(attempts) == stock['attempts'] and attempts[-1]['attempt'] == stock['attempts']
            and attempts[-1]['returncode'] == 0 and attempts[-1]['stdout_bytes'] == originals['stdout']['bytes']
            and 0 <= stock['elapsed_seconds'] - attempts[-1]['elapsed_seconds'] < 1
            and attempts[-1]['stderr_sha256'] == hashlib.sha256(b'').hexdigest(),
            'Actual successful guarded stock authentication; receipt timestamp follows attempt recording')
    lines = (R / AUTH_STDOUT[0]).read_text().splitlines()
    require(lines[:3] == ['boot=' + BOOT, 'reason=34', '4.19.294'] and lines[3].startswith('#1 ')
            and [word for word in lines[4].split() if word.startswith('root=')] == ['root=/dev/mmcblk0p6']
            and lines[-2:] == [META + '  /dev/mmcblk0p1', META + '  /dev/mmcblk0p2'],
            'Saved current stock2 root/code/reason/full metadata context required; UID not claimed')
    recovery_ref = pinned(CURRENT_RECOVERY); pinned(RECOVERY_SOURCE)
    recovered = json.loads((R / CURRENT_RECOVERY[0]).read_text())
    require(recovered['status'] == 'clean_p11_ready_no_export' and recovered['boot_id'] == BOOT
            and recovered['stock_receipt_sha256'] == STOCK[1] and recovered['source_sha256'] == RECOVERY_SOURCE[1]
            and type(recovered['preen_count']) is int and recovered['preen_count'] in (0, 1)
            and recovered['no_export'] is True and recovered['boot_selected'] is False and recovered['rebooted'] is False,
            'Current conditional single journal recovery required; no export or historical boot relabel')
    if recovered['preen_count'] == 0:
        require(recovered['superblock_before'] == {'state': 1, 'error_count': 0, 'needs_recovery': False, 'last_orphan': 0}
                and 'recovery' not in recovered, 'Zero preen allowed only for an already strictly clean p11')
    else:
        recovery = recovered['recovery']
        require(recovery['status'] == 'p11_preen_completed_and_frozen_clean_gates_passed'
                and recovery['boot_id'] == BOOT and recovery['metadata_sha256'] == META
                and recovery['child_starts'] == 1 and recovery['e2fsck_exit'] == 0 and recovery['retries'] == 0
                and all(recovery[key] is False for key in ('mounted', 'provisioned', 'armed', 'rebooted', 'boot_committed')),
                'Current one-preen native clean/stock2 receipt required')
    pinned(CLEAN_SB); clean_superblock((R / CLEAN_SB[0]).read_bytes())
    return ({**stock_ref, 'originals': originals, 'ready': True}, historical['actual_startup_stage'],
            {**recovery_ref, 'ready': True}, historical['actual_https_stage'])


def expected_writer(firmware, image):
    """Ten exact V23 literals; reverse proof preserves all original guards."""
    pinned(V23_SCRIPT)
    old = (R / V23_SCRIPT[0]).read_text()
    changes = [('# Guardian32 PID1-zero current-boot acceptance successor; unchanged signed bootfs inherits prior QEMU evidence.', '# Guardian33 kernel11 device-BPF successor; targeted kernel11 QEMU passed; hardware remains unaccepted.'), ('image=/tmp/kernel10-ubuntu26-v23-candidate.pkgtb', 'image=/tmp/kernel11-ubuntu26-v24-candidate.pkgtb'), ('lock=/tmp/kernel10-ubuntu26-v23-flash.lock', 'lock=/tmp/kernel11-ubuntu26-v24-flash.lock'), ('5a9233f2aa13a473daebc612f4d29654cf06fed90638e25266f38331e1e47fbd', 'a6dd363892b5d9871432b3edcfd4e0db7795b7e603063c83a92e0a2cef730650'), ('= 89073364 ] || fail package_length', '= 89164516 ] || fail package_length'), ('> /tmp/kernel10-ubuntu26-v23-flash.log 2>&1', '> /tmp/kernel11-ubuntu26-v24-flash.log 2>&1'), ('prefix_hash /dev/bootfs1 12493580', 'prefix_hash /dev/bootfs1 12584732'), ('be94b37cfd11bbeb80e33dd1f1a54359a09cf0173aeda2d8726168772695f695', '67b413d0ac5991fc2bd2f6eba0a987797f89c5ee9e38603ca8889f6bc6dcfef8'), ('7ae270b468099fd566df31b2f292b880d0c066126f7f69007341e3df47320528', '9f3692bef440bcf6da68f279e79f2594e57d617299ff3c6078dfe0412edec5fa'), ('KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS', 'KERNEL11_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS')]
    expected = old
    for before, after in changes:
        require(expected.count(before) == 1, 'Unique fixed writer substitution required')
        expected = expected.replace(before, after, 1)
    require((R / SCRIPT[0]).read_text() == expected, 'Any original writer/guard/readback change refused')
    reverse = expected
    for before, after in reversed(changes):
        require(reverse.count(after) == 1, 'Unique fixed reverse substitution required')
        reverse = reverse.replace(after, before, 1)
    require(reverse == old, 'Exact V23 one-write/full-preservation source required')



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
    historical_v22 = historical_v22_provenance()
    stock, startup, recovery, https = current_provenance(historical_v22)
    rescue = install_receipt(RESCUE_RECEIPT, True)
    candidate = install_receipt(CANDIDATE_RECEIPT, False)
    refs = {key: declared(row) for key, row in [('firmware', FW), ('image', IMAGE), ('wrapper_manifest', WRAPPER_MANIFEST),
            ('script', SCRIPT), ('stage', STAGE), ('guardian_manifest', GUARDIAN_MANIFEST), ('guardian_receipt', GUARDIAN_RECEIPT),
            ('packer', PACKER), ('guardian_source_report', GUARDIAN_SOURCE_REPORT), ('guardian_focused_validation', GUARDIAN_FOCUSED), ('guardian_pid1_focused_validation', GUARDIAN_PID1_FOCUSED)]}
    ready = (BOOT is not None and stock['ready'] and recovery['ready'] and CLEAN_SB[1] is not None
             and all(row['sha256'] is not None for row in refs.values()))
    if ready:
        # The new runtime has source-bound focused evidence, not a fresh whole-loop claim.
        guardian = json.loads((R / GUARDIAN_MANIFEST[0]).read_text())
        receipt = json.loads((R / GUARDIAN_RECEIPT[0]).read_text())
        require(guardian['status'] == 'built_kernel11_identity_successor' and guardian['native_returncode'] == 0
                and guardian['static_elf_passed'] is True and guardian['compiled_input_inventory_matches'] is True
                and guardian['identity_header_sha256'] == '5fdc4366c0f7ea248e35ef175351f73de9c00745f7b0947d65cbfd8ee21fe42c'
                and guardian['identity_delta']['changed_rows'] == 0 and guardian['identity_delta']['unchanged_rows'] == 213
                and guardian['identity_delta']['all_header_bytes_unchanged'] is False
                and guardian['identity_only_successor'] is True
                and guardian['kernel_identity']['image_sha256'] == KERNEL_SHA
                and guardian['kernel_identity']['notes_sha256'] == KERNEL_NOTES_SHA
                and guardian['source_report']['sha256'] == GUARDIAN_SOURCE_REPORT[1]
                and guardian['focused_validation']['sha256'] == GUARDIAN_FOCUSED[1]
                and guardian['focused_new_case_count'] == 0 and guardian['reused_pid1_case_count'] == 21 and guardian['compile_count'] == 1
                and guardian['guardian_compile_count'] == 1 and guardian['accept_client_compile_count'] == 0
                and guardian['accept_client_reused'] is True and guardian['accept_client']['sha256'] == CLIENT_SHA
                and guardian['pid1_focused_validation']['sha256'] == GUARDIAN_PID1_FOCUSED[1]
                and guardian['reused_focused_case_count'] == 39
                and guardian['full_production_loop_validation_passed'] is False
                and guardian['physical_boot_validated'] is False,
                'Actual guardian33 one-compile/client0/two-literal kernel11 identity required')
        require(receipt['executable']['sha256'] == GUARDIAN_SHA
                and receipt['source_report']['sha256'] == GUARDIAN_SOURCE_REPORT[1]
                and receipt['focused_validation']['sha256'] == GUARDIAN_FOCUSED[1]
                and receipt['pid1_focused_validation']['sha256'] == GUARDIAN_PID1_FOCUSED[1]
                and receipt['accept_client']['sha256'] == CLIENT_SHA
                and receipt['guardian_compile_count'] == 1 and receipt['accept_client_compile_count'] == 0
                and receipt['full_production_loop_validation_passed'] is False,
                'Guardian33 trusted executable and truthful validation receipt required')
        spec = importlib.util.spec_from_file_location('fixed_v24_pure_packer', R / PACKER[0])
        packer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packer)
        packer.verify_outputs()  # Pure fixed-output/source verifier; no pack operation.
        firmware = json.loads((R / FW[0]).read_text())
        wrapper = json.loads((R / WRAPPER_MANIFEST[0]).read_text())
        stage = json.loads((R / STAGE[0]).read_text())
        require(firmware['status'] == 'kernel11_guardian33_v24_locally_signed_not_flash_accepted'
                and firmware['image'] == refs['image'] and firmware['stage_manifest'] == refs['stage']
                and firmware['guardian_manifest']['sha256'] == GUARDIAN_MANIFEST[1]
                and firmware['guardian_receipt']['sha256'] == GUARDIAN_RECEIPT[1]
                and firmware['outer']['entire_signed_bootfs_byte_identical'] is False
                and firmware['original_timestamps_preserved'] is True
                and firmware['kernel_sha256'] == KERNEL_SHA and firmware['targeted_qemu']['sha256'] == TARGETED_QEMU[1]
                and firmware['new_signature_verified'] is True and firmware['uboot_lzo_exact_kernel_match'] is True, 'Exact V24 newly signed kernel11 firmware/guardian33 chain')
        require(stage['inputs']['guardian_sha256'] == GUARDIAN_SHA
                and stage['inputs']['guardian_manifest_sha256'] == GUARDIAN_RECEIPT[1]
                and stage['inputs']['kernel_sha256'] == KERNEL_SHA, 'Trusted SquashFS guardian33/kernel11 required')
        require(wrapper['script'] == refs['script'] and wrapper['image'] == refs['image']
                and wrapper['firmware_manifest'] == refs['firmware'] and wrapper['guard_and_writer_bytes_preserved'] is True
                and wrapper['remote_image'] == REMOTE_IMAGE and wrapper['remote_lock'] == REMOTE_LOCK
                and wrapper['remote_log'] == REMOTE_LOG, 'Exact guarded V24 generated writer')
        expected_writer(firmware, refs['image'])
    _, function_sha = transport_node()
    return {'schema': 1, 'status': 'fixed_v24_kernel11_inactive_slot1_flash_source_plan', 'wrapper': ref(Path(__file__)),
            'boot_id': BOOT, 'metadata_sha256': META, 'artifacts': refs, 'historical_v15_proof': history,
            'historical_rescue_stage': rescue, 'historical_candidate_stage': candidate,
            'actual_startup_stage': startup, 'current_stock2_identity': stock,
            'current_p11_recovery': recovery, 'actual_https_stage': https, 'historical_v22_proof': historical_v22,
            'https_stage_scope': 'historical_v22_eaa59_not_current_stock', 'persisted_client_sha256': CLIENT_SHA,
            'guardian_focused_new_cases': 0, 'guardian_focused_reused_cases': 39, 'guardian_pid1_focused_reused_cases': 21,
            'kernel_sha256': KERNEL_SHA, 'kernel_notes_sha256': KERNEL_NOTES_SHA, 'targeted_qemu': pinned(TARGETED_QEMU),
            'writer_ancestor': pinned(V23_SCRIPT), 'outer_wrapper_ancestor': pinned(V23_OUTER), 'guardian_full_production_loop_validated': False,
            'guardian_physical_boot_validated': False,
            'transport_source': pinned(TRANSPORT), 'transport_function_sha256': function_sha,
            'remote_image': REMOTE_IMAGE, 'remote_script': REMOTE_SCRIPT, 'remote_lock': REMOTE_LOCK, 'remote_log': REMOTE_LOG,
            'evidence_output': str(OUT.relative_to(R)), 'expected_rc_sha256': RC_SHA,
            'expected_current_rescue_helper_sha256': CURRENT_RESCUE_SHA, 'expected_startup_sha256': STARTUP_SHA,
            'original_stock2_hashes': {'bootfs2': 'ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256',
                                       'rootfs2': '51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465'},
            'clean_superblock': declared(CLEAN_SB), 'full1024_clean_gate_before_transfer_and_immediate_preflash': True,
            'ready_for_execution': ready and rescue['ready'] and candidate['ready'], 'only_inactive_slot1_written': True,
            'boot_selected': False, 'rebooted': False, 'boot_committed': False, 'ACK_sent': False,
            'limits': ['V15 rescue/candidate staging receipts are historical evidence, not new same-boot staging claims.',
                       'Historical V18 startup and V22 HTTPS/client persistence are distinct from fresh current stock2/conditional journal recovery/full1024 clean proof.',
                       'Full1024 clean UUID/state/error/orphan/recovery gate is fresh before transfer and hash-bound again immediately before the original writer.',
                       'Frozen writer retains stock2 state/code, complete stock2/GPT/full p11 before/after and inactive readback guards.',
                       'Unique V24 output/files/lock/log are retained on failure; no automatic retry, selector, reboot or acceptance.',
                       'Old39 and21 PID1 cases remain historical source-bound proof; only targeted kernel11 QEMU is new. Whole-firmware QEMU and physical native acceptance remain unclaimed.']}


def execute(plan, approved):
    require(hashlib.sha256(canonical(plan)).hexdigest() == approved, 'Exact reviewed execution plan SHA required')
    require(plan['ready_for_execution'] is True, 'All firmware and actual/historical evidence pins required before any output/transport')
    OUT.mkdir(parents=True, exist_ok=False)
    transport = transport_only()
    result = {**plan, 'approved_execution_plan_sha256': approved, 'flash_started': False,
              'status': 'started_fixed_v24_kernel11_inactive_flash'}

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
        require(lines.count('KERNEL11_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS') == 1,
                'One complete frozen-writer success marker required')
        result.update(status='fixed_v24_kernel11_inactive_slot1_readback_passed_no_boot_selection', flash_started=True)
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

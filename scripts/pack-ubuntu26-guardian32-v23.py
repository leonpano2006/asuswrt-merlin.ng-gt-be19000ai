#!/usr/bin/env python3
"""Fixed V23 guardian32 current-boot acceptance successor of completed V15 firmware.

Default is a pure local plan. An exact plan SHA permits one host copy/pack/list/
readback; failure is retained. No signing, compiler, target, QEMU or device IO.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import types

R = Path(__file__).resolve().parents[1]
PACKER = {'path': 'scripts/pack-ubuntu26-guardian29-successor-v1.py',
          'sha256': 'c941c29fa7f7edf39607f0cd13fbcb6c5b0e9123fc3473e25c8fff60bbfd7e6d', 'bytes': 30556}
V15_PLAN = {'path': 'build/ubuntu26-bootstrap/guardian29-successor-source-plan-v1/plan.json',
            'sha256': 'ba8d9f2144db1db112d4ae45be1c25c507042b4c1c182dc657364e27df531201'}
V15_FINISH = {'path': 'reports/ubuntu26/guardian29-firmware-finish-v2.json',
              'sha256': '4eb502cc295c69bad84e300249f42276c4e1acf6d07bfa9f0ebd45ca6ab5fa2c'}
V15_FIRMWARE = {'path': 'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v15-lan-ssh-policy/manifest.json',
                'sha256': 'cb2f3ae9657ae92e563be14187fcddf7ec6456f0a0edcf48b94f9b4291ec5295'}
V15_IMAGE = {'path': 'build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v15-lan-ssh-policy_TRIAL.pkgtb',
             'sha256': '0ca0e99f11c5c6711a3d0cbf8ffcee18eed3bdc1d5d5b35c49a0d63b364b9916', 'bytes': 89065172}
V15_STAGE = {'path': 'build/ubuntu26-bootstrap/device-lan-ssh-policy-v1/manifest.json',
             'sha256': '6fa6b283d8322e021cabc3ddd0d2c90d3423aea3db30a06df7ac691a66d13b2c'}
V15_ROOT = {'path': 'build/ubuntu26-bootstrap/device-lan-ssh-policy-v1/bootstrap.zstd.squashfs',
            'sha256': '9982c9ee897658e347adcf293593cbffe954fb7224281de23e3743c7edb585e4', 'bytes': 76570624}
V15_META = {'path': 'build/ubuntu26-bootstrap/device-lan-ssh-policy-v1/root/usr/libexec/leon-boot/manifest.json',
            'sha256': '7112d4dfe4e6990d73af3ee218a22df42280c75c38639a08704b9760456b1d0f'}
VERIFIER = {'path': 'scripts/build-asus-accepted-v32-native.py',
            'sha256': 'c1cf544a727bb4a8ccd2a5f094478a1666eca6c1ce33798ecffb08e38ee19b6e'}
FOCUSED = {'path': 'reports/ubuntu26/guardian-v31-focused-validation-v1.json',
           'sha256': '3990ccc55feb827195d968bc2534c25b352c46677a9a97c9fae6be502382c2be'}
GUARD_MANIFEST = {'path': 'build/asus-trial-runtime/native-v32-pid1-zero-time/manifest.json',
                  'sha256': '50819fdb7ed3dac11ba81d96a3839c3aa25882774d6f2337f08687c2fdc9b773'}
GUARD_RECEIPT = {'path': 'build/asus-trial-runtime/native-v32-pid1-zero-time/guardian-receipt.json',
                 'sha256': '80474ff08bf9cdef99b69c7d3d859a1cce45b23da7390584e80574211bef45e5'}
GUARD = {'path': 'build/asus-trial-runtime/native-v32-pid1-zero-time/guardian-integrated',
         'sha256': 'fb835e1fb8ea92504af809ecc9aee4ff0488f416c82d7f7ac5e6364266d6ba6e'}
V22_PACKER = {'path': 'scripts/pack-ubuntu26-guardian31-v22.py', 'sha256': '04018a70250045c0b06f7884ce6f91c1f1f0863795108f6f2dfd693062f19832'}
V22_FIRMWARE = {'path': 'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v22-accepted-this-boot-guardian31/manifest.json', 'sha256': 'f0e9abcffb2b59065d74b3d9d69a5d562ac87e5a0ab827d0e7617c0af65195aa'}
PID1_FOCUSED = {'path': 'build/asus-accepted-runtime/pid1-zero-time-fixture-v1/result.json', 'sha256': '9b3d89f11dce2b7d5189d0e773cfb3a68b65a98915aa1efc08a2150c2d7f018b'}
BASE = R / 'build/ubuntu26-bootstrap/device-lan-ssh-policy-v1'
STAGE = R / 'build/ubuntu26-bootstrap/device-scoped-udev-guardian32-v23'
WORK = R / 'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v23-accepted-this-boot-guardian32'
IMAGE = R / 'build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v23-accepted-this-boot-guardian32_TRIAL.pkgtb'
GENERATED = ('reuse-plan.json', 'boot-manifest.expected.json', 'derived-source-plan.json')
PAYLOADS = {}
PACK = None


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def json_bytes(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def fixed_file(item):
    path = R / item['path']
    require(not Path(item['path']).is_absolute() and '..' not in Path(item['path']).parts,
            'Fixed relative input required')
    require(path.is_file() and not path.is_symlink(), 'Regular fixed input required')
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == item['sha256'] and
            ('bytes' not in item or len(data) == item['bytes']), 'Pinned input changed: ' + str(path))
    return data


def function_text(source, name):
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == name]
    require(len(nodes) == 1 and not nodes[0].decorator_list, 'Unique frozen function required')
    node = nodes[0]
    return ''.join(source.splitlines(True)[node.lineno - 1:node.end_lineno])


def replace_once(source, old, new):
    require(source.count(old) == 1, 'Exact frozen replacement required: ' + old[:80])
    return source.replace(old, new)


def load_pack():
    """Load pinned definitions; only two precisely delimited functions change."""
    source = fixed_file(PACKER).decode()
    pack = types.ModuleType('frozen_v15_packer_definitions_for_v23')
    pack.__file__ = str(R / PACKER['path'])
    exec(compile(source, pack.__file__, 'exec'), pack.__dict__)
    pack.__file__ = __file__
    pack.BASE, pack.STAGE, pack.WORK, pack.IMAGE = BASE, STAGE, WORK, IMAGE
    pack.inputs = inputs
    pack.write_generated_payloads = write_generated_payloads
    execute = function_text(source, 'execute')
    execute = replace_once(execute, '    WORK.mkdir(mode=0o755, exist_ok=False)\n',
                           '    WORK.mkdir(mode=0o755, exist_ok=False)\n    write_generated_payloads()\n')
    extract = ("    commands.append(run([TOOLS['unsquashfs']['path'], '-no-progress', '-processors', '12', '-d', str(readback), str(packed)],\n"
               "                        WORK / 'packed-readback.log'))\n")
    replacement = ("    previous_umask = os.umask(0)\n    try:\n"
                   "        commands.append(run([TOOLS['unsquashfs']['path'], '-no-progress', '-processors', '12', '-d', str(readback), str(packed)],\n"
                   "                            WORK / 'packed-readback.log'))\n"
                   "    finally:\n        os.umask(previous_umask)\n")
    execute = replace_once(execute, extract, replacement)
    verify = function_text(source, 'validate_outputs')
    verify = replace_once(verify, "'packed-readback', 'manifest.json'}, 'Complete work output inventory')",
                          "'packed-readback', 'manifest.json', 'reuse-plan.json',\n"
                          "                                               'boot-manifest.expected.json', 'derived-source-plan.json'}, 'Complete work output inventory')")
    for old, new in [('staged_guardian29_signed_bootfs_successor_local_only', 'staged_guardian32_v23_signed_bootfs_successor_local_only'),
                     ('guardian29_repacked_with_byte_identical_signed_bootfs_not_flash_accepted',
                      'guardian32_v23_repacked_with_byte_identical_signed_bootfs_not_flash_accepted')]:
        execute = replace_once(execute, old, new)
        verify = replace_once(verify, old, new)
    execute = replace_once(execute, 'Whole v11 signed bootfs/signature proof reused;',
                           'Whole V15 signed bootfs/signature proof reused;')
    exec(compile(execute + '\n' + verify, __file__ + ':frozen-packer-successor', 'exec'), pack.__dict__)
    return pack


def payload_ref(name, value):
    data = json_bytes(value)
    PAYLOADS[name] = data
    return {'path': str((WORK / name).relative_to(R)), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def inputs():
    global PAYLOADS
    require(__debug__, 'Python -O forbidden')
    require(all(x['sha256'] is not None for x in (VERIFIER, GUARD_MANIFEST, GUARD_RECEIPT, GUARD, PID1_FOCUSED)), 'Pending native31 pins block before outputs or old tree reads')
    fixed_file(V22_PACKER); fixed_file(V22_FIRMWARE)
    pack = PACK
    PAYLOADS = {}
    old_plan = pack.read_json(V15_PLAN)
    pack.bind_nested(old_plan)
    old_reuse = pack.read_json(old_plan['reuse_plan'])
    pack.bind_nested(old_reuse)
    finish = pack.read_json(V15_FINISH)
    firmware = pack.read_json(V15_FIRMWARE)
    baseline = pack.read_json(V15_STAGE)
    require(finish['status'] == 'existing_sole_pack_outputs_verified_after_failed_finish_sidecar' and
            finish['first_complete_readonly_verification']['exit_code'] == 0 and
            finish['first_complete_readonly_verification']['reported_status'] == 'fixed_successor_file_verification_passed',
            'Actual completed V15 read-only verification required')
    for name, pin in [('image', V15_IMAGE), ('firmware_manifest', V15_FIRMWARE),
                      ('stage_manifest', V15_STAGE), ('packed_root', V15_ROOT)]:
        require({k: finish['outputs'][name][k] for k in pin} == pin, 'V15 final receipt binding')
        pack.pinned(pin)
    require(firmware['stage_manifest']['sha256'] == V15_STAGE['sha256'] and firmware['image']['sha256'] == V15_IMAGE['sha256']
            and firmware['status'] == 'guardian29_repacked_with_byte_identical_signed_bootfs_not_flash_accepted'
            and firmware['outer']['entire_signed_bootfs_byte_identical'] is True
            and firmware['outer']['new_signature_operation'] is False, 'Completed V15 firmware provenance')
    require(baseline['status'] == 'staged_guardian29_signed_bootfs_successor_local_only' and baseline['module_count'] == 181
            and baseline['module_inventory_sha256'] == old_reuse['module_inventory_sha256'], 'Exact V15 stage/module evidence')
    pack.validate_tree(BASE / 'root', baseline['inventory'])
    for name in pack.CHANGES:
        require((BASE / 'root' / name).lstat().st_nlink == 1, 'Changed baseline leaf has hardlinks')
    guardian = pack.module(VERIFIER, 'fixed_guardian32_readonly_verifier').verify_successor(pack.pinned(GUARD_MANIFEST)[0])
    receipt = pack.read_json(GUARD_RECEIPT)
    focused = pack.read_json(FOCUSED)
    pid1_focused = pack.read_json(PID1_FOCUSED)
    require(focused['status'] == 'v31_new39_focused_cases_passed_without_replay'
            and focused['passed_case_count'] == 39 and focused['repeated_case_count'] == 0
            and focused['full_production_loop_validated'] is False and focused['physical_boot_validated'] is False
            and guardian['focused_validation'] == FOCUSED and guardian['reused_focused_case_count'] == 39
            and guardian['pid1_focused_validation'] == PID1_FOCUSED
            and guardian['full_production_loop_validation_passed'] is False, 'Source-bound old39 ancestry and current physical limits required')
    require(pid1_focused['status'] == 'pure_production_pid1_zero_start_parser_fixture_passed'
            and pid1_focused['returncode'] == 0 and pid1_focused['compile_count'] == pid1_focused['fixture_run_count'] == 1
            and guardian['focused_new_case_count'] == pid1_focused['expected_case_count']
            and guardian['guardian_compile_count'] == 1 and guardian['accept_client_compile_count'] == 0
            and guardian['accept_client_reused'] is True, 'Actual narrow PID1 proof and one guardian compile/client reuse required')
    pack.pinned(GUARD)
    require(guardian['identity_delta']['changed_rows'] == 0 and guardian['identity_delta']['unchanged_rows'] == 213
            and guardian['identity_header_sha256'] == '8b48431ce3982a58c6b39bb5f8c0e846cab4552a53053652f3f7daee8ab91ff6', 'All v30 startup-aware regular identities preserved')
    require(receipt['executable'] == GUARD and receipt['build_manifest'] == GUARD_MANIFEST and
            receipt['deployment_gate_enabled'] is True and receipt['fixture'] is False and receipt['hardware_adapter'] is True
            and receipt['static_no_interpreter_or_needed'] is True and receipt['runtime_accepted'] is False
            and receipt['flash_accepted'] is False, 'Fixed trusted unaccepted guardian32 receipt')
    old_meta = pack.read_json(V15_META)
    reuse = copy.deepcopy(old_reuse)
    reuse.update(status='source_only_guardian32_v23_bootstrap_reuse_plan_pack_not_performed',
                 baseline_firmware=V15_FIRMWARE, baseline_stage=V15_STAGE, baseline_rootfs=V15_ROOT,
                 new_guardian_manifest=GUARD_MANIFEST, new_guardian_receipt=GUARD_RECEIPT, new_guardian=GUARD,
                 new_guardian_source_proof=GUARD_MANIFEST,
                 new_guardian_source_delta={'manifest': GUARD_MANIFEST, 'identity_delta': guardian['identity_delta']},
                 completed_v15_pack_proof=V15_FINISH, completed_v22_packer=V22_PACKER, completed_v22_firmware=V22_FIRMWARE,
                 pid1_focused_validation=PID1_FOCUSED,
                 scope=['V15 root-init, fsck, handoff, kernel10/181 modules, vendor rc/loader/web and every other bootstrap inode remain exact.',
                        'Whole signed V15 bootfs bytes are inherited; its original V11 signature proof keeps that original scope.',
                        'Guardian32 changes only fixed PID1 start-time parsing; all213 identities and35 other runtime sources, sole watchdog ownership, bounded workers and diagnostic ID are exact guardian31.',
                        'Old39 focused cases retain their original v31 source hashes without replay; new PID1-only proof is separate. The unchanged client0ae4 is reused, and no new full-loop claim is made.',
                        'Prior QEMU/loop proofs keep their original image/source hashes; no new exact-image QEMU, signing, target execution or physical acceptance.'])
    reuse_ref = payload_ref('reuse-plan.json', reuse)
    metadata = copy.deepcopy(old_meta)
    metadata.update(guardian_sha256=GUARD['sha256'], guardian_manifest_sha256=GUARD_RECEIPT['sha256'],
                    bootstrap_evidence_reuse_sha256=reuse_ref['sha256'])
    require({k for k in old_meta.keys() | metadata.keys() if old_meta.get(k) != metadata.get(k)} ==
            {'guardian_sha256', 'guardian_manifest_sha256', 'bootstrap_evidence_reuse_sha256'}, 'Exactly three boot metadata fields')
    metadata_ref = payload_ref('boot-manifest.expected.json', metadata)
    expected = copy.deepcopy(baseline['inventory'])
    delta = []
    for name, digest in [(pack.GUARD_PATH, GUARD['sha256']), (pack.META_PATH, metadata_ref['sha256'])]:
        before = copy.deepcopy(expected[name])
        require(before['kind'] == stat.S_IFREG and before['mode'] == (0o755 if name == pack.GUARD_PATH else 0o644), 'Frozen changed leaf type/mode')
        expected[name] = {**before, 'sha256': digest}
        delta.append({'path': name, 'before': before, 'after': expected[name]})
    require({name for name in expected if expected[name] != baseline['inventory'][name]} == pack.CHANGES,
            'Exactly two changed bootstrap leaves')
    plan = copy.deepcopy(old_plan)
    plan.update(status='source_only_guardian32_v23_stage_pack_plan', baseline_firmware=V15_FIRMWARE,
                baseline_firmware_image=V15_IMAGE, baseline_stage=V15_STAGE, baseline_rootfs=V15_ROOT,
                new_guardian_manifest=GUARD_MANIFEST, new_guardian_receipt=GUARD_RECEIPT, new_guardian_file=GUARD,
                reuse_plan=reuse_ref, old_boot_manifest=V15_META, expected_boot_manifest=metadata_ref,
                expected_root_inventory_delta=delta, source_ancestor_plan=V15_PLAN, source_ancestor_packer=PACKER,
                guardian_verifier=VERIFIER, completed_v15_pack_proof=V15_FINISH,
                completed_v22_packer=V22_PACKER, completed_v22_firmware=V22_FIRMWARE, pid1_focused_validation=PID1_FOCUSED,
                future_exclusive_outputs={'stage': str(STAGE.relative_to(R)), 'firmware_work': str(WORK.relative_to(R)),
                                          'firmware_image': str(IMAGE.relative_to(R)),
                                          'flash_wrapper': 'build/ubuntu26-flash/kernel10-ubuntu26-twentythird-accepted-guardian32-v1'},
                future_operations_after_review=['One exclusive copy/pack/list/readback with two bootstrap leaf replacements.',
                                                'Readback extraction alone uses umask0 then restores the old umask; packed all-root metadata must match.',
                                                'Whole signed V15 bootfs unchanged; only outer rootfs size/hash change, original timestamp restored.',
                                                'No compiler, target execution, signing key, QEMU, device, flash, selection, reboot or acceptance.'])
    plan['outer_rootfs_node'].update(sha256=V15_ROOT['sha256'], bytes=V15_ROOT['bytes'])
    source_ref = payload_ref('derived-source-plan.json', plan)
    pack.SOURCE_PLAN = source_ref
    fit = pack.module(pack.FITLIB, 'fixed_fitlib_guardian32_v23')
    old = pack.old_fit(plan, fit)
    require(pack.digest(fit.images(old)[pack.BOOT_NODE][1]) == firmware['outer']['bootfs_sha256'] ==
            old_plan['entire_bootfs_reuse']['sha256'], 'Whole V15 signed bootfs binding')
    for tool in pack.TOOLS.values():
        path = Path(tool['path'])
        require(pack.sha(path) == tool['sha256'] and os.access(path, os.X_OK), 'Pinned host archive tool')
    payload_refs = {name: {'path': str((WORK / name).relative_to(R)), 'sha256': pack.digest(data), 'bytes': len(data)}
                    for name, data in PAYLOADS.items()}
    for name, data in PAYLOADS.items():
        path = WORK / name
        if os.path.lexists(path):
            require(pack.read_regular(path) == data, 'Existing generated payload changed')
    execution = {'schema': 1, 'status': 'fixed_guardian32_v23_stage_pack_execution_plan',
                 'builder': pack.ref(Path(__file__)), 'frozen_packer': PACKER, 'source_ancestor_plan': V15_PLAN,
                 'source_plan': source_ref, 'guardian_verifier': VERIFIER, 'fitlib': pack.FITLIB,
                 'completed_v15_pack_proof': V15_FINISH, 'completed_v22_packer': V22_PACKER,
                 'completed_v22_firmware': V22_FIRMWARE, 'pid1_focused_validation': PID1_FOCUSED, 'guardian_manifest': GUARD_MANIFEST, 'guardian_receipt': GUARD_RECEIPT,
                 'tools': pack.TOOLS, 'tool_environment': pack.TOOL_ENV,
                 'baseline_inventory_sha256': pack.digest(pack.canonical(baseline['inventory'])),
                 'expected_inventory_sha256': pack.digest(pack.canonical(expected)),
                 'inode_counts': {str(k): v for k, v in pack.KINDS.items()}, 'changed_paths': sorted(pack.CHANGES),
                 'changed_boot_manifest_fields': plan['root_metadata_fields_changed_only'], 'future_outputs': plan['future_exclusive_outputs'],
                 'generated_payloads': payload_refs, 'expected_boot_manifest': metadata, 'reuse_scope': reuse['scope'],
                 'packed_all_uid_gid_zero_required': True, 'packed_readback_inventory_entries': 4372,
                 'readback_only_umask_zero_then_restore': True,
                 'mksquashfs_argv': [pack.TOOLS['mksquashfs']['path'], str(STAGE / 'root'), str(STAGE / 'bootstrap.zstd.squashfs'),
                                   '-noappend', '-all-root', '-comp', 'zstd', '-Xcompression-level', '22', '-b', '524288',
                                   '-processors', '12', '-no-progress'],
                 'no_new_signing_kernel_decoder_qemu_device': True, 'failure_retained_no_retry': True}
    return plan, baseline, expected, firmware, fit, old, execution


def write_generated_payloads():
    require(set(PAYLOADS) == set(GENERATED), 'Exactly three derived local packaging payloads')
    for name in GENERATED:
        PACK.create_file(WORK / name, PAYLOADS[name], 0o444)


def verify_outputs():
    """Fixed V23 artifact verifier for later wrappers; file reads only."""
    global PACK
    require(__debug__, 'Python -O forbidden')
    PACK = load_pack()
    return PACK.validate_outputs(inputs())


def main():
    global PACK
    require(__debug__, 'Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true')
    group.add_argument('--verify-only', action='store_true')
    group.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    PACK = load_pack()
    verified = inputs()
    gate = PACK.digest(PACK.canonical(verified[-1]))
    if args.execute_plan_sha256 is not None:
        require(args.execute_plan_sha256 == gate, 'Exact reviewed V23 plan required before any output')
        for output in (STAGE, WORK, IMAGE):
            PACK.absent(output)
        try:
            PACK.execute(verified, args.execute_plan_sha256)
        except Exception as exc:
            if WORK.is_dir() and not WORK.is_symlink() and not os.path.lexists(WORK / 'failure.json'):
                PACK.write_json(WORK / 'failure.json', {'status': 'failed_pack_evidence_retained_no_retry',
                                'builder': PACK.ref(Path(__file__)), 'approved_plan_sha256': args.execute_plan_sha256,
                                'error': str(exc), 'device_accessed': False, 'tests_or_compiler_run': False})
            raise
    elif args.verify_only:
        result = PACK.validate_outputs(verified)
        print(json.dumps({'status': 'fixed_v23_successor_file_verification_passed', 'image': result['image'],
                          'manifest': PACK.ref(WORK / 'manifest.json'), 'device_accessed': False}, indent=2))
    else:
        print(json.dumps({'status': 'verified_v23_source_only_no_output_written',
                          'execution_plan_sha256': gate, 'plan': verified[-1]}, indent=2))


if __name__ == '__main__':
    main()

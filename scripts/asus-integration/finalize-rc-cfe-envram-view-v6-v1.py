#!/usr/bin/env python3
"""Finish the existing v6 receipt by file/ELF inspection; never rebuild or run RC."""
import hashlib
import json
from pathlib import Path
import subprocess

R = Path(__file__).resolve().parents[2]
B = R / 'build/asus-rc-recovery'
OLD = B / 'revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v5'
NEW = B / 'revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v6'
SOURCE_MANIFEST = R / 'build/asus-cfe-readonly/cfe-envram-view-v1/manifest.json'
TEST_REPORT = R / 'reports/ubuntu26/asus-cfe-envram-view-v1.json'
REPORT = R / 'reports/ubuntu26/asus-cfe-envram-view-v6-build-v1.json'
PINS = {
    'build/asus-cfe-readonly/cfe-envram-view-v1/manifest.json': 'de7596a2b4331d9fa9695dff6509279b9e3a28240c774e52e580fac34ac67fd5',
    'reports/ubuntu26/asus-cfe-envram-view-v1.json': '4fc0f007b557a72219b3860e1c06a99288f5b4171ba5ef1d7fc9cf919cb80774',
    'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v5/revision-result.json': '5d4dd575a33371f8565cbd33971d11c08c6128193a824b4ebbbeb062ffe8d940',
    'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v5/linked/rc': '394ac07c81aa4da019cd62087923e83b673f842c7552bc519b22981041a4fd20',
    'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v5/linked/libovpn.so': '403a08d0c65b8365f411e43e14c1cc3fc64e99b8bedba09dd6844cb03ce49771',
    'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-v4/linked/rc': 'af9b497f7791d75031772c894d17f886ba99dbac687262d9933133aa65a752fe',
    'scripts/asus-integration/build-asuswrt6-rc-candidate.py': '213aad861fc8d799481747008d1b2d6a29825ffb299cccffa129453fcdb0af32',
    'scripts/asus-integration/build-rc-port-revision.py': '1fd2434c93569ab8ec4cdbe2eda171f2cfe6383b04eb4bdd3276a0325af4bc82',
    'scripts/asus-integration/link-asuswrt6-rc-candidate.py': '2e7b1dbcee996b5084d9684931d8e9016d4e274f971dee26964d256a7664c5a2',
}


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ref(p):
    return {'path': str(p.relative_to(R)), 'sha256': sha(p)}


def load(p):
    return json.loads(p.read_text())


def tree(p):
    return {str(f.relative_to(p)): sha(f) for f in sorted(p.rglob('*'))
            if f.is_file() and not f.is_symlink()}


def normalize(args):
    return [a.replace(str(NEW), str(OLD)) for a in args]


def main():
    assert __debug__ and not REPORT.exists() and not (NEW / 'revision-result.json').exists()
    for path, digest in PINS.items():
        assert sha(R / path) == digest, path
    initial = load(NEW / 'revision-inputs.json')
    assert initial['builder_sha256'] == sha(R / 'scripts/asus-integration/build-rc-port-revision-ccache-v1.py')
    assert all(sha(B / 'linked' / name) == digest for name, digest in initial['old_artifacts'].items())
    sm = load(SOURCE_MANIFEST)
    assert all(sha(R / row['path']) == row['sha256'] for row in sm['base_inputs'] + sm['outputs'])
    assert sha(R / sm['patch']['path']) == sm['patch']['sha256']
    fixture = load(TEST_REPORT)
    assert fixture['status'] == 'three_new_source_bound_view_checks_passed' and len(fixture['checks']) == 3
    old_sources, new_sources = tree(OLD / 'compile-source'), tree(NEW / 'compile-source')
    assert old_sources.keys() == new_sources.keys() and len(old_sources) == 188
    changed = [p for p in old_sources if old_sources[p] != new_sources[p]]
    assert changed == ['release/src/router/rc/ate.c']
    for row in sm['outputs']:
        relative = row['path'].split('/source/', 1)[1]
        assert new_sources[relative] == row['sha256']
    old, new = load(OLD / 'compile-result.json'), load(NEW / 'compile-result.json')
    assert old['compiler'] == new['compiler'] and old['compiler_sha256'] == new['compiler_sha256']
    assert sha(Path(new['compiler'])) == new['compiler_sha256']
    assert old['flags'] == normalize(new['flags'])
    assert new['selected_objects'] == old['selected_objects']
    assert new['retained_model_objects'] == old['retained_model_objects']
    assert len(new['results']) == 67 and len(new['retained_model_objects']) == 56
    prefix = new['ccache']['prefix']
    assert len(prefix) == 4 and prefix[-1].endswith('/usr/bin/ccache')
    assert new['ccache']['version'] == 'ccache version 4.12.3' and new['ccache']['remote_storage_disabled'] is True
    by_object = {row['object']: row for row in old['results']}
    for row in new['results']:
        assert row['returncode'] == 0 and row['command'][:len(prefix)] == prefix
        underlying = row['command'][len(prefix):]
        assert underlying[0] == new['compiler']
        assert normalize(underlying) == by_object[row['object']]['command']
        assert '-D_TIME_BITS=32' in underlying and '-D_FILE_OFFSET_BITS=32' in underlying
        assert '-D_TIME_BITS=64' not in underlying
        assert sha(R / row['source']) == row['source_sha256']
        assert sha(NEW / 'objects' / (row['object'] + '.o')) == row['object_sha256']
    assert sha(OLD / 'objects/ledg.o') == sha(NEW / 'objects/ledg.o')
    links = load(NEW / 'link-result.json')
    old_links = load(OLD / 'link-result.json')
    assert [row['target'] for row in links['links']] == ['libovpn.so', 'rc']
    for row, previous in zip(links['links'], old_links['links']):
        assert row['returncode'] == 0 and normalize(row['command']) == previous['command']
    assert all(row['returncode'] == 0 for row in links['libovpn_compile'])
    rgb = load(NEW / 'ledg-linked-proof.json')
    assert rgb['linked_rc_sha256'] == sha(NEW / 'linked/rc')
    assert len(rgb['five_linked_mov_instructions']) == 5 and rgb['qis_role_call_preserved']
    rc = NEW / 'linked/rc'
    assert sha(rc) == '7e00ff39b48ff4b5efcba7829b1d4849343c88232af3090038bd53b1e9791355'
    proof = NEW / 'elf-inspection-v1'
    proof.mkdir()
    output = subprocess.check_output(['readelf', '-h', '-A', '-l', '-d', str(rc)], text=True)
    (proof / 'rc-readelf.txt').write_text(output)
    assert 'ELF32' in output and 'Machine:                           ARM' in output
    assert 'Version5 EABI, soft-float ABI' in output and '/lib/ld-linux.so.3' in output
    assert 'Tag_CPU_arch: v8' in output and 'NEON for ARMv8' in output
    needed = [line.split('[')[1].split(']')[0] for line in output.splitlines() if '(NEEDED)' in line]
    old_rc = next(row for row in old_links['artifacts'] if row['path'].endswith('/rc'))
    assert needed == old_rc['needed']
    failure = NEW / 'abi-proof/init-final-cc1.log'
    invocation_log = B / 'device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v6-build.log'
    assert '-###: error while loading shared libraries' in failure.read_text()
    assert 'StopIteration' in invocation_log.read_text()
    assert all((NEW / ('abi-proof/' + name)).is_file() for name in ['native-probe', 'armel-probe'])
    receipt = {
        'schema': 1, 'status': 'compiled_linked_source_and_ELF_inspection_passed',
        'production_ready': False, 'scope': 'One local ARMEL build; no RC/device execution or deployment',
        'finalizer': ref(Path(__file__)), 'source_manifest': ref(SOURCE_MANIFEST),
        'focused_fixture': ref(TEST_REPORT),
        'builder': ref(R / 'scripts/asus-integration/build-rc-port-revision-ccache-v1.py'),
        'compiler_wrapper': ref(R / 'scripts/asus-integration/build-asuswrt6-rc-candidate-ccache-v1.py'),
        'compile': ref(NEW / 'compile-result.json'), 'link': ref(NEW / 'link-result.json'),
        'rgb': ref(NEW / 'ledg-linked-proof.json'), 'ELF': ref(proof / 'rc-readelf.txt'),
        'source_delta': {'source_files': 188, 'changed': changed, 'inserted_lines': 2,
                         'CFE_header_MAC_parser_legacy_paths_byte_identical': True},
        'compile_status': {'compiled': 67, 'failed': 0, 'retained_model_objects': 56,
                           'underlying_compiler': new['compiler'], 'compiler_sha256': new['compiler_sha256'],
                           'flags_and_object_selection_equal_v5': True,
                           'ccache': new['ccache'], 'remote_cache_disabled': True},
        'ABI': {'policy': 'Frozen ARMEL time32/off32 with Cortex-A53 softfp; command prefix removed for comparison',
                'frozen_v5_proof': ref(OLD / 'abi-role-proof.json'),
                'ELF32_ARM_EABI5_softfloat': True, 'needed_equal_v5': True,
                'further_role_probe_or_QEMU_run': False},
        'initial_invocation': {'returncode': 1, 'log': ref(invocation_log), 'checker_error': ref(failure),
                               'cause': 'Inherited ABI checker used command[0] (ccache loader) as GCC for -###',
                               'inherited_native_and_ARMEL_role_probe_auto_ran_before_receipt_failure': True,
                               'recompilation_or_repeated_probe_after_failure': False},
        'old_CFE_23_cases_and_storage_BSP_kernel_receipts_reused': True,
        'hardware_operation_performed': False, 'ship_only': ref(rc),
        'incidental_new_libovpn_do_not_ship': ref(NEW / 'linked/libovpn.so'),
        'frozen_old_artifacts': [{'path': path, 'sha256': digest} for path, digest in PINS.items()],
    }
    report = dict(initial)
    report.update(status=receipt['status'], old_artifacts_unchanged=True,
                  new_artifacts={name: sha(NEW / 'linked' / name) for name in ['rc', 'libovpn.so']},
                  ledg_patch=ref(NEW / 'ledg-object-patch.json'),
                  validation=receipt)
    (NEW / 'revision-result.json').write_text(json.dumps(report, indent=2) + '\n')
    receipt['revision_result'] = ref(NEW / 'revision-result.json')
    REPORT.write_text(json.dumps(receipt, indent=2) + '\n')
    assert all(sha(R / path) == digest for path, digest in PINS.items())
    print(json.dumps({'revision_result': ref(NEW / 'revision-result.json'), 'report': ref(REPORT),
                      'RC': ref(rc), 'compiled': 67, 'new_checks': 3}))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Independent read-only source and exported artifact binding; no execution."""
import hashlib
import json
import re
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/ubuntu26-bsp-update/native-v2'
OUT = R / 'build/ubuntu26-envrams-view-update/native-v1'
REPORT = R / 'reports/ubuntu26/envrams-view-updater-source-binding-native-v1.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path)}


def checked_ref(row):
    relative = Path(row['path'])
    assert not relative.is_absolute() and '..' not in relative.parts
    path = R / relative
    assert path.is_file() and not path.is_symlink() and sha(path) == row['sha256']
    return path


def tree(path):
    result = {}
    for leaf in sorted(path.rglob('*')):
        assert not leaf.is_symlink()
        if leaf.is_dir():
            continue
        assert leaf.is_file()
        result[leaf.relative_to(path).as_posix()] = sha(leaf)
    return result


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    assert not REPORT.exists()
    assert sha(BASE / 'manifest.json') == '3f993744f1586f29d255ca190eb1d2e06b1205ac959a9a266a41521b85a4322a'
    assert sha(OUT / 'manifest.json') == '34483f2715f20a8b0a16f9833cfd43560cdbddcc27e5aeea60b4a2bd5d4d2ec4'
    previous = json.loads((BASE / 'manifest.json').read_text())
    build = json.loads((OUT / 'manifest.json').read_text())
    expected = {}
    for row in previous['sources']:
        path = checked_ref(row)
        name = 'hardware-provision.c' if row['path'] == 'build/ubuntu26-hardware-order/native-v1/source/provision.c' else path.name
        assert name not in expected
        expected[name] = row['sha256']
    payload = previous['embedded_payload_header']
    checked_ref(payload)
    expected['bsp-payload.h'] = payload['sha256']
    for row in previous['required_bsp_resources']:
        name = 'resources/' + Path(row['path']).name
        assert name not in expected or expected[name] == row['sha256']
        expected[name] = row['sha256']
    assert tree(BASE / 'source') == expected == build['frozen_source_bindings']
    for key in ['builder', 'template', 'baseline', 'installed_old_identity_evidence', 'new_rc_manifest', 'new_etc_launch_manifest', 'native_build_environment', 'reused_transaction_evidence', 'reused_transaction_log', 'reused_guard_and_preservation']:
        checked_ref(build[key])
    for row in build['build_outputs']:
        checked_ref(row)
    for relative, digest in build['frozen_previous_and_unused_artifact_files'].items():
        checked_ref({'path': relative, 'sha256': digest})
    for relative, digest_map in build['frozen_previous_output_trees'].items():
        assert tree(R / relative) == digest_map

    source = (BASE / 'source/provision.c').read_text()
    rows = []
    names = ['rc']
    assert [row['name'] for row in build['variants']] == names
    for variant in build['variants']:
        name = variant['name']
        assert variant['fixed_target'] == '/usr/libexec/asus/' + name
        old_binary, new_binary = checked_ref(variant['old_binary']), checked_ref(variant['new_binary'])
        substitutions = [
            ('#define BSP_NAME "bsp-ownership"', '#define BSP_NAME "' + name + '"'),
            ('#define BSP_TEMP "bsp-ownership.leon-update"', '#define BSP_TEMP "' + name + '.leon-update"'),
            ('#define BSP_OLD_SHA "f51beb4faf20bac73df894a7752b385a06436967d782e3c264e48416e24ddbc9"', '#define BSP_OLD_SHA "' + sha(old_binary) + '"'),
            ('--update-bsp-ownership', '--update-fixed-asus-helper'),
            ('bsp_ownership_updated', 'cfe_defaults_helper_updated'),
        ]
        desired = source
        for original, replacement in substitutions:
            assert desired.count(original) == 1
            desired = desired.replace(original, replacement)
        snapshot = OUT / name / 'source'
        generated = checked_ref(variant['source']).read_text()
        assert generated == desired
        restored = generated
        for original, replacement in reversed(substitutions):
            assert restored.count(replacement) == 1
            restored = restored.replace(replacement, original)
        assert restored == source
        actual = tree(snapshot)
        assert actual == variant['source_snapshot_bindings'] and set(actual) == set(expected)
        assert {key: value for key, value in actual.items() if key not in ['provision.c', 'bsp-payload.h']} == {key: value for key, value in expected.items() if key not in ['provision.c', 'bsp-payload.h']}
        bodies = {}
        for function in ['update_preserve', 'update_preserved_equal', 'bsp_parent', 'bsp_file', 'bsp_resources', 'bsp_update']:
            pattern = r'static int ' + function + r'\([^\n]*\) \{.*?\n\}'
            original, updated = re.findall(pattern, source, re.S), re.findall(pattern, generated, re.S)
            assert len(original) == len(updated) == 1 and original == updated
            bodies[function] = hashlib.sha256(original[0].encode()).hexdigest()
        assert bodies == variant['unchanged_functions_sha256']
        header = checked_ref(variant['payload_header']).read_text()
        assert header.splitlines()[0] == '#define BSP_NEW_SHA "' + sha(new_binary) + '"'
        payload_bytes = bytes(int(value, 16) for value in re.findall(r'0x([0-9a-f]{2})', header))
        assert payload_bytes == new_binary.read_bytes()
        compiled = Path('/tmp/be19000ai-asus-native-build-v2/work/envrams-view-update-native-v1') / name
        for relative, digest in actual.items():
            assert sha(compiled / relative) == digest
        updater = checked_ref(variant['updater'])
        assert sha(compiled / 'updater') == sha(updater)
        for row in variant['outputs']:
            path = checked_ref(row)
            assert sha(compiled / path.name) == row['sha256']
        elf = (OUT / name / 'elf.txt').read_text()
        assert 'INTERP' not in elf and 'NEEDED' not in elf and 'AArch64' in elf and 'DYN (Position-Independent Executable file)' in elf
        assert not (OUT / name / 'badargs.stdout').read_bytes() and not (OUT / name / 'badargs.stderr').read_bytes() and not (OUT / name / 'nondevice.stdout').read_bytes()
        assert (OUT / name / 'nondevice.stderr').read_bytes() == b'LEON_BSP_UPDATE_REFUSED stage=stock-root-and-native-namespace temporary_created=0 published=0 retained_for_review=true\n'
        assert variant['fresh_checks']['invalid_arguments_exit'] == 64 and variant['fresh_checks']['nondevice_refusal_exit'] == 1
        rows.append({'name': name, 'fixed_target': variant['fixed_target'], 'old_binary': variant['old_binary'], 'new_binary': variant['new_binary'], 'source_snapshot_files': actual, 'unchanged_functions_sha256': bodies, 'updater': ref(updater), 'only_five_literal_substitutions_and_payload': True, 'whole_source_reverse_delta_proved': True, 'embedded_payload_bytes_match_reviewed_binary': True, 'compiler_working_sources_match_saved_snapshot': True, 'compiled_and_exported_updater_match': True, 'static_elf_and_recorded_refusal_outputs_rechecked': True})
    record = {'schema': 1, 'status': 'independent_frozen_source_and_compiled_artifact_binding_passed', 'verifier': ref(Path(__file__)), 'build_manifest': ref(OUT / 'manifest.json'), 'baseline': ref(BASE / 'manifest.json'), 'variants': rows, 'all_base_source_file_bytes_pinned': True, 'all_previous_output_trees_and_inputs_unchanged': True, 'guard_and_preservation_source_files_unchanged': True, 'bounded_parent_and_transaction_bodies_unchanged': True, 'old_transaction_and_resource_cases_not_rerun': True, 'new_target_execution': False, 'network_used': False, 'device_operated': False, 'git_operation': False, 'scope': 'Read-only independent source, embedded bytes, compiler working snapshot and exported artifact comparisons. No compilation or executable invocation; build refusal records verified as retained evidence.'}
    with REPORT.open('x') as handle:
        handle.write(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'report': ref(REPORT), 'updaters': [row['updater'] for row in rows]}))


if __name__ == '__main__':
    main()

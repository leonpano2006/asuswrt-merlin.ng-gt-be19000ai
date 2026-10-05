#!/usr/bin/env python3
"""Prepare one source-bound focused fixture; never compile or execute it.

Default and --plan-only are read-only. --write-source freezes one source/input
closure and a future native worker for separate review and authorization.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-candidate-v15/install-v1'
BASE_SHA = '18c2470a65afa9d2aad2e5e9676b810f6a1757ab4f89bb9b1a1196987a2ff984'
OUT = R / 'build/asus-trial-candidate-v15/focused-fixture-source-v1'
TEMPLATE = R / 'scripts/asus-integration/trial-snapshot/candidate-v15-focused-fixture-v1.c'
TEMPLATE_SHA = '75b0faad6bc3c6b710eee53305f05627de0db3ca27e6d99ce6f1fd4fe8f564df'
FIXTURE_PLAN = R / 'build/asus-trial-candidate-v15/source-plan-v2/focused-fixture-plan.json'
FIXTURE_PLAN_SHA = '3cf25bb5ce87175c38cd65be121f4b7c96562509977eb42a67f41b5e2897ebf2'
WORK_LABEL = 'trial-candidate-v15-focused-fixture-v1'
ORIGINAL_RULE = R / 'build/asus-udev-dummy0-policy/package-v1/original-99-systemd.rules'
BUSYBOX = R / 'build/asus-private-shell/native-v4/busybox-native'
BUSYBOX_SHA = '686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6'


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return sha_bytes(path.read_bytes())


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}


def inventory(path):
    return {p.relative_to(path).as_posix(): sha(p) for p in sorted(path.rglob('*')) if p.is_file()}


def pinned(row):
    name = Path(row['path'])
    assert not name.is_absolute() and '..' not in name.parts
    path = R / name
    assert path.is_file() and not path.is_symlink() and sha(path) == row['sha256']
    if 'bytes' in row:
        assert path.stat().st_size == row['bytes']
    return path


def once(source, old, new):
    assert source.count(old) == 1
    return source.replace(old, new, 1)


def prepare():
    assert sha(BASE / 'manifest.json') == BASE_SHA
    base = json.loads((BASE / 'manifest.json').read_text())
    assert base['compile_count'] == 1 and base['native_worker_returncode'] == 0
    assert base['compiled_input_inventory_matches'] and base['static_elf_passed']
    assert not base['fixture_executed'] and not base['installer_executed']
    assert inventory(BASE / 'source') == base['source_inventory']
    pinned(base['installer'])
    assert sha(TEMPLATE) == TEMPLATE_SHA and sha(FIXTURE_PLAN) == FIXTURE_PLAN_SHA
    source = (BASE / 'source/install.c').read_text()
    main = source[source.index('int RECOVERY_INSTALL_MAIN('):]
    first = '    stage="all-fixed-candidate-file-and-link-preflights";\n'
    limit = '    stage="sync-readback-and-preservation";\n'
    assert main.count(first) == main.count(limit) == 1
    preflight = main[main.index(first):main.index(limit)]
    final_start = '    for(unsigned i=0;i<RECOVERY_CHECK_COUNT;i++)\n'
    final_end = '    close(root);root=-1;\n'
    assert main.count(final_start) == main.count(final_end) == 1
    final_loops = main[main.index(final_start):main.index(final_end)]
    assert preflight.count('recheck(&context)') == 1
    assert preflight.count('install_recovery(') == 1
    assert 'target_preflight(' in preflight and 'candidate_link_check(' in preflight
    assert 'IDENTITY_COUNT' in final_loops and 'RECOVERY_PAYLOAD_COUNT' in final_loops
    assert 'RECOVERY_LINK_COUNT' in final_loops
    files = {
        'candidate-focused-fixture.c': TEMPLATE.read_bytes(),
        'candidate-preflight-publish.inc': preflight.encode(),
        'candidate-final-loops.inc': final_loops.encode(),
    }
    inputs = []
    payloads = base['regular_payloads']
    assert len(payloads) == 10 and len([row for row in payloads if 'old' in row]) == 2
    for row in payloads[:2]:
        path = pinned(row['old'])
        inputs.append({'source_ref': ref(path), 'target': row['target'].lstrip('/'),
                       'sha256': row['old']['sha256'], 'bytes': row['old']['bytes'],
                       'mode': row['old']['mode']})
    checks = base['check_only_preserve']
    assert len(checks) == 7 and sha(ORIGINAL_RULE) == checks[0]['sha256']
    for i, row in enumerate(checks):
        path = ORIGINAL_RULE if i == 0 else pinned(row)
        assert sha(path) == row['sha256'] and path.stat().st_size == row['bytes']
        inputs.append({'source_ref': ref(path), 'target': row['target'].lstrip('/'),
                       'sha256': row['sha256'], 'bytes': row['bytes'], 'mode': row['mode']})
    assert sha(BUSYBOX) == BUSYBOX_SHA
    inputs.append({'source_ref': ref(BUSYBOX), 'target': 'usr/libexec/asus/busybox',
                   'sha256': BUSYBOX_SHA, 'bytes': BUSYBOX.stat().st_size, 'mode': '0755'})
    assert len(inputs) == 10 and len(set(row['target'] for row in inputs)) == 10
    old_rc = pinned(payloads[1]['old']).read_bytes()
    assert old_rc[:4] == b'\x7fELF'
    corrupt_sha = sha_bytes(b'\0' + old_rc[1:])
    header = 'struct fixture_input { const char *source,*target,*sha; size_t size; mode_t mode; };\n'
    header += 'static const struct fixture_input fixture_inputs[]={\n'
    for i, row in enumerate(inputs):
        row['copied_name'] = 'input-' + str(i)
        native = '/work/' + WORK_LABEL + '/inputs/' + row['copied_name']
        header += '{' + json.dumps(native) + ',' + json.dumps(row['target']) + ',' + json.dumps(row['sha256'])
        header += ',' + str(row['bytes']) + ',' + row['mode'] + '},\n'
    header += '};\n#define FIXTURE_INPUT_COUNT (sizeof(fixture_inputs)/sizeof(fixture_inputs[0]))\n'
    header += '#define FIXTURE_CORRUPT_RC_SHA ' + json.dumps(corrupt_sha) + '\n'
    files['fixture-inputs.h'] = header.encode()
    old_worker = (BASE / 'build.sh').read_text()
    assert sha_bytes(old_worker.encode()) == base['compile_worker_sha256']
    assert old_worker.count(base['native_work_label']) == 3
    worker = old_worker.replace(base['native_work_label'], WORK_LABEL)
    copy_line = 'cp -r "$inputs/source"/. "$root/work/' + WORK_LABEL + '/"\n'
    worker = once(worker, copy_line, copy_line + 'cp -r "$inputs/inputs" "$root/work/' + WORK_LABEL + '/inputs"\n')
    worker = once(worker, ' install.c slot-proof.c sha256.c -o install-additions',
                  ' candidate-focused-fixture.c slot-proof.c sha256.c -o focused-fixture')
    worker = once(worker, 'readelf -h -l -d install-additions >elf.txt',
                  'readelf -h -l -d focused-fixture >fixture-elf.txt\n'
                  'timeout --signal=TERM --kill-after=1s 90s ./focused-fixture >fixture-result.jsonl 2>fixture.stderr')
    record = {
        'schema': 1, 'status': 'focused_fixture_sources_prepared_only_not_compiled_or_run',
        'builder': ref(Path(__file__)), 'production_manifest': ref(BASE / 'manifest.json'),
        'production_installer': base['installer'], 'fixture_plan': ref(FIXTURE_PLAN),
        'template': ref(TEMPLATE), 'output': OUT.relative_to(R).as_posix(), 'native_work_label': WORK_LABEL,
        'production_source_inventory': base['source_inventory'],
        'additional_source_inventory': {name: sha_bytes(data) for name, data in sorted(files.items())},
        'exact_production_main_regions': {
            'preflight_recheck_publish': {'sha256': sha_bytes(preflight.encode()), 'bytes': len(preflight.encode())},
            'preservation_and_all_leaf_link_final_loops': {'sha256': sha_bytes(final_loops.encode()), 'bytes': len(final_loops.encode())},
        },
        'inputs': inputs, 'input_kind': 'fixed nonsecret policy/binaries; no enrolled private key input',
        'synthetic_identity_files': 16, 'public_prefix_only_from_pinned_payload_header': True,
        'recheck_seam': 'Macro only around copied region after production include; counted inert boundary, never frozen guard definition/calls.',
        'write_seam': 'Actual included write calls wrapped; fault arms only exact row4 data pointer and root-owned0600 temporary inode, short-write then one EIO. Fixture seeding uses original write.',
        'fault_row': {'index': 4, 'target': payloads[4]['target'], 'sha256': payloads[4]['sha256']},
        'native_worker_sha256': sha_bytes(worker.encode()),
        'gcc_flags_inherited_exactly': True, 'native_fixture_timeout_seconds': 90,
        'scenario_groups': 3, 'case_variants': 4,
        'success_verified_new_noop_is_explicit_after_success_not_failure_retry': True,
        'automatic_retry': False, 'compiled': False, 'executed': False,
        'old_tests_QEMU_device_firmwarepack_actions': False,
        'limits': [
            'Source binding is not fixture test evidence.',
            'No production main, physical recheck, CID/GPT/stock metadata, mount, WDT or guardian path is entered.',
            'Frozen hardware/device guards retain prior proof scope and are not claimed passed through a fixture seam.',
            'Private temporary regular-filesystem behavior does not establish physical ext4 or hostile-writer guarantees.',
            'All four fixture trees/partial temp are intentionally retained for bounded local inspection.',
        ],
    }
    return record, files, inputs, worker


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--plan-only', action='store_true')
    mode.add_argument('--write-source', action='store_true')
    args = parser.parse_args()
    record, files, inputs, worker = prepare()
    if not args.write_source:
        print(json.dumps(record, indent=2))
        return
    if OUT.exists():
        raise RuntimeError('Immutable source output already exists')
    OUT.mkdir(parents=True, exist_ok=False)
    source = OUT / 'source'
    shutil.copytree(BASE / 'source', source)
    for name, data in files.items():
        path = source / name
        assert not path.exists()
        path.write_bytes(data)
        path.chmod(0o644)
    assert inventory(source) == {**record['production_source_inventory'], **record['additional_source_inventory']}
    inputs_dir = OUT / 'inputs'
    inputs_dir.mkdir()
    for row in inputs:
        dest = inputs_dir / row['copied_name']
        shutil.copyfile(pinned(row['source_ref']), dest)
        dest.chmod(0o644)
        assert sha(dest) == row['sha256']
    (OUT / 'future-build-and-one-run.sh').write_text(worker)
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'source_prepared_only': True,
                      'compiled': False, 'fixture_executed': False}, indent=2))


if __name__ == '__main__':
    main()

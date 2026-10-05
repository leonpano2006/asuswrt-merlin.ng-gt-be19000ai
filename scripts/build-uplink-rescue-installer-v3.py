#!/usr/bin/env python3
"""Source-bound fixed socket-parent rescue installer; default is a read-only plan.

One future static compile requires the exact reviewed plan digest. No helper,
fixture, version probe, service, device or inherited installer is executed.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-uplink-rescue/install-v2'
BASE_SHA = '96d7ee155a4b6070d893aa47570dd2b971907c72fb9a60773b8bb3eded852406'
C = R / 'scripts/asus-integration/uplink-rescue/install-v3.c'
C_SHA = 'aec2d619bdad361facb7e016680535772504d2e5c92d212a8fede58f91729216'
DIAGNOSIS = R / 'evidence/ubuntu26/device-uplink-rescue-live/preflight-diagnosis-v1/result.json'
DIAGNOSIS_SHA = '7b5e5aa5a977dfb30b7f9bc31e209fc281aee8d4de9247f9c17c8c12b7a38910'
ENV = R / 'build/asus-native-build/v2/result.json'
ENV_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
OUT = R / 'build/asus-uplink-rescue/install-v3'
WORK = 'uplink-rescue-installer-v3'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    assert path.is_file() and not path.is_symlink()
    return digest(path.read_bytes())


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def inventory(path):
    assert not any(p.is_symlink() for p in path.rglob('*'))
    return {p.relative_to(path).as_posix(): sha(p) for p in sorted(path.rglob('*')) if p.is_file()}


def once(value, before, after):
    assert value.count(before) == 1
    return value.replace(before, after, 1)


def prepare():
    for path, pin in [(BASE / 'manifest.json', BASE_SHA), (C, C_SHA), (DIAGNOSIS, DIAGNOSIS_SHA), (ENV, ENV_SHA)]:
        assert sha(path) == pin
    base = json.loads((BASE / 'manifest.json').read_text())
    assert base['compile_count'] == 1 and not base['installer_executed']
    assert len(base['source_inventory']) == 21 and inventory(BASE / 'source') == base['source_inventory']
    diagnosis = json.loads(DIAGNOSIS.read_text())
    assert diagnosis['status'] == 'fixed_rescue_preflight_metadata_inspection_complete'
    assert diagnosis['full1024_superblock_unchanged']
    assert diagnosis['native_result']['failed_preflights'] == 1
    assert diagnosis['native_result']['payload_count'] == 7 and diagnosis['native_result']['link_count'] == 1
    assert diagnosis['superblock_before'] == diagnosis['superblock_after'] == {
        'state': 1, 'needs_recovery': False, 'error_count': 0, 'last_orphan': 0}
    files = {p.relative_to(BASE / 'source').as_posix(): p.read_bytes()
             for p in sorted((BASE / 'source').rglob('*')) if p.is_file()}
    original = files['install.c'].decode()
    new = C.read_text()
    start = new.index('/* The one proven missing parent. All ancestors remain existing-only.')
    end = new.index('#ifndef RECOVERY_INSTALL_MAIN\n', start)
    helper = new[start:end]
    reverse = new[:start] + new[end:]
    substitutions = [
        ('    unsigned enabled=0,replaced=0;\n', '    unsigned enabled=0,replaced=0,directories_created=0;\n'),
        ('    struct candidate_link_state links[RECOVERY_LINK_COUNT]={0};\n',
         '    struct candidate_link_state links[RECOVERY_LINK_COUNT]={0};\n    struct rescue_socket_parent socket_parent={0};\n'),
        ('    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)\n        if(candidate_link_check(root,&recovery_links[i],1,&links[i].present,&links[i].before))goto done;\n',
         '    if(rescue_socket_parent_preflight(root,&socket_parent))goto done;\n    if(socket_parent.present)\n        for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)\n            if(candidate_link_check(root,&recovery_links[i],1,&links[i].present,&links[i].before))goto done;\n'),
        ('    stage="publish-fixed-inactive-uplink-rescue";\n',
         '    stage="publish-fixed-socket-parent";\n    if(rescue_socket_parent_publish(root,&socket_parent,&directories_created))goto done;\n    stage="publish-fixed-inactive-uplink-rescue";\n'),
        ('    close(root);root=-1;\n', '    if(rescue_socket_parent_preserved(root,&socket_parent))goto done;\n    close(root);root=-1;\n'),
        ('mode_changed=%d links=%u retained_for_review=', 'mode_changed=%d links=%u directories_created=%u retained_for_review='),
        ('stage,temporary,published,replaced,mode_changed,enabled);', 'stage,temporary,published,replaced,mode_changed,enabled,directories_created);'),
        ('\\"links_created\\":%u,\\"mode_changed\\":false', '\\"links_created\\":%u,\\"directories_created\\":%u,\\"mode_changed\\":false'),
        ('argv[3],argv[2],published,replaced,temporary,enabled);', 'argv[3],argv[2],published,replaced,temporary,enabled,directories_created);')]
    for before, after in reversed(substitutions):
        reverse = once(reverse, after, before)
    assert reverse == original
    files['install.c'] = new.encode()
    sources = {name: digest(raw) for name, raw in sorted(files.items())}
    assert [name for name in sources if sources[name] != base['source_inventory'][name]] == ['install.c']
    delta = ''.join(difflib.unified_diff(original.splitlines(True), new.splitlines(True),
                                        fromfile='frozen-install-v2/install.c', tofile='fixed-parent-install-v3/install.c'))
    worker = (BASE / 'build.sh').read_text()
    assert digest(worker.encode()) == base['compile_worker_sha256']
    assert worker.count(base['native_work_label']) == 3
    worker = worker.replace(base['native_work_label'], WORK)
    # Preserve the original V15 baseline/fixture/package/check-only closure.
    plan = dict(base)
    for key in ['source_output', 'approved_compile_plan_sha256', 'installer', 'elf', 'build_log',
                'reverse_literal_transform_equals_frozen_install_c', 'literal_substitutions',
                'required_new_parent_already_exists']:
        plan.pop(key, None)
    plan.update(schema=1, status='source_bound_fixed_socket_parent_rescue_installer_compile_plan_only',
        builder=ref(Path(__file__)), rescue_v2_baseline=ref(BASE / 'manifest.json'),
        rescue_v2_installer=base['installer'], native_environment=ref(ENV),
        diagnosis=ref(DIAGNOSIS), installer_source=ref(C), output=OUT.relative_to(R).as_posix(),
        native_work_label=WORK, source_inventory=sources, changed_source_files=['install.c'],
        frozen_guard_and_transaction_sources_unchanged={name: value for name, value in sources.items() if name != 'install.c'},
        source_delta_sha256=digest(delta.encode()), source_delta_bytes=len(delta.encode()),
        fixed_parent_helper_sha256=digest(helper.encode()), fixed_parent_helper_bytes=len(helper.encode()),
        main_literal_substitutions=substitutions, reverse_parent_transform_equals_frozen_install_c=True,
        compile_worker_sha256=digest(worker.encode()), worker_flags_inherited_exactly=True,
        compiler_version_probes=0, compile_count=0, source_or_installer_compiled=False,
        compiled_input_inventory_matches=False, static_elf_passed=False,
        fixed_socket_parent_creation_only=True,
        fixed_socket_parent='/' + 'etc/systemd/system/sockets.target.wants',
        existing_parent_policy='All existing ancestors remain create=0/root0755/nofollow/samedev. Only fixed socketparent may be missing; valid existing parent is never chmoded.',
        parent_publication_policy='All seven payload and identity/prerequisite/file/link preflights and full recheck precede fixed mkdir0700; newly-created parent only chmod0755/fsyncdir+ancestor; refuse raced appearance.',
        parent_inode_preservation_required=True, native_identity_files=16,
        future_device_result_path='evidence/ubuntu26/device-uplink-rescue-live/install-v3/result.json',
        installer_executed=False, device_accessed=False, fixtures_oldtests_QEMU_run=False,
        limits=['Sequential publication may retain a newly-created directory/owned temp/partial additions on failure; accurate count, no rollback/retry or ARM.',
                'Shared flock excludes cooperating writers only; mkdir/open and rename are not hostile-writer compare-and-swap.',
                'Root owns sole future compile and device staging; this source plan executes neither installer nor tests.'])
    plan['expected_fresh_installer_stdout'] = dict(base['expected_fresh_installer_stdout'], directories_created=1)
    assert plan['baseline'] == base['baseline'] and plan['baseline_installer'] == base['baseline_installer']
    assert plan['regular_payloads'] == base['regular_payloads'] and plan['check_only_preserve'] == base['check_only_preserve']
    return plan, files, delta, worker


def compile_once(plan, files, delta, worker, approved):
    if OUT.exists():
        raise RuntimeError('Immutable output already exists; no retry')
    root = Path(json.loads(ENV.read_text())['root'])
    assert root.as_posix() == '/tmp/be19000ai-asus-native-build-v2'
    if (root / 'work' / WORK).exists():
        raise RuntimeError('Immutable native work label already exists')
    OUT.mkdir(parents=True, exist_ok=False)
    for name, raw in files.items():
        path = OUT / 'source' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw); path.chmod(0o644)
    assert inventory(OUT / 'source') == plan['source_inventory']
    (OUT / 'compile-plan.json').write_bytes(canonical(plan))
    (OUT / 'source-delta.patch').write_text(delta)
    (OUT / 'build.sh').write_text(worker)
    inputs = Path(tempfile.mkdtemp(prefix='leon-rescue-install-v3-build-')); inputs.chmod(0o755)
    shutil.copytree(OUT / 'source', inputs / 'source')
    shutil.copyfile(OUT / 'build.sh', inputs / 'build.sh')
    with (OUT / 'build.log').open('wb') as log:
        run = subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'),
                              str(root), str(inputs)], stdout=log, stderr=subprocess.STDOUT)
    (OUT / 'native-returncode.json').write_text(json.dumps({'native_returncode': run.returncode, 'compile_dispatch_count': 1}) + '\n')
    if run.returncode:
        raise RuntimeError('Sole build failed; output retained, no retry')
    work = root / 'work' / WORK
    assert inventory(work) == {**plan['source_inventory'], 'install-additions': sha(work / 'install-additions'),
                              'elf.txt': sha(work / 'elf.txt')}
    for name in ['install-additions', 'elf.txt']:
        shutil.copyfile(work / name, OUT / name)
        (OUT / name).chmod(0o755 if name == 'install-additions' else 0o644)
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'DYN (Position-Independent Executable file)' in elf
    assert 'INTERP' not in elf and 'NEEDED' not in elf
    manifest = dict(plan, status='source_bound_static_additive_uplink_rescue_installer_built',
                    approved_compile_plan_sha256=approved, compile_count=1, native_returncode=0,
                    installer=ref(OUT / 'install-additions'), elf=ref(OUT / 'elf.txt'),
                    compiled_input_inventory_matches=True, static_elf_passed=True, source_or_installer_compiled=True,
                    build_log=ref(OUT / 'build.log'))
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return {'manifest': ref(OUT / 'manifest.json'), 'installer': manifest['installer']}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true')
    group.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan, files, delta, worker = prepare()
    gate = digest(canonical(plan))
    if args.execute_plan_sha256 is None:
        result = {'plan_sha256': gate, 'plan': plan}
    else:
        if not re.fullmatch('[0-9a-f]{64}', args.execute_plan_sha256) or args.execute_plan_sha256 != gate:
            raise RuntimeError('Exact reviewed plan SHA required; no compile started')
        result = compile_once(plan, files, delta, worker, gate)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

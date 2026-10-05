#!/usr/bin/env python3
"""Fixed v15 candidate installer; default and --plan-only are read-only.

The single future compile requires --execute-plan-sha256 matching the exact
deterministic source/payload/builder plan. No fixture or device action runs.
"""
import argparse
import ast
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-sysctl-diagnostic/install-v1'
OUT = R / 'build/asus-trial-candidate-v15/install-v1'
PROPOSAL = R / 'build/asus-trial-candidate-v15/source-plan-v1/plan.json'
PROPOSAL_SHA = '5db90a85a6bc35ca3001b487df3a12d7d73611cbc9be6132d92b99874800a649'
BASE_SHA = 'b30844e496747b53ab7920fca7fc3e6c55f6aada0d03aee636ff9683d9d45c31'
INTEGRATION = R / 'build/asus-trial-candidate-v15/source-plan-v2/candidate-integration.c'
INTEGRATION_SHA = '65d37877da1c1112ae9448e15323fafa04da39013cf3a086d78c95046fd09eb7'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
ENVIRONMENT_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
WORK_LABEL = 'trial-candidate-v15-installer-v1'
CLI = '--install-native-trial-candidate-v15'
STATUS = 'native_trial_candidate_v15_staged'


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return sha_bytes(path.read_bytes())


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}


def canonical(record):
    return (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()


def pinned(row):
    name = Path(row['path'])
    if name.is_absolute() or '..' in name.parts:
        raise RuntimeError('Unsafe source reference')
    path = R / name
    assert path.is_file() and not path.is_symlink() and sha(path) == row['sha256'], row['path']
    if 'bytes' in row:
        assert path.stat().st_size == row['bytes'], row['path']
    return path


def inventory(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def function(source, name):
    # One C definition, with braces balanced while comments/strings are skipped.
    starts = set()
    for pattern in (r'static int ' + re.escape(name) + r'\(', r'int ' + re.escape(name) + r'\('):
        for match in re.finditer(pattern, source):
            starts.add(source.rfind('\n', 0, match.start()) + 1)
    assert len(starts) == 1, name
    start = starts.pop()
    i, state, depth = source.index('{', start), None, 0
    while i < len(source):
        ch, pair = source[i], source[i:i+2]
        if state in ('"', "'"):
            if ch == '\\':
                i += 2
                continue
            if ch == state:
                state = None
        elif state == '/*':
            if pair == '*/':
                state = None
                i += 2
                continue
        elif state == '//':
            if ch == '\n':
                state = None
        elif pair in ('/*', '//'):
            state = pair
            i += 2
            continue
        elif ch in ('"', "'"):
            state = ch
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return source[start:i+1]
        i += 1
    raise RuntimeError('Unterminated function: ' + name)


def once(source, old, new):
    assert source.count(old) == 1
    return source.replace(old, new, 1)


def main_transform(old):
    generated = once(old, '"--install-native-sysctl-diagnostic"', json.dumps(CLI))
    generated = once(generated, 'volume_fd=-1,mode_changed=0,enabled=0;',
                     'volume_fd=-1,mode_changed=0;\n    unsigned enabled=0,replaced=0;')
    generated = once(generated, '    struct stat original_rule_before,original_rule_after;',
        '''    struct stat original_rule_before,original_rule_after,old_timer_before,old_timer_after;
    struct stat checks_before[RECOVERY_CHECK_COUNT],checks_after[RECOVERY_CHECK_COUNT];
    struct candidate_leaf leaves[RECOVERY_PAYLOAD_COUNT]={0};
    struct candidate_link_state links[RECOVERY_LINK_COUNT]={0};''')
    generated = once(generated,
        '    if(update_preserve(root,&context,&before)||enrolled_identity(root)||identity_all(root,identity_before)||dummy0_original_rule_matches(root,&original_rule_before)||enable_link(root,0))goto done;',
        '''    if(update_preserve(root,&context,&before)||enrolled_identity(root)||identity_all(root,identity_before)||dummy0_original_rule_matches(root,&original_rule_before)||enable_link(root,0)||
       candidate_checks(root,checks_before)||candidate_link_check(root,&recovery_old_timer,0,NULL,&old_timer_before))goto done;''')
    generated = once(generated,
        '''    stage="install-independent-key-config-and-device-socket";
    if(install_recovery(root,&published,&temporary,&mode_changed,&enabled))goto done;''',
        '''    stage="all-fixed-candidate-file-and-link-preflights";
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++)
        if(target_preflight(root,&recovery_payloads[i],&leaves[i]))goto done;
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)
        if(candidate_link_check(root,&recovery_links[i],1,&links[i].present,&links[i].before))goto done;
    /* Same immutable physical recheck under the same lock, before publication. */
    if(recheck(&context))goto done;
    stage="publish-fixed-inactive-v15-candidate";
    if(install_recovery(root,leaves,links,&published,&replaced,&temporary,&enabled))goto done;''')
    generated = once(generated,
        '       enrolled_identity(root)||identity_all(root,identity_after)||enable_link(root,0)||dummy0_original_rule_matches(root,&original_rule_after)||original_rule_before.st_dev!=original_rule_after.st_dev||original_rule_before.st_ino!=original_rule_after.st_ino)goto done;',
        '''       enrolled_identity(root)||identity_all(root,identity_after)||enable_link(root,0)||dummy0_original_rule_matches(root,&original_rule_after)||
       !candidate_stat_unchanged(&original_rule_before,&original_rule_after)||candidate_checks(root,checks_after)||
       candidate_link_check(root,&recovery_old_timer,0,NULL,&old_timer_after)||!candidate_stat_unchanged(&old_timer_before,&old_timer_after))goto done;
    for(unsigned i=0;i<RECOVERY_CHECK_COUNT;i++)
        if(!candidate_stat_unchanged(&checks_before[i],&checks_after[i]))goto done;''')
    generated = once(generated,
        '        int failed=fstat(root,&volume)||recovery_file(dir,name,volume.st_dev,&recovery_payloads[i],0644,&leaf);close(dir);if(failed)goto done;',
        '''        int failed=fstat(root,&volume)||recovery_file(dir,name,volume.st_dev,&recovery_payloads[i],recovery_payloads[i].mode,&leaf)||
            !candidate_same_inode(&leaves[i].published,&leaf);close(dir);if(failed)goto done;''')
    generated = once(generated, '    close(root);root=-1;',
        '''    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++) {
        struct stat leaf;
        if(candidate_link_check(root,&recovery_links[i],0,NULL,&leaf)||
           !candidate_same_inode(&links[i].published,&leaf))goto done;
    }
    close(root);root=-1;''')
    start = generated.index('    if(rc)fprintf(stderr,')
    end = generated.index('\n    return rc;', start)
    generated = generated[:start] + r'''    if(rc)fprintf(stderr,"LEON_TRIAL_CANDIDATE_INSTALL_REFUSED stage=%s temporary=%u additions=%u replacements=%u mode_changed=%d links=%u retained_for_review=true armed=false rebooted=false\n",stage,temporary,published,replaced,mode_changed,enabled);
    else printf("{\"schema\":1,\"status\":\"native_trial_candidate_v15_staged\",\"boot_id\":\"%s\",\"metadata_sha256\":\"%s\",\"additions_published\":%u,\"replacements_published\":%u,\"temporary_created\":%u,\"links_created\":%u,\"mode_changed\":false,\"native_identity_unchanged\":true,\"known_preserved_leaf_inodes_unchanged\":true,\"prerequisites_unchanged\":true,\"package_database_updated\":false,\"armed\":false,\"rebooted\":false,\"boot_committed\":false}\n",argv[3],argv[2],published,replaced,temporary,enabled);''' + generated[end:]
    return generated


def header(proposal, base):
    public = re.findall(r'static const char recovery_host_public\[\]=[^\n]+;',
                        (BASE / 'source/recovery-payload.h').read_text())
    assert len(public) == 1
    result = pinned(proposal['source_delta_contract']['descriptor_layout']).read_text() + '\n'
    rows = proposal['replacements'] + proposal['additions']
    for i, row in enumerate(rows):
        data = pinned(row).read_bytes()
        assert 1 <= len(data) <= 16 * 1024 * 1024
        if row['target'] != '/usr/libexec/asus/rc':
            assert len(data) <= 256 * 1024
        result += f'static const unsigned char recovery_data_{i}[]={{\n'
        result += '\n'.join(','.join(f'0x{b:02x}' for b in data[n:n+16]) + ','
                            for n in range(0, len(data), 16)) + '\n};\n'
    result += 'static const struct recovery_payload recovery_payloads[]={\n'
    for i, row in enumerate(rows):
        old = row.get('old')
        result += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        result += f',recovery_data_{i},sizeof(recovery_data_{i}),' + row['mode'] + ','
        result += (json.dumps(old['sha256']) + ',' + str(old['bytes']) if old else 'NULL,0') + '},\n'
    result += '};\n#define RECOVERY_PAYLOAD_COUNT (sizeof(recovery_payloads)/sizeof(recovery_payloads[0]))\n'
    native = base['original_rule_check_only']
    result += 'static const struct recovery_payload recovery_original_rule={'
    result += json.dumps(native['path'].lstrip('/')) + ',' + json.dumps(native['sha256'])
    result += ',NULL,' + str(native['bytes']) + ',0644,NULL,0};\n'
    checks = proposal['check_only_preserve']
    assert checks[0]['target'] == native['path'] and checks[0]['sha256'] == native['sha256']
    result += 'static const struct recovery_payload recovery_checks[]={\n'
    for row in checks[1:]:
        pinned(row)
        result += '{' + json.dumps(row['target'].lstrip('/')) + ',' + json.dumps(row['sha256'])
        result += ',NULL,' + str(row['bytes']) + ',' + row['mode'] + ',NULL,0},\n'
    result += '};\n#define RECOVERY_CHECK_COUNT (sizeof(recovery_checks)/sizeof(recovery_checks[0]))\n'
    result += 'static const struct candidate_link recovery_links[]={\n'
    for row in proposal['links']:
        result += '{' + json.dumps(row['path'].lstrip('/')) + ',' + json.dumps(row['target']) + '},\n'
    result += '};\n#define RECOVERY_LINK_COUNT (sizeof(recovery_links)/sizeof(recovery_links[0]))\n'
    timer = proposal['old_timer_alias']
    result += 'static const struct candidate_link recovery_old_timer={'
    result += json.dumps(timer['path'].lstrip('/')) + ',' + json.dumps(timer['target']) + '};\n'
    return (result + public[0] + '\n').encode()


def prepare():
    assert sha(PROPOSAL) == PROPOSAL_SHA and sha(BASE / 'manifest.json') == BASE_SHA
    proposal = json.loads(PROPOSAL.read_text())
    base = json.loads((BASE / 'manifest.json').read_text())
    assert inventory(BASE / 'source') == base['source_inventory']
    assert sha(INTEGRATION) == INTEGRATION_SHA and sha(ENVIRONMENT) == ENVIRONMENT_SHA
    assert len(proposal['replacements']) == 2 and len(proposal['additions']) == 8
    assert len(proposal['links']) == 2 and len(proposal['check_only_preserve']) == 7
    assert not proposal['external_trusted_guardian']['p11_guardian_payload']
    for row in proposal['source_references']:
        pinned(row)
    for row in proposal['replacements'] + proposal['additions']:
        pinned(row)
        assert row['uid'] == row['gid'] == 0 and row['mode'] in ('0644', '0755')
        assert row['target'].startswith('/') and '..' not in Path(row['target']).parts
        if row['role'] == 'replace':
            pinned(row['old'])
            assert row['old']['mode'] == row['mode'] and row['old']['nlink'] == 1
    guardian = proposal['external_trusted_guardian']
    pinned(guardian['required_guardian_binary'])
    receipt = json.loads(pinned(guardian['required_guardian_receipt']).read_text())
    manifest = json.loads(pinned(guardian['required_guardian_manifest']).read_text())
    assert receipt['executable']['sha256'] == guardian['required_guardian_binary']['sha256']
    assert manifest['outputs']['guardian-integrated'] == guardian['required_guardian_binary']['sha256']
    evidence = manifest['candidate_evidence']
    rc_receipt, rc_proof = pinned(evidence['rc_two_object_build']), pinned(evidence['rc_build_proof'])
    assert evidence['target_files']['/usr/libexec/asus/rc']['sha256'] == proposal['replacements'][1]['sha256']
    files = {p.relative_to(BASE / 'source').as_posix(): p.read_bytes()
             for p in sorted((BASE / 'source').rglob('*')) if p.is_file()}
    old = files['install.c'].decode()
    integration = INTEGRATION.read_text()
    names = ['target_preflight', 'install_target', 'install_recovery', 'RECOVERY_INSTALL_MAIN']
    original = {name: function(old, name) for name in names}
    changed = {name: function(integration, name) for name in names[:-1]}
    changed[names[-1]] = main_transform(original[names[-1]])
    generated = old
    for name in names:
        generated = once(generated, original[name], changed[name])
    transplant = pinned(proposal['source_delta_contract']['replacement_function']).read_text()
    helpers = integration[:integration.index('static int target_preflight(')]
    block = '\n' + transplant + '\n' + helpers
    generated = once(generated, changed[names[0]], block + changed[names[0]])
    reverse = once(generated, block, '')
    for name in names:
        reverse = once(reverse, changed[name], original[name])
    assert reverse == old
    unchanged = proposal['source_delta_contract']['unchanged_install_functions']
    for name in unchanged:
        assert function(old, name) == function(generated, name), name
    files['install.c'] = generated.encode()
    files['recovery-payload.h'] = header(proposal, base)
    hashes = {name: sha_bytes(data) for name, data in sorted(files.items())}
    changed_files = sorted(name for name in hashes if hashes[name] != base['source_inventory'][name])
    assert changed_files == ['install.c', 'recovery-payload.h']
    delta = ''.join(difflib.unified_diff(old.splitlines(True), generated.splitlines(True),
                                       fromfile='frozen/install.c', tofile='v15/install.c'))
    # Parse the frozen builder's string constant; never import or execute it.
    old_builder = pinned(base['builder'])
    workers = [node.value.value for node in ast.walk(ast.parse(old_builder.read_text()))
               if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
               and isinstance(node.value.value, str)
               and any(isinstance(t, ast.Name) and t.id == 'worker' for t in node.targets)]
    assert len(workers) == 1 and workers[0].count('trial-sysctl-diagnostic-v1') == 3
    worker = workers[0].replace('trial-sysctl-diagnostic-v1', WORK_LABEL)
    record = {
        'schema': 1, 'status': 'source_bound_v15_compile_plan_only',
        'builder': ref(Path(__file__)), 'proposal': ref(PROPOSAL), 'integration': ref(INTEGRATION),
        'baseline': ref(BASE / 'manifest.json'), 'native_environment': ref(ENVIRONMENT),
        'output': OUT.relative_to(R).as_posix(), 'native_work_label': WORK_LABEL,
        'cli': CLI, 'result_status': STATUS, 'source_inventory': hashes,
        'changed_source_files': changed_files,
        'frozen_sources_unchanged': {name: value for name, value in hashes.items() if name not in changed_files},
        'reverse_transform_equals_frozen': True,
        'unchanged_function_sha256': {name: sha_bytes(function(old, name).encode()) for name in unchanged},
        'source_delta_sha256': sha_bytes(delta.encode()), 'source_delta_bytes': len(delta.encode()),
        'header_bytes': len(files['recovery-payload.h']),
        'regular_payloads': proposal['replacements'] + proposal['additions'],
        'links': proposal['links'], 'check_only_preserve': proposal['check_only_preserve'],
        'old90_timer_preserved': proposal['old_timer_alias'], 'external_trusted_guardian': guardian,
        'rc_build_receipt': ref(rc_receipt), 'rc_build_proof': ref(rc_proof),
        'compile_worker_sha256': sha_bytes(worker.encode()),
        'worker_flags_inherited_exactly': True,
        'fixture_autoexecution': False, 'old_tests_QEMU_or_device_actions': False,
        'multi_file_atomicity_claimed': False,
        'limits': ['No compiled ELF or physical behavior established by read-only plan.',
                   'Guardian29 requires a separately reviewed signed SquashFS successor before selection.',
                   'Sequential partial/temp publication is retained for review; no automatic retry or rollback.',
                   'Shared flock excludes cooperating writers only.',
                   'No native package registration, service activation, accounts/keys or boot metadata changes.'],
    }
    return record, files, delta, worker


def compile_once(record, files, delta, worker, approved):
    assert sha_bytes(canonical(record)) == approved
    if OUT.exists():
        raise RuntimeError('Immutable output already exists')
    root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    assert root.as_posix() == '/tmp/be19000ai-asus-native-build-v2'
    if (root / 'work' / WORK_LABEL).exists():
        raise RuntimeError('Immutable native work label already exists')
    OUT.mkdir(parents=True, exist_ok=False)
    source = OUT / 'source'
    for name, data in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o644)
    assert inventory(source) == record['source_inventory']
    (OUT / 'approved-compile-plan.json').write_bytes(canonical(record))
    (OUT / 'source-delta.patch').write_text(delta)
    (OUT / 'build.sh').write_text(worker)
    inputs = Path(tempfile.mkdtemp(prefix='leon-trial-candidate-v15-'))
    inputs.chmod(0o755)
    shutil.copytree(source, inputs / 'source')
    (inputs / 'build.sh').write_text(worker)
    with (OUT / 'build.log').open('w') as log:
        subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'),
                        str(root), str(inputs)], stdout=log, stderr=subprocess.STDOUT, check=True)
    compiled = root / 'work' / WORK_LABEL
    assert inventory(compiled) == {**record['source_inventory'],
                                  'install-additions': sha(compiled / 'install-additions'),
                                  'elf.txt': sha(compiled / 'elf.txt')}
    for name in ('install-additions', 'elf.txt'):
        shutil.copyfile(compiled / name, OUT / name)
        (OUT / name).chmod(0o755 if name == 'install-additions' else 0o644)
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    result = dict(record, status='source_bound_static_v15_candidate_installer_built',
                  approved_compile_plan_sha256=approved, compile_count=1,
                  installer=ref(OUT / 'install-additions'), elf=ref(OUT / 'elf.txt'),
                  source_delta=ref(OUT / 'source-delta.patch'),
                  build_log=ref(OUT / 'build.log'), fixture_executed=False,
                  old_tests_QEMU_device_actions=False)
    (OUT / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--plan-only', action='store_true', help='Read-only; also the default')
    mode.add_argument('--execute-plan-sha256', help='Explicit future single compile of this exact source plan')
    args = parser.parse_args()
    record, files, delta, worker = prepare()
    digest = sha_bytes(canonical(record))
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': digest, 'plan': record}, indent=2))
        return
    if not re.fullmatch('[0-9a-f]{64}', args.execute_plan_sha256) or args.execute_plan_sha256 != digest:
        raise RuntimeError('Exact reviewed source-plan SHA required; no build started')
    result = compile_once(record, files, delta, worker, digest)
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'installer': result['installer']}, indent=2))


if __name__ == '__main__':
    main()

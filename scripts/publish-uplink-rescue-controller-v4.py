#!/usr/bin/env python3
"""Plan one private controller-v4 leaf; never execute the controller.

Default only reads frozen local receipts and sources. Publication requires the
exact reviewed canonical plan, writes one absent leaf through a quoted heredoc,
and preserves the eighteen existing regular leaves before and after the write.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

R = Path(__file__).resolve().parents[1]
DEST = '/tmp/leon-uplink-rescue-tools'
OUT = R / 'evidence/ubuntu26/host51-uplink-rescue-tools-live/add-controller-v4'
OLD_RECEIPT = ('evidence/ubuntu26/host51-uplink-rescue-tools-live/publish-v1/result.json',
               '50b2487ca35370e21084ffad1bfea66e4741e3fa39db3a0d38d661ff2d83f5ef')
TIMEOUT_RECEIPT = ('evidence/ubuntu26/host51-uplink-rescue-tools-live/add-timeout-v3/result.json',
                   '9986acb3bba05dc54328df63f41e6184a3ae0f5a1b9fe9103d8b9fefd11673ee')
TIMEOUT_PLAN = ('build/asus-uplink-rescue/timeout-publication-plan-v3/plan.json',
                '5c67e2d06c68222a5ed22c58607645c2a5f79408c86efd4d2c0e7469a710fd15')
REPLAY = ('build/asus-uplink-rescue/controller-readback-replay-v1/result.json',
          '1ee5e44c764626ba13e08788685bd2683ba8de0a7e6de793936706547f9fce16')
# Root requires the future full functional fixture PASS before publication.
# Deliberately pending; saved-dump replay does not satisfy this requirement.
FUNCTIONAL_PROOF = ('build/qemu/uplink-rescue-focused-v7/result.json', 'a4acb168140c04e95ea3e9eadcec1e21626dc6b5fda265fdcd8a02d79e833fcd')
CONTROLLER = ('scripts/asus-integration/uplink-rescue/controller-transient-v4.sh',
              'e8acbc4c1e6fc1a0dcf48f6e78fc71007bd57ef6909145413c3d1cae6adde5e3')
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py',
             'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
BUSYBOX_SHA = '8c4bfc9f0eea3d3eccba647e9ca814ae1359b988743cad58914196ae2c74aabd'
DIRS = (('', 170477, 'drwx------'), ('/bin', 170479, 'drwxr-xr-x'),
        ('/lib', 170480, 'drwxr-xr-x'))
EXISTING = {'bin/ip-full', 'lib/libbpf.so.1', 'lib/libelf.so.1', 'lib/libmnl.so.0',
            'lib/libz.so.1', 'lib/libgcc_s.so.1', 'lib/libc.so', 'ip-run.sh',
            'controller.sh', 'known-host-fsync', 'enroll-public-known-host.sh',
            'bin/timeout', 'timeout-run.sh', 'controller-v3.sh',
            'resume-public-known-host-v2.sh', '.bundle.tar', '.timeout-add-v3.sh',
            '.timeout-add-v3.tar'}


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def ref(name, expected=None):
    p = R / name
    require(p.is_file() and not p.is_symlink(), 'regular local input required: ' + name)
    raw = p.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    require(expected is None or digest == expected, 'pinned input changed: ' + name)
    return {'path': name, 'sha256': digest, 'bytes': len(raw)}


def directory_checks():
    commands = []
    for suffix, inode, mode in DIRS:
        p = DEST + suffix
        expr = ('NR==1{ok=(NF==10&&$1==' + str(inode) + '&&$2=="' + mode +
                '"&&$3>0&&$4==0&&$5==0&&$10=="' + p + '")}END{exit(NR!=1||!ok)}')
        commands += ['test -d ' + p, 'test ! -L ' + p,
                     '$BB ls -ldni ' + p + ' | $BB awk ' + shlex.quote(expr)]
    return commands


def file_checks(row):
    p = DEST + '/' + row['destination']
    mode = {0o755: '-rwxr-xr-x', 0o644: '-rw-r--r--', 0o600: '-rw-------'}[row['mode']]
    expr = ('NR==1{ok=(NF==10&&$1~/^[0-9]+$/&&$2=="' + mode +
            '"&&$3==1&&$4==0&&$5==0&&$6==' + str(row['bytes']) +
            '&&$10=="' + p + '")}END{exit(NR!=1||!ok)}')
    return ['test -f ' + p, 'test ! -L ' + p,
            '$BB ls -ldni ' + p + ' | $BB awk ' + shlex.quote(expr),
            'test "$(hash ' + p + ')" = ' + row['sha256']]


def remote_script(preserved, controller, raw):
    require(raw.endswith(b'\n') and b'\0' not in raw, 'newline-terminated shell source required')
    text = raw.decode('ascii')
    delimiter = 'LEON_FIXED_CONTROLLER_V4_' + controller['sha256'].upper()
    require(delimiter not in text.splitlines(), 'heredoc delimiter collision')
    commands = ['set -eu', 'set -o pipefail', 'umask 077', 'export LC_ALL=C',
                'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'export PATH', 'BB=/bin/busybox',
                'test "$($BB id -u)" = 0', 'test "$($BB uname -m)" = armv7l',
                'test "$($BB cat /sys/class/net/br-lan/address)" = 02:00:00:f0:00:02',
                "hash() { \"$BB\" sha256sum \"$1\" | \"$BB\" awk 'NR==1&&$1~/^[0-9a-f]+$/&&length($1)==64{h=$1} END{if(NR!=1||h==\"\")exit 1;print h}'; }",
                'test "$(hash /bin/busybox)" = ' + BUSYBOX_SHA]
    commands += directory_checks()
    for row in preserved:
        commands += file_checks(row)
    target = DEST + '/controller-v4.sh'
    commands += ['test ! -e ' + target, 'test ! -L ' + target, 'set -C']
    prefix = '\n'.join(commands) + '\n$BB cat > ' + target + " <<'" + delimiter + "'\n"
    commands = ['set +C', '$BB chmod 755 ' + target]
    commands += file_checks(controller) + directory_checks()
    for row in preserved:
        commands += file_checks(row)
    reply = {'schema': 1, 'status': 'private_controller_v4_leaf_added', 'new_files': 1,
             'existing_files_preserved': 18, 'network_changed': False,
             'trust_changed': False, 'controller_executed': False}
    commands.append('printf ' + shlex.quote(json.dumps(reply, separators=(',', ':')) + '\n'))
    script = (prefix + text + delimiter + '\n' + '\n'.join(commands) + '\n').encode('ascii')
    require(len(script) <= 65536, 'stdin script exceeds 64KiB limit')
    return script, reply


def prepare():
    require(__debug__, 'Python -O forbidden')
    inputs = {key: ref(*pin) for key, pin in
              [('original_publication', OLD_RECEIPT), ('timeout_publication', TIMEOUT_RECEIPT),
               ('timeout_plan', TIMEOUT_PLAN), ('saved_dump_replay', REPLAY),
               ('controller', CONTROLLER), ('transport', TRANSPORT)]}
    old = json.loads((R / OLD_RECEIPT[0]).read_text())
    done = json.loads((R / TIMEOUT_RECEIPT[0]).read_text())
    saved = json.loads((R / TIMEOUT_PLAN[0]).read_text())
    prior = saved['plan']
    replay = json.loads((R / REPLAY[0]).read_text())
    require(old['status'] == 'private_controller_tools_published' and old['published'] is True
            and old['returncode'] == 0 and len(old['files']) == 11, 'successful original publication required')
    require(done['status'] == 'private_timeout_leaves_added' and done['returncode'] == 0
            and done['script_upload_returncode'] == 0 and done['new_files'] == 4
            and done['old_files_preserved'] == 11 and done['network_changed'] is False
            and done['trust_changed'] is False and done['existing_files_replaced'] == 0,
            'successful inert timeout publication required')
    require(hashlib.sha256(canonical(prior)).hexdigest() == saved['plan_sha256'] == done['approved_plan_sha256']
            and prior['old_files'] == old['files'] == done['old_files']
            and prior['source'] == done['source'] and len(prior['new_files']) == 4
            and done['old_publication'] == inputs['original_publication'], 'timeout receipt and approved plan must agree')
    require(replay['status'] == 'one_saved_dump_positive_and_strict_negative_replay_passed'
            and replay['replay_invocations'] == 1 and len(replay['cases']) == 2
            and all(c['passed'] is True and c['outer_timeout'] is False for c in replay['cases'])
            and replay['cases'][0]['observed'] == {'parser_rc': '0', 'A': '1', 'R': '0', 'LOCAL': '1'}
            and replay['cases'][1]['returncode'] == 1
            and replay['network_namespace_vm_or_device_actions'] is False
            and replay['production_controller_executed'] is False, 'completed saved-dump replay required')
    preserved = [dict(row) for row in old['files'] + prior['new_files']]
    require(done['private_script_path'] == DEST + '/.timeout-add-v3.sh'
            and done['private_script_path'] == done['auxiliary_private_script'], 'fixed retained v3 script required')
    preserved += [dict(destination='.bundle.tar', mode=0o600, bytes=old['bundle_bytes'], sha256=old['bundle_sha256']),
                  dict(destination='.timeout-add-v3.sh', mode=0o600, bytes=done['private_script_bytes'], sha256=done['private_script_sha256']),
                  dict(destination='.timeout-add-v3.tar', mode=0o600, bytes=done['bundle_bytes'], sha256=done['bundle_sha256'])]
    require(len(preserved) == 18 and {row['destination'] for row in preserved} == EXISTING,
            'exact eighteen existing leaves required')
    for row in preserved:
        require(row['mode'] in (0o755, 0o644, 0o600) and 0 < row['bytes'] <= 2 * 1024 * 1024
                and len(row['sha256']) == 64 and all(c in '0123456789abcdef' for c in row['sha256']),
                'invalid preserved file descriptor')
    controller = dict(inputs['controller'], destination='controller-v4.sh', mode=0o755)
    require(controller['bytes'] == 12430, 'fixed controller size required')
    functional = None
    if FUNCTIONAL_PROOF is not None:
        functional = ref(*FUNCTIONAL_PROOF)
        tested = json.loads((R / FUNCTIONAL_PROOF[0]).read_text())
        require(tested['status'] == 'passed' and tested['stop_reason'] == 'fixture_complete'
                and tested['first_failure'] is None and tested['vm_network_devices'] == []
                and tested['host_drives_or_shared_filesystems'] == [] and tested['port_forwarding'] == []
                and tested['device_accessed'] is False and tested['retries'] == 0,
                'one isolated full functional fixture PASS required')
        prepared_row = tested['preparation']
        prepared_ref = ref(prepared_row['path'], prepared_row['sha256'])
        require(prepared_row.items() <= prepared_ref.items(), 'functional preparation reference differs')
        prepared = json.loads((R / prepared_row['path']).read_text())
        require(any(row['sha256'] == CONTROLLER[1] and row['path'] == CONTROLLER[0]
                    for row in prepared['sources']), 'functional fixture must bind exact controller-v4 source')
        inputs['functional_preparation'] = prepared_ref
    source = (R / CONTROLLER[0]).read_bytes()
    script, reply = remote_script(preserved, controller, source)
    nodes = [n for n in ast.parse((R / TRANSPORT[0]).read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    require(len(nodes) == 1 and not nodes[0].decorator_list, 'only frozen transport required')
    return {'schema': 1, 'status': 'private_controller_v4_publication_plan_only',
            'source': ref(str(Path(__file__).relative_to(R))), 'inputs': inputs,
            'preserved_files': preserved, 'new_file': controller,
            'remote_exec': 'exec /bin/busybox ash -s', 'ssh_exec_request_limit_bytes': 4096,
            'stdin_script_sha256': hashlib.sha256(script).hexdigest(), 'stdin_script_bytes': len(script),
            'expected_reply': reply, 'output': str(OUT.relative_to(R)),
            'functional_proof': functional, 'ready_for_execution': functional is not None,
            'network_changed': False, 'trust_changed': False, 'controller_executed': False,
            'limits': ['Only one fresh controller-v4.sh leaf is created; no new auxiliary file or archive.',
                       'Retain incomplete target and evidence on failure; no automatic retry or cleanup.',
                       'Root0700 namespace and absent/noclobber checks coordinate this operation; hostile root writers are not excluded.',
                       'Saved-dump replay is not Kernel10 or physical .51 controller acceptance.']}


def execute(plan, gate):
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'exact reviewed plan required')
    require(plan['ready_for_execution'], 'completed source and prerequisite bindings required')
    raw = (R / CONTROLLER[0]).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == plan['new_file']['sha256'], 'controller changed')
    script, reply = remote_script(plan['preserved_files'], plan['new_file'], raw)
    require(hashlib.sha256(script).hexdigest() == plan['stdin_script_sha256']
            and len(script) == plan['stdin_script_bytes'], 'reviewed stdin script changed')
    nodes = [n for n in ast.parse((R / TRANSPORT[0]).read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    env = {'__builtins__': {}, 'shlex': shlex}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'frozen-transport-only', 'exec'), env)
    argv = env['transport']('true')
    argv[-1] = plan['remote_exec']
    require(len(argv[-1].encode()) <= 4096, 'short SSH exec required')
    OUT.mkdir(parents=True, exist_ok=False)
    result = dict(plan, approved_plan_sha256=gate, status='private_controller_v4_started_outcome_unknown')
    try:
        run = subprocess.run(argv, input=script, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        (OUT / 'stdout').write_bytes(run.stdout)
        (OUT / 'stderr').write_bytes(run.stderr)
        result['returncode'] = run.returncode
        require(run.returncode == 0, 'publication failed; retain target and evidence, no retry')
        require(json.loads(run.stdout) == reply, 'exact publication reply required')
        result.update(reply, published=True)
    except subprocess.TimeoutExpired as exc:
        (OUT / 'stdout').write_bytes(exc.stdout or b'')
        (OUT / 'stderr').write_bytes(exc.stderr or b'')
        result.update(status='private_controller_v4_timeout_retained_no_retry')
        raise
    except Exception as exc:
        result.update(status='private_controller_v4_failed_retained_no_retry', error=str(exc))
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'output': str(OUT.relative_to(R))}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan = prepare()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': hashlib.sha256(canonical(plan)).hexdigest(), 'plan': plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()

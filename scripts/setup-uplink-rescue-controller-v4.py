#!/usr/bin/env python3
"""Source-only one-shot direct .51 setup; pending receipts prohibit execution.

No default network action. Execute needs the exact reviewed plan and completed
functional/publication pins. Failure retains controller state and local evidence;
there is no retry, cleanup, boot selection, router command, or SSH login claim.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

R = Path(__file__).resolve().parents[1]
OUT = R / 'evidence/ubuntu26/host51-uplink-rescue-controller-live/setup-v1'
TOOLS = '/tmp/leon-uplink-rescue-tools'
STATE = '/tmp/leon-uplink-rescue-controller/state'
CONTROLLER = ('scripts/asus-integration/uplink-rescue/controller-transient-v4.sh',
              'e8acbc4c1e6fc1a0dcf48f6e78fc71007bd57ef6909145413c3d1cae6adde5e3')
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py',
             'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
CLOSURE = ('build/asus-uplink-rescue/controller-tools-v1/manifest.json',
           '86b33a71845343a03313975a0be137e3471c692f513c53b9745d3f9171b245d7')
FUNCTIONAL_PROOF = ('build/qemu/uplink-rescue-focused-v7/result.json', 'a4acb168140c04e95ea3e9eadcec1e21626dc6b5fda265fdcd8a02d79e833fcd')
PUBLISHER_RECEIPT = ('evidence/ubuntu26/host51-uplink-rescue-tools-live/add-controller-v4/result.json', 'd3b05ef02face4f4bf891f3d5fb06db1dcfdfb096c36b3d5e292bddde2d64c7e')
HOSTPIN_SHA = '38624da2217743620b0fd6f952dcd07bd657adce56e443c7e916121f0d282ae6'
ENTRY_SHA = '7ab149a094d08cebdb6a68291b4c86c31ab8c800656f86f8f89ba2c350f4ec61'
BUSYBOX_SHA = '8c4bfc9f0eea3d3eccba647e9ca814ae1359b988743cad58914196ae2c74aabd'
CONFIGURED = 'LEON_RESCUE_CONTROLLER configured=169.254.190.51/32 peer=169.254.190.15/32 normal_lan=preserved'
SELF, PEER = '169.254.190.51', '169.254.190.15'


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
    require(expected is None or digest == expected, 'changed pinned input: ' + name)
    return {'path': name, 'sha256': digest, 'bytes': len(raw)}


def metadata(path, mode, size=None, inode=None):
    expr = ('NR==1{ok=(NF==10&&$1~/^[0-9]+$/&&$2=="' + mode +
            '"&&$3>0&&$4==0&&$5==0&&$10=="' + path + '")')
    if mode.startswith('-'):
        expr += '&&$3==1'
    if size is not None:
        expr += '&&$6==' + str(size)
    if inode is not None:
        expr += '&&$1==' + str(inode)
    expr += '}END{exit(NR!=1||!ok)}'
    kind = 'test -f ' if mode.startswith('-') else 'test -d '
    return [kind + path, 'test ! -L ' + path,
            '$BB ls -ldni ' + path + ' | $BB awk ' + shlex.quote(expr)]


def common_checks():
    lines = ['set -eu', 'set -o pipefail', 'export LC_ALL=C',
             'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'export PATH', 'BB=/bin/busybox',
             'test "$($BB id -u)" = 0', 'test "$($BB uname -m)" = armv7l',
             "hash() { \"$BB\" sha256sum \"$1\" | \"$BB\" awk 'NR==1&&$1~/^[0-9a-f]+$/&&length($1)==64{h=$1} END{if(NR!=1||h==\"\")exit 1;print h}'; }",
             'test "$(hash /bin/busybox)" = ' + BUSYBOX_SHA]
    lines += ['test "$($BB readlink /proc/self/ns/net)" = "$($BB readlink /proc/1/ns/net)"',
              'test "$($BB cat /sys/class/net/br-lan/address)" = 02:00:00:f0:00:02']
    for suffix, mode, inode in [('', 'drwx------', 170477), ('/bin', 'drwxr-xr-x', 170479),
                                 ('/lib', 'drwxr-xr-x', 170480)]:
        lines += metadata(TOOLS + suffix, mode, inode=inode)
    lines += metadata(TOOLS + '/controller-v4.sh', '-rwxr-xr-x', 12430)
    lines += ['test "$(hash ' + TOOLS + '/controller-v4.sh)" = ' + CONTROLLER[1]]
    lines += metadata('/root', 'drwxr-x---') + metadata('/root/.ssh', 'drwxr-xr-x')
    lines += metadata('/root/.ssh/known_hosts', '-rw-------', 670, 807)
    lines += ['test "$(hash /root/.ssh/known_hosts)" = ' + HOSTPIN_SHA,
              'entry_hash=$($BB awk ' + shlex.quote('$1=="[leon-ubuntu26-be19000ai]:2223"{n++;print} END{exit(n!=1)}') +
              ' /root/.ssh/known_hosts | $BB sha256sum | $BB awk ' +
              shlex.quote('NR==1{h=$1} END{if(NR!=1||length(h)!=64)exit 1;print h}') + ')',
              'test "$entry_hash" = ' + ENTRY_SHA]
    return lines


def make_commands(tool_rows):
    setup = '\n'.join(common_checks() + ['exec /bin/busybox ash ' + TOOLS + '/controller-v4.sh --setup'])
    require(len(setup.encode()) <= 4096, 'setup SSH exec exceeds 4096 bytes')
    lines = common_checks()
    for row in tool_rows:
        path = TOOLS + '/' + row['destination']
        lines += metadata(path, '-rwxr-xr-x' if row['mode'] == 0o755 else '-rw-r--r--', row['bytes'])
        lines += ['test "$(hash ' + path + ')" = ' + row['sha256']]
    lines += metadata('/tmp/leon-uplink-rescue-controller', 'drwx------')
    lines += metadata(STATE, '-rw-------')
    lines += ['$BB ls -ldni ' + STATE + ' | $BB awk ' + shlex.quote('NR==1{ok=($6>0&&$6<=256)} END{exit(NR!=1||!ok)}'),
              'TIMEOUT=' + TOOLS + '/timeout-run.sh', 'IP=' + TOOLS + '/ip-run.sh',
              "printf 'LEON_CONTROLLER_CAPTURE_V1\\n'",
              "printf 'HOSTPIN=807:" + HOSTPIN_SHA + ':' + ENTRY_SHA + "\\n'",
              "printf 'BOOT='; $BB cat /proc/sys/kernel/random/boot_id",
              "printf 'IFINDEX='; $BB cat /sys/class/net/br-lan/ifindex"]
    for name, command, cap in [('state', '$BB cat ' + STATE, 257),
                               ('addr', '$IP -N -o -4 addr show', 65537),
                               ('routes', '$IP -N -o -4 route show table all', 65537),
                               ('rules', '$IP -N -4 rule show', 65537)]:
        lines += ["printf 'BEGIN_" + name + "\\n'",
                  '$TIMEOUT -s TERM -k 1 3 ' + command + ' | $BB head -c ' + str(cap),
                  "printf 'END_" + name + "\\n'"]
    capture = ('\n'.join(lines) + '\n').encode()
    require(len(capture) <= 32768, 'bounded read-only capture source required')
    return setup, capture


def prepare():
    require(__debug__, 'Python -O forbidden')
    inputs = {key: ref(*pin) for key, pin in [('controller', CONTROLLER), ('transport', TRANSPORT), ('closure', CLOSURE)]}
    require(inputs['controller']['bytes'] == 12430, 'fixed controller size required')
    closure = json.loads((R / CLOSURE[0]).read_text())
    rows = []
    for artifact in closure['artifacts']:
        row = artifact['elf']
        path = Path(row['path'])
        path = path if path.is_absolute() else R / path
        destination = path.relative_to(R / 'build/asus-uplink-rescue/controller-tools-v1').as_posix()
        rows.append(dict(row, destination=destination,
                         mode=0o755 if path.name in ('ip-full', 'libc.so') else 0o644))
    require(len(rows) == 7, 'frozen seven-ELF closure required')
    for name, digest, target, size in [
            ('scripts/asus-integration/uplink-rescue/ip-full-private-run.sh', '53b21a39f5de6393725ca63a38378b4e772faa1f8ef378087ef470a36be337e1', 'ip-run.sh', 299),
            ('scripts/asus-integration/uplink-rescue/timeout-private-run.sh', 'f887d0cdd35e3b87429e6553ee86cc83e9018315f3eac644813859d56e8ae27c', 'timeout-run.sh', 303),
            ('build/asus-uplink-rescue/controller-timeout-v1/bin/timeout', 'eee267c8317aff3902f573c1e5f0052a723b2a3521cb2903377caea04ec8c7df', 'bin/timeout', 33264)]:
        row = ref(name, digest)
        require(row['bytes'] == size, 'fixed tool size differs')
        rows.append(dict(row, destination=target, mode=0o755))
    for row in rows:
        path = Path(row['path'])
        relative = str(path.relative_to(R)) if path.is_absolute() else row['path']
        checked = ref(relative, row['sha256'])
        require(checked['bytes'] == row['bytes'], 'tool size differs')
    ready = FUNCTIONAL_PROOF is not None and PUBLISHER_RECEIPT is not None
    functional = publication = None
    if ready:
        functional, publication = ref(*FUNCTIONAL_PROOF), ref(*PUBLISHER_RECEIPT)
        tested = json.loads((R / FUNCTIONAL_PROOF[0]).read_text())
        done = json.loads((R / PUBLISHER_RECEIPT[0]).read_text())
        require(tested['status'] == 'passed' and tested['stop_reason'] == 'fixture_complete'
                and tested['first_failure'] is None and tested['vm_network_devices'] == []
                and tested['host_drives_or_shared_filesystems'] == [] and tested['port_forwarding'] == []
                and tested['device_accessed'] is False and tested['retries'] == 0, 'isolated full functional PASS required')
        require(done['status'] == 'private_controller_v4_leaf_added' and done['published'] is True
                and done['returncode'] == 0 and done['new_files'] == 1 and done['existing_files_preserved'] == 18
                and done['network_changed'] is False and done['trust_changed'] is False
                and done['controller_executed'] is False and done['functional_proof'] == functional
                and done['new_file']['sha256'] == CONTROLLER[1] and done['new_file']['bytes'] == 12430
                and done['new_file']['destination'] == 'controller-v4.sh' and done['new_file']['mode'] == 0o755,
                'actual one-leaf publication PASS required')
    nodes = [n for n in ast.parse((R / TRANSPORT[0]).read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    require(len(nodes) == 1 and not nodes[0].decorator_list, 'only frozen transport required')
    setup, capture = make_commands(rows)
    return {'schema': 1, 'status': 'one_controller_v4_setup_plan_only', 'source': ref(str(Path(__file__).relative_to(R))),
            'inputs': inputs, 'functional_proof': functional, 'publication_receipt': publication,
            'ready_for_execution': ready, 'setup_command': setup, 'capture_source_sha256': hashlib.sha256(capture).hexdigest(),
            'capture_source_bytes': len(capture), 'tool_rows': rows, 'output': str(OUT.relative_to(R)),
            'total_operation_timeout_seconds': 60, 'capture_timeout_seconds_max': 30,
            'setup_invocations': 1, 'automatic_retry': False, 'cleanup_invoked': False,
            'limits': ['Setup changes only the production controller-owned temporary rescue address and peer route.',
                       'Failure retains state and evidence; no cleanup or foreign-state retry.',
                       'Known_hosts is checked only by metadata and hashes; no private key file is read or transmitted.',
                       'Configured/readback prove controller state only; no router SSH login, ACK, boot selection or recovery claim.']}


def verify_capture(raw):
    text = raw.decode('ascii')
    prefix = 'LEON_CONTROLLER_CAPTURE_V1\nHOSTPIN=807:' + HOSTPIN_SHA + ':' + ENTRY_SHA + '\n'
    require(text.startswith(prefix), 'exact public hostpin capture header required')
    rest = text[len(prefix):]
    identity, index, rest = rest.split('\n', 2)
    require(re.fullmatch(r'BOOT=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', identity)
            and re.fullmatch(r'IFINDEX=[1-9][0-9]*', index), 'capture boot/index identity differs')
    sections = {}
    for name in ('state', 'addr', 'routes', 'rules'):
        begin, end = 'BEGIN_' + name + '\n', 'END_' + name + '\n'
        require(rest.startswith(begin) and rest.count(end) == 1, 'capture framing differs: ' + name)
        body, rest = rest[len(begin):].split(end, 1)
        require(body.endswith('\n') and 0 < len(body.encode()) <= (256 if name == 'state' else 65536), 'capture cap or newline differs')
        sections[name] = body
    require(rest == '', 'unexpected capture tail')
    state = sections['state'].splitlines()
    require(len(state) == 4 and state[0] == 'LEON_CONTROLLER_RESCUE_V1'
            and re.fullmatch(r'boot=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', state[1])
            and re.fullmatch(r'index=[1-9][0-9]*', state[2]) and state[3] == 'phase=ACTIVE', 'exact ACTIVE state required')
    require(state[1][5:] == identity[5:] and state[2][6:] == index[8:], 'state boot/index no longer current')
    normal = owned = 0
    for line in sections['addr'].splitlines():
        words = line.replace('\\', ' ').split()
        if len(words) >= 4 and words[1:4] == ['br-lan', 'inet', '192.168.100.51/24']:
            normal += int(sum(words[i:i+2] == ['scope', '0'] for i in range(4, len(words))) == 1 and words[4:].count('br-lan') == 1)
        if any(w.split('/')[0] in (SELF, PEER) or w == 'br-lan:lr' for w in words):
            owned += 1
            require(len(words) >= 4 and words[1:4] == ['br-lan', 'inet', SELF + '/32'], 'foreign rescue address')
            require(words[4:] == ['scope', '253', 'noprefixroute', 'br-lan:lr', 'valid_lft', 'forever', 'preferred_lft', 'forever'], 'exact rescue address attributes required')
    require(normal == owned == 1, 'normal/owned address count differs')
    peer = local = default = 0
    for line in sections['routes'].splitlines():
        words = line.split()
        if not words:
            continue
        if words[0] == 'default':
            default += 1
            require(words[:5] == ['default', 'via', '192.168.100.1', 'dev', 'br-lan'], 'normal default changed')
        selected = words[:2]
        if any(w in (PEER, PEER + '/32') for w in selected):
            peer += 1
            require(words[0] in (PEER, PEER + '/32'), 'foreign peer route type')
            attrs = words[1:]
            require(len(attrs) % 2 == 0, 'peer attributes malformed')
            pairs = list(zip(attrs[::2], attrs[1::2]))
            require(len(pairs) == len(set(pairs)) and set(pairs) in (
                {('dev','br-lan'),('proto','186'),('scope','253'),('src',SELF),('metric','42760')},
                {('dev','br-lan'),('proto','186'),('scope','253'),('src',SELF),('metric','42760'),('table','254')}), 'exact peer route required')
        if any(w in (SELF, SELF + '/32') for w in selected):
            local += 1
            require(words[0] == '2' and len(words[2:]) == 10, 'exact numeric local route required')
            attrs = words[2:]
            pairs = list(zip(attrs[::2], attrs[1::2]))
            require(len(pairs) == len(set(pairs)) and set(pairs) == {('dev','br-lan'),('table','255'),('proto','2'),('scope','254'),('src',SELF)}, 'exact local route required')
    require(peer == local == default == 1, 'peer/local/default route count differs')
    rules = [line.split() for line in sections['rules'].splitlines() if line.strip()]
    require(len(rules) == 3 and {tuple(w) for w in rules} == {('0:','from','all','lookup','255'),('32766:','from','all','lookup','254'),('32767:','from','all','lookup','253')}, 'policy rules changed')
    return {'status': 'controller_active_readback_verified', 'owned_address_count': 1, 'peer_route_count': 1,
            'local_route_count': 1, 'normal_lan_preserved': True, 'default_preserved': True,
            'rules_preserved': True, 'known_hosts_inode': 807, 'known_hosts_sha256': HOSTPIN_SHA,
            'public_2223_entry_sha256': ENTRY_SHA, 'boot_id': state[1][5:], 'ifindex': int(state[2][6:]),
            'router_login_or_ack_proven': False}, sections


def execute(plan, gate):
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'exact reviewed plan required')
    require(plan['ready_for_execution'], 'functional PASS and actual publication receipt required')
    setup, capture = make_commands(plan['tool_rows'])
    require(setup == plan['setup_command'] and hashlib.sha256(capture).hexdigest() == plan['capture_source_sha256'], 'reviewed command differs')
    nodes = [n for n in ast.parse((R / TRANSPORT[0]).read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    env = {'__builtins__': {}, 'shlex': shlex}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'frozen-transport-only', 'exec'), env)
    argv = env['transport']('true'); argv[-1] = setup
    OUT.mkdir(parents=True, exist_ok=False)
    result = dict(plan, approved_plan_sha256=gate, status='one_controller_setup_started_outcome_unknown')
    started = time.monotonic()
    try:
        call = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        (OUT/'setup.stdout').write_bytes(call.stdout); (OUT/'setup.stderr').write_bytes(call.stderr)
        result['setup_returncode'] = call.returncode
        require(call.returncode == 0 and call.stdout.decode('ascii').splitlines().count(CONFIGURED) == 1, 'sole setup refused or marker absent; retain state')
        remaining = 60 - (time.monotonic() - started)
        require(remaining > 0, 'overall deadline exhausted; state retained')
        argv = env['transport']('true'); argv[-1] = 'exec /bin/busybox ash -s'
        readback = subprocess.run(argv, input=capture, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(30, remaining))
        (OUT/'capture.stdout').write_bytes(readback.stdout); (OUT/'capture.stderr').write_bytes(readback.stderr)
        result['capture_returncode'] = readback.returncode
        require(readback.returncode == 0, 'read-only capture failed; retain state')
        verified, sections = verify_capture(readback.stdout)
        for name, body in sections.items():
            (OUT/name).write_text(body)
        result.update(status='one_controller_v4_setup_and_readback_verified', readback=verified,
                      elapsed_seconds=time.monotonic()-started, setup_executed=True,
                      cleanup_executed=False, router_accessed=False, private_key_read=False)
    except subprocess.TimeoutExpired as exc:
        (OUT/'timeout.stdout').write_bytes(exc.stdout or b''); (OUT/'timeout.stderr').write_bytes(exc.stderr or b'')
        result.update(status='one_controller_v4_timeout_state_retained_no_retry')
        raise
    except Exception as exc:
        result.update(status='one_controller_v4_failed_state_retained_no_retry', error=str(exc))
        raise
    finally:
        (OUT/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps({'status':result['status'],'output':str(OUT.relative_to(R))}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args(); plan = prepare()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256':hashlib.sha256(canonical(plan)).hexdigest(),'plan':plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()

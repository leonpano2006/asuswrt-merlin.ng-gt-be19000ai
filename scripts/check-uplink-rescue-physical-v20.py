#!/usr/bin/env python3
"""Bounded physical backup-login check. Default prints scope; never sends ACK."""
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
TRANSPORT = R / 'scripts/deploy-cfe-recovery-p11.py'
TRANSPORT_SHA = 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7'
OUT = R / 'evidence/ubuntu26/trial-live/twentieth-uplink-backup'
HOSTS_SHA = '38624da2217743620b0fd6f952dcd07bd657adce56e443c7e916121f0d282ae6'
MAC = '02:00:00:f0:00:01'
TOOLS = '/tmp/leon-uplink-rescue-tools'
REMOTE_CHECK = '''set -eu
test "$(id -u)" = 1000
test "$(cat /proc/1/comm)" = systemd
test "$(cat /sys/class/net/eth0/address)" = 02:00:00:f0:00:01
test "$(findmnt -n -o FSTYPE /)" = ext4
test "$(findmnt -n -o UUID /)" = ea8e47b8-c606-406c-b931-d2244d26ec55
test "$(uname -r)" = 4.19.294
case "$(uname -v)" in '#10 '*) : ;; *) exit 1 ;; esac
set -- $SSH_CONNECTION
test "$#" = 4
test "$1" = 169.254.190.51
test "$3" = 169.254.190.15
test "$4" = 2223
printf 'LEON_PHYSICAL_UPLINK_NATIVE_LOGIN_PASS uid=1000 source=169.254.190.51 target=169.254.190.15 port=2223\n'
cat /proc/sys/kernel/random/boot_id
uname -r
uname -v
findmnt -n -o SOURCE,FSTYPE,OPTIONS /
'''


def transport():
    assert hashlib.sha256(TRANSPORT.read_bytes()).hexdigest() == TRANSPORT_SHA
    nodes = [n for n in ast.parse(TRANSPORT.read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    assert len(nodes) == 1 and not nodes[0].decorator_list
    namespace = {'__builtins__': {}, 'shlex': shlex}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(TRANSPORT), 'exec'), namespace)
    argv = namespace['transport']('')
    return argv[:-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--duration', type=int, default=300)
    args = parser.parse_args()
    assert __debug__ and 1 <= args.duration <= 300
    scope = {'schema': 1, 'source': '169.254.190.51', 'peer': '169.254.190.15', 'port': 2223,
             'expected_ethernet_mac': MAC, 'strict_pre_enrolled_native_host_key': True,
             'private_key_stays_on_host51': True, 'network_configuration_changed': False,
             'ack_sent': False, 'boot_accepted': False, 'evidence_output': str(OUT.relative_to(R))}
    base = transport()
    if not args.execute:
        print(json.dumps(scope))
        return
    OUT.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    result = {**scope, 'status': 'backup_not_yet_verified', 'attempts': 0}

    def call(name, command, timeout):
        try:
            run = subprocess.run(base + [command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=timeout)
            stdout, stderr, rc = run.stdout, run.stderr, run.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, rc = exc.stdout or b'', exc.stderr or b'', 124
        (OUT / (name + '.stdout')).write_bytes(stdout)
        (OUT / (name + '.stderr')).write_bytes(stderr)
        return rc, stdout

    try:
        while time.monotonic() - started < args.duration:
            result['attempts'] += 1
            index = result['attempts']
            remaining = args.duration - (time.monotonic() - started)
            guard = ('set -eu; set -- $(sha256sum /root/.ssh/known_hosts); test "$1" = ' + HOSTS_SHA + '; ')
            probe = (guard + TOOLS + '/timeout-run.sh -s TERM -k 1 3 /bin/busybox ping '
                     '-c 1 -W 1 -I 169.254.190.51 169.254.190.15 >/dev/null 2>&1 || :; '
                     'exec ' + TOOLS + '/timeout-run.sh -s TERM -k 1 3 ' + TOOLS
                     + '/ip-run.sh -o neigh show to 169.254.190.15')
            rc, raw = call(f'{index:02}-neighbor', probe, min(15, remaining))
            rows = raw.decode(errors='replace').splitlines()
            matching = [row for row in rows if re.fullmatch(
                r'169\.254\.190\.15 dev br-lan lladdr ' + re.escape(MAC) + r' (?:REACHABLE|STALE|DELAY|PROBE)\s*', row)]
            if rc == 0 and len(rows) == len(matching) == 1:
                remaining = args.duration - (time.monotonic() - started)
                if remaining <= 0:
                    break
                login = shlex.join(['dbclient', '-T', '-K', '5', '-I', '30', '-i', '/root/.ssh/netpanel',
                                   '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
                                   '-o', 'StrictHostKeyChecking=yes', '-o', 'ProxyCommand=nc 169.254.190.15 2223',
                                   '-p', '2223', 'MastermixStudios@[leon-ubuntu26-be19000ai]:2223', REMOTE_CHECK])
                rc, raw = call(f'{index:02}-native-login', guard + 'exec ' + login, min(40, remaining))
                lines = raw.decode(errors='replace').splitlines()
                if rc == 0 and len(lines) >= 5 and lines[0] == (
                        'LEON_PHYSICAL_UPLINK_NATIVE_LOGIN_PASS uid=1000 source=169.254.190.51 target=169.254.190.15 port=2223'):
                    assert re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', lines[1])
                    result.update(status='actual_native_uplink_backup_login_verified',
                                  native_boot_id=lines[1], neighbor_mac=MAC,
                                  ssh_source_and_destination_verified=True, native_uid=1000,
                                  native_pid1='systemd', root_fstype='ext4')
                    break
            remaining = args.duration - (time.monotonic() - started)
            if remaining > 0:
                time.sleep(min(10, remaining))
    finally:
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
    if result['status'] != 'actual_native_uplink_backup_login_verified':
        raise SystemExit(1)


if __name__ == '__main__':
    main()

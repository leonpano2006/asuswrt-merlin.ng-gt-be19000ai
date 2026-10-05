#!/usr/bin/env python3
"""Read only the active BCM LAN/DNS handoff facts, never credentials/NVRAM dumps."""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
from pathlib import Path
import re
import socket
import paramiko

ROOT = Path(__file__).resolve().parents[1]
COMMAND = r'''set -eu
test "$(nvram get productid)" = GT-BE19000AI
printf 'BOOT_ID='; cat /proc/sys/kernel/random/boot_id
printf 'UPTIME='; cat /proc/uptime
printf 'KERNEL='; uname -a
for name in sw_mode re_mode lan_proto lan_ipaddr lan_netmask lan_gateway lan_dns lan_dns1 lan_dns2; do
 printf 'NVRAM_%s=' "$name"; nvram get "$name"
done
for path in /etc/resolv.conf /tmp/resolv.conf /tmp/resolv.dnsmasq; do
 printf 'RESOLVER_PATH=%s\n' "$path"
 ls -ld "$path" || :
 if test -f "$path"; then awk '/^(nameserver|search|domain|options)[ \t]/ {print}' "$path"; fi
done
printf 'ADDRESS_BEGIN\n'
ip addr show dev br0
printf 'ADDRESS_END\nROUTE_BEGIN\n'
ip route show
ip -6 route show
printf 'ROUTE_END\nMETADATA_RO_BEGIN\n'
cat /sys/class/block/mmcblk0p1/ro /sys/class/block/mmcblk0p2/ro
printf 'METADATA_RO_END\n'
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    output = ROOT / 'evidence/ubuntu26/native-network' / args.label
    assert not output.exists()
    password = getpass.getpass('Router SSH password: ')
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        connection = socket.create_connection(('192.168.100.15', 22), timeout=8, source_address=('192.168.100.36', 0))
        client.connect('192.168.100.15', sock=connection, username='MastermixStudios', password=password,
                       allow_agent=False, look_for_keys=False, timeout=8, banner_timeout=8, auth_timeout=8)
        password = None
        stdin, stdout, stderr = client.exec_command(COMMAND, timeout=20)
        stdin.channel.shutdown_write()
        data, errors = stdout.read(), stderr.read()
        code = stdout.channel.recv_exit_status()
    finally:
        client.close()
    output.mkdir(parents=True, mode=0o700)
    capture = output / 'capture.txt'
    capture.touch(mode=0o600)
    capture.write_bytes(data + errors)
    record = {'captured_at_utc': datetime.now(timezone.utc).isoformat(), 'returncode': code,
              'command_sha256': hashlib.sha256(COMMAND.encode()).hexdigest(),
              'capture_sha256': hashlib.sha256(capture.read_bytes()).hexdigest(),
              'scope': 'Read-only selected LAN DNS, addresses/routes, uptime and metadata write-protection flags.',
              'router_or_AI_board_modified': False, 'contains_passwords_or_private_keys': False}
    (output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    raise SystemExit(code)

if __name__ == '__main__':
    main()

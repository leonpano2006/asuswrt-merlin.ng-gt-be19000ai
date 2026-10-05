#!/usr/bin/env python3
"""One strict primary SSH snapshot after an OpenSSH banner; never sends ACK."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import time

R = Path(__file__).resolve().parents[1]
OUT = R / 'evidence/ubuntu26/trial-live/twentyfirst-primary-readonly-v1'
KH = R / 'evidence/ubuntu26/device-identity-live/ubuntu-known_hosts'
KH_SHA = '4238c5cc4ce2c7363eb491894192d7a926eaf1165a03b135b9621ea47ee922a7'
KEY_SHA = '208b0e8d4a18194d0da78a722eed6b361ccce51f3a3643a9575c4f3c50c04db3'
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
BODY = '''set +e
printf 'BOOT='; cat /proc/sys/kernel/random/boot_id
printf 'PID1='; cat /proc/1/comm
findmnt -n -o SOURCE,FSTYPE,UUID /
printf 'UID='; id -u
printf 'KERNEL_RELEASE='; uname -r
printf 'KERNEL_VERSION='; uname -v
printf 'ROOT_OPTIONS='; findmnt -n -o OPTIONS /
systemctl show leon-asus-prepare.service -p ActiveState -p SubState -p Result -p ExecMainStatus
systemctl show leon-asus-rescue-link.service -p ActiveState -p SubState -p Result -p ExecMainStatus -p StatusText
systemctl show leon-asus-ssh-uplink-rescue.socket -p ActiveState -p SubState -p Result
printf 'PRIVATE_SH='; readlink /usr/share/asus/commands/sbin/sh
printf 'ETH0_MASTER='; readlink /sys/class/net/eth0/master
for f in carrier speed operstate brport/state; do printf 'ETH0_%s=' "$f"; cat "/sys/class/net/eth0/$f"; done
timeout 2 /usr/sbin/ip -4 -o address show dev br0
timeout 2 /usr/sbin/ip -4 -o address show dev eth0
awk 'NR==1 || $2=="00000000"' /proc/net/route
ps -eo pid,comm,args | awk '$2 ~ /lldpd|amas|asus/ {print}'
timeout 3 /usr/bin/journalctl --boot --unit=leon-asus-prepare.service --output=cat --no-pager --lines=20
timeout 3 /usr/bin/journalctl --boot --unit=leon-asus-rescue-link.service --output=cat --no-pager --lines=40
timeout 3 /usr/bin/journalctl --boot --unit=leon-asus-broker.service --grep='^LEON_NETWORK_POLICY' --output=cat --no-pager --lines=12
'''


def save(name, data):
    fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(OUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def verify_snapshot(raw, rc):
    rows = raw.decode('utf-8', errors='replace').splitlines()
    def one(prefix):
        found = [row[len(prefix):] for row in rows if row.startswith(prefix)]
        assert len(found) == 1
        return found[0]
    boot = one('BOOT=')
    assert rows[0] == 'BOOT=' + boot and re.fullmatch(UUID, boot)
    assert rc == 0 and one('PID1=') == 'systemd' and one('UID=') == '0'
    assert rows.count('/dev/mmcblk0p11 ext4 ea8e47b8-c606-406c-b931-d2244d26ec55') == 1
    assert one('KERNEL_RELEASE=') == '4.19.294' and one('KERNEL_VERSION=').startswith('#10 ')
    options = one('ROOT_OPTIONS=').split(',')
    assert options.count('rw') == 1 and 'ro' not in options
    return boot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    scope = {'schema': 1, 'source': '192.168.100.35', 'destination': '192.168.100.15:22',
             'strict_pre_enrolled_native_host_key': True, 'ack_sent': False,
             'settings_changed': False, 'network_configuration_changed': False,
             'service_health_verified': False, 'boot_accepted': False,
             'evidence_output': str(OUT.relative_to(R))}
    assert __debug__
    assert hashlib.sha256(KH.read_bytes()).hexdigest() == KH_SHA
    if not args.execute:
        print(json.dumps(scope))
        return
    import paramiko
    OUT.mkdir(mode=0o700, parents=True, exist_ok=False)
    save('attempt.json', (json.dumps(scope, indent=2) + '\n').encode())
    save('command.txt', BODY.encode())
    result = {**scope, 'status': 'primary_not_verified', 'returncode': None}
    password = None
    client = paramiko.SSHClient()
    client.load_host_keys(str(KH))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    channel = None
    raw, err = bytearray(), bytearray()
    try:
        password = getpass.getpass('Router SSH password (memory only): ')
        connection.settimeout(5)
        connection.bind(('192.168.100.35', 0))
        connection.connect(('192.168.100.15', 22))
        client.connect('192.168.100.15', username='MastermixStudios', password=password,
                       sock=connection, allow_agent=False, look_for_keys=False,
                       timeout=5, banner_timeout=5, auth_timeout=5)
        key = client.get_transport().get_remote_server_key()
        result['host_key_sha256_hex'] = hashlib.sha256(key.asbytes()).hexdigest()
        assert result['host_key_sha256_hex'] == KEY_SHA
        command = 'sudo -S -p "" /bin/sh -c ' + shlex.quote(BODY)
        stdin, stdout, stderr = client.exec_command(command, timeout=15)
        channel = stdout.channel
        stdin.write(password + '\n')
        stdin.flush()
        stdin.channel.shutdown_write()
        deadline = time.monotonic() + 20
        while True:
            if channel.recv_ready():
                raw.extend(channel.recv(min(4096, 65537 - len(raw))))
            if channel.recv_stderr_ready():
                err.extend(channel.recv_stderr(min(4096, 8193 - len(err))))
            assert len(raw) <= 65536 and len(err) <= 8192
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                result['returncode'] = channel.recv_exit_status()
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('bounded primary snapshot deadline')
            time.sleep(0.02)
        boot = verify_snapshot(bytes(raw), result['returncode'])
        result.update(status='actual_native_primary_login_verified', native_boot_id=boot,
                      native_pid1='systemd', native_uid=0, root_fstype='ext4', root_writable=True,
                      root_uuid='ea8e47b8-c606-406c-b931-d2244d26ec55', kernel_release='4.19.294',
                      kernel_build_prefix='#10 ')
    except Exception as error:
        result['error_class'] = type(error).__name__
    finally:
        if channel is not None:
            channel.close()
        client.close()
        connection.close()
        password = None
        save('stdout', bytes(raw))
        save('stderr', bytes(err))
        save('result.json', (json.dumps(result, indent=2) + '\n').encode())
        print(json.dumps(result), flush=True)
    if result['status'] != 'actual_native_primary_login_verified':
        raise SystemExit(1)


if __name__ == '__main__':
    main()

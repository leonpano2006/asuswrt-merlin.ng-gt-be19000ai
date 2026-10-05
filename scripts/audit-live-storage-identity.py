#!/usr/bin/env python3
"""Read-only BCM filesystem identity capture; no NVRAM or mount modifications."""
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
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--label', required=True)
parser.add_argument('--parse-existing', action='store_true', help='Parse a saved capture without connecting again')
args = parser.parse_args()
assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
out = ROOT / 'evidence/ubuntu26/storage-identity' / args.label
assert args.parse_existing or not out.exists()
password = None if args.parse_existing else getpass.getpass('Router SSH password: ')
client = paramiko.SSHClient()
client.load_system_host_keys()
client.set_missing_host_key_policy(paramiko.RejectPolicy())
command = r'''set -eu
test "$(nvram get productid)" = GT-BE19000AI
printf 'MODEL='; nvram get productid
printf 'KERNEL='; uname -r
printf 'BOOT_ID='; cat /proc/sys/kernel/random/boot_id
printf 'CMDLINE='; cat /proc/cmdline
printf 'DATA_DEVICE='; readlink -f /dev/data
printf 'JFFS_DEVICE='; readlink -f /dev/jffs
printf 'DEFAULTS_DEVICE='; readlink -f /dev/defaults
printf 'AIBOARD_DEVICE='; readlink -f /dev/aiboard
printf 'BLOCK_FS_IDENTITY_BEGIN\n'
blkid /dev/mmcblk0p7 /dev/mmcblk0p8 /dev/mmcblk0p9 /dev/mmcblk0p10
printf 'BLOCK_FS_IDENTITY_END\n'
printf 'MOUNTINFO_BEGIN\n'
awk '$5 == "/data" || $5 == "/jffs" || $5 == "/mnt/defaults" || $5 == "/tmp/mnt/defaults" || $5 == "/mnt/nvram" || $5 == "/ai" {print}' /proc/self/mountinfo
printf 'MOUNTINFO_END\n'
for path in /mnt/defaults /tmp/mnt/defaults /mnt/nvram /ai; do
 printf 'PATH_IDENTITY=%s\n' "$path"
 ls -ld "$path" || :
 readlink -f "$path" || :
done
for part in mmcblk0p7 mmcblk0p8 mmcblk0p9 mmcblk0p10; do
 printf 'PARTITION=%s\n' "$part"
 cat "/sys/class/block/$part/start" "/sys/class/block/$part/size" "/sys/class/block/$part/ro"
done
printf 'NVRAM_FILE_METADATA_BEGIN\n'
for path in /data/.kernel_nvram.setting /data/.kernel_nvram.setting_new /data/.kernel_nvram.setting_old /data/.wlsromcustomerfile.nvm /rom/etc/wlan/kernel_nvram.setting /mnt/defaults/wl/nvram.nvm; do
 printf 'FILE=%s\n' "$path"
 if test -f "$path"; then ls -ln "$path"; sha256sum "$path"; else printf 'NOT_A_REGULAR_FILE\n'; fi
done
printf 'NVRAM_FILE_METADATA_END\n'
'''
capture = out / 'capture.txt'
if args.parse_existing:
    data = capture.read_bytes()
    metadata = out / 'capture-meta.json'
    code = json.loads(metadata.read_text())['returncode'] if metadata.exists() else None
else:
    try:
        connection = socket.create_connection(('192.168.100.15', 22), timeout=8,
                                              source_address=('192.168.100.36', 0))
        client.connect('192.168.100.15', sock=connection, username='MastermixStudios',
                       password=password, allow_agent=False, look_for_keys=False,
                       timeout=8, banner_timeout=8, auth_timeout=8)
        password = None
        stdin, stdout, stderr = client.exec_command(command, timeout=25)
        stdin.channel.shutdown_write()
        data = stdout.read()
        error = stderr.read()
        code = stdout.channel.recv_exit_status()
    finally:
        client.close()
    out.mkdir(parents=True, mode=0o700)
    capture.touch(mode=0o600)
    capture.write_bytes(data + error)
    (out / 'capture-meta.json').write_text(json.dumps({'returncode': code, 'stderr': error.decode(errors='replace'), 'command_sha256': hashlib.sha256(command.encode()).hexdigest()}) + '\n')
text = data.decode(errors='replace')
identities = {}
for role, part in [('data', 'mmcblk0p7'), ('jffs', 'mmcblk0p9')]:
    matches = re.findall(r'^/dev/' + part + r': (.+)$', text, re.M)
    assert len(matches) == 1, (role, 'missing or duplicate block identity')
    fields = dict(re.findall(r'(\w+)="([^"]*)"', matches[0]))
    # This stock BusyBox blkid prints UUID only. Establish filesystem type and
    # exact device number from the same capture's mountinfo instead.
    mounts = re.findall(r'^\d+ \d+ (179:(?:7|9)) / /' + role + r' \S+ - (\S+) (\S+) \S+$', text, re.M)
    assert len(mounts) == 1 and mounts[0] == ('179:' + part.rsplit('p', 1)[1], 'ext4', '/dev/' + role)
    assert fields.get('TYPE', 'ext4') == 'ext4'
    assert re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', fields['UUID'])
    assert re.search(r'^' + role.upper() + '_DEVICE=/dev/' + part + '$', text, re.M)
    identities[role] = {'device': '/dev/' + part, 'uuid': fields['UUID'], 'type': 'ext4', 'mountinfo_device': mounts[0][0]}
assert code is None or code == 0
report = {'observed_at_utc': datetime.fromtimestamp(capture.stat().st_mtime, timezone.utc).isoformat(),
          'ssh_command_returncode': code,
          'model': 'GT-BE19000AI', 'identities': identities,
          'capture_sha256': hashlib.sha256(capture.read_bytes()).hexdigest(),
          'command_sha256': hashlib.sha256(command.encode()).hexdigest(),
          'scope': 'Read-only existing BCM /data and /jffs UUID/mount/partition identity; no rootfs, partition, NVRAM, boot slot or AI-board changes.',
          'activation_allowed': False}
(out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))

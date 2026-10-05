#!/usr/bin/env python3
"""Read BCM boot selection and both metadata copies without opening a watchdog."""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import zlib
import paramiko

ROOT = Path(__file__).resolve().parents[1]
COMMAND = r'''set -eu
test "$(nvram get productid)" = GT-BE19000AI
printf 'BOOT_ID='; cat /proc/sys/kernel/random/boot_id
printf 'UPTIME='; cat /proc/uptime
uname -a
cat /proc/cmdline
test "$(sha256sum /bin/bcm_bootstate | awk '{print $1}')" = 2b01eb80604ef66aa21a99178c70501eeb8a2c458132d133051a241373c5c845
test "$(sha256sum /lib/libbcm_flashutil.so | awk '{print $1}')" = 18c98a3c45d78b7ccc26e82a94ea225ac3b422d123b6b783f71691f5639fb0d0
/bin/bcm_bootstate
printf 'BOOTSTATE_RESET_REASON='; cat /proc/bootstate/reset_reason; printf '\n'
for n in 1 2; do
 printf 'METADATA_%s_BEGIN\n' "$n"
 test "$(cat /sys/class/block/mmcblk0p$n/dev)" = "179:$n"
 test "$(cat /sys/class/block/mmcblk0p$n/size)" = 512
 cat /sys/class/block/mmcblk0p$n/dev /sys/class/block/mmcblk0p$n/size /sys/class/block/mmcblk0p$n/ro
 printf 'METADATA_%s_END\n' "$n"
done
if test -e /var/gpt_modified.txt; then echo GPT_MODIFIED_MARKER=present; else echo GPT_MODIFIED_MARKER=absent; fi
for name in wdtd watchdog; do printf 'PROCESS_%s=' "$name"; pidof "$name" || :; done
for name in state status timeout nowayout bootstatus identity; do
 path="/sys/class/watchdog/watchdog0/$name"
 if test -f "$path"; then printf 'WATCHDOG_%s=' "$name"; cat "$path"; fi
done
'''
STOCK_STORAGE = r'''set -eu
printf 'STORAGE_PROGRAM_HASHES_BEGIN\n'
sha256sum /sbin/rc /lib/libdisk.so /usr/lib/libshared.so /rom/etc/init.d/partitioncfg /rom/etc/init.d/mount-data.inc
printf 'STORAGE_PROGRAM_HASHES_END\n'
ls -l /sbin/asus_mmc 2>&1 || :
printf 'MMC_SYSFS='; readlink /sys/block/mmcblk0
printf 'MMC_DEVICE_SYSFS='; readlink /sys/block/mmcblk0/device
printf 'MMC_CID='; cat /sys/block/mmcblk0/device/cid
printf 'MMC_SIZE_SECTORS='; cat /sys/block/mmcblk0/size
printf 'MMC_LOGICAL_BLOCK_SIZE='; cat /sys/block/mmcblk0/queue/logical_block_size
printf 'PERSISTENT_MOUNTS_BEGIN\n'
awk '$1 ~ /^\/dev\/(mmcblk0p[789]|mmcblk0p10|data|defaults|jffs|aiboard)$/ { print }' /proc/mounts
printf 'PERSISTENT_MOUNTS_END\n'
for n in 7 8 9 10; do
 printf 'PERSISTENT_PARTITION_%s\n' "$n"
 cat "/sys/class/block/mmcblk0p$n/dev" "/sys/class/block/mmcblk0p$n/start" "/sys/class/block/mmcblk0p$n/size"
 blkid "/dev/mmcblk0p$n"
done
printf 'ORIGINAL_SLOT2_HASHES_BEGIN\n'
sha256sum /dev/mmcblk0p5 /dev/mmcblk0p6
printf 'ORIGINAL_SLOT2_HASHES_END\n'
'''

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', required=True)
    p.add_argument('--stock-storage', action='store_true', help='Also hash current storage programs and complete original slot2 partitions, read-only')
    args = p.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    out = ROOT / 'evidence/ubuntu26/boot-metadata' / args.label
    assert not out.exists()
    password = getpass.getpass('Router SSH password: ')
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    os.umask(0o077)
    commands = []
    def execute(command):
        commands.append(command)
        stdin, stdout, stderr = client.exec_command(command, timeout=60 if args.stock_storage else 25)
        stdin.channel.shutdown_write()
        data, errors = stdout.read(), stderr.read()
        code = stdout.channel.recv_exit_status()
        if code:
            raise RuntimeError(f'Read-only query failed: exit{code}, stderr={errors.decode(errors="replace")[:1000]}')
        return data
    try:
        sock = socket.create_connection(('192.168.100.15', 22), timeout=8, source_address=('192.168.100.36', 0))
        client.connect('192.168.100.15', sock=sock, username='MastermixStudios', password=password,
                       allow_agent=False, look_for_keys=False, timeout=8, banner_timeout=8, auth_timeout=8)
        password = None
        before = execute('cat /proc/sys/kernel/random/boot_id').decode().strip()
        capture = execute(COMMAND)
        if args.stock_storage:
            capture += execute(STOCK_STORAGE)
        copies = [execute(f'dd if=/dev/mmcblk0p{n} bs=4096 count=64') for n in [1, 2]]
        after = execute('cat /proc/sys/kernel/random/boot_id').decode().strip()
    finally:
        client.close()
    assert before == after and re.fullmatch(r'[0-9a-f-]{36}', before)
    out.mkdir(parents=True, mode=0o700)
    (out / 'capture.txt').write_bytes(capture)
    records = []
    for n, data in enumerate(copies, 1):
        assert len(data) == 262144
        (out / f'metadata{n}.bin').write_bytes(data)
        length = (struct.unpack_from('<I', data, 4)[0] - 4) & 0xffff
        stored_crc = struct.unpack_from('<I', data, 8)[0]
        payload = data[12:12 + length]
        fields = {}
        for key in ['COMMITTED', 'VALID', 'SEQ']:
            found = re.search(rb'(?:^|\x00)' + key.encode() + rb'=([0-9,]+)\x00', payload)
            assert found, key
            fields[key] = found[1].decode()
        records.append({'number': n, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                        'crc_valid': zlib.crc32(payload) == stored_crc, 'fields': fields})
    report = {'captured_at_utc': datetime.now(timezone.utc).isoformat(), 'boot_id': before,
              'boot_unchanged_during_capture': True, 'capture_sha256': hashlib.sha256(capture).hexdigest(),
              'command_sha256': hashlib.sha256('\n'.join(commands).encode()).hexdigest(),
              'metadata_copies': records, 'copies_identical': copies[0] == copies[1],
              'stock_storage_programs_and_fallback_slot_hashed': args.stock_storage,
              'scope': 'Read-only boot selection, raw partition metadata and passive watchdog sysfs; no watchdog open/ioctl/ping.',
              'device_modified': False, 'hardware_reset_or_automatic_recovery_proven': False}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if all(r['crc_valid'] for r in records) else 1)

if __name__ == '__main__':
    main()

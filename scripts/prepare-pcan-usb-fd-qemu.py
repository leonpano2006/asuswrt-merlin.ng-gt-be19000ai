#!/usr/bin/env python3
"""Build an offline PCAN module load/unload smoke test (no USB passthrough)."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import stat

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel-tree', type=Path, required=True)
p.add_argument('--output-dir', type=Path, default=ROOT / 'build/pcan-usb-fd/qemu')
p.add_argument('--busybox', type=Path, default=ROOT / 'build/busybox')
a = p.parse_args()
a.output_dir.mkdir(parents=True, exist_ok=True)
modules = ['drivers/usb/common/usb-common.ko', 'drivers/usb/core/usbcore.ko',
           'net/can/can.ko', 'net/can/can-raw.ko', 'drivers/net/can/can-dev.ko',
           'drivers/net/can/usb/peak_usb/peak_usb.ko']
files = {'bin/busybox': a.busybox}
files.update({'modules/' + Path(name).name: a.kernel_tree / name for name in modules})
init = '''#!/bin/busybox sh
export PATH=/bin
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
fail() { echo LAB_PCAN_MODULE_FAILED; poweroff -f; }
trap fail EXIT
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
for m in usb-common usbcore can can-raw can-dev peak_usb; do
    insmod /modules/$m.ko
    echo LAB_PCAN_MODULE_LOADED=$m
done
test -d /sys/bus/usb/drivers/peak_usb
grep -q '^peak_usb ' /proc/modules
grep -q '^can_raw ' /proc/modules
echo LAB_PCAN_REGISTERED_PASS
for m in peak_usb can_raw can_dev can usbcore usb_common; do
    rmmod $m
    echo LAB_PCAN_MODULE_UNLOADED=$m
done
test ! -d /sys/bus/usb/drivers/peak_usb
echo LAB_PCAN_UNREGISTERED_PASS
trap - EXIT
echo QEMU_PCAN_MODULE_COMPLETE
poweroff -f
'''
entries = {x: (stat.S_IFDIR | 0o755, b'', 0, 0) for x in ['bin', 'dev', 'proc', 'sys', 'modules']}
entries.update({n: (stat.S_IFREG | 0o755, f.read_bytes(), 0, 0) for n, f in files.items()})
entries.update({'init': (stat.S_IFREG | 0o755, init.encode(), 0, 0),
                'dev/console': (stat.S_IFCHR | 0o600, b'', 5, 1),
                'dev/null': (stat.S_IFCHR | 0o666, b'', 1, 3),
                'TRAILER!!!': (0, b'', 0, 0)})
data = bytearray()
for ino, (name, (mode, payload, major, minor)) in enumerate(entries.items(), 1):
    n = name.encode() + b'\0'
    fields = [ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0, len(payload), 0, 0, major, minor, len(n), 0]
    data += b'070701' + ''.join(f'{v:08x}' for v in fields).encode() + n
    data += b'\0' * (-len(data) % 4)
    data += payload
    data += b'\0' * (-len(data) % 4)
archive = a.output_dir / 'pcan-usb-fd-module.cpio.gz'
archive.write_bytes(gzip.compress(data, compresslevel=1, mtime=0))
record = {'archive': str(archive), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
          'files': {n: {'source': str(f), 'sha256': hashlib.sha256(f.read_bytes()).hexdigest()} for n, f in files.items()},
          'complete_marker': 'QEMU_PCAN_MODULE_COMPLETE',
          'no_hardware_passthrough': True,
          'limitations': ['Module registration/load/unload only; no adapter enumeration or CAN traffic']}
(a.output_dir / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))

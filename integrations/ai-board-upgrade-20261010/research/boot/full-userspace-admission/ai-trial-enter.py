#!/usr/bin/python3
"""AI-only systemd entry transaction; parent stages it, this audit never runs it.

The process owns both ENV arming and the first graceful reboot, so loss of the
workstation or SSH cannot split those steps. It performs no GPIO reset.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import struct
import subprocess
import zlib

KEYS = {'bootcmd', 'altbootcmd', 'bootcount', 'upgrade_available',
        'leon_ramtrial', 'leon_ramload', 'leon_ramboot'}
ONESHOT = ('if setenv bootcmd bootmmc && saveenv; then run leon_ramload; fi; '
           'setenv bootargs; setenv skip_fdt_update; bootmmc')
ROOT_UUID = 'e46de487-2d50-4bfb-9365-33ea9027d40e'
TOOL_HASHES = {
    '/usr/bin/fw_printenv': '3c1c7952e7b8877c5897bcbdf4125fb43d9bd5252e38c331aeaae02186557100',
    '/usr/lib/libubootenv.so.0.3.5': '1307197984043407b8464e5013d83d743e907726c72de6564668c1435cf68f61',
}


def private_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as src:
        st = os.fstat(src.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise RuntimeError('Expected root-owned single-link mode0600 file')
        data = src.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError('Input too large')
    return data


def save_event(folder, name, fields):
    fd = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(fields, out, sort_keys=True)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())


def active_environment():
    rows = []
    for dev in ('/dev/mmcblk0p6', '/dev/mmcblk0p7'):
        with open(dev, 'rb') as src:
            src.seek(0xff0000)
            raw = src.read(0x10000)
        if len(raw) != 0x10000 or zlib.crc32(raw[5:]) & 0xffffffff != struct.unpack_from('<I', raw)[0]:
            raise RuntimeError('Environment CRC mismatch')
        fields = dict(item.split(b'=', 1) for item in raw[5:].split(b'\0') if b'=' in item)
        rows.append((raw[4], fields))
    if rows[0][0] == rows[1][0] and rows[0][1] != rows[1][1]:
        raise RuntimeError('Ambiguous equal-serial environment')
    row = rows[0] if ((rows[0][0] - rows[1][0]) & 255) < 128 else rows[1]
    return row


def verify_selected(expected):
    serial, fields = active_environment()
    for key, value in expected.items():
        actual = fields.get(key.encode())
        if (actual is not None if value is None else actual != value.encode()):
            raise RuntimeError('Selected environment mismatch: ' + key)
    if fields.get(b'boot_slot') != b'2' or fields.get(b'bootlimit') != b'3':
        raise RuntimeError('Stock B selection changed')
    if any(key in fields for key in (b'bootargs', b'skip_fdt_update', b'leon_ai_guard_seen')):
        raise RuntimeError('Unexpected saved temporary setting')
    return serial


def store_environment(folder, filename, expected):
    # Actual libubootenv client syntax: key=value, with key= deleting a key.
    text = ''.join(key + '=' + (expected[key] if expected[key] is not None else '') + '\n'
                   for key in sorted(expected))
    fd = os.open(folder / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    # Do not timeout-kill the writer during a redundant-environment store.
    # Arbitrary blocked storage/PID1 is outside the SSH-loss guarantee.
    result = subprocess.run(['/usr/bin/fw_setenv', '-s', str(folder / filename)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, close_fds=True)
    if result.returncode:
        raise RuntimeError('Environment store failed')
    serial = verify_selected(expected)
    os.sync()
    return serial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    if os.geteuid() != 0:
        raise RuntimeError('Requires root on AI')
    raw = private_file(args.plan, 16384)
    if hashlib.sha256(raw).hexdigest() != args.plan_sha256:
        raise RuntimeError('Plan digest mismatch')
    plan = json.loads(raw)
    nonce = plan['nonce']
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise RuntimeError('Invalid nonce')
    folder = Path('/run/leon-ai-enter-' + nonce)
    if args.plan != folder / 'plan.json' or folder.is_symlink():
        raise RuntimeError('Unexpected entry directory')
    st = folder.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError('Unsafe entry directory')
    private_file(Path(__file__), 32768)
    save_event(folder, 'owner-lock.json', {'nonce': nonce, 'pid': os.getpid()})
    original, armed = plan['original'], plan['environment']
    if set(original) != KEYS or set(armed) != KEYS:
        raise RuntimeError('Unexpected environment key set')
    for cohort in (original, armed):
        for key, value in cohort.items():
            if value is not None and (not isinstance(value, str) or not value or '\n' in value or '\r' in value or '\0' in value or len((key + '=' + value).encode()) > 1022):
                raise RuntimeError('Invalid environment value')
    if any(armed.get(k) != v for k, v in {'bootcmd': 'run leon_ramtrial', 'altbootcmd': 'bootmmc', 'bootcount': '2', 'upgrade_available': '1', 'leon_ramtrial': ONESHOT}.items()):
        raise RuntimeError('Unexpected trial guard')
    if any(original.get(k) != v for k, v in {'bootcmd': 'bootmmc', 'bootcount': '0', 'upgrade_available': '0', 'leon_ramtrial': None, 'leon_ramload': None, 'leon_ramboot': None}.items()):
        raise RuntimeError('Unexpected original guard')
    if not armed['leon_ramload'] or not armed['leon_ramboot']:
        raise RuntimeError('Missing admitted load/boot script')
    if platform.release() != '5.15.140' or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != plan['initial_ai_boot_id']:
        raise RuntimeError('Initial stock boot changed')
    root = subprocess.check_output(['/usr/bin/findmnt', '-no', 'SOURCE,UUID', '/'], timeout=8).decode().split()
    if root != ['/dev/mmcblk0p13', ROOT_UUID]:
        raise RuntimeError('Root B identity mismatch')
    if Path('/usr/bin/fw_setenv').resolve() != Path('/usr/bin/fw_printenv').resolve():
        raise RuntimeError('Unexpected environment tool route')
    for filename, digest in TOOL_HASHES.items():
        path = Path(filename)
        if path.stat().st_uid != 0 or path.stat().st_mode & 0o022 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Environment tool/library mismatch')
    with open('/dev/mmcblk0p17', 'rb') as src:
        src.seek(4096)
        misc = src.read(32).hex()
    if misc != '0041424202000302000000080200000000000000000000000000000000000000':
        raise RuntimeError('Stock B metadata changed')
    serial = verify_selected(original)
    save_event(folder, 'ready.json', {'nonce': nonce, 'pid': os.getpid(), 'initial_ai_boot_id': plan['initial_ai_boot_id'], 'plan_sha256': args.plan_sha256, 'active_serial': serial})
    try:
        serial = store_environment(folder, 'arm.env', armed)
        save_event(folder, 'armed.json', {'nonce': nonce, 'active_serial': serial, 'both_env_crc_valid': True})
        # Record intent before submission. No dependency on an SSH acknowledgement.
        save_event(folder, 'reboot-requested.json', {'nonce': nonce, 'command': '/bin/systemctl --no-block reboot'})
        result = subprocess.run(['/bin/systemctl', '--no-block', 'reboot'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12)
        if result.returncode:
            raise RuntimeError('Orderly reboot explicitly rejected')
        # Normal shutdown may already be in progress. No ENV operation follows.
        try:
            save_event(folder, 'reboot-accepted.json', {'nonce': nonce, 'returncode': 0})
        except OSError:
            pass
        return 0
    except subprocess.TimeoutExpired:
        # A timed-out systemctl request can already be queued. Do not race it
        # with a restore write; the fixed BCM recovery watchdog remains active.
        save_event(folder, 'reboot-outcome-unknown.json', {'nonce': nonce, 'error': 'systemctl_timeout', 'environment_left_armed': True})
        return 2
    except Exception as exc:
        result = {'nonce': nonce, 'error': type(exc).__name__, 'original_restored': False}
        try:
            result['active_serial'] = store_environment(folder, 'restore.env', original)
            result['original_restored'] = True
            result['both_env_crc_valid'] = True
        except Exception as restore_error:
            result['restore_error'] = type(restore_error).__name__
        save_event(folder, 'abort.json', result)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

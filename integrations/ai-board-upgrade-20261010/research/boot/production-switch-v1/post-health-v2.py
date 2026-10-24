#!/usr/bin/python3
"""Source-only production re-arm; no GPIO, reboot, service restart or workloads.

The current candidate boot must already have saved stock next boot. Health is
bounded to 300 seconds with reads at most five seconds. ENV stores deliberately
have no timeout/kill, as in the reviewed ai-trial-enter.py. This is not a durable
BCM coordinator: after re-arm, bounded automatic cold recovery is not promised.
"""
import argparse
import fcntl
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
import time
import zlib

KEYS = {'bootcmd', 'altbootcmd', 'bootcount', 'upgrade_available',
        'leon_ramtrial', 'leon_ramload', 'leon_ramboot'}
ONESHOT = ('if setenv bootcmd bootmmc && saveenv; then run leon_ramload; fi; '
           'setenv bootargs; setenv skip_fdt_update; bootmmc')
KERNEL = '6.12.62-leonai7+'
ROOT_UUID = 'e46de487-2d50-4bfb-9365-33ea9027d40e'
HOME_UUID = '1dc03244-18dc-4aff-87f4-c6b300a9cc97'
UNITS = ['systemd-networkd.service', 'avahi-daemon.service', 'docker.service',
         'containerd.service', 'usage-stats.service', 'systemd-timesyncd.service',
         'systemd-modules-load.service']
CONTAINERS = ['formal-portainer-asus', 'homeassistant-asus', 'slm-asus']
TOOL_HASHES = {
    '/usr/bin/fw_printenv': '3c1c7952e7b8877c5897bcbdf4125fb43d9bd5252e38c331aeaae02186557100',
    '/usr/lib/libubootenv.so.0.3.5': '1307197984043407b8464e5013d83d743e907726c72de6564668c1435cf68f61',
}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def private_file(path, limit):
    # Same root/private/non-symlink contract as reviewed ai-trial-enter.py.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as src:
        st = os.fstat(src.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                and stat.S_IMODE(st.st_mode) == 0o600, 'unsafe_private_file')
        data = src.read(limit + 1)
    require(len(data) <= limit, 'input_too_large')
    return data


def active_environment():
    # Reused raw CRC/serial selection from reviewed ai-trial-enter.py.
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
    # key=value syntax and non-timeout writer copied from reviewed entry source.
    text = ''.join(key + '=' + (expected[key] if expected[key] is not None else '') + '\n'
                   for key in sorted(expected))
    fd = os.open(folder / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    result = subprocess.run(['/usr/bin/fw_setenv', '-s', str(folder / filename)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, close_fds=True)
    if result.returncode:
        raise RuntimeError('Environment store failed')
    serial = verify_selected(expected)
    os.sync()
    return serial


def command(argv):
    """Fixed read-only queries, at most five seconds; never the ENV writer."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
                             env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    try:
        # Reserve the final quarter-second for owned-child cleanup.
        out, err = child.communicate(timeout=4.75)
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            child.communicate(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass
        raise
    require(child.returncode == 0 and len(out) <= 65536 and len(err) <= 4096,
            'read_command_failed:' + argv[0])
    return out.decode('utf-8', 'strict')


def hash_file(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as src:
        st = os.fstat(src.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                and not st.st_mode & 0o022 and st.st_size == expected['bytes'],
                'unsafe_cohort_file:' + str(path))
        digest = hashlib.sha256()
        for part in iter(lambda: src.read(65536), b''):
            digest.update(part)
    require(digest.hexdigest() == expected['sha256'], 'cohort_digest:' + str(path))


def plan_check(plan, path, plan_sha256):
    require(set(plan) == {'schema', 'deployment_nonce', 'cohort_dir', 'kernel_release',
                         'environment', 'files', 'module_manifest_sha256',
                         'module_file_count'}, 'plan_schema_keys')
    nonce = plan['deployment_nonce']
    require(plan['schema'] == 1 and isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce),
            'plan_identity')
    cohort = Path('/home/leon-fulltrial-' + nonce)
    require(plan['cohort_dir'] == str(cohort) and path == cohort / 'plan.json', 'plan_path')
    for parent in (cohort, cohort.parent):
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'unsafe_cohort_directory')
    require(stat.S_IMODE(cohort.stat().st_mode) == 0o700 and plan['kernel_release'] == KERNEL,
            'cohort_identity')
    env = dict(plan['environment'])
    require(set(env) == KEYS, 'environment_key_set')
    for key, value in env.items():
        require(isinstance(value, str) and value and not any(c in value for c in '\r\n\0')
                and len((key + '=' + value).encode()) <= 1022, 'environment_value')
    fixed = {'bootcmd': 'run leon_ramtrial', 'altbootcmd': 'bootmmc', 'bootcount': '2',
             'upgrade_available': '1', 'leon_ramtrial': ONESHOT}
    require(all(env.get(k) == v for k, v in fixed.items()), 'environment_guard')
    require(env['leon_ramboot'].count('@PLAN_SHA256@') == 1
            and all('@PLAN_SHA256@' not in value for key, value in env.items() if key != 'leon_ramboot'),
            'plan_digest_placeholder')
    env['leon_ramboot'] = env['leon_ramboot'].replace('@PLAN_SHA256@', plan_sha256)
    files = plan['files']
    require(isinstance(files, dict) and 4 <= len(files) <= 32
            and {'Image', 'board.dtb', 'initramfs.cpio.gz', 'modules.sha256', 'post-health.py'} <= set(files),
            'cohort_file_set')
    for name, expected in files.items():
        require(re.fullmatch('[A-Za-z0-9_.-]+', name) and name not in {'.', '..', 'plan.json'},
                'cohort_file_name')
        require(set(expected) == {'bytes', 'sha256'} and type(expected['bytes']) is int
                and 0 < expected['bytes'] <= 67108864
                and isinstance(expected['sha256'], str)
                and re.fullmatch('[0-9a-f]{64}', expected['sha256']), 'cohort_file_metadata')
    require(files['Image'] == {'bytes': 15933448,
            'sha256': '5158ca81f22caea4fcabfcd7091a9a3e7c9ae4aec901994cee5411a2877513a1'}
            and files['board.dtb'] == {'bytes': 65536,
            'sha256': 'c8004fedc08a4f3127ad2acc502d8c30de506548a5af198f4c92733f0b952cb0'},
            'qualified_kernel_dt_changed')
    sizes = [format(files[n]['bytes'], 'x') for n in ('Image', 'initramfs.cpio.gz', 'board.dtb')]
    loads = []
    for name, address, size in zip(('Image', 'initramfs.cpio.gz', 'board.dtb'),
                                  ('0x07c00000', '0x08d00000', '0x18d00000'), sizes):
        loads.append('ext4load mmc 0.0:12 ' + address + ' /' + cohort.name + '/' + name
                     + ' 0x' + size + ' && test "${filesize}" = "' + size + '"')
    require(env['leon_ramload'] == 'if ' + ' && '.join(loads) + '; then run leon_ramboot; fi',
            'noncanonical_loader')
    bootargs = ('console=ttyS0,115200 rdinit=/init init=/__trial_no_rootfs root=/dev/mmcblk0p13 '
                'rootfstype=ext4 ro panic=0 cma=524288000@1556086784 leakage=871 '
                'systemd.unified_cgroup_hierarchy=0 systemd.log_target=kmsg systemd.log_level=info '
                'initcall_debug leon_trial=' + nonce + ' leon_production_plan=' + plan_sha256)
    expected_boot = ('if setenv bootargs "' + bootargs + '" && setenv skip_fdt_update 0x12; '
                     'then booti 0x07c00000 0x08d00000:0x' + sizes[1] + ' 0x18d00000; fi')
    require(env['leon_ramboot'] == expected_boot, 'noncanonical_boot')
    require(plan['module_manifest_sha256'] == files['modules.sha256']['sha256']
            == '7d30a2c3ad8fda41eeaf0c357eb443189909a8dcb48287275ea5640b0ddaa4d9'
            and plan['module_file_count'] == 451, 'qualified_modules_changed')
    return cohort, env


def integrity(plan, cohort):
    for name, expected in plan['files'].items():
        hash_file(cohort / name, expected)
    manifest = (cohort / 'modules.sha256').read_text()
    rows = manifest.splitlines()
    require(len(rows) == plan['module_file_count'], 'module_file_count')
    seen = set()
    for row in rows:
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_+./-]+)', row)
        require(match is not None, 'module_manifest_row')
        digest, name = match.groups()
        parts = Path(name).parts
        require(parts[0] == KERNEL and '..' not in parts and name not in seen, 'module_manifest_path')
        seen.add(name)
        path = cohort / 'modules' / name
        require(path.resolve() == path, 'module_symlink')
        hash_file(path, {'bytes': path.stat().st_size, 'sha256': digest})


def health(cohort):
    require(platform.release() == KERNEL, 'kernel_release')
    root = command(['/usr/bin/findmnt', '-no', 'SOURCE,UUID', '/']).split()
    home = command(['/usr/bin/findmnt', '-no', 'SOURCE,UUID', '/home']).split()
    require(root == ['/dev/mmcblk0p13', ROOT_UUID], 'root_B_identity')
    require(home == ['/dev/mmcblk0p18', HOME_UUID], 'home_identity')
    mount_rows = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    mounts = [row for row in mount_rows if row[4] == '/lib/modules']
    home_mounts = [row for row in mount_rows if row[4] == '/home']
    require(len(mounts) == 1 and len(home_mounts) == 1 and 'ro' in mounts[0][5].split(',')
            and mounts[0][3] == '/' + cohort.name + '/modules'
            and mounts[0][2] == home_mounts[0][2], 'modules_ro_bind')
    filesystems = [row[row.index('-') + 1] for row in mount_rows]
    require('cgroup' in filesystems and not any(row[4] == '/sys/fs/cgroup' and row[row.index('-') + 1] == 'cgroup2' for row in mount_rows), 'cgroup_v1_not_active')
    for marker in ('/system-update', '/etc/system-update',
                   '/etc/systemd/system/multi-user.target.wants/arc_first_time.service',
                   '/etc/systemd/system/basic.target.wants/resize-helper.service'):
        require(not os.path.lexists(marker), 'pending_update_or_factory_marker')
    for folder in ('/etc/deb-postinsts', '/etc/rpm-postinsts'):
        if Path(folder).is_dir():
            require(not any(Path(folder).iterdir()), 'pending_postinst')
    thp = Path('/sys/kernel/mm/transparent_hugepage/enabled').read_text().strip()
    require('[madvise]' in thp, 'thp_policy')
    raw = command(['/bin/systemctl', 'show', *UNITS,
                   '-p', 'Id,LoadState,ActiveState,SubState,Result,ExecMainStatus'])
    units = {}
    for block in raw.strip().split('\n\n'):
        values = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        if 'Id' in values:
            units[values['Id']] = values
    require(all(units.get(name, {}).get('LoadState') == 'loaded'
                and units[name].get('ActiveState') == 'active'
                and units[name].get('Result') == 'success'
                and units[name].get('ExecMainStatus') == '0' for name in UNITS), 'native_units')
    arc_raw = command(['/bin/systemctl', 'show', 'arc_cmd_helper.service',
                       '-p', 'Id,LoadState,Type,ActiveState,Result,ExecMainStatus'])
    arc = dict(line.split('=', 1) for line in arc_raw.splitlines() if '=' in line)
    require(arc.get('LoadState') == 'not-found' or (arc.get('Result') == 'success'
            and arc.get('ExecMainStatus') == '0' and (arc.get('ActiveState') == 'active'
            or (arc.get('Type') == 'oneshot' and arc.get('ActiveState') == 'inactive'))), 'arc_contract')
    docker_rows = command(['/usr/bin/docker', 'inspect', '--format',
                           '{{.Id}} {{.Name}} {{.State.Running}} {{.State.Status}} {{.State.StartedAt}} {{.RestartCount}}',
                           *CONTAINERS]).splitlines()
    containers = []
    for line in docker_rows:
        parts = line.split()
        require(len(parts) == 6 and parts[2] == 'true' and parts[3] == 'running', 'native_docker_state')
        containers.append({'id': parts[0], 'name': parts[1].lstrip('/'), 'running': True,
                           'status': parts[3], 'started_at': parts[4], 'restart_count': int(parts[5])})
    require(len(containers) == 3 and {item['name'] for item in containers} == set(CONTAINERS),
            'native_docker_three')
    owners = set()
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            if (process / 'comm').read_text().strip() != 'tee-supplicant':
                continue
            for fd in (process / 'fd').iterdir():
                try:
                    if os.readlink(fd) == '/dev/teepriv0':
                        owners.add(int(process.name))
                except OSError:
                    pass
        except OSError:
            pass
    require(len(owners) == 1, 'actual_tee_owner_count')
    return {'pass': True, 'kernel': KERNEL, 'root_source': root[0], 'root_uuid': root[1],
            'home_source': home[0], 'home_uuid': home[1], 'mandatory_units': units,
            'arc_cmd_helper': arc, 'original_containers': containers, 'tee_owners': sorted(owners),
            'modules_readonly': True, 'modules_bind_source': str(cohort / 'modules'),
            'cgroup_hierarchy': 'v1', 'thp_policy': thp}


def status(folder, row, name='status.json'):
    target = folder / name
    temp = folder / (name + '-' + str(os.getpid()) + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(row, out, sort_keys=True)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, target)


def enabled(cohort, nonce, plan_sha256):
    path = cohort / 'enable-default.json'
    if not path.exists() and not path.is_symlink():
        return False
    value = json.loads(private_file(path, 1024))
    require(value == {'schema': 1, 'deployment_nonce': nonce, 'plan_sha256': plan_sha256},
            'enable_marker_binding')
    return True


def deadline_signal(signum, frame):
    raise RuntimeError('health_deadline_300s')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    require(os.geteuid() == 0, 'requires_root')
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch('[0-9a-f-]{36}', boot_id), 'boot_id')
    folder = Path('/run/leon-production')
    require(folder.is_dir() and not folder.is_symlink()
            and folder.stat().st_uid == 0 and stat.S_IMODE(folder.stat().st_mode) == 0o700,
            'private_runtime')
    private_file(folder / 'boot-id', 128)
    require((folder / 'boot-id').read_text().strip() == boot_id, 'bootstrap_boot_id')
    # A finished deferred run releases this lock, allowing one later enable run.
    # The same lock rejects concurrently running health/re-arm owners.
    owner_fd = os.open(folder / 'health-owner.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    owner_stat = os.fstat(owner_fd)
    require(stat.S_ISREG(owner_stat.st_mode) and owner_stat.st_uid == 0 and owner_stat.st_nlink == 1
            and stat.S_IMODE(owner_stat.st_mode) == 0o600, 'health_owner_permissions')
    fcntl.flock(owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    row = {'schema': 1, 'boot_id': boot_id, 'pid': os.getpid(), 'status': 'HEALTH_PENDING',
           'armed': False, 'automatic_bounded_cold_recovery': False, 'stock_next_boot_verified': False}
    status(folder, row)
    signal.signal(signal.SIGALRM, deadline_signal)
    signal.alarm(300)
    fallback = None
    writing = False
    try:
        raw = private_file(args.plan, 32768)
        require(re.fullmatch('[0-9a-f]{64}', args.plan_sha256)
                and hashlib.sha256(raw).hexdigest() == args.plan_sha256, 'embedded_plan_digest')
        plan = json.loads(raw)
        cohort, environment = plan_check(plan, args.plan, args.plan_sha256)
        fallback = dict(environment, bootcmd='bootmmc', bootcount='0', upgrade_available='0')
        require(Path(__file__) == cohort / 'post-health.py', 'post_health_path')
        private_file(Path(__file__), 65536)
        row.update(cohort=str(cohort), deployment_nonce=plan['deployment_nonce'], plan_sha256=args.plan_sha256)
        integrity(plan, cohort)
        require(Path('/usr/bin/fw_setenv').resolve() == Path('/usr/bin/fw_printenv').resolve(),
                'environment_tool_route')
        for filename, digest in TOOL_HASHES.items():
            path = Path(filename)
            st = path.stat()
            require(st.st_uid == 0 and not st.st_mode & 0o022, 'environment_tool_permissions')
            require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'environment_tool_digest')
        with open('/dev/mmcblk0p17', 'rb') as src:
            src.seek(4096)
            require(src.read(32).hex() == '0041424202000302000000080200000000000000000000000000000000000000',
                    'stock_B_metadata')
        while True:
            uptime = float(Path('/proc/uptime').read_text().split()[0])
            if uptime >= 90:
                break
            time.sleep(min(1.0, 90.0 - uptime))
        row['native_health'] = health(cohort)
        row['native_health'].update(cohort_verified=True, module_files_verified=plan['module_file_count'],
                                    cohort_files_verified=sorted(plan['files']))
        row['active_serial_before'] = verify_selected(fallback)
        row.update(stock_next_boot_verified=True, both_env_crc_valid=True)
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id, 'boot_changed')
        row.update(status='READY_SAVED_STOCK', uptime_seconds=uptime)
        status(folder, row, 'ready.json')
        if not enabled(cohort, plan['deployment_nonce'], args.plan_sha256):
            signal.alarm(0)
            status(folder, row)
            return 0
        row.update(status='HEALTH_ACCEPTED_WRITE_PENDING', enable_marker_verified=True)
        status(folder, row)
        # Health deadline ends here. Never timeout/terminate redundant ENV storage.
        signal.alarm(0)
        writing = True
        row['active_serial_after'] = store_environment(folder, 'arm.env', environment)
        row.update(status='ARMED', armed=True, both_env_crc_valid=True,
                   stock_next_boot_verified=False, bootcmd='run leon_ramtrial')
        status(folder, row)
        status(folder, row, 'rearmed.json')
        return 0
    except Exception as exc:
        signal.alarm(0)
        row.update(status='REJECTED', error=type(exc).__name__ + ':' + str(exc)[:300])
        if writing:
            row.update(status='ENV_WRITE_FAILED', stock_next_boot_verified=False)
            try:
                row['restore_serial'] = store_environment(folder, 'restore-stock.env', fallback)
                row.update(stock_next_boot_verified=True, both_env_crc_valid=True, armed=False)
            except Exception as restore_error:
                row['restore_error'] = type(restore_error).__name__ + ':' + str(restore_error)[:300]
        elif fallback is not None:
            try:
                verify_selected({'bootcmd': 'bootmmc', 'altbootcmd': 'bootmmc'})
                row.update(stock_next_boot_verified=True, both_env_crc_valid=True)
            except Exception as verify_error:
                row['fallback_verify_error'] = type(verify_error).__name__ + ':' + str(verify_error)[:300]
        status(folder, row)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

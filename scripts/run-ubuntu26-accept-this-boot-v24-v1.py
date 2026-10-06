#!/usr/bin/env python3
"""Bounded, explicitly trusted SSH/sudo transport for V24 kernel11 current-boot acceptance.
Accepts this exact healthy boot only after both logins, targeted same-boot Docker proof and unchanged client installation ancestry; no permanent CFE commit, ACK or service action.
Password exists only in process memory and SSH stdin; no PTY, argv/env/log secret.
"""
import argparse
import base64
import getpass
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = ROOT / 'scripts/asus-integration/accepted-guard/accept-this-boot-v24-v1.sh'
SOURCE_SHA = '53690ede2b1d8a3115c462bfb53880087ae0619b834be2a58aec8c90b3c06932'
PRIMARY = ('evidence/ubuntu26/trial-live/twentyfourth-primary-readonly-v1/result.json', '140a85f2d206a4a8ccbd0938b3e6081e3ab4f47145231cc07c5b49e6b4b4eeac')
PRIMARY_STDOUT = ('evidence/ubuntu26/trial-live/twentyfourth-primary-readonly-v1/stdout', '232c2da32762527af9af0949ad1a1007927582d05b926e70cb28750f107b6f90')
BACKUP = ('evidence/ubuntu26/trial-live/twentyfourth-uplink-backup/result.json', '437513c2b729df5e48f7c1f0d9689513149d41a3442a409b025d5f5be6043c3c')
COMPLETION = b'CURRENT_BOOT_ACCEPT_END same_boot=true accepted_this_boot=true metadata_committed=2 permanent=false'
SMOKE = ('evidence/ubuntu26/docker-repair-v1/docker-container-smoke-v3/result.json', '08bfedfb9145a6934ec217956d431cbe6e2082cdc7703ca20ec46cf13c220d97')
SMOKE_CAPTURE = ('evidence/ubuntu26/docker-repair-v1/docker-container-smoke-v3/capture.txt', '0ac636ce29ee590655989dcfeb90078be34015503d5a231737316e9b588b165f')
SMOKE_SOURCE_SHA = '2eb3cd67ed5712c863c973083737684554600d4f88773b02d9c883cb7e184a70'
PROBE_SHA = 'e614d0efe0a5acd827b2890a0f1b299b871cf9fad20849ceebbbf56fdf39eab3'
KNOWN_HOSTS = ROOT / 'evidence/ubuntu26/device-identity-live/ubuntu-known_hosts'
KNOWN_HOSTS_SHA = '4238c5cc4ce2c7363eb491894192d7a926eaf1165a03b135b9621ea47ee922a7'
CLIENT_INSTALL = ('evidence/ubuntu26/trial-live/twentysecond-accept-client-install-v1/result.json', '0bc408e1e516ad63b5c1d9c7aca68df80cb014c720a769dceab039fed6783468')
STOCK_BOOT = '00000000-0000-4000-8000-000000000004'
MAX_OUTPUT = 196608

class Refused(Exception):
    pass

def require(condition, reason):
    if not condition:
        raise Refused(reason)

def trusted_file(path, max_size):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid in (0, os.getuid()) and not st.st_mode & 0o022,
                'unsafe_local_file_owner_or_mode')
        require(0 < st.st_size <= max_size, 'local_file_size_out_of_bounds')
        data = os.read(fd, max_size + 1)
        require(len(data) == st.st_size, 'local_file_changed_or_truncated')
        return data
    finally:
        os.close(fd)

def proof_bytes(row, maximum):
    require(row[1] is not None, 'both_actual_login_proof_pins_pending')
    raw = trusted_file(ROOT / row[0], maximum)
    require(hashlib.sha256(raw).hexdigest() == row[1], 'actual_login_proof_hash_mismatch')
    return raw

def verified_login_proofs(expected):
    boot = str(uuid.UUID(expected))
    primary = json.loads(proof_bytes(PRIMARY, 65536))
    raw = proof_bytes(PRIMARY_STDOUT, MAX_OUTPUT).decode('utf-8', errors='strict')
    require(primary['status'] == 'actual_native_primary_login_verified' and primary['native_boot_id'] == boot
            and primary['returncode'] == 0 and primary['ack_sent'] is False and primary['settings_changed'] is False
            and primary['source'] == '192.168.100.35' and primary['destination'] == '192.168.100.15:22'
            and primary['host_key_sha256_hex'] == '208b0e8d4a18194d0da78a722eed6b361ccce51f3a3643a9575c4f3c50c04db3'
            and primary['strict_pre_enrolled_native_host_key'] is True
            and primary['native_pid1'] == 'systemd' and primary['native_uid'] == 0
            and primary['root_writable'] is True and primary['root_uuid'] == 'ea8e47b8-c606-406c-b931-d2244d26ec55'
            and primary['kernel_release'] == '4.19.294' and primary['kernel_build_prefix'] == '#11 ',
            'actual_primary_native_login_required')
    lines = raw.splitlines()
    require(lines[0] == 'BOOT=' + boot and 'PID1=systemd' in lines
            and lines.count('PID1=systemd') == 1
            and lines.count('/dev/mmcblk0p11 ext4 ea8e47b8-c606-406c-b931-d2244d26ec55') == 1
            and lines.count('KERNEL_RELEASE=4.19.294') == 1
            and lines.count('KERNEL_VERSION=#11 SMP PREEMPT Sat Oct 3 12:00:00 UTC 2026') == 1,
            'primary_same_boot_native_context_required')
    backup = json.loads(proof_bytes(BACKUP, 65536))
    require(backup['status'] == 'actual_native_uplink_backup_login_verified' and backup['native_boot_id'] == boot
            and backup['source'] == '169.254.190.51' and backup['peer'] == '169.254.190.15' and backup['port'] == 2223
            and backup['neighbor_mac'] == backup['expected_ethernet_mac'] == '02:00:00:f0:00:01'
            and backup['ssh_source_and_destination_verified'] is True and backup['strict_pre_enrolled_native_host_key'] is True
            and backup['native_uid'] == 1000 and backup['native_pid1'] == 'systemd' and backup['root_fstype'] == 'ext4'
            and backup['network_configuration_changed'] is False and backup['ack_sent'] is False and backup['boot_accepted'] is False,
            'actual_same_boot_strict_backup_login_required')
    smoke = json.loads(proof_bytes(SMOKE, 65536))
    captured = proof_bytes(SMOKE_CAPTURE, MAX_OUTPUT)
    require(type(smoke['returncode']) is int and smoke['returncode'] == 0 and smoke['root'] is True
            and smoke['script_sha256'] == SMOKE_SOURCE_SHA
            and smoke['capture_sha256'] == SMOKE_CAPTURE[1] == hashlib.sha256(captured).hexdigest()
            and smoke['upload']['sha256'] == PROBE_SHA
            and re.fullmatch(r'/var/tmp/leon-development-upload\.[A-Za-z0-9]{8}/archive\.deb', smoke['upload']['remote']),
            'actual_targeted_docker_smoke_source_capture_and_probe_required')
    smoke_lines = captured.decode('utf-8', errors='strict').splitlines()
    require(smoke_lines.count('DOCKER_CONTAINER_CGROUP2_NETWORK_DEVICE_FILTER_PASSED boot=' + boot) == 1
            and smoke_lines.count('CONTAINER_EXEC_OK') == 1
            and smoke_lines.count('CONTAINER_NETWORK_AND_LIMITS_OK') == 1,
            'unique_actual_same_boot_docker_limits_network_and_device_completion_required')
    identities = {}
    for phase in ('BEFORE', 'AFTER'):
        prefix = 'ASUS_SMOKE_IDENTITY_' + phase + ' '
        matches = [line for line in smoke_lines if line.startswith(prefix)]
        require(len(matches) == 1, 'one_actual_broker_rc_lifetime_marker_per_phase_required')
        identity = re.fullmatch(prefix + r'broker=([1-9][0-9]*) start=([1-9][0-9]*) rc=([1-9][0-9]*) start=([1-9][0-9]*) same_private_namespace=true carrier=1 speed=10000 forwarding=3 modules=dhd,hnd', matches[0])
        require(identity is not None, 'canonical_broker_rc_and_physical_network_module_point_proof_required')
        identities[phase] = identity.groups()
    require(identities['BEFORE'] == identities['AFTER'] and identities['BEFORE'][0] != identities['BEFORE'][2],
            'same_actual_broker_and_direct_rc_pid_starttime_before_after_required')
    installed = json.loads(proof_bytes(CLIENT_INSTALL, 65536))
    # Historical package installation is ancestry only. The current device-side
    # acceptance body independently verifies exact root-owned client bytes.
    require(installed['status'] == 'snapshot_collected' and installed['remote_exit_code'] == 0
            and installed['snapshot_complete'] is True
            and installed['observed_boot'] == '00000000-0000-4000-8000-000000000027'
            and installed['guardian_ack_sent'] is False and installed['boot_accepted'] is False,
            'unchanged_inert_client_package_install_ancestry_required')
    return boot

def choose_boot(observed, expected):
    try:
        boot = str(uuid.UUID(observed.strip()))
    except ValueError:
        raise Refused('invalid_remote_boot_uuid') from None
    require(boot != STOCK_BOOT, 'still_known_stock2_boot')
    if expected != 'not-stock':
        require(boot == str(uuid.UUID(expected)), 'unexpected_boot_uuid')
    return boot

def capture(transport, command, deadline, stdin=b'', limit=MAX_OUTPUT):
    channel = transport.open_session(timeout=min(5, max(0.1, deadline-time.monotonic())))
    channel.settimeout(3)
    output = bytearray()
    errors = bytearray()
    try:
        channel.exec_command(command)
        if stdin:
            channel.sendall(stdin)
        channel.shutdown_write()
        while True:
            require(time.monotonic() < deadline, 'ssh_command_deadline')
            progressed = False
            for ready, recv, dst in ((channel.recv_ready, channel.recv, output),
                                     (channel.recv_stderr_ready, channel.recv_stderr, errors)):
                while ready():
                    require(time.monotonic() < deadline, 'ssh_command_deadline')
                    chunk = recv(4096)
                    if not chunk:
                        break
                    dst.extend(chunk)
                    require(len(output)+len(errors) <= limit, 'ssh_output_limit')
                    progressed = True
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                return channel.recv_exit_status(), bytes(output), bytes(errors)
            if not progressed:
                time.sleep(0.02)
    finally:
        channel.close()

def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())

def command_for(source, boot):
    return ' '.join(shlex.quote(x) for x in [
        '/usr/bin/sudo', '-S', '-p', '', '/usr/bin/env', '-i',
        'PATH=/usr/sbin:/usr/bin', 'LC_ALL=C',
        '/usr/bin/timeout', '--signal=TERM', '--kill-after=2s', '65s',
        '/bin/bash', '--noprofile', '--norc', '-c', source.decode('utf-8'),
        'leon-readonly-acceptance', boot])

def main():
    if not __debug__:
        raise RuntimeError('python -O is not permitted')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True, help='literal IPv4/IPv6 address')
    p.add_argument('--source-ip', help='optional literal local IP to bind the trusted SSH transport')
    p.add_argument('--port', type=int, default=22)
    p.add_argument('--username', default='MastermixStudios')
    p.add_argument('--known-hosts', type=Path, required=True, help='explicit trusted public keys, no TOFU')
    p.add_argument('--password', action='store_true', required=True, help='prompt using getpass; never takes a value')
    p.add_argument('--expected-boot', required=True, help='exact UUID, or not-stock (pin fresh observed UUID throughout)')
    p.add_argument('--source', type=Path, default=DEFAULT_SCRIPT)
    p.add_argument('--source-sha256', required=True, help='hash of the reviewed device-side source')
    p.add_argument('--output', type=Path, required=True, help='new private local directory, must not exist')
    a = p.parse_args()
    require(a.expected_boot != 'not-stock', 'exact_same_boot_required_after_both_logins')
    verified_login_proofs(a.expected_boot)
    require(a.source.resolve() == DEFAULT_SCRIPT and a.source_sha256 == SOURCE_SHA, 'fixed_v24_current_boot_accept_source_required')
    require(a.host == '192.168.100.15' and a.source_ip == '192.168.100.35' and a.port == 22
            and a.username == 'MastermixStudios', 'fixed_primary_native_acceptance_transport_required')
    target_address = ipaddress.ip_address(a.host)
    if a.source_ip:
        require(ipaddress.ip_address(a.source_ip).version == target_address.version,
                'source_and_target_ip_family_mismatch')
    require(1 <= a.port <= 65535, 'invalid_port')
    require(re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_-]{0,31}', a.username), 'invalid_username')
    require(re.fullmatch(r'[a-f0-9]{64}', a.source_sha256), 'invalid_source_hash')
    if a.expected_boot != 'not-stock':
        require(str(uuid.UUID(a.expected_boot)) != STOCK_BOOT, 'expected_boot_is_stock')
    source = trusted_file(a.source, 65536)
    require(hashlib.sha256(source).hexdigest() == a.source_sha256, 'source_hash_mismatch')
    trust = trusted_file(a.known_hosts, 1048576)
    require(a.known_hosts.resolve() == KNOWN_HOSTS and hashlib.sha256(trust).hexdigest() == KNOWN_HOSTS_SHA,
            'fixed_pre_enrolled_native_known_hosts_required')
    os.umask(0o077)
    a.output.mkdir(mode=0o700)
    # Evidence preserves exact nonsecret source and trust hashes, not credentials.
    write_private(a.output/'device-source.sh', source)
    result = {'schema':1, 'status':'not_connected', 'read_only':False,
              'host':a.host, 'port':a.port, 'username':a.username,
              'source_ip':a.source_ip,
              'source_sha256':a.source_sha256,
              'prerequisite_proofs':{'primary':PRIMARY,'primary_stdout':PRIMARY_STDOUT,'backup':BACKUP,
                                     'targeted_docker':SMOKE,'targeted_docker_capture':SMOKE_CAPTURE,
                                     'client_install_ancestry_only':CLIENT_INSTALL},
              'known_hosts_sha256':hashlib.sha256(trust).hexdigest(),
              'expected_boot':a.expected_boot, 'forbidden_stock_boot':STOCK_BOOT,
              'total_deadline_seconds':95, 'remote_deadline_seconds':65,
              'stdout_stderr_limit_bytes':MAX_OUTPUT,
              'services_changed':False, 'guardian_ack_sent':False, 'boot_accepted':None, 'boot_acceptance_intended':True, 'permanent_boot_commit':False}
    client = None; sock = None; timer = None
    started = time.monotonic()
    try:
        import paramiko
        keys = paramiko.HostKeys()
        for line in trust.decode('ascii').splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            entry = paramiko.hostkeys.HostKeyEntry.from_line(line)
            require(entry is not None, 'invalid_known_hosts_line')
            for hostname in entry.hostnames:
                keys.add(hostname, entry.key.get_name(), entry.key)
        host_label = a.host if a.port == 22 else f'[{a.host}]:{a.port}'
        require(keys.lookup(host_label) is not None, 'host_absent_from_explicit_trust')
        password = getpass.getpass('Ubuntu SSH and sudo password (memory only): ')
        require(password and '\n' not in password and '\r' not in password and len(password.encode()) <= 1024,
                'invalid_password_input')
        # Start wall deadline after the human prompt; all network actions are covered.
        started = time.monotonic(); deadline = started + 95
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        for hostname in keys:
            for kind, key in keys[hostname].items(): client.get_host_keys().add(hostname, kind, key)
        logger = logging.getLogger('leon_acceptance.ssh'); logger.handlers=[logging.NullHandler()]; logger.propagate=False
        client.set_log_channel('leon_acceptance.ssh')
        sock = socket.socket(socket.AF_INET6 if ':' in a.host else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        def close_transport():
            try: client.close()
            except Exception: pass
            try: sock.close()
            except Exception: pass
        timer = threading.Timer(95, close_transport); timer.daemon=True; timer.start()
        if a.source_ip:
            sock.bind((a.source_ip,0))
        sock.connect((a.host,a.port))
        client.connect(a.host, port=a.port, username=a.username, sock=sock, password=password,
                       timeout=8, banner_timeout=8, auth_timeout=8, look_for_keys=False, allow_agent=False,
                       gss_auth=False, gss_kex=False)
        transport = client.get_transport()
        key = transport.get_remote_server_key()
        result['server_public_fingerprint']='SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        code, out, err = capture(transport, '/usr/bin/id -u', min(deadline,time.monotonic()+5),limit=4096)
        require(code == 0 and out.strip() == b'1000', 'ssh_identity_not_native_uid1000')
        code, out, err = capture(transport, '/usr/bin/cat /proc/sys/kernel/random/boot_id', min(deadline,time.monotonic()+5),limit=4096)
        require(code == 0, 'boot_read_failed')
        boot = choose_boot(out.decode('ascii'), a.expected_boot)
        result['observed_boot']=boot
        code, out, err = capture(transport, command_for(source, boot), deadline,
                                stdin=(password+'\n').encode())
        # The commands cannot access the password; also suppress accidental secret reflection.
        secret=password.encode(); out=out.replace(secret,b'[REDACTED]') if secret else out
        result.update({'remote_exit_code':code, 'stdout_bytes':len(out), 'stderr_bytes':len(err),
                       'stderr_sha256':hashlib.sha256(err).hexdigest()})
        password=None; secret=None
        write_private(a.output/'capture.txt',out)
        result['capture_sha256']=hashlib.sha256(out).hexdigest()
        result['snapshot_complete']=code == 0 and out.splitlines().count(COMPLETION) == 1
        result['checks']=[line for line in out.decode('utf-8',errors='replace').splitlines() if line.startswith('CHECK ')]
        result['status']='snapshot_collected' if result['snapshot_complete'] else 'incomplete_or_refused'
        result['functional_acceptance']=False
        result['boot_accepted']=True if result['snapshot_complete'] else None
        result['not_proven']='Physical/user-observable functions and permanent boot acceptance remain separate.'
    except Exception as e:
        # Never serialize exception messages from authentication/subprocesses.
        result['status']='refused_or_transport_failed'
        result['error']=str(e) if isinstance(e,Refused) else type(e).__name__
    finally:
        if timer: timer.cancel()
        if client: client.close()
        if sock: sock.close()
        result['elapsed_seconds']=round(time.monotonic()-started,3)
        write_private(a.output/'result.json',(json.dumps(result,indent=2)+'\n').encode())
    print(json.dumps({'status':result['status'],'result':str(a.output/'result.json')},sort_keys=True))
    return 0 if result['status']=='snapshot_collected' and result.get('remote_exit_code')==0 else 1

if __name__=='__main__':
    try:
        sys.exit(main())
    except Refused as e:
        print('refused: '+str(e),file=sys.stderr);sys.exit(2)

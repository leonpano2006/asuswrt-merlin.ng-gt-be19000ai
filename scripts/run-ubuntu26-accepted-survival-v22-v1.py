#!/usr/bin/env python3
"""Source-only V22 before/after accepted-current-boot survival snapshots.
All future proof pins fail closed. Reuses strict read-only SSH/sudo transport;
no upload, WDT access, service action, ACK, acceptance or permanent commit.
Password exists only in memory/SSH stdin; no PTY or logged secret.
"""
import argparse
import importlib.util
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
sys.dont_write_bytecode = True
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = ROOT / 'scripts/asus-integration/accepted-guard/survival-readonly-v22-v1.sh'
SOURCE_SHA = 'f0fe7310d226fef1ad765781e373587b1c124971edc6e89ac997e6421677662e'
PRIMARY = ('evidence/ubuntu26/trial-live/twentysecond-primary-readonly-v1/result.json', None)
PRIMARY_STDOUT = ('evidence/ubuntu26/trial-live/twentysecond-primary-readonly-v1/stdout', None)
BACKUP = ('evidence/ubuntu26/trial-live/twentysecond-uplink-backup/result.json', None)
ACCEPTANCE = ('evidence/ubuntu26/trial-live/twentysecond-current-boot-accept-v1/result.json', None)
BEFORE = ('evidence/ubuntu26/trial-live/twentysecond-accepted-survival-before-v1/result.json', None)
OBSERVER_STOP = ('evidence/ubuntu26/trial-live/twentysecond-observer-stop-v1/result.json', None)
OBSERVER_SOURCE_SHA = 'abaf531c5b91822401097cdf1128f56ea9e8d9f05429acbad9d2609d07035ee0'
PARSER = ('scripts/asus-integration/boot-diagnostics/parse.py', 'f3693a5ef4c2cd32f72a2b173c166daaa0a0de4b9b7ae3a5869ba1c944a99082')
NATIVE31 = ('build/asus-trial-runtime/native-v31-accepted-this-boot/manifest.json', '1ef66bfa5950fb2a0aed7afd2d592ab7af8e259f82eeb6e2e29e173568b89ab8')
BUILD_ID = 'db073b0093c879ef60d4cb4cbbdf14df9bf678260b0f1f9ec34de094e15386e7'
COMPLETION = b'ACCEPTED_SURVIVAL_END same_boot=true accepted_this_boot=true same_guardian=true same_watchdog_fd=true read_only=true no_ack=true'
STOCK_BOOT = '00000000-0000-4000-8000-000000000035'
OUTPUTS = {phase: ROOT / ('evidence/ubuntu26/trial-live/twentysecond-accepted-survival-' + phase + '-v1') for phase in ('before', 'after')}
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
    require(primary['returncode'] == 0 and primary['ack_sent'] is False and primary['settings_changed'] is False
            and primary['source'] == '192.168.100.35' and primary['destination'] == '192.168.100.15:22'
            and primary['host_key_sha256_hex'] == '208b0e8d4a18194d0da78a722eed6b361ccce51f3a3643a9575c4f3c50c04db3',
            'actual_primary_native_login_required')
    lines = raw.splitlines()
    require(lines[0] == 'BOOT=' + boot and 'PID1=systemd' in lines
            and '/dev/mmcblk0p11 ext4 ea8e47b8-c606-406c-b931-d2244d26ec55' in lines,
            'primary_same_boot_native_context_required')
    backup = json.loads(proof_bytes(BACKUP, 65536))
    require(backup['status'] == 'actual_native_uplink_backup_login_verified' and backup['native_boot_id'] == boot
            and backup['source'] == '169.254.190.51' and backup['peer'] == '169.254.190.15' and backup['port'] == 2223
            and backup['neighbor_mac'] == backup['expected_ethernet_mac'] == '02:00:00:f0:00:01'
            and backup['ssh_source_and_destination_verified'] is True and backup['strict_pre_enrolled_native_host_key'] is True
            and backup['native_uid'] == 1000 and backup['native_pid1'] == 'systemd' and backup['root_fstype'] == 'ext4'
            and backup['network_configuration_changed'] is False and backup['ack_sent'] is False and backup['boot_accepted'] is False,
            'actual_same_boot_strict_backup_login_required')
    return boot

def local_ref(path):
    raw = trusted_file(path, MAX_OUTPUT)
    return {'path':str(path.relative_to(ROOT)), 'sha256':hashlib.sha256(raw).hexdigest(), 'bytes':len(raw)}

def pinned_capture(receipt):
    path = ROOT / receipt['capture_path'] if 'capture_path' in receipt else None
    # Existing strict transports use sibling capture.txt and capture_sha256.
    require(path is None, 'unexpected_alternate_capture_path')
    return receipt['capture_sha256']

def acceptance_proof(boot):
    raw = proof_bytes(ACCEPTANCE,65536); receipt=json.loads(raw)
    require(receipt['status']=='snapshot_collected' and receipt['remote_exit_code']==0
            and receipt['snapshot_complete'] is True and receipt['observed_boot']==boot
            and receipt['source_sha256']=='6139685fd5465591b9f1475ca544449d98df3a50d2cd69ae23eb19a61876aedf'
            and receipt['guardian_ack_sent'] is False and receipt['boot_accepted'] is True
            and receipt['boot_acceptance_intended'] is True and receipt['permanent_boot_commit'] is False,
            'actual_same_boot_current_acceptance_required')
    capture_path=(ROOT/ACCEPTANCE[0]).with_name('capture.txt')
    captured=trusted_file(capture_path,MAX_OUTPUT)
    require(hashlib.sha256(captured).hexdigest()==pinned_capture(receipt),'actual_acceptance_capture_hash')
    lines=captured.decode('utf-8',errors='strict').splitlines()
    for text in ['LEON_ACCEPT_STATUS boot_id='+boot+' accepted_this_boot=0 metadata_committed=2',
                 'LEON_ACCEPT_THIS_BOOT_OK boot_id='+boot+' same_owner=true metadata_committed=2',
                 'LEON_ACCEPT_STATUS boot_id='+boot+' accepted_this_boot=1 metadata_committed=2',
                 'CURRENT_BOOT_ACCEPT_END same_boot=true accepted_this_boot=true metadata_committed=2 permanent=false']:
        require(lines.count(text)==1,'exact_actual_acceptance_marker_required')
    return {'receipt':local_ref(ROOT/ACCEPTANCE[0]),'capture':local_ref(capture_path)}

def host_boot_id():
    with open('/proc/sys/kernel/random/boot_id','rb') as stream: raw=stream.read(65)
    require(len(raw)==37,'local_host_boot_uuid_length')
    return str(uuid.UUID(raw.decode('ascii').strip()))

def phase_proofs(phase,boot):
    accepted=acceptance_proof(boot)
    before=stop=None
    if phase=='after':
        before=json.loads(proof_bytes(BEFORE,MAX_OUTPUT))
        require(before['status']=='accepted_current_boot_survival_before_verified'
                and before['observed_boot']==boot and before['remote_exit_code']==0
                and before['snapshot_complete'] is True and before['read_only'] is True
                and before['source_sha256']==SOURCE_SHA and before['acceptance_proof']==accepted,
                'actual_before_snapshot_required')
        capture=trusted_file((ROOT/BEFORE[0]).with_name('capture.txt'),MAX_OUTPUT)
        require(hashlib.sha256(capture).hexdigest()==before['capture_sha256'],'actual_before_capture_hash')
        stop=json.loads(proof_bytes(OBSERVER_STOP,MAX_OUTPUT))
        require(stop['schema']==1 and stop['status']=='observer_stopped_and_reaped_no_further_ack'
                and stop['native_boot_id']==boot and stop['observer_stopped'] is True and stop['observer_reaped'] is True
                and stop['observer_source_sha256']==OBSERVER_SOURCE_SHA
                and stop['host_boot_id']==before['host_boot_id']==host_boot_id(),
                'actual_same_host_observer_stop_reap_required')
        ticks=stop['stopped_monotonic_ns']
        require(type(ticks) is int and ticks>=before['completed_monotonic_ns']
                and time.monotonic_ns()-ticks>100_000_000_000,'observer_free_100_seconds_not_yet_observed')
        log_path=ROOT/stop['observer_log']['path'];log=trusted_file(log_path,MAX_OUTPUT)
        require(local_ref(log_path)==stop['observer_log'],'actual_final_observer_log_hash')
        events=[json.loads(line) for line in log.decode('utf-8').splitlines()]
        require(events and events[-1]['event']=='observer_stopped' and events[-1]['boot_id']==boot
                and events[-1]['permanent_acceptance'] is False and events[-1]['acknowledgements']>0
                and events[-1]['last_sequence']>0,'actual_final_observer_stopped_event_required')
        before['saved_receipt_ref']=local_ref(ROOT/BEFORE[0]);stop['saved_receipt_ref']=local_ref(ROOT/OBSERVER_STOP[0])
    return accepted,before,stop

def diagnostic_parser():
    require(hashlib.sha256(trusted_file(ROOT/PARSER[0],65536)).hexdigest()==PARSER[1],'frozen_crc_parser_required')
    native=json.loads(trusted_file(ROOT/NATIVE31[0],65536))
    require(hashlib.sha256((ROOT/NATIVE31[0]).read_bytes()).hexdigest()==NATIVE31[1]
            and native['diagnostic_build_id']==BUILD_ID,'actual_native31_diagnostic_build_binding')
    spec=importlib.util.spec_from_file_location('fixed_survival_diag_parser',ROOT/PARSER[0])
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def validate_capture(raw,phase,boot):
    lines=raw.decode('utf-8',errors='strict').splitlines()
    require(lines.count(COMPLETION.decode())==1 and lines.count('SURVIVAL_BEGIN phase='+phase+' boot_id='+boot)==1
            and lines.count('LEON_ACCEPT_STATUS boot_id='+boot+' accepted_this_boot=1 metadata_committed=2')==1,
            'exact_same_boot_accepted_snapshot_required')
    def field(name,pattern):
        rows=[line[len(name)+1:] for line in lines if line.startswith(name+'=')]
        require(len(rows)==1 and re.fullmatch(pattern,rows[0]),'snapshot_field_'+name)
        return rows[0]
    values={name:int(field(name,r'[0-9]+')) for name in ('GUARDIAN_PID','GUARDIAN_STARTTIME','WATCHDOG_FD','CURRENT_BOOTTIME_MS')}
    require(values['GUARDIAN_PID']>1 and values['GUARDIAN_STARTTIME']>0,'guardian_identity')
    values['WATCHDOG_ID']=field('WATCHDOG_ID',r'[0-9]+:[0-9]+:[0-9a-f]+:[0-9a-f]+')
    values['DIAGNOSTIC_ID']=field('DIAGNOSTIC_ID',r'[0-9]+:[0-9]+')
    encoded=field('DIAGNOSTIC_BASE64',r'[A-Za-z0-9+/]+==')
    require(len(encoded)==21848,'fixed_diagnostic_base64_length')
    data=base64.b64decode(encoded,validate=True);require(len(data)==16384,'fixed_diagnostic_length')
    parser=diagnostic_parser()
    slots=[parser.record(data[index*8192:(index+1)*8192],index) for index in (0,1)]
    require(all(row['status']=='valid' and row['boot_id']==boot and row['build_sha256']==BUILD_ID for row in slots),
            'both_crc_records_exact_boot_build_required')
    record=slots[1];payload={}
    for line in record['payload'].splitlines():
        require('=' in line,'diagnostic_payload_shape');key,value=line.split('=',1)
        require(re.fullmatch('[a-z_]+',key) and key not in payload,'diagnostic_payload_unique_keys');payload[key]=value
    require(payload.get('producer')=='guardian' and payload.get('first_failure')=='none','unfailed_guardian_record')
    numeric=('monotonic_ms','handed','failed','last_successful_keepalive_ms','lan_sequence',
             'worker_pid','worker_started_ms','worker_failed','worker_have_result','worker_bits',
             'worker_wait_status_valid','worker_raw_wait_status','worker_killed',
             'metadata_worker_pid','metadata_worker_started_ms','metadata_worker_failed','metadata_worker_have_result',
             'metadata_worker_result','metadata_worker_wait_status_valid','metadata_worker_raw_wait_status','metadata_worker_killed')
    state={}
    for name in numeric:
        require(name in payload and re.fullmatch(r'[0-9]{1,20}',payload[name]),'numeric_guardian_field_'+name)
        state[name]=int(payload[name]);require(state[name]<=2**64-1,'numeric_guardian_bound')
    for name,value in {'handed':1,'failed':0,'worker_pid':0,'worker_failed':0,'worker_have_result':1,
                       'worker_wait_status_valid':1,'worker_raw_wait_status':0,'worker_killed':0,
                       'metadata_worker_pid':0,'metadata_worker_failed':0,'metadata_worker_have_result':1,
                       'metadata_worker_result':1,'metadata_worker_wait_status_valid':1,'metadata_worker_raw_wait_status':0,
                       'metadata_worker_killed':0}.items():require(state[name]==value,'fresh_completed_guardian_'+name)
    require(state['worker_bits']>>8==7 and not(state['worker_bits']&~1799),'fresh_core7_required')
    now=values['CURRENT_BOOTTIME_MS'];stamp=state['monotonic_ms']
    # /proc/uptime rounds to centiseconds; allow at most20ms clock quantization.
    require(stamp<=now+20 and max(0,now-stamp)<=6500,'fresh_diagnostic_record_required')
    for key,ttl in [('last_successful_keepalive_ms',10000),('worker_started_ms',15000),('metadata_worker_started_ms',15000)]:
        require(0<state[key]<=stamp and max(0,now-state[key])<ttl,'fresh_guardian_'+key)
    values['guardian_record']=record;values['guardian_state']=state
    return values,data

def compare_after(current,before,stop):
    previous=before['survival_snapshot']
    for key in ('GUARDIAN_PID','GUARDIAN_STARTTIME','WATCHDOG_FD','WATCHDOG_ID','DIAGNOSTIC_ID'):
        require(current[key]==previous[key],'same_owner_descriptor_identity_'+key)
    require(current['CURRENT_BOOTTIME_MS']-previous['CURRENT_BOOTTIME_MS']>100000
            and current['guardian_record']['sequence']>previous['guardian_record']['sequence']
            and current['guardian_state']['last_successful_keepalive_ms']>previous['guardian_state']['last_successful_keepalive_ms']
            and current['guardian_state']['lan_sequence']==previous['guardian_state']['lan_sequence'],
            'observer_free_advancing_owner_keepalive_required')
    return (time.monotonic_ns()-stop['stopped_monotonic_ns'])/1e9

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

def command_for(source, boot, phase):
    return ' '.join(shlex.quote(x) for x in [
        '/usr/bin/sudo', '-S', '-p', '', '/usr/bin/env', '-i',
        'PATH=/usr/sbin:/usr/bin', 'LC_ALL=C',
        '/usr/bin/timeout', '--signal=TERM', '--kill-after=2s', '65s',
        '/bin/bash', '--noprofile', '--norc', '-c', source.decode('utf-8'),
        'leon-accepted-survival-readonly', boot, phase])

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
    p.add_argument('--output', type=Path, required=True, help='fixed new phase evidence directory')
    p.add_argument('--phase', required=True, choices=['before','after'])
    a = p.parse_args()
    require(a.expected_boot != 'not-stock', 'exact_same_boot_required_after_both_logins')
    verified_login_proofs(a.expected_boot)
    accepted,before,stop=phase_proofs(a.phase,str(uuid.UUID(a.expected_boot)))
    require(a.output.resolve()==OUTPUTS[a.phase],'fixed_exclusive_phase_output_required')
    require(a.source.resolve() == DEFAULT_SCRIPT and a.source_sha256 == SOURCE_SHA, 'fixed_v22_survival_source_required')
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
    os.umask(0o077)
    a.output.mkdir(mode=0o700)
    # Evidence preserves exact nonsecret source and trust hashes, not credentials.
    write_private(a.output/'device-source.sh', source)
    result = {'schema':1, 'status':'not_connected', 'read_only':True,
              'host':a.host, 'port':a.port, 'username':a.username,
              'source_ip':a.source_ip,
              'source_sha256':a.source_sha256,
              'known_hosts_sha256':hashlib.sha256(trust).hexdigest(),
              'expected_boot':a.expected_boot, 'forbidden_stock_boot':STOCK_BOOT,
              'total_deadline_seconds':95, 'remote_deadline_seconds':65,
              'stdout_stderr_limit_bytes':MAX_OUTPUT,
              'services_changed':False, 'guardian_ack_sent':False, 'boot_acceptance_requested':False,
              'acceptance_proof':accepted,'phase':a.phase,'host_boot_id':host_boot_id(),
              'before_receipt':None if before is None else before['saved_receipt_ref'],
              'observer_stop_receipt':None if stop is None else stop['saved_receipt_ref']}
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
        code, out, err = capture(transport, command_for(source, boot, a.phase), deadline,
                                stdin=(password+'\n').encode())
        # The commands cannot access the password; also suppress accidental secret reflection.
        secret=password.encode(); out=out.replace(secret,b'[REDACTED]') if secret else out
        result.update({'remote_exit_code':code, 'stdout_bytes':len(out), 'stderr_bytes':len(err),
                       'stderr_sha256':hashlib.sha256(err).hexdigest()})
        password=None; secret=None
        write_private(a.output/'capture.txt',out)
        result['capture_sha256']=hashlib.sha256(out).hexdigest()
        complete=code==0 and out.splitlines().count(COMPLETION)==1
        require(complete,'complete_readonly_snapshot_required')
        snapshot,diagnostic=validate_capture(out,a.phase,boot)
        if a.phase=='after':result['observer_free_elapsed_seconds']=compare_after(snapshot,before,stop)
        write_private(a.output/'diagnostics.bin',diagnostic)
        result.update(snapshot_complete=True,survival_snapshot=snapshot,accepted_this_boot=True,
                      diagnostic_sha256=hashlib.sha256(diagnostic).hexdigest(),
                      completed_monotonic_ns=time.monotonic_ns(),
                      status='accepted_current_boot_survival_'+a.phase+'_verified',
                      functional_acceptance=False,permanent_boot_commit=False,
                      not_proven='Point snapshots and observer-free survival; no permanent acceptance or watchdog-failure injection.')
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
    return 0 if result['status']=='accepted_current_boot_survival_'+a.phase+'_verified' and result.get('remote_exit_code')==0 else 1

if __name__=='__main__':
    try:
        sys.exit(main())
    except Refused as e:
        print('refused: '+str(e),file=sys.stderr);sys.exit(2)

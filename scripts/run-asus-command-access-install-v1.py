#!/usr/bin/env python3
"""Install the reviewed terminal/locale addition without reboot or service actions."""
import getpass
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import socket
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('readonly_transport', ROOT / 'scripts/run-ubuntu26-wifi-vif-v23-readonly-v1.py')
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
import paramiko

script = ROOT / 'scripts/asus-integration/command-access/install-v1.sh'
source = script.read_bytes()
kh = ROOT / 'evidence/ubuntu26/device-identity-live/ubuntu-known_hosts'
assert hashlib.sha256(kh.read_bytes()).hexdigest() == '4238c5cc4ce2c7363eb491894192d7a926eaf1165a03b135b9621ea47ee922a7'
outdir = ROOT / 'evidence/ubuntu26/asus-command-access-install-v1'
outdir.mkdir(mode=0o700)
password = getpass.getpass('Ubuntu SSH password (memory only): ')
client = paramiko.SSHClient()
client.load_host_keys(str(kh))
client.set_missing_host_key_policy(paramiko.RejectPolicy())
sock = socket.socket()
sock.settimeout(8)
sock.bind(('192.168.100.35', 0))
result = {'read_only': False, 'source_sha256': hashlib.sha256(source).hexdigest(), 'settings_changed': True}
try:
    sock.connect(('192.168.100.15',22))
    client.connect('192.168.100.15', username='MastermixStudios', password=password, sock=sock,
                   timeout=8, auth_timeout=8, banner_timeout=8, look_for_keys=False, allow_agent=False)
    deb = ROOT / 'build/asus-command-access/package-v2/leon-asus-command-access_0.1+leonb53.1_all.deb'
    assert hashlib.sha256(deb.read_bytes()).hexdigest() == '6511224e34f77440bac1ca1c07220d36ec0dc0b0ff009022952fe6d27d4d6dd2'
    incoming = '/tmp/leon-command-access-' + uuid.uuid4().hex
    with client.open_sftp() as sftp:
        sftp.mkdir(incoming, mode=0o700)
        sftp.put(str(deb), incoming+'/package.deb')
    command = '/usr/bin/sudo -S -p \"\" /usr/bin/timeout --kill-after=5s 180s /bin/bash --noprofile --norc -c ' + shlex.quote(source.decode()) + ' terminal-support ' + shlex.quote(incoming+'/package.deb')
    rc, out, err = transport.capture(client.get_transport(), command, time.monotonic()+190, stdin=(password+'\n').encode(), limit=65536)
    out = out.replace(password.encode(),b'[REDACTED]')
    err = err.replace(password.encode(),b'[REDACTED]')
    transport.write_private(outdir/'capture.txt',out+err)
    result.update(returncode=rc, complete=rc==0 and b'ASUS_COMMAND_ACCESS_INSTALLED' in out,
                  capture_sha256=hashlib.sha256(out+err).hexdigest())
    print(out.decode(errors='replace'))
    if err: print(err.decode(errors='replace'))
finally:
    password = None
    client.close()
    sock.close()
    transport.write_private(outdir/'result.json',(json.dumps(result,indent=2)+'\n').encode())

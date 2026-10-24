#!/usr/bin/env python3
"""One bounded native SSH diagnostic; no root, package actions, or service changes."""
import getpass
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import socket
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('readonly_transport', ROOT / 'scripts/run-ubuntu26-wifi-vif-v23-readonly-v1.py')
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
import paramiko

script = ROOT / 'scripts/asus-integration/acceptance/terminal-preview-v1.sh'
source = script.read_bytes()
kh = ROOT / 'evidence/ubuntu26/device-identity-live/ubuntu-known_hosts'
assert hashlib.sha256(kh.read_bytes()).hexdigest() == '4238c5cc4ce2c7363eb491894192d7a926eaf1165a03b135b9621ea47ee922a7'
outdir = ROOT / 'evidence/ubuntu26/terminal-preview-v1'
outdir.mkdir(mode=0o700)
password = getpass.getpass('Ubuntu SSH password (memory only): ')
client = paramiko.SSHClient()
client.load_host_keys(str(kh))
client.set_missing_host_key_policy(paramiko.RejectPolicy())
sock = socket.socket()
sock.settimeout(8)
sock.bind(('192.168.100.35', 0))
result = {'read_only': True, 'source_sha256': hashlib.sha256(source).hexdigest(), 'settings_changed': False}
try:
    sock.connect(('192.168.100.15',22))
    client.connect('192.168.100.15', username='MastermixStudios', password=password, sock=sock,
                   timeout=8, auth_timeout=8, banner_timeout=8, look_for_keys=False, allow_agent=False)
    command = '/usr/bin/timeout --kill-after=2s 20s /bin/bash --noprofile --norc -c ' + shlex.quote(source.decode())
    rc, out, err = transport.capture(client.get_transport(), command, time.monotonic()+25, limit=32768)
    out = out.replace(password.encode(),b'[REDACTED]')
    err = err.replace(password.encode(),b'[REDACTED]')
    transport.write_private(outdir/'capture.txt',out+err)
    result.update(returncode=rc, complete=rc==0 and b'LOCALE_DIALOG_READONLY_END' in out,
                  capture_sha256=hashlib.sha256(out+err).hexdigest())
    print(out.decode(errors='replace'))
    if err: print(err.decode(errors='replace'))
finally:
    password = None
    client.close()
    sock.close()
    transport.write_private(outdir/'result.json',(json.dumps(result,indent=2)+'\n').encode())

#!/usr/bin/env python3
"""Observe fixed SSH banners only; default prints scope and sends no traffic."""
import argparse
import json
import os
from pathlib import Path
import socket
import time

R = Path(__file__).resolve().parents[1]
OUT = R / 'evidence/ubuntu26/trial-live/twentysecond-startup-banner-v1'
SOURCE = '192.168.100.35'
HOSTS = ('192.168.100.15', '192.168.100.56')


def save(name, data):
    path = OUT / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(OUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def observe(host, remaining):
    begun = time.monotonic()
    deadline = begun + min(1.0, remaining)
    raw = bytearray()
    row = {'host': host, 'port': 22, 'source': SOURCE, 'socket_budget_seconds': min(1.0, remaining)}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.bind((SOURCE, 0))
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect((host, 22))
            while len(raw) < 256 and b'\n' not in raw:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError('bounded banner deadline')
                connection.settimeout(left)
                chunk = connection.recv(min(64, 256 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
        first = bytes(raw).split(b'\n', 1)[0].rstrip(b'\r')
        row['first_line_hex'] = first.hex()
        try:
            line = first.decode('ascii')
        except UnicodeDecodeError:
            row['classification'] = 'non_ascii_first_line'
        else:
            row['first_line'] = line
            folded = line.casefold()
            row['classification'] = ('openssh' if folded.startswith('ssh-2.0-openssh') else
                                     'dropbear' if folded.startswith('ssh-2.0-dropbear') else
                                     'other_or_empty')
    except (OSError, TimeoutError) as error:
        row.update(classification='not_yet_observed', error_class=type(error).__name__,
                   error_errno=getattr(error, 'errno', None), partial_first_line_hex=bytes(raw).split(b'\n', 1)[0].hex())
    row['elapsed_seconds'] = round(time.monotonic() - begun, 6)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    scope = {'schema': 1, 'window_seconds': 300, 'source': SOURCE, 'hosts': list(HOSTS), 'port': 22,
             'socket_budget_seconds': 1, 'first_line_cap_bytes': 256, 'password_attempted': False,
             'authenticated': False, 'native_boot_verified': False, 'settings_changed': False,
             'network_configuration_changed': False, 'ack_sent': False,
             'evidence_output': str(OUT.relative_to(R))}
    if not args.execute:
        print(json.dumps(scope))
        return
    OUT.mkdir(mode=0o700, parents=True, exist_ok=False)
    save('attempt.json', (json.dumps(scope, indent=2) + '\n').encode())
    started = time.monotonic()
    result = {**scope, 'status': 'no_openssh_banner_after_window', 'observations': 0}
    try:
        while time.monotonic() - started < 300:
            for host in HOSTS:
                left = 300 - (time.monotonic() - started)
                if left <= 0:
                    break
                row = observe(host, left)
                result['observations'] += 1
                save(f"observation-{result['observations']:03}.json", (json.dumps(row, indent=2) + '\n').encode())
                if row['classification'] == 'openssh':
                    result.update(status='openssh_banner_observed', host=host, first_line=row['first_line'])
                    return
            left = 300 - (time.monotonic() - started)
            if left > 0:
                time.sleep(min(5, left))
    finally:
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        save('result.json', (json.dumps(result, indent=2) + '\n').encode())
        print(json.dumps(result), flush=True)
    raise SystemExit(1)


if __name__ == '__main__':
    main()

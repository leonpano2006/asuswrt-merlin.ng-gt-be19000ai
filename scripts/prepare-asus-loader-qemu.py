#!/usr/bin/env python3
"""Offline ASUS loader diagnostics; never run an ASUS executable's entry point.

Trace mode resolves dependencies and relocations, then exits before constructors.
The fixture has no host mounts, network, proprietary modules or NVRAM device.
The newer armel libc is a BE98 reference, not an installed Ubuntu runtime.
"""
import gzip
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import re

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / 'build/kernel9-ui1-rootfs'
REFERENCE = Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100/glibc244-b53-20260915/builds/armel/stage/lib')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--label', required=True)
parser.add_argument('--crypt-library', type=Path)
parser.add_argument('--crypt-probe', action='append', type=Path, default=[])
args = parser.parse_args()
assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
assert bool(args.crypt_library) == bool(args.crypt_probe)
OUT = ROOT / 'build/asus-loader-qemu' / args.label
assert not OUT.exists(), 'Preserve previous fixture attempts'
OUT.mkdir(parents=True, exist_ok=True)
entries = {}
inputs = []


def add(name, payload, mode=0o644, kind=stat.S_IFREG):
    parent = PurePosixPath(name).parent
    if str(parent) != '.':
        directory(str(parent))
    entries[name] = (kind | mode, payload)


def directory(name):
    if name in entries:
        assert stat.S_ISDIR(entries[name][0]), name
        return
    add(name, b'', 0o755, stat.S_IFDIR)


def elf_machine(data):
    return struct.unpack_from('<H', data, 18)[0] if data[:4] == b'\x7fELF' else None


def resolved_vendor(name):
    parts = list(PurePosixPath(name).parts)
    stack = []
    for _ in range(128):
        if not parts:
            return VENDOR.joinpath(*stack)
        item = parts.pop(0)
        if item in ('', '.', '/'):
            continue
        if item == '..':
            if not stack:
                raise ValueError('Escaping vendor path')
            stack.pop()
            continue
        path = VENDOR.joinpath(*stack, item)
        if path.is_symlink():
            target = PurePosixPath(os.readlink(path))
            if target.is_absolute():
                stack = []
            parts = list(target.parts) + parts
        else:
            stack.append(item)
    raise ValueError('Vendor symlink loop')


def copy_file(source, destination, provenance):
    data = source.read_bytes()
    add(destination, data, source.stat().st_mode & 0o777)
    inputs.append({'source': str(source), 'destination': destination,
                   'sha256': hashlib.sha256(data).hexdigest(), 'role': provenance})


for base in ('lib', 'usr/lib'):
    for source in sorted((VENDOR / base).iterdir()):
        if source.is_symlink():
            resolved = resolved_vendor(str(source.relative_to(VENDOR)))
        elif source.is_file():
            resolved = source
        else:
            continue
        if resolved.is_file() and elf_machine(resolved.read_bytes()) == 40:
            # Materialize each alias inside the isolated library directory.
            # This never creates an absolute link into the Ubuntu/host /lib.
            copy_file(resolved, 'vendor/' + str(source.relative_to(VENDOR)), 'unchanged_vendor_armel_library')
for source in sorted(REFERENCE.iterdir()):
    if source.is_file() and elf_machine(source.read_bytes()) == 40:
        copy_file(source, 'newlib/' + source.name, 'BE98_glibc244_diagnostic_reference_only')
runtimes = ['vendor', 'glibc244']
probes = []
probe_contracts = {}
if args.crypt_library:
    crypt_report = json.loads((ROOT / 'reports/ubuntu26/asus-libcrypt-compat.json').read_text())
    assert hashlib.sha256(args.crypt_library.read_bytes()).hexdigest() == crypt_report['candidate']['sha256']
    known_probes = {Path(p['path']).name: p for p in crypt_report['probes']}
    assert elf_machine(args.crypt_library.read_bytes()) == 40
    copy_file(args.crypt_library, 'newcrypt/libcrypt.so.1', 'fresh_BE19000AI_compatibility_candidate')
    runtimes.append('glibc244_crypt')
    for probe in args.crypt_probe:
        assert re.fullmatch(r'[A-Za-z0-9_-]+', probe.name)
        assert probe.name not in probes and elf_machine(probe.read_bytes()) == 40
        contract = known_probes[probe.name]
        assert hashlib.sha256(probe.read_bytes()).hexdigest() == contract['sha256']
        assert contract['expected_markers']
        probe_contracts[probe.name] = {k: contract[k] for k in ('sha256', 'expected_markers')}
        copy_file(probe, 'probes/' + probe.name, 'benign_crypt_vector_and_legacy_ABI_probe')
        probes.append(probe.name)
    assert set(probes) == set(known_probes), 'Include the complete crypt probe suite'

programs = ['sbin/rc', 'usr/sbin/httpd', 'usr/sbin/cfg_client', 'usr/sbin/cfg_server',
            'usr/sbin/wl', 'usr/sbin/wlconf', 'usr/sbin/hostapd', 'usr/sbin/wpa_supplicant',
            'usr/sbin/eapd', 'usr/sbin/acsd2', 'usr/libexec/ledg-node/rc']
selected = []
for program in programs:
    source = resolved_vendor(program)
    if not source.is_file():
        # Vendor versions sometimes move a helper between sbin and usr/sbin.
        alternatives = [resolved_vendor(d + '/' + PurePosixPath(program).name) for d in ('sbin', 'usr/sbin', 'bin', 'usr/bin')]
        source = next((f for f in alternatives if f.is_file()), source)
    assert source.is_file(), program
    assert elf_machine(source.read_bytes()) == 40, program
    name = program.replace('/', '__')
    copy_file(source, 'programs/' + name, 'trace_only_no_program_entry')
    selected.append(name)

for name in ('bin', 'dev', 'proc', 'sys', 'tmp'):
    directory(name)
copy_file(ROOT / 'build/busybox', 'bin/busybox', 'static_test_harness')
add('bin/busybox', (ROOT / 'build/busybox').read_bytes(), 0o755)
add('QEMU_LAB_GUEST', b'offline diagnostic\n')
init = '''#!/bin/busybox sh
export PATH=/bin
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
set -eu
echo QEMU_LAB_INIT_REACHED
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount --make-rprivate /
for runtime in RUNTIMES; do
 if test "$runtime" = vendor; then
  loader=/vendor/lib/ld-linux.so.3
  library_path=/vendor/lib:/vendor/usr/lib
 elif test "$runtime" = glibc244; then
  loader=/newlib/ld-linux.so.3
  library_path=/newlib:/vendor/lib:/vendor/usr/lib
 else
  loader=/newlib/ld-linux.so.3
  library_path=/newcrypt:/newlib:/vendor/lib:/vendor/usr/lib
 fi
 for program in PROGRAMS; do
  echo "LAB_ASUS_LOADER_BEGIN runtime=$runtime program=$program"
  rc=0
  timeout -s KILL 8 env LD_TRACE_LOADED_OBJECTS=1 LD_WARN=1 LD_BIND_NOW=1 "$loader" --inhibit-cache --library-path "$library_path" "/programs/$program" || rc=$?
  echo "LAB_ASUS_LOADER_END runtime=$runtime program=$program rc=$rc"
 done
done
for probe in PROBES; do
 echo "LAB_ASUS_CRYPT_PROBE_BEGIN probe=$probe"
 rc=0
 timeout -s KILL 8 /newlib/ld-linux.so.3 --inhibit-cache --library-path /newcrypt:/newlib:/vendor/lib:/vendor/usr/lib "/probes/$probe" || rc=$?
 echo "LAB_ASUS_CRYPT_PROBE_END probe=$probe rc=$rc"
done
echo QEMU_ASUS_LOADER_DIAGNOSTIC_COMPLETE
poweroff -f
'''.replace('PROGRAMS', ' '.join(selected)).replace('RUNTIMES', ' '.join(runtimes)).replace('PROBES', ' '.join(probes))
add('init', init.encode(), 0o755)
entries['TRAILER!!!'] = (0, b'')
archive = bytearray()
for i, (name, (mode, data)) in enumerate(entries.items(), 1):
    encoded = name.encode() + b'\0'
    values = [i, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
    archive += b'070701' + ''.join(f'{v:08x}' for v in values).encode() + encoded
    archive += b'\0' * (-len(archive) % 4)
    archive += data
    archive += b'\0' * (-len(archive) % 4)
image = OUT / 'asus-loader.cpio.gz'
image.write_bytes(gzip.compress(archive, compresslevel=1, mtime=0))
report = {'scope': 'Diagnostic-only dependency and relocation trace; no ASUS daemon startup, hardware or Ubuntu integration acceptance.',
          'programs': selected, 'runtimes': runtimes, 'crypt_probes': probes,
          'crypt_probe_contracts': probe_contracts,
          'inputs': inputs, 'initramfs': str(image.relative_to(ROOT)),
          'initramfs_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
          'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'trace_mode_source': 'build/ubuntu26-glibc/source/elf/rtld.c:2015-2211; trace LD_WARN relocations use __RTLD_NOIFUNC and _exit before program startup',
          'limitations': ['Trace mode cannot exercise dlopen/runtime plugins, hardware ioctls, generated config or service actions.',
                         'The old vendor loader is retained only as the reference baseline; newlib is not a Debian package.']}
(OUT / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ['scope', 'programs', 'initramfs_sha256']}, indent=2))

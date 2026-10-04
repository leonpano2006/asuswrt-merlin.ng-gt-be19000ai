#!/usr/bin/env python3
"""Build standalone static probes without executing any of them."""
import hashlib, json, subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
source = ROOT/'scripts/time64-probe.c'
out = ROOT/'build/time64'
out.mkdir(parents=True, exist_ok=True)
report = {'source': str(source.relative_to(ROOT)), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
          'compiler_version': subprocess.check_output(['clang', '--version'], text=True).splitlines()[0],
          'builds': [], 'executed_on_host': False, 'executed_in_qemu_user': False, 'physical_acceptance_pending': True}
for name, target, extra in [('arm64', 'aarch64-linux-gnu', []),
                            ('armel', 'arm-linux-gnueabi', ['-marm', '-mfloat-abi=soft']),
                            ('armhf', 'arm-linux-gnueabihf', ['-marm', '-mfloat-abi=hard'])]:
    path = out/('time64-probe-'+name)
    command = ['clang', '--target='+target, '-mcpu=cortex-a53+crc+crypto', '-fuse-ld=lld',
               '-static', '-nostdlib', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
               '-fomit-frame-pointer', '-fno-pie', '-O2', '-Wall', '-Wextra', '-Werror',
               '-Wl,-e,_start', '-Wl,--build-id=none', *extra, str(source), '-o', str(path)]
    run = subprocess.run(command, capture_output=True, text=True)
    (out/(name+'-build.log')).write_text(run.stdout+run.stderr)
    if run.returncode:
        print(run.stdout+run.stderr)
        raise SystemExit(run.returncode)
    info = subprocess.check_output(['file', str(path)], text=True).strip()
    headers = subprocess.check_output(['readelf', '-h', str(path)], text=True)
    attributes = subprocess.check_output(['readelf', '-A', str(path)], text=True)
    segments = subprocess.check_output(['readelf', '-l', str(path)], text=True)
    assert 'INTERP' not in segments
    report['builds'].append({'name': name, 'target': target, 'command': command,
        'binary': str(path.relative_to(ROOT)), 'bytes': path.stat().st_size,
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'file': info,
        'elf_header': headers, 'arm_attributes': attributes,
        'static_no_interpreter': True, 'compile_returncode': 0})
    print(info)
target = ROOT/'reports/time64/probe-build.json'
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(report, indent=2)+'\n')

#!/usr/bin/env python3
"""Verify the staged BusyBox patch with source-derived ABI probes; no device I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BE98 = Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100')
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--be98-root', type=Path, default=DEFAULT_BE98)
p.add_argument('--output', type=Path, default=ROOT/'build/ubuntu26-busybox-time64')
p.add_argument('--report', type=Path, default=ROOT/'reports/ubuntu26/busybox-time64-patch-test.json')
a = p.parse_args()
work = a.output.resolve()
if work.exists():
    raise SystemExit('Output exists; preserve previous evidence and choose a new --output.')
work.mkdir(parents=True)
base = a.be98_root.resolve()/'glibc244-b53-20260915'
uapi_source = a.be98_root.resolve()/'systemd-features-20260917/sdk/usr/include'
uapi = work/'aarch64-uapi'
uapi.mkdir()
for directory in ['asm', 'asm-generic', 'linux']:
    if not (uapi_source/directory).is_dir():
        raise SystemExit('Missing recorded native UAPI input: '+str(uapi_source/directory))
    (uapi/directory).symlink_to(uapi_source/directory, target_is_directory=True)
policy = json.loads((ROOT/'configs/ubuntu26/userspace-patches.json').read_text())
entry = policy['patches'][0]
patch = ROOT/entry['path']
def sha(data):
    return hashlib.sha256(data).hexdigest()
def run(cmd, env=None, expected=0):
    out = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
    if out.returncode != expected:
        raise RuntimeError(shlex.join(cmd)+'\n'+out.stdout+'\n'+out.stderr)
    return out
assert sha(patch.read_bytes()) == entry['sha256']
source_revision = run(['git', '-C', str(ROOT/'source'), 'rev-parse', 'HEAD']).stdout.strip()
assert source_revision == policy['source_commit']
original = run(['git', '-C', str(ROOT/'source'), 'show', source_revision+':'+entry['source_path']]).stdout
assert sha(original.encode()) == entry['source_sha256']
with tempfile.TemporaryDirectory(prefix='asus-busybox-time64-') as temp:
    root = Path(temp)
    target = root/entry['source_path']
    target.parent.mkdir(parents=True)
    target.write_text(original)
    env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(root.parent))
    for flags in [ ['--check'], [], ['--reverse', '--check'] ]:
        run(['git', '-C', str(root), 'apply', *flags, str(patch)], env)
    patched = target.read_text()
assert sha(patched.encode()) == entry['result_sha256']
helpers = {}
for label, content in [('original', original), ('patched', patched)]:
    start = content.index('static void get_mono(struct timespec *ts)\n')
    end = content.index('\n#else\n\nunsigned long long FAST_FUNC monotonic_ns', start)
    helper = content[start:end]
    assert helper.count('static void get_mono') == 1 and helper.count('FAST_FUNC monotonic_') == 4
    folder = work/label
    folder.mkdir()
    (folder/'busybox-monotonic.inc').write_text(helper+'\n')
    helpers[label] = sha((helper+'\n').encode())
probe = ROOT/'scripts/busybox-time64-probe.c'
results = []
for label, abi, bits, libc_branch, expected in [
        ('original', 'armel', 64, False, 10),
        ('patched', 'armel', 64, True, 0),
        ('patched', 'armhf', 64, True, 0),
        ('patched', 'armel', 32, False, 0),
        ('patched', 'aarch64', 64, True, 0)]:
    cfg_path = base/'builds'/abi/'configuration.json'
    cfg = json.loads(cfg_path.read_text())
    stage = base/'builds'/abi/'stage'
    libdir = stage/cfg['configuration']['slibdir'].lstrip('/')
    crt = stage/cfg['configuration']['libdir'].lstrip('/')
    cc = [x for x in shlex.split(cfg['cc']) if not x.startswith('--sysroot=')]
    flags = ['-mcpu=cortex-a53+crypto+crc'] if abi == 'aarch64' else [
        '-march=armv8-a+crc+crypto', '-mtune=cortex-a53',
        '-mfpu=crypto-neon-fp-armv8', '-mfloat-abi='+('softfp' if abi == 'armel' else 'hard')]
    defines = [] if abi == 'aarch64' else (['-D_TIME_BITS=64', '-D_FILE_OFFSET_BITS=64'] if bits == 64 else ['-U_TIME_BITS', '-U_FILE_OFFSET_BITS'])
    binary = work/(label+'-'+abi+'-time'+str(bits))
    include_flags = ['-isystem', str(stage/'usr/include'), '-isystem', str(uapi)] if abi == 'aarch64' else []
    command = cc+['--sysroot='+str(stage), '-B'+str(crt)+'/', *include_flags, '-std=c11', '-O2',
        '-Wall', '-Wextra', '-Werror', *flags, *defines, '-DEXPECT_TIME_BITS='+str(bits),
        '-I'+str(work/label), '-L'+str(crt), '-L'+str(libdir), str(probe)]
    env = dict(os.environ)
    if 'host_library_dir' in cfg:
        env['LD_LIBRARY_PATH'] = cfg['host_library_dir']
    run(command+['-o', str(binary)], env)
    preprocessed = run(command+['-E', '-P'], env).stdout
    body = re.search(r'static void get_mono\(struct timespec \*ts\)\s*\{(.*?)\n\}', preprocessed, re.S)
    assert body
    has_libc = 'if (clock_gettime(' in body.group(1)
    has_raw = 'if (syscall(' in body.group(1)
    assert has_libc == libc_branch and has_raw != libc_branch, (label,abi,bits,body.group(1))
    loader_name = {'armel':'ld-linux.so.3', 'armhf':'ld-linux-armhf.so.3', 'aarch64':'ld-linux-aarch64.so.1'}[abi]
    loader = stage/cfg['configuration']['rtlddir'].lstrip('/')/loader_name
    execution = ([] if abi == 'aarch64' else ['qemu-arm', '-cpu', 'max']) + [
        str(loader), '--inhibit-cache', '--library-path', str(libdir), str(binary)]
    outcome = run(execution, expected=expected)
    marker = 'BUSYBOX_TIMESPEC_LAYOUT_MISMATCH' if expected else 'BUSYBOX_MONOTONIC_ABI_PASS checks=65 clock_writes=0'
    assert marker in outcome.stdout
    elf = run(['readelf', '-h', '-d', str(binary)]).stdout
    needed = re.findall(r'Shared library: \[(.*?)\]', elf)
    assert set(needed).issubset({'libc.so.6', loader_name}), needed
    results.append({'source':label, 'abi':abi, 'time_bits':bits,
        'libc_wrapper_branch':has_libc, 'legacy_raw_branch':has_raw,
        'build_command':command+['-o',str(binary)], 'runtime_command':execution,
        'compiler':run(cc+['--version'],env).stdout.splitlines()[0],
        'runtime_libc_sha256':sha((libdir/'libc.so.6').read_bytes()),
        'runtime_loader_sha256':sha(loader.read_bytes()),
        'configuration_sha256':sha(cfg_path.read_bytes()),
        'binary_sha256':sha(binary.read_bytes()),'needed':needed,
        'exit':outcome.returncode,'stdout':outcome.stdout,'stderr':outcome.stderr})
report = {'status':'pass', 'scope':'Focused source-derived helper test; no full BusyBox/ASUS build, device access or global clock changes',
    'source_revision':source_revision,'patch':entry,
    'patch_check':'git apply --check, apply, reverse --check in isolated temporary source tree; exact output hash matched',
    'probe_source':{'path':str(probe.relative_to(ROOT)), 'sha256':sha(probe.read_bytes())},
    'helper_source_sha256':helpers,
    'native_uapi':{str(uapi_source/f):sha((uapi_source/f).read_bytes()) for f in ['asm/unistd.h','asm-generic/unistd.h','linux/version.h']},
    'results':results,
    'summary':{'old_armel_time64_failure_reproduced':True,'patched_abi_variants_passed':4,'checks_per_passing_variant':65,'global_clock_writes':0},
    'limitations':['ARM32 runs use qemu-user and the host kernel; these are not a fresh kernel9 system-mode or hardware test.',
                   'The native arm64 helper runs on the build host with explicit recorded glibc loader.',
                   'Only the exact get_mono and four monotonic helper functions are built; remaining BusyBox applets and ASUS integration require separate validation.',
                   'Time32 is built only as a regression fixture; production newly built components remain time64 by default.',
                   'cfg shared-memory and rfctime interfaces are intentionally unmodified.']}
a.report.parent.mkdir(parents=True,exist_ok=True)
a.report.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'pass','report':str(a.report),'old_time64_bug_reproduced':True,'patched_abi_variants_passed':4},indent=2))

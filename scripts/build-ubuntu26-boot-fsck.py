#!/usr/bin/env python3
"""Build a private native e2fsck closure without changing stock loader paths."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-b53-v3.tar'
BASE_SHA = '303cafac152c86df9ac78a7c677e718ec411074dd7c73f33a3f0db26df59fda5'
PREFIX = '/usr/libexec/leon-boot'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--device', required=True)
    args = parser.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    assert args.device in ['/dev/loop1', '/dev/loop1p11', '/dev/mmcblk0p11']
    assert sha(BASE) == BASE_SHA
    output = ROOT / 'build/ubuntu26-boot-fsck' / args.label
    output.mkdir(parents=True, exist_ok=False)
    inputs = Path(tempfile.mkdtemp(prefix='ubuntu-boot-fsck-inputs-'))
    inputs.chmod(0o755)
    bundle = output / 'stage'
    private = bundle / PREFIX[1:]
    (private / 'lib').mkdir(parents=True)
    source = ROOT / 'scripts/asus-integration/boot-fsck.c'
    shutil.copyfile(source, inputs / source.name)
    records = []
    with tarfile.open(BASE) as archive:
        members = {m.name.removeprefix('./').lstrip('/'): m for m in archive}
        def resolve(name):
            parts = list(PurePosixPath(name).parts)
            if parts and parts[0] == '/': parts.pop(0)
            for _ in range(40):
                changed = False
                for i in range(1, len(parts) + 1):
                    current = '/'.join(parts[:i])
                    item = members.get(current)
                    if item and (item.issym() or item.islnk()):
                        link = list(PurePosixPath(item.linkname).parts)
                        if item.islnk() or item.linkname.startswith('/'):
                            if link and link[0] == '/': link.pop(0)
                            newparts = link + parts[i:]
                        else:
                            newparts = parts[:i - 1] + link + parts[i:]
                        parts = []
                        for part in newparts:
                            if part == '..':
                                assert parts, item.linkname
                                parts.pop()
                            elif part not in ['', '.']: parts.append(part)
                        changed = True
                        break
                if not changed:
                    item = members.get('/'.join(parts))
                    return item if item and item.isfile() else None
            raise ValueError('symlink loop: ' + name)
        pending = [('/usr/sbin/e2fsck', 'e2fsck')]
        copied = {}
        while pending:
            srcpath, target = pending.pop()
            if target in copied:
                continue
            member = resolve(srcpath)
            assert member and member.uid == 0 and not member.mode & 0o022, srcpath
            dest = private / target
            dest.write_bytes(archive.extractfile(member).read())
            dest.chmod(0o755 if target in ['e2fsck', 'lib/ld-linux-aarch64.so.1'] else 0o644)
            elf = subprocess.check_output(['readelf', '-h', '-l', '-d', str(dest)], text=True)
            assert 'AArch64' in elf
            assert '(RPATH)' not in elf and '(RUNPATH)' not in elf
            digest = sha(dest)
            copied[target] = digest
            records.append({'source_path': srcpath, 'tar_member': member.name,
                            'path': PREFIX + '/' + target, 'sha256': digest})
            for interp in re.findall(r'Requesting program interpreter: (.*?)\]', elf):
                assert interp == '/lib/ld-linux-aarch64.so.1'
                pending.append((interp, 'lib/ld-linux-aarch64.so.1'))
            for needed in re.findall(r'\(NEEDED\).*?\[(.*?)\]', elf):
                assert re.fullmatch(r'[A-Za-z0-9_.+-]+', needed)
                library = next((d + needed for d in ['/usr/lib/aarch64-linux-gnu/', '/lib/aarch64-linux-gnu/'] if resolve(d + needed)), None)
                assert library, needed
                pending.append((library, 'lib/' + needed))
    (private / 'e2fsck.conf').write_text('# Private early-boot configuration; do not inherit the stock root config.\n')
    (private / 'e2fsck.conf').chmod(0o644)
    header = '#define BOOT_FSCK_DEVICE ' + json.dumps(args.device) + '\n'
    header += 'static const char *const boot_fsck_files[] = {\n'
    header += ',\n'.join('  ' + json.dumps(p['path']) for p in records)
    header += ',\n  "' + PREFIX + '/e2fsck.conf"\n};\n'
    (inputs / 'boot-fsck-policy.h').write_text(header)
    script = r'''set -euo pipefail
umask 022
root="$1"; inputs="$2"; label="$3"
mount --make-rprivate /
mkdir -m 0755 "$root/work/boot-fsck-$label"
cp "$inputs"/boot-fsck*.[ch] "$root/work/boot-fsck-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/boot-fsck-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
ccache gcc-16 -std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -static-pie -Wl,-z,relro,-z,now boot-fsck.c -o boot-fsck
gcc-16 --version > compiler.txt
readelf -h -l -d -n boot-fsck > elf.txt
set +e
./boot-fsck --version > wrong-arguments.txt 2>&1
code=$?
set -e
test "$code" = 64
BUILD
'''
    (inputs / 'build.sh').write_text(script)
    envfile = ROOT / 'build/asus-native-build/v2/result.json'
    env = json.loads(envfile.read_text())
    assert env['status'] == 'prepared'
    buildroot = Path(env['root'])
    with (output / 'build.log').open('w') as log:
        result = subprocess.run(['mmdebstrap', '--unshare-helper', '/bin/bash', str(inputs / 'build.sh'), str(buildroot), str(inputs), args.label], stdout=log, stderr=subprocess.STDOUT)
    record = {'status': 'failed', 'returncode': result.returncode,
              'device': args.device, 'scope': 'candidate-device-policy' if args.device == '/dev/mmcblk0p11' else 'offline-qemu-fixture',
              'base_sha256': BASE_SHA, 'source_sha256': sha(source), 'builder_sha256': sha(Path(__file__)),
              'native_build_manifest_sha256': sha(envfile), 'closure': records,
              'preserves_stock_arm64_loader': True, 'flash_accepted': False}
    if result.returncode == 0:
        built = buildroot / ('work/boot-fsck-' + args.label)
        for name in ['compiler.txt', 'elf.txt', 'wrong-arguments.txt']:
            shutil.copyfile(built / name, output / name)
        assert 'INTERP' not in (output / 'elf.txt').read_text()
        shutil.copyfile(built / 'boot-fsck', private / 'fsck')
        (private / 'fsck').chmod(0o755)
        shutil.copyfile(inputs / 'boot-fsck-policy.h', output / 'boot-fsck-policy.h')
        for folder in [bundle, *[p for p in bundle.rglob('*') if p.is_dir()]]:
            folder.chmod(0o755)
        inventory = {str(p.relative_to(bundle)): {'sha256': sha(p), 'mode': oct(p.stat().st_mode & 0o777)} for p in bundle.rglob('*') if p.is_file()}
        record.update(status='built', static_wrapper_no_interpreter=True, payload=inventory)
    (output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'output': str(output)}, indent=2))
    raise SystemExit(result.returncode)

if __name__ == '__main__':
    main()

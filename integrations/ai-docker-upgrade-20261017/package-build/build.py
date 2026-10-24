#!/usr/bin/env python3
"""Build a local, reversible static Docker cohort package for the AI board."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
TASK = HERE.parent
VERSION = '29.9.1'
PACKAGE_VERSION = VERSION + '+leonai2'
ROOT = HERE / 'root'
BIN = f'/usr/libexec/leon-ai-docker/{VERSION}/bin'
MANIFEST = json.loads((TASK / 'candidate-manifest.json').read_text())

def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def put(path, text, mode=0o644):
    p = ROOT / path.lstrip('/')
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)

if ROOT.exists():
    raise SystemExit('Refusing to overwrite an existing package root')
ROOT.mkdir()
for name, metadata in MANIFEST['files'].items():
    src = TASK / 'candidate/docker' / name
    if src.stat().st_size != metadata['bytes'] or sha(src) != metadata['sha256']:
        raise SystemExit(f'Candidate verification failed: {name}')
    dst = ROOT / BIN.lstrip('/') / name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    dst.chmod(0o755)

put('/etc/leon-ai-docker/daemon.json', json.dumps({
    'data-root': '/home/docker',
    'storage-driver': 'overlay2',
    'features': {'containerd-snapshotter': False},
    'exec-opts': ['native.cgroupdriver=cgroupfs'],
}, indent=2) + '\n')
put('/etc/leon-ai-docker/containerd.toml', '''version = 4
root = "/var/lib/containerd"
state = "/run/containerd"
imports = []
disabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]

[plugins."io.containerd.server.v1.grpc"]
  address = "/run/containerd/containerd.sock"
''')
runtime_path = BIN + ':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
put('/etc/systemd/system/docker.service.d/40-leon-runtime.conf', f'''# Managed by leon-ai-docker-engine. Lifecycle is controlled separately.
[Service]
Environment="PATH={runtime_path}"
ExecStart=
ExecStart={BIN}/dockerd -H fd:// --containerd=/run/containerd/containerd.sock --config-file=/etc/leon-ai-docker/daemon.json
''')
put('/etc/systemd/system/containerd.service.d/40-leon-runtime.conf', f'''# Managed by leon-ai-docker-engine. Lifecycle is controlled separately.
[Service]
Environment="PATH={runtime_path}"
ExecStart=
ExecStart={BIN}/containerd --config=/etc/leon-ai-docker/containerd.toml
''')
put('/etc/profile.d/leon-ai-docker.sh', f'''# Prefer the complete, versioned Docker cohort in login shells.
case ":${{PATH:-}}:" in
  *":{BIN}:"*) ;;
  *) PATH="{BIN}:${{PATH:-/usr/sbin:/usr/bin:/sbin:/bin}}" ;;
esac
export PATH
''')
(ROOT / 'usr/bin').mkdir(parents=True, exist_ok=True)
(ROOT / 'usr/bin/leon-docker').symlink_to(BIN + '/docker')

preinst = f'''#!/bin/sh
set -eu
root=${{DPKG_ROOT:-}}
for name in docker ctr; do
    path="$root/usr/local/bin/$name"
    expected="{BIN}/$name"
    if [ -e "$path" ] || [ -L "$path" ]; then
        if [ ! -L "$path" ] || [ "$(readlink "$path")" != "$expected" ]; then
            echo "Refusing to replace existing $path" >&2
            exit 1
        fi
    fi
done
exit 0
'''
postinst = f'''#!/bin/sh
set -eu
root=${{DPKG_ROOT:-}}
if [ "${{1:-}}" = configure ]; then
    mkdir -p "$root/usr/local/bin" "$root/var/lib/leon-ai-docker"
    chmod 755 "$root/usr/local/bin"
    chmod 700 "$root/var/lib/leon-ai-docker"
    for name in docker ctr; do
        path="$root/usr/local/bin/$name"
        expected="{BIN}/$name"
        marker="$root/var/lib/leon-ai-docker/$name.link"
        if [ ! -e "$path" ] && [ ! -L "$path" ]; then
            ln -s "$expected" "$path"
            printf '%s\\n' "$expected" > "$marker"
            chmod 600 "$marker"
        elif [ ! -L "$path" ] || [ "$(readlink "$path")" != "$expected" ]; then
            echo "Refusing to replace existing $path" >&2
            exit 1
        fi
    done
    if [ -z "$root" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
fi
exit 0
'''
cleanup = f'''root=${{DPKG_ROOT:-}}
for name in docker ctr; do
    path="$root/usr/local/bin/$name"
    expected="{BIN}/$name"
    marker="$root/var/lib/leon-ai-docker/$name.link"
    if [ -f "$marker" ] && [ "$(cat "$marker")" = "$expected" ]; then
        if [ -L "$path" ] && [ "$(readlink "$path")" = "$expected" ]; then
            rm -- "$path"
        fi
        rm -- "$marker"
    fi
done
rmdir "$root/var/lib/leon-ai-docker" 2>/dev/null || true
'''
put('/DEBIAN/preinst', preinst, 0o755)
put('/DEBIAN/postinst', postinst, 0o755)
put('/DEBIAN/prerm', '#!/bin/sh\nset -eu\nif [ "${1:-}" = remove ]; then\n' + cleanup + 'fi\nexit 0\n', 0o755)
put('/DEBIAN/postrm', '''#!/bin/sh
set -eu
case "${1:-}" in
  remove|purge)
''' + cleanup + '''    if [ -z "$root" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
    ;;
esac
exit 0
''', 0o755)
put('/DEBIAN/conffiles', '/etc/leon-ai-docker/daemon.json\n/etc/leon-ai-docker/containerd.toml\n')
put('/usr/share/doc/leon-ai-docker-engine/README', f'''AI board Docker runtime overlay, {PACKAGE_VERSION}

This package preserves all native /usr/bin Docker/containerd/runc binaries.
Its eight upstream binaries are stored together in {BIN}.
Systemd drop-ins select this cohort and its own two configuration files.
Docker retains /home/docker, overlay2 and cgroupfs. The containerd image store
remains disabled. Containerd retains /var/lib/containerd and /run/containerd.
Its two CRI plugins are disabled; Docker uses the existing containerd socket.
No container data or existing Docker configuration is edited by this package.

Installation and removal never start, stop, or restart a service. The deployment
controller must stop workloads/daemons and preserve metadata before replacing a
runtime, then explicitly start and validate them. Maintainer scripts only reload
systemd units. A metadata downgrade is NOT guaranteed safe: removing this package
alone is not a sufficient rollback after a newer daemon has migrated data.
The deployment controller must restore its pre-upgrade metadata snapshot when
rolling back to the original daemon.

CLI access: new login shells prepend the versioned binary directory to PATH.
/usr/bin/leon-docker is an explicit versioned alias. /usr/local/bin/docker and
/usr/local/bin/ctr are created only if absent. Conflicting existing paths block
installation. Only exact symlinks recorded as created by this package are removed.
Use an absolute versioned path or 'hash -r' in already-open shells.
Existing Docker Compose plugins are not replaced.

Remove with dpkg --remove leon-ai-docker-engine after the controller has stopped
the new daemons. Drop-ins/profile/binaries are ordinary package files and are
removed. The two /etc/leon-ai-docker configuration files remain as conffiles;
dpkg --purge removes them. Original service units and binaries stay in place.

Source: {MANIFEST['url']}
Source archive SHA256: {MANIFEST['sha256']}
The packaged candidate-manifest.json records every upstream binary hash.
''')
put('/usr/share/doc/leon-ai-docker-engine/candidate-manifest.json', json.dumps(MANIFEST, indent=2) + '\n')
installed_size = (sum(p.stat().st_size for p in ROOT.rglob('*') if p.is_file() and not p.is_symlink()) + 1023) // 1024
put('/DEBIAN/control', f'''Package: leon-ai-docker-engine
Version: {PACKAGE_VERSION}
Architecture: arm64
Maintainer: Local AI board administration <root@localhost>
Section: admin
Priority: optional
Installed-Size: {installed_size}
Description: Versioned Docker static runtime overlay for the BE19000AI AI board
 Preserves native binaries and service units, selecting a complete official
 Docker cohort through removable drop-ins. Service lifecycle and metadata
 rollback are explicitly controlled by the deployment procedure.
''')
md5 = []
for p in sorted(ROOT.rglob('*')):
    if p.is_file() and not p.is_symlink() and 'DEBIAN' not in p.relative_to(ROOT).parts:
        md5.append(hashlib.md5(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(ROOT)))
put('/DEBIAN/md5sums', '\n'.join(md5) + '\n')
scripts = [str(ROOT / 'DEBIAN' / x) for x in ('preinst', 'postinst', 'prerm', 'postrm')]
subprocess.run(['shellcheck', '-s', 'sh', *scripts, str(ROOT / 'etc/profile.d/leon-ai-docker.sh')], check=True)
deb = HERE / f'leon-ai-docker-engine_{PACKAGE_VERSION}_arm64.deb'
subprocess.run(['dpkg-deb', '--root-owner-group', '--threads-max=2', '-Zxz', '-z1', '--build', str(ROOT), str(deb)], check=True)
result = {
    'package': deb.name, 'version': PACKAGE_VERSION, 'architecture': 'arm64',
    'sha256': sha(deb), 'bytes': deb.stat().st_size,
    'source_archive_sha256': MANIFEST['sha256'],
    'binaries': {name: {'path': BIN + '/' + name, 'sha256': sha(ROOT / BIN.lstrip('/') / name)} for name in MANIFEST['files']},
    'files': [],
    'conffiles': ['/etc/leon-ai-docker/daemon.json', '/etc/leon-ai-docker/containerd.toml'],
    'automatic_service_actions': ['daemon-reload only'],
}
for p in sorted(ROOT.rglob('*')):
    if 'DEBIAN' in p.relative_to(ROOT).parts or p.is_dir():
        continue
    item = {'path': '/' + str(p.relative_to(ROOT)), 'mode': oct(p.lstat().st_mode & 0o777)}
    if p.is_symlink():
        item['symlink'] = os.readlink(p)
    else:
        item.update({'sha256': sha(p), 'bytes': p.stat().st_size})
    result['files'].append(item)
(HERE / 'package-manifest.json').write_text(json.dumps(result, indent=2) + '\n')
with (HERE / 'package-contents.txt').open('w') as f:
    subprocess.run(['dpkg-deb', '--contents', str(deb)], stdout=f, check=True)
print(json.dumps({'package': str(deb), 'sha256': result['sha256'], 'bytes': result['bytes']}, indent=2))

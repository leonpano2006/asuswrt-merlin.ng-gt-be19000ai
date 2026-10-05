#!/usr/bin/env python3
"""Package the private ASUS shell without replacing any Ubuntu executable."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

R = Path(__file__).resolve().parents[1]
W = R / 'build/asus-private-shell/packages'
W.mkdir(exist_ok=True)
BB = R / 'build/asus-private-shell/native-v4'
HELPERS = R / 'build/asus-native-helpers/v3'
VERSION = '0.2+asus3006.102.9'
def sha(p):
    with p.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
build = json.loads((BB / 'result.json').read_text())
assert build['status'] == 'built' and sha(BB / 'busybox-native') == build['binary_sha256']
helpers = json.loads((HELPERS / 'result.json').read_text())
assert helpers['status'] == 'built'
ash = next(p for p in helpers['outputs'] if p['path'].endswith('/ash'))
assert sha(HELPERS / 'ash') == ash['sha256']
stock = json.loads((R / 'build/asus-private-shell/stock-applets.json').read_text())
assert stock['returncode'] == 0
assert stock['stdout'].splitlines() == (BB / 'applets.txt').read_text().splitlines()
record = {'schema_version': 1, 'package': 'leon-asus-shell', 'version': VERSION,
          'architecture': 'arm64', 'source_commit': build['source_commit'],
          'compiler': build['compiler'], 'applets': build['applet_count'],
          'same_applet_list_as_stock': True, 'sets_uid': False,
          'global_shell_or_applet_paths_modified': False, 'maintainer_scripts': False,
          'runtime_accepted': False, 'production_accepted': False,
          'inputs': [{'path': str(p.relative_to(R)), 'sha256': sha(p)} for p in [BB/'result.json', BB/'busybox-native', HELPERS/'result.json', HELPERS/'ash', R/'scripts/asus-integration/ash-entry.c']]}
with tempfile.TemporaryDirectory(prefix='asus-shell-deb-', dir=W) as tmp:
    stage = Path(tmp) / 'stage'
    (stage/'DEBIAN').mkdir(parents=True)
    libexec = stage / 'usr/libexec/asus'
    libexec.mkdir(parents=True)
    shutil.copyfile(BB/'busybox-native', libexec/'busybox')
    shutil.copyfile(HELPERS/'ash', libexec/'ash')
    for file in libexec.iterdir(): file.chmod(0o755)
    applets = libexec / 'sh-applets'
    applets.mkdir()
    for name in ['[', '[[', 'test', 'echo', 'printf']:
        (applets / name).symlink_to('../busybox')
    doc = stage/'usr/share/doc/leon-asus-shell'
    doc.mkdir(parents=True)
    for original,name in [(BB/'config','config'),(BB/'applets.txt','applets.txt')]:
        shutil.copyfile(original, doc/name)
    license = R/'build/asus-private-shell/pinned-source/release/src/router/busybox/LICENSE'
    shutil.copyfile(license, doc/'copyright')
    (doc/'build-manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    (stage/'DEBIAN/control').write_text(f'''Package: leon-asus-shell
Version: {VERSION}
Architecture: arm64
Section: admin
Priority: optional
Maintainer: Leon BCM Project <root@localhost>
Depends: libc6 (>= 2.44), libcrypt1 (>= 1:4.5.1)
Description: Private ASUS-compatible shell for the BCM service namespace
 Matching GT-BE19000AI BusyBox with a native signal-mask shell entry.
 No global applet links, setuid bit, service activation or host shell replacement.
''')
    sums=[]
    for path in sorted(stage.rglob('*')):
        if path.is_file() and 'DEBIAN' not in path.parts:
            sums.append(hashlib.md5(path.read_bytes()).hexdigest()+'  '+str(path.relative_to(stage)))
    (stage/'DEBIAN/md5sums').write_text('\n'.join(sums)+'\n')
    for path in [stage,*stage.rglob('*')]:
        if path.is_symlink():
            os.utime(path,(1791072000,1791072000), follow_symlinks=False)
            continue
        if path.is_dir(): path.chmod(0o755)
        elif path.parent != libexec: path.chmod(0o644)
        os.utime(path,(1791072000,1791072000))
    package = W/f'leon-asus-shell_{VERSION}_arm64.deb'
    assert not package.exists()
    subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','--build',str(stage),str(package)],check=True,
                   env={**os.environ,'SOURCE_DATE_EPOCH':'1791072000'},stdout=subprocess.DEVNULL)
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(package)]))) as archive:
        files=[]
        for member in archive:
            path=member.name.removeprefix('./')
            assert member.uid==member.gid==0 and not member.mode & 0o6000
            if member.isdir(): continue
            assert (member.isfile() or member.issym()) and (path.startswith('usr/libexec/asus/') or path.startswith('usr/share/doc/leon-asus-shell/'))
            if member.issym():
                assert path.removeprefix('usr/libexec/asus/sh-applets/') in ['[', '[[', 'test', 'echo', 'printf'] and member.linkname == '../busybox'
            files.append(path)
    record.update(status='built',package_path=str(package.relative_to(R)),sha256=sha(package),bytes=package.stat().st_size,files=files)
(W/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({key:record[key] for key in ['status','package_path','sha256','applets','same_applet_list_as_stock']},indent=2))

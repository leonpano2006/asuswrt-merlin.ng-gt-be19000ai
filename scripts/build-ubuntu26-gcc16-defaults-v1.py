#!/usr/bin/python3
"""Build six real native GCC16 defaults packages from audited Ubuntu defaults.

Only local packaging and archive inspection. No compiler/maintainer execution,
APT database changes, network, services, or device access. This is a new local
source-generated defaults family, not a rebuild of the upstream source archive.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1] / 'build/ubuntu26-development'
OUT = ROOT / 'defaults-v1'
OLD = Path('/tmp/be19000ai-ubuntu26-gcc-1000')
NATIVE = Path('/tmp/be19000ai-asus-native-build-v2')
REPO = Path(__file__).resolve().parents[1]
VERSION = '4:16.2.0-0leonb53.1'
TOOL_VERSION = '16.2.0-3ubuntu1+leonb53.1'
PACKAGES = ('gcc', 'g++', 'cpp', 'gcc-aarch64-linux-gnu',
            'g++-aarch64-linux-gnu', 'cpp-aarch64-linux-gnu')
DEPENDS = {
 'cpp-aarch64-linux-gnu': f'cpp-16-aarch64-linux-gnu (= {TOOL_VERSION})',
 'gcc-aarch64-linux-gnu': f'cpp-aarch64-linux-gnu (= {VERSION}), gcc-16-aarch64-linux-gnu (= {TOOL_VERSION})',
 'g++-aarch64-linux-gnu': f'cpp-aarch64-linux-gnu (= {VERSION}), gcc-aarch64-linux-gnu (= {VERSION}), g++-16-aarch64-linux-gnu (= {TOOL_VERSION})',
 'cpp': f'cpp-16 (= {TOOL_VERSION}), cpp-aarch64-linux-gnu (= {VERSION})',
 'gcc': f'cpp (= {VERSION}), cpp-aarch64-linux-gnu (= {VERSION}), gcc-16 (= {TOOL_VERSION}), gcc-aarch64-linux-gnu (= {VERSION})',
 'g++': f'cpp (= {VERSION}), cpp-aarch64-linux-gnu (= {VERSION}), gcc (= {VERSION}), g++-16 (= {TOOL_VERSION}), g++-aarch64-linux-gnu (= {VERSION}), gcc-16 (= {TOOL_VERSION})',
}

def require(ok, why):
 if not ok: raise RuntimeError(why)

def sha(data): return hashlib.sha256(data).hexdigest()

def ref(path):
 data = path.read_bytes()
 return {'path': str(path), 'sha256': sha(data), 'bytes': len(data)}

def paragraphs(path):
 result = {}
 for paragraph in path.read_text().split('\n\n'):
  fields = {}
  for line in paragraph.splitlines():
   if ': ' in line and not line.startswith(' '):
    key, value = line.split(': ', 1); fields[key] = value
  if 'Package' in fields: result[fields['Package']] = fields
 return result

def native_resolve(path):
 # Resolve absolute/relative namespace paths inside the frozen native buildroot.
 seen = set()
 for _ in range(64):
  require(path not in seen, 'Native link loop'); seen.add(path)
  parts = path.split('/'); changed = False
  for i in range(2, len(parts) + 1):
   prefix = '/'.join(parts[:i]); p = NATIVE / prefix.lstrip('/')
   if p.is_symlink():
    target = os.readlink(p)
    base = target if target.startswith('/') else posixpath.join(posixpath.dirname(prefix), target)
    path = posixpath.normpath(posixpath.join(base, *parts[i:])); changed = True; break
  if not changed:
   p = NATIVE / path.lstrip('/')
   require(p.is_file(), 'Native target missing: ' + path)
   return path
 raise RuntimeError('Native link depth')

def alternatives_scripts():
 return {
  'gcc': {
   'postinst': '''#!/bin/sh
set -e
case "$1" in configure)
 update-alternatives --quiet --install /usr/bin/cc cc /usr/bin/gcc 20 --slave /usr/share/man/man1/cc.1.gz cc.1.gz /usr/share/man/man1/gcc.1.gz
 update-alternatives --quiet --install /usr/bin/c89 c89 /usr/bin/c89-gcc 20 --slave /usr/share/man/man1/c89.1.gz c89.1.gz /usr/share/man/man1/c89-gcc.1.gz
 update-alternatives --quiet --install /usr/bin/c99 c99 /usr/bin/c99-gcc 20 --slave /usr/share/man/man1/c99.1.gz c99.1.gz /usr/share/man/man1/c99-gcc.1.gz
 ;; esac
''',
   'prerm': '''#!/bin/sh
set -e
case "$1" in remove|deconfigure)
 update-alternatives --quiet --remove cc /usr/bin/gcc
 update-alternatives --quiet --remove c89 /usr/bin/c89-gcc
 update-alternatives --quiet --remove c99 /usr/bin/c99-gcc
 ;; esac
'''},
  'g++': {
   'postinst': '''#!/bin/sh
set -e
case "$1" in configure)
 update-alternatives --quiet --install /usr/bin/c++ c++ /usr/bin/g++ 20 --slave /usr/share/man/man1/c++.1.gz c++.1.gz /usr/share/man/man1/g++.1.gz
 ;; esac
''',
   'prerm': '''#!/bin/sh
set -e
case "$1" in remove|deconfigure) update-alternatives --quiet --remove c++ /usr/bin/g++ ;; esac
'''},
  'cpp': {
   'postinst': '''#!/bin/sh
set -e
case "$1" in configure) update-alternatives --quiet --install /lib/cpp cpp /usr/bin/cpp 10 ;; esac
''',
   'prerm': '''#!/bin/sh
set -e
case "$1" in remove|deconfigure) update-alternatives --quiet --remove cpp /usr/bin/cpp ;; esac
'''},
 }

def inspect_archive(deb, expected, scripts):
 raw = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)])
 rows = []; found = set()
 with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
  for m in archive:
   name = m.name.removeprefix('./').lstrip('/')
   require(m.uid == m.gid == 0, 'Non-root archive owner')
   if m.isdir():
    require(m.mode == 0o755, 'Directory mode mismatch'); continue
   require(name in expected and name not in found, 'Unexpected/duplicate payload'); found.add(name)
   x = expected[name]
   require(m.mode == x['mode'], 'Leaf mode mismatch')
   row = {'path': '/' + name, 'mode': m.mode, 'uid': m.uid, 'gid': m.gid}
   if x['kind'] == 'symlink':
    require(m.issym() and m.linkname == x['target'], 'Link mismatch')
    row.update(kind='symlink', target=m.linkname)
   else:
    require(m.isfile() and sha(archive.extractfile(m).read()) == sha(x['data']), 'File mismatch')
    row.update(kind='regular', sha256=sha(x['data']), bytes=len(x['data']))
   rows.append(row)
 require(found == set(expected), 'Missing archive leaf')
 control_raw = subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(deb)])
 with tarfile.open(fileobj=io.BytesIO(control_raw)) as archive:
  files = {}
  for m in archive:
   require(m.uid == m.gid == 0, 'Control owner mismatch')
   if m.isdir(): require(m.mode == 0o755, 'Control directory mode'); continue
   name = m.name.removeprefix('./')
   require(m.isfile() and name in {'control','md5sums',*scripts}, 'Unexpected control hook')
   require(m.mode == (0o755 if name in scripts else 0o644), 'Control mode mismatch')
   files[name] = archive.extractfile(m).read()
  for name, data in scripts.items(): require(files[name] == data.encode(), 'Maintainer script mismatch')
 return rows

def main():
 require(__debug__, 'Python -O is unsupported')
 require(not OUT.exists(), 'Immutable output already exists')
 old = paragraphs(OLD / 'var/lib/dpkg/status')
 native = paragraphs(NATIVE / 'var/lib/dpkg/status')
 for pkg in PACKAGES:
  require(old[pkg]['Source'] == 'gcc-defaults (1.230ubuntu1)' and old[pkg]['Version'] == '4:15.2.0-5ubuntu1', 'Audited defaults mismatch')
 for pkg in ('gcc-16','g++-16','cpp-16','gcc-16-aarch64-linux-gnu','g++-16-aarch64-linux-gnu','cpp-16-aarch64-linux-gnu'):
  require(native[pkg]['Version'] == TOOL_VERSION and native[pkg]['Architecture'] == 'arm64', 'Custom native dependency mismatch')
 inputs = [ref(OLD / 'var/lib/dpkg/status'), ref(NATIVE / 'var/lib/dpkg/status'),
           ref(REPO / 'build/ubuntu26-gcc/bootstrap.json'), ref(REPO / 'build/ubuntu26-gcc/build-package-manifest.tsv')]
 planned = {}; omissions = []; native_links = []
 for pkg in PACKAGES:
  info = OLD / 'var/lib/dpkg/info'
  listing = info / (pkg + '.list'); checksums = info / (pkg + '.md5sums')
  inputs.extend([ref(listing), ref(checksums)])
  for suffix in ('.postinst','.prerm'):
   p = info / (pkg + suffix)
   if p.exists(): inputs.append(ref(p))
  for line in checksums.read_text().splitlines():
   digest, name = line.split(None, 1)
   require(hashlib.md5((OLD / name).read_bytes()).hexdigest() == digest, 'Installed baseline checksum mismatch')
  leaves = {}
  for original in listing.read_text().splitlines():
   name = original.lstrip('/'); p = OLD / name
   if p.is_symlink():
    target = os.readlink(p).replace('-15','-16').replace('/15/','/16/')
    if name == 'usr/share/man/man1/cpp.1.gz':
     omissions.append({'package':pkg,'path':'/'+name,'reason':'Custom cpp-16 has no cpp-16.1.gz; avoid dangling alias'})
     continue
    leaves[name] = {'kind':'symlink','target':target,'mode':0o777}
    if name.startswith(('usr/bin/','usr/lib/bfd-plugins/')):
     dst = posixpath.normpath(target if target.startswith('/') else posixpath.join(posixpath.dirname('/'+name), target))
     native_links.append({'path':'/'+name,'target':target,'resolved_native_target':native_resolve(dst)})
   elif p.is_file():
    inputs.append(ref(p)); leaves[name] = {'kind':'regular','data':p.read_bytes(),'mode':0o755 if name in ('usr/bin/c89-gcc','usr/bin/c99-gcc') else 0o644}
  planned[pkg] = leaves
 # Replace the upstream changelog with truthful local source-generated history.
 changelog = f'''leon-gcc16-defaults ({VERSION}) resolute; urgency=medium

  * Native arm64 defaults derived from installed Ubuntu gcc-defaults 1.230ubuntu1.
  * Route generic/native-prefixed compiler and LTO tools to the existing custom
    GCC 16.2 packages, with exact dependencies and distribution alternatives.
  * No compiler or runtime binaries are rebuilt or copied.

 -- BE19000AI local integration <local@invalid>  Tue, 06 Oct 2026 10:00:00 +0000
'''.encode()
 planned['cpp-aarch64-linux-gnu']['usr/share/doc/cpp-aarch64-linux-gnu/changelog.Debian.gz'] = {'kind':'regular','data':gzip.compress(changelog,mtime=0),'mode':0o644}
 scripts = alternatives_scripts()
 OUT.mkdir(mode=0o755,parents=True)
 result = {'schema':1,'status':'building','version':VERSION,'architecture':'arm64',
  'source_derivation':'Local source-generated package family from installed authenticated Ubuntu defaults payload/metadata; no upstream source archive rebuild',
  'upstream_baseline_source':'gcc-defaults 1.230ubuntu1','upstream_baseline_version':'4:15.2.0-5ubuntu1',
  'custom_compiler_version':TOOL_VERSION,'inputs':inputs,'builder':ref(Path(__file__)),
  'builder_invocations':1,'deb_build_invocations':0,'compiler_invocations':0,
  'packages':[],'native_default_links':native_links,'omitted_dangling_man_aliases':omissions,
  'maintainer_scripts_scope':'Only dpkg configure/remove alternatives registration for cc,c++,c89,c99,cpp; scripts not executed during build',
  'compiler_or_runtime_binaries_copied':False,'fake_generic_provides':False,
  'device_accessed':False,'network_accessed':False,'apt_database_changed':False,
  'services_started':False,'installed':False}
 try:
  for pkg in PACKAGES:
   stage = OUT / 'stage' / pkg; stage.mkdir(parents=True)
   for name, leaf in planned[pkg].items():
    p = stage / name; p.parent.mkdir(parents=True,exist_ok=True)
    if leaf['kind'] == 'symlink': p.symlink_to(leaf['target'])
    else: p.write_bytes(leaf['data']); p.chmod(leaf['mode'])
   control = stage / 'DEBIAN'; control.mkdir()
   meta = f'''Package: {pkg}
Source: leon-gcc16-defaults
Version: {VERSION}
Architecture: arm64
Section: devel
Priority: optional
Maintainer: BE19000AI local integration <local@invalid>
Depends: {DEPENDS[pkg]}
Description: Native GNU {'C++' if pkg.startswith('g++') else 'C preprocessor' if pkg.startswith('cpp') else 'C'} default entry points for custom GCC 16
 Routes default commands to the installed custom native arm64 GCC 16 packages.
 Contains reviewed entrypoint links and distribution-style alternatives only.
 No compiler/runtime binaries, services, or boot configuration are replaced.
'''
   # These are real gcc/g++ packages; no virtual gcc/g++ or build-essential Provides.
   (control / 'control').write_text(meta)
   md5 = ''.join(hashlib.md5(x['data']).hexdigest()+'  '+name+'\n' for name,x in sorted(planned[pkg].items()) if x['kind']=='regular')
   (control / 'md5sums').write_text(md5)
   for name,data in scripts.get(pkg,{}).items(): (control / name).write_text(data); (control / name).chmod(0o755)
   for p in stage.rglob('*'):
    if p.is_symlink(): continue
    if p.is_dir(): p.chmod(0o755)
    elif p.parent == control: p.chmod(0o755 if p.name in scripts.get(pkg,{}) else 0o644)
   stage.chmod(0o755)
   deb = OUT / f'{pkg}_{VERSION.split(":", 1)[1]}_arm64.deb'
   result['deb_build_invocations'] += 1
   subprocess.run(['dpkg-deb','--root-owner-group','-Zzstd','--build',str(stage),str(deb)],check=True)
   rows = inspect_archive(deb,planned[pkg],scripts.get(pkg,{}))
   result['packages'].append({'name':pkg,'architecture':'arm64','version':VERSION,
    'depends':DEPENDS[pkg],'deb':ref(deb),'files':rows,
    'maintainer_scripts':{name:{'sha256':sha(data.encode()),'bytes':len(data.encode())} for name,data in scripts.get(pkg,{}).items()},
    'archive_owner_mode_hash_verified':True})
  require(result['deb_build_invocations']==6 and len(result['packages'])==6,'Incomplete family')
  result['status']='six_real_native_gcc16_defaults_packages_built_not_installed'
  result['all_archive_owners_root']=True; result['all_archive_directories_mode0755']=True
  (OUT / 'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps({'status':result['status'],'manifest':ref(OUT/'manifest.json'),'packages':[x['deb'] for x in result['packages']]},indent=2))
 except Exception as error:
  result['status']='failed_retained_no_automatic_retry';result['error']=str(error)
  (OUT / 'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
  raise

if __name__=='__main__': main()

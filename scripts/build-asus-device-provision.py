#!/usr/bin/env python3
"""Build device-local identity code and exercise only isolated synthetic inputs."""
import argparse,hashlib,io,json,posixpath,re,shutil,subprocess,tarfile,tempfile
from pathlib import Path
from elftools.elf.elffile import ELFFile
R=Path(__file__).resolve().parents[1];S=R/'scripts/asus-integration/device-provision'
ARCHIVE=R/'build/ubuntu26-rootfs/ubuntu26-bcm-asus-runtime07-archive-sealed-v1.tar'
ARCHIVE_SHA='2f0eafc638180019bb44b230e71877e200886e9c6afc9895bb299b0d6e4ca688'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 if not __debug__:raise RuntimeError("Optimized Python cannot verify the device identity build policy")
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);p.add_argument('--identity-only',action='store_true');p.add_argument('--identity-test-manifest',type=Path);a=p.parse_args();assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
 out=R/'build/asus-device-provision'/a.label;out.mkdir(parents=True,exist_ok=False);inp=Path(tempfile.mkdtemp(prefix='asus-device-provision-src-'));inp.chmod(0o755)
 assert sha(ARCHIVE)==ARCHIVE_SHA
 closure={};links={}
 with tarfile.open(ARCHIVE) as tar:
  entries={m.name.removeprefix('./'):m for m in tar}
  def resolve(path):
   parts=posixpath.normpath('/'+path.lstrip('/')).lstrip('/').split('/');followed=0;i=0
   while i<len(parts):
    current='/'.join(parts[:i+1]);member=entries[current]
    if member.issym():
     links['/'+current]=member.linkname;followed+=1;assert followed<40
     target=member.linkname if member.linkname.startswith('/') else posixpath.join('/'+posixpath.dirname(current),member.linkname)
     parts=posixpath.normpath(posixpath.join(target,*parts[i+1:])).lstrip('/').split('/');i=0;continue
    if member.islnk():followed+=1;assert followed<40;parts=posixpath.normpath('/'+member.linkname).lstrip('/').split('/');i=0;continue
    i+=1
   name='/'.join(parts);member=entries[name];assert member.isfile() and member.uid==0 and not(member.mode&0o022);return '/'+name,tar.extractfile(member).read()
  for alias in ['bin','sbin','lib','lib64']:
   if alias in entries and entries[alias].issym():links['/'+alias]=entries[alias].linkname
  todo=['/usr/sbin/useradd','/usr/bin/ssh-keygen']
  for name in entries:
   if name.startswith('usr/lib/aarch64-linux-gnu/libnss_') and name.endswith('.so.2'):todo.append('/'+name)
  for name in ['etc/nsswitch.conf','etc/login.defs','etc/default/useradd','etc/ld.so.cache']:
   if name in entries:todo.append('/'+name)
  while todo:
   name,data=resolve(todo.pop());
   if name in closure:continue
   closure[name]=hashlib.sha256(data).hexdigest()
   if data[:4]!=b'\x7fELF':continue
   elf=ELFFile(io.BytesIO(data));assert elf.header.e_machine=='EM_AARCH64'
   for segment in elf.iter_segments():
    if segment.header.p_type=='PT_INTERP':todo.append(segment.get_interp_name())
   dynamic=elf.get_section_by_name('.dynamic')
   if dynamic:
    for tag in dynamic.iter_tags():
     assert tag.entry.d_tag not in ['DT_RPATH','DT_RUNPATH'],(name,tag.entry.d_tag)
     if tag.entry.d_tag=='DT_NEEDED':
      candidate='/usr/lib/aarch64-linux-gnu/'+tag.needed
      assert candidate.lstrip('/') in entries,candidate;todo.append(candidate)
 lines=['/* Exact final Ubuntu archive helper closure, generated, no secrets. */','#ifndef LEON_PROVISION_POLICY_H','#define LEON_PROVISION_POLICY_H','#define LEON_PROVISION_GENERATION "be19000ai-ubuntu26-kernel10-systemd-v1\\n"','#define LEON_PROVISION_ARCHIVE_SHA256 "'+ARCHIVE_SHA+'"','struct leon_provision_file {const char *path,*sha256;};','static const struct leon_provision_file leon_provision_files[]={']
 for name,digest in sorted(closure.items()):lines.append('{'+json.dumps(name)+','+json.dumps(digest)+'},')
 lines+=['};','#define LEON_PROVISION_FILE_COUNT (sizeof(leon_provision_files)/sizeof(leon_provision_files[0]))','struct leon_provision_link {const char *path,*target;};','static const struct leon_provision_link leon_provision_links[]={']
 for name,target in sorted(links.items()):lines.append('{'+json.dumps(name)+','+json.dumps(target)+'},')
 lines+=['};','#define LEON_PROVISION_LINK_COUNT (sizeof(leon_provision_links)/sizeof(leon_provision_links[0]))','#endif']
 (out/'provision-policy.h').write_text('\n'.join(lines)+'\n');shutil.copyfile(out/'provision-policy.h',inp/'provision-policy.h')
 sources=[];(out/'source-snapshot').mkdir()
 files=[S/name for name in ['identity.h','identity.c','identity-fixture.c']]+[R/'scripts/asus-integration/openssh'/name for name in ['control.h','validate.h']]+[R/'scripts/asus-integration/trial-guard/runtime/sha256-compat.h']
 if not a.identity_only:files.extend([S/'coordinator.c',R/'scripts/asus-integration/slot-proof/p11-clear-view.h'])
 test_evidence=None
 if a.identity_test_manifest:
  tested=a.identity_test_manifest.resolve();tm=json.loads(tested.read_text());assert tm['passed'] and tm['returncode']==0
  prior=R/tm['build_manifest']['path'];assert sha(prior)==tm['build_manifest']['sha256'];pm=json.loads(prior.read_text());known={x['path']:x['sha256'] for x in pm['sources']}
  for source in files:
   if source.name not in ['coordinator.c','p11-clear-view.h']:assert sha(source)==known[str(source.relative_to(R))],source
  assert sha(out/'provision-policy.h')==pm['generated_policy_sha256']
  results=tested.parent/'result.json';assert sha(results)==tm['result_sha256'];tr=json.loads(results.read_text());assert tr['passed'] and len(tr['cases'])==19
  test_evidence={'path':str(tested.relative_to(R)),'sha256':sha(tested),'result':{'path':str(results.relative_to(R)),'sha256':sha(results)}}
 for source in files:shutil.copyfile(source,inp/source.name);shutil.copyfile(source,out/'source-snapshot'/source.name);sources.append({'path':str(source.relative_to(R)),'sha256':sha(source)})
 shutil.copyfile(R/'build/asus-trial-runtime/native-v15/sha256.c',inp/'sha256.c')
 root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 worker=r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"; identity_only="$4"
mount --make-rprivate /
mkdir -m0755 "$root/work/device-provision-$label"
cp "$inputs"/*.[ch] "$root/work/device-provision-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" "$identity_only" <<'BUILD'
set -euo pipefail
cd "/work/device-provision-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -static-pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" identity.c identity-fixture.c -o identity-fixture
if test "$2" = no; then
 ccache gcc-16 "${flags[@]}" coordinator.c identity.c sha256.c -o device-provision
 readelf -h -l -d device-provision > device-elf.txt
 ./device-provision --provision-device-identity > coordinator-refusal.log 2>&1 && exit 1 || test "$?" = 1
 grep -Fx 'LEON_DEVICE_IDENTITY_REFUSED stage=stock-root-and-namespace' coordinator-refusal.log
 ./device-provision --invalid > coordinator-badargs.log 2>&1 && exit 1 || test "$?" = 64
 test ! -s coordinator-badargs.log
fi
gcc-16 --version > compiler.txt
BUILD
'''
 (inp/'build.sh').write_text(worker)
 with (out/'build.log').open('w') as log:subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(inp/'build.sh'),str(root),str(inp),a.label,'yes' if a.identity_only else 'no'],stdout=log,stderr=subprocess.STDOUT,check=True)
 stage=root/('work/device-provision-'+a.label)
 for name in ['identity-fixture','device-provision','device-elf.txt','compiler.txt','coordinator-refusal.log','coordinator-badargs.log']:
  if(stage/name).exists():shutil.copyfile(stage/name,out/name)
 for name in ['identity-fixture','device-provision']:
  if(out/name).exists():(out/name).chmod(0o755)
 receipt={'status':'compiled_identity_only' if a.identity_only else 'compiled_runtime_unvalidated','identity_only':a.identity_only,'sources':sources,'helper_closure':closure,'resolved_archive_symlinks':links,'archive':{'path':str(ARCHIVE.relative_to(R)),'sha256':ARCHIVE_SHA},'generated_policy_sha256':sha(out/'provision-policy.h'),'outputs':{name:sha(out/name) for name in ['identity-fixture','device-provision','device-elf.txt','compiler.txt','coordinator-refusal.log','coordinator-badargs.log'] if(out/name).exists()},'synthetic_tests_passed':bool(test_evidence),'identity_transaction_validation_passed':bool(test_evidence),'identity_test_evidence':test_evidence,'coordinator_nondevice_refusal_passed':not a.identity_only,'production_ready':False,'device_accessed':False,'real_credentials_read':False,'services_started':False,'stock_network_namespace_available':False,'device_coordinator_mount_namespace_only':True,'synthetic_tests_network_isolated':True,'builder_sha256':sha(Path(__file__))};(out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n');print(str(out/'manifest.json'))
if __name__=='__main__':main()

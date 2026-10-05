#!/usr/bin/env python3
"""Build a static readonly, exact-root verifier. Never opens a device or connects."""
import argparse,collections,hashlib,json,os,posixpath,re,shutil,stat,subprocess,tarfile,tempfile
from pathlib import Path,PurePosixPath
R=Path(__file__).resolve().parents[1];S=R/'scripts/asus-integration/root-verify'
ARCHIVE=R/'build/ubuntu26-provisioning/runtime07-archive-v1/trial-root-needs-device-identity.tar'
ARCHIVE_SHA='4dd32d7e630eb3f09d0e990c05979411cfd7dee27e390419b7d6bb5986be0ca9'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def norm(p):
 p=str(PurePosixPath(p));assert not p.startswith('/') and '..' not in PurePosixPath(p).parts;assert all(ord(c)>=32 and ord(c)!=127 for c in p);return p
def c(s):return json.dumps(s,ensure_ascii=True)
def generate(archive,public,out,with_boot_diagnostics=False):
 entries={};attrs=[];raw={}
 with tarfile.open(archive) as t:
  for m in t:
   name=norm(m.name);assert name not in entries
   kind=stat.S_IFDIR if m.isdir() else stat.S_IFLNK if m.issym() else stat.S_IFREG if m.isfile() or m.islnk() else stat.S_IFCHR if m.ischr() else stat.S_IFBLK if m.isblk() else 0;assert kind
   content=t.extractfile(m).read() if m.isfile() else None
   if name in ['etc/passwd','etc/shadow','etc/group','etc/gshadow','etc/subuid','etc/subgid'] or name.startswith('etc/skel/'):raw[name]=content
   start=len(attrs)
   for k,v in m.pax_headers.items():
    if k.startswith('SCHILY.xattr.'):attrs.append((k.removeprefix('SCHILY.xattr.'),v.encode('utf-8','surrogateescape')))
   entries[name]={'path':name,'type':kind,'mode':m.mode,'uid':m.uid,'gid':m.gid,'links':1,'size':m.size if m.isfile() else 0,'digest':hashlib.sha256(content).hexdigest() if content is not None else '', 'target':m.linkname if m.issym() else '', 'canonical_name':norm(m.linkname) if m.islnk() else None,'attr_start':start,'attrs':len(attrs)-start,'special':0,'identity':0,'major':m.devmajor,'minor':m.devminor}
 archive_names=set(entries)
 def payload(name,data,mode=0o644,uid=0,gid=0,kind=stat.S_IFREG,special=0,target=''):
  attrs0=entries.get(name,{});entries[name]={'path':name,'type':kind,'mode':mode,'uid':uid,'gid':gid,'links':1,'size':len(data),'digest':hashlib.sha256(data).hexdigest(),'target':target,'canonical_name':None,'attr_start':attrs0.get('attr_start',0),'attrs':attrs0.get('attrs',0),'special':special,'identity':1,'major':0,'minor':0}
 admin='MastermixStudios'
 for name in ['passwd','shadow','group','gshadow','subuid','subgid']:
  assert raw['etc/'+name] is not None and not any(line.startswith((admin+':').encode()) for line in raw['etc/'+name].splitlines())
  payload('etc/'+name+'-',raw['etc/'+name],0o640 if name in ('shadow','gshadow') else 0o644,0,42 if name in ('shadow','gshadow') else 0)
 payload('etc/passwd',raw['etc/passwd']+b'MastermixStudios:x:1000:1000::/home/MastermixStudios:/bin/bash\n')
 for name,suffix in [('group',b'MastermixStudios:x:1000:\n'),('gshadow',b'MastermixStudios:!::\n')]:
  lines=raw['etc/'+name].splitlines(keepends=True);found=0
  for i,line in enumerate(lines):
   if line.startswith(b'sudo:'):
    fields=line.rstrip(b'\n').split(b':');assert len(fields)==4 and fields[-1]==b'';fields[-1]=b'MastermixStudios';lines[i]=b':'.join(fields)+b'\n';found+=1
  assert found==1;payload('etc/'+name,b''.join(lines)+suffix,0o640 if name=='gshadow' else 0o644,0,42 if name=='gshadow' else 0)
 payload('etc/shadow',b'',0o640,0,42,special=1)
 for name in ['subuid','subgid']:
  assert raw['etc/'+name]==b'';payload('etc/'+name,b'MastermixStudios:100000:65536\n')
 payload('home/'+admin,b'',0o750,1000,1000,stat.S_IFDIR)
 for name,data in raw.items():
  if name.startswith('etc/skel/'):
   original=entries[name];assert original['type']==stat.S_IFREG;payload('home/'+admin+'/'+name.removeprefix('etc/skel/'),data,original['mode'],1000,1000)
 payload('var/lib/leon-asus-ssh',b'',0o700,kind=stat.S_IFDIR)
 payload('var/lib/leon-asus-ssh/provision.lock',b'',0o600)
 payload('var/lib/leon-asus-ssh/account',b'LEON_SSH_ACCOUNT_V1 MastermixStudios 1000\n',0o600)
 payload('var/lib/leon-asus-ssh/device-identity',b'LEON_SSH_DEVICE_V1_OK\n',0o600)
 payload('lost+found',b'',0o700,kind=stat.S_IFDIR);entries['lost+found']['identity']=0
 for typ,name in [('ssh-rsa','rsa'),('ecdsa-sha2-nistp256','ecdsa'),('ssh-ed25519','ed25519')]:
  payload('etc/ssh/ssh_host_'+name+'_key',b'',0o600,special=2)
  payload('etc/ssh/ssh_host_'+name+'_key.pub',b'',0o644,special=3,target=public[typ])
 if with_boot_diagnostics:
  # Explicit post-provision overlay, not a blanket exemption for runtime data.
  diag='etc/leon/boot-diagnostics';dropdir='etc/systemd/system/leon-asus-resolver.path.d';drop=dropdir+'/10-leon-ordering.conf'
  assert not {diag,dropdir,drop}&set(entries)
  approved=R/'configs/ubuntu26/asus-resolver-ordering/10-leon-ordering.conf'
  assert sha(approved)=='2a51b2b2ad2dc3393dcf6557824683548d1d0118d9416e7d4f0470ba5f63a7d4'
  payload(diag,bytes(16384),0o600,special=4)
  payload(dropdir,b'',0o755,kind=stat.S_IFDIR)
  payload(drop,approved.read_bytes(),0o644)
 names=sorted(entries);indices={n:i for i,n in enumerate(names)};groups=collections.Counter()
 for e in entries.values():
  if e['type']==stat.S_IFREG:
   canonical=e['canonical_name'] or e['path'];seen=set()
   while entries[canonical]['canonical_name']:
    assert canonical not in seen;seen.add(canonical);canonical=entries[canonical]['canonical_name']
   e['final_canonical']=canonical;groups[canonical]+=1
 for e in entries.values():
  e['canonical']=-1
  if e['type']==stat.S_IFREG:
   original=entries[e['final_canonical']];e['links']=groups[e['final_canonical']]
   if e['canonical_name']:
    for k in ['size','digest','attr_start','attrs']:e[k]=original[k]
    e['canonical']=indices[e['final_canonical']]
 lines=['/* Generated exact activated archive + narrowly reviewed identity-v8 deltas. */','#ifndef RV_POLICY_H','#define RV_POLICY_H','#include <stdint.h>','#define RV_ARCHIVE_SHA '+c(ARCHIVE_SHA),'#define RV_SHADOW_BASE '+c(raw['etc/shadow'].decode()),'struct rv_attr {const char *name;const unsigned char *data;unsigned size;};']
 for i,(name,b) in enumerate(attrs):lines.append('static const unsigned char rv_attr_data_'+str(i)+'[]={'+','.join(str(x) for x in b)+'};')
 lines+=['static const struct rv_attr rv_attrs[]={']
 for i,(name,b) in enumerate(attrs):lines.append('{'+c(name)+',rv_attr_data_'+str(i)+','+str(len(b))+'},')
 if not attrs:lines.append('{0,0,0},')
 lines+=['};','struct rv_entry {const char *path,*digest,*target;uint64_t size;unsigned type,mode,uid,gid,links,attr_start,attrs,special,identity,major,minor;int canonical;};','static const struct rv_entry rv_entries[]={']
 for name in names:
  e=entries[name];vals=[c(e[k]) for k in ['path','digest','target']]+[str(e[k]) for k in ['size','type','mode','uid','gid','links','attr_start','attrs','special','identity','major','minor','canonical']];lines.append('{'+','.join(vals)+'},')
 lines+=['};','#define RV_COUNT (sizeof(rv_entries)/sizeof(rv_entries[0]))','#endif'];(out/'root-policy.h').write_text('\n'.join(lines)+'\n')
 return {'entries':len(entries),'archive_entries':len(archive_names),'mutable_paths':[n for n,e in entries.items() if e['identity']],'extra_filesystem_entry':'lost+found root:root0700 empty','xattrs':len(attrs),'semantics':'Exact uid/gid/mode/type, non-directory nlink, hardlink identity, all xattrs, every regular payload and symlink target; timestamps are lifetime checked, not compared to archive because useradd and mount metadata legitimately change.'}
def main():
 if not __debug__:raise RuntimeError('Optimized Python disables evidence gates')
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--public-receipt',type=Path,required=True);p.add_argument('--with-boot-diagnostics',action='store_true');a=p.parse_args();assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
 out=R/'build/ubuntu26-root-verifier'/a.label;out.mkdir(parents=True,exist_ok=False);assert sha(ARCHIVE)==ARCHIVE_SHA
 text=a.public_receipt.read_text();public={}
 for line in text.splitlines():
  if line.startswith('public_key '):
   value=line.removeprefix('public_key ');kind=value.split(' ')[0];assert re.fullmatch(r'[A-Za-z0-9@._+-]+ [A-Za-z0-9+/=]+',value) and kind not in public;public[kind]=value
 assert len(public)==3
 policy=generate(ARCHIVE,public,out,a.with_boot_diagnostics)
 policy['boot_diagnostics_overlay']=a.with_boot_diagnostics
 policy['booted_root_limit']='This does not permit unrelated runtime changes such as machine-id, journals or new slot-token files. It cannot certify the current booted root by adding this option alone.'
 sourcefiles=[S/'verify.c',S/'verify.h',S/'coordinator.c',R/'scripts/asus-integration/device-provision/identity.c',R/'scripts/asus-integration/device-provision/identity.h',R/'scripts/asus-integration/openssh/validate.h',R/'scripts/asus-integration/openssh/control.h',R/'scripts/asus-integration/slot-proof/p11-clear-view.h',R/'scripts/asus-integration/trial-guard/runtime/sha256-compat.h',R/'build/asus-trial-runtime/native-v17-enabled/sha256.c']
 inp=Path(tempfile.mkdtemp(prefix='leon-root-verifier-'));inp.chmod(0o755);snapshot=out/'source-snapshot';snapshot.mkdir()
 for f in sourcefiles:shutil.copyfile(f,inp/f.name);shutil.copyfile(f,snapshot/f.name)
 shutil.copyfile(out/'root-policy.h',inp/'root-policy.h')
 root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 worker=r'''set -euo pipefail
root="$1";inputs="$2";label="$3"
mount --make-rprivate /
mkdir -m0755 "$root/work/root-verifier-$label"
cp "$inputs"/*.[ch] "$root/work/root-verifier-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/root-verifier-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
ccache gcc-16 -std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-misleading-indentation -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now coordinator.c verify.c identity.c sha256.c -o root-verify
readelf -h -l -d root-verify > elf.txt
./root-verify --verify-p11-readonly > nondevice.log 2>&1 && exit 1 || test "$?" = 1
grep -Fx 'LEON_ROOT_VERIFY_REFUSED stage=stock-root-and-namespace' nondevice.log
BUILD
'''
 (inp/'build.sh').write_text(worker)
 with (out/'build.log').open('w') as log:subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(inp/'build.sh'),str(root),str(inp),a.label],stdout=log,stderr=subprocess.STDOUT,check=True)
 for n in ['root-verify','elf.txt','nondevice.log']:shutil.copyfile(root/('work/root-verifier-'+a.label)/n,out/n)
 (out/'root-verify').chmod(0o755)
 r={'status':'built_readonly_verifier_fixture_pending','scope':'new local tool; no device operation','archive':{'path':str(ARCHIVE.relative_to(R)),'sha256':ARCHIVE_SHA},'public_receipt':{'path':str(a.public_receipt),'sha256':sha(a.public_receipt)},'policy':policy,'policy_sha256':sha(out/'root-policy.h'),'sources':[{'path':str(f.relative_to(R)),'sha256':sha(f)} for f in sourcefiles],'executable':{'path':str((out/'root-verify').relative_to(R)),'sha256':sha(out/'root-verify')},'nondevice_refusal_passed':True,'device_accessed':False,'secret_exports':False,'private_mount_readonly_noload':True,'fixture_passed':False,'builder_sha256':sha(Path(__file__))};(out/'manifest.json').write_text(json.dumps(r,indent=2)+'\n');print(str(out/'manifest.json'))
if __name__=='__main__':main()

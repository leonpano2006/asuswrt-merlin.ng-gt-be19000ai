#!/usr/bin/env python3
"""Read-only installed-payload ownership/mode peer audit of an offline rootfs tar."""
import argparse,collections,hashlib,json,tarfile
from pathlib import Path,PurePosixPath
R=Path(__file__).resolve().parents[1]
def canonical(n):
 p=PurePosixPath(n);assert not p.is_absolute() and '..' not in p.parts
 return str(p)
def sha(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--rootfs',required=True,type=Path);p.add_argument('--label',required=True);a=p.parse_args();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 owners=collections.defaultdict(set);versions={};rows={}
 with tarfile.open(a.rootfs) as t:
  for m in t:
   n=canonical(m.name);assert n not in rows;rows[n]=m
   if n.startswith('var/lib/dpkg/info/') and n.endswith('.list') and m.isfile():
    package=Path(n).name.removesuffix('.list')
    for path in t.extractfile(m).read().decode(errors='replace').splitlines():owners[canonical(path.removeprefix('/'))].add(package)
   if n=='var/lib/dpkg/status':
    for para in t.extractfile(m).read().decode().split('\n\n'):
     fields={l.split(': ',1)[0]:l.split(': ',1)[1] for l in para.splitlines() if ': ' in l and not l[0].isspace()}
     if fields.get('Status')=='install ok installed':versions[fields['Package']+':'+fields['Architecture']]=fields['Version']
  writable=[];privileged=[];executables=[];special=[]
  for name,m in rows.items():
   if m.issym():continue
   effective=m
   if m.islnk():
    seen=set()
    while effective.islnk():
     target=canonical(effective.linkname);assert target not in seen;seen.add(target);effective=rows[target]
   item={'path':name,'mode':oct(effective.mode),'uid':effective.uid,'gid':effective.gid,'kind':'directory' if m.isdir() else 'regular' if m.isfile() else 'hardlink' if m.islnk() else 'special','packages':sorted(owners.get(name,[]))}
   if effective.mode&0o022:
    if m.isdir() and effective.mode&0o1000 and name in ['tmp','var/tmp','run/lock']:special.append({**item,'classification':'expected sticky shared directory'})
    elif m.isdir() and name=='var/mail' and effective.mode==0o2775:special.append({**item,'classification':'standard mail-group spool directory'})
    else:writable.append(item)
   if effective.mode&0o6000 and not m.isdir():privileged.append(item)
   if (m.isfile() or m.islnk()) and effective.mode&0o111 and effective.mode&0o022:executables.append(item)
 critical=[x for x in writable if x['path']=='.' or x['path'].startswith(('usr/','etc/','bin/','sbin/','lib/','lib64/'))]
 counts=collections.Counter(p for x in critical for p in x['packages']);unknown=[x for x in critical if not x['packages']]
 report={'schema_version':1,'scope':'Installed tar metadata with dpkg list ownership for all installed packages; no live state or services accessed. This does not replace maintainer-script security review or prove every original official archive mode.','rootfs':{'path':str(a.rootfs),'sha256':sha(a.rootfs)},'installed_packages':versions,'entry_count':len(rows),'critical_group_or_world_writable':critical,'critical_count':len(critical),'critical_by_package':dict(counts),'critical_unowned':unknown,'other_nonsticky_writable': [x for x in writable if x not in critical],'intentional_special_modes':special,'writable_executables':executables,'setuid_setgid_files':privileged,'custom_setuid_files':[x for x in privileged if any(p.startswith('leon-') for p in x['packages'])],'runtime_accepted':False,'router_access':False,'read_only':True,'builder_sha256':sha(Path(__file__))}
 out=R/'reports/ubuntu26'/('installed-modes-'+a.label+'.json');out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'report':str(out),'packages':len(versions),'critical_count':len(critical),'critical_by_package':dict(counts),'writable_executables':executables,'custom_setuid_files':report['custom_setuid_files'],'critical_unowned':unknown},indent=2))
if __name__=='__main__':main()

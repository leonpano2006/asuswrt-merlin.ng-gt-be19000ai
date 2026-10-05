#!/usr/bin/env python3
"""Check private aliases against exact base + runtime payloads without execution."""
import argparse,hashlib,json,posixpath,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
j=json.loads(a.manifest.read_text());projection=Path(j['source_projection']);pr=json.loads(projection.read_text())
assert sha(projection)==j['source_projection_sha256'];base=R/pr['base']['path'];assert sha(base)==pr['base']['sha256']
regular={};links={}
with tarfile.open(base) as archive:
 for m in archive:
  name='/'+m.name.removeprefix('./')
  if m.isfile():regular[name]={'sha256':hashlib.sha256(archive.extractfile(m).read()).hexdigest(),'mode':m.mode,'uid':m.uid,'gid':m.gid,'provider':'base'}
  elif m.issym():links[name]=posixpath.normpath(m.linkname if m.linkname.startswith('/') else posixpath.join(posixpath.dirname(name),m.linkname))
  elif m.islnk():links[name]='/'+m.linkname.removeprefix('./').lstrip('/')
for x in pr['files']:
 source=projection.parent/'stage'/x['target'].lstrip('/');assert sha(source)==x['sha256']
 regular[x['target']]={'sha256':x['sha256'],'mode':x['mode'],'uid':0,'gid':0,'provider':'runtime'}
for x in pr['aliases']:links[x['path']]=x['target']
def resolve(path):
 seen=set()
 for _ in range(64):
  assert path not in seen,('loop',path);seen.add(path)
  parts=path.split('/');changed=False
  for i in range(2,len(parts)+1):
   prefix='/'.join(parts[:i])
   if prefix in links:
    path=posixpath.normpath(links[prefix]+'/'+ '/'.join(parts[i:]));changed=True;break
  if not changed:return path
 raise AssertionError('deep link')
checked=[];deferred=[]
for link in sorted((R/j['payload']/'usr/share/asus/commands').rglob('*')):
 if not link.is_symlink():continue
 target=link.readlink().as_posix();view='/usr/'+link.relative_to(R/j['payload']/'usr/share/asus/commands').as_posix()
 if target=='/usr/libexec/asus/command-denied':
  deferred.append({'path':view,'target':target,'provider':'native integration package; must be present before namespace launch'});continue
 final=resolve(target);assert final in regular,(view,target,final)
 f=regular[final];assert f['uid']==f['gid']==0 and not f['mode']&0o022,(view,f)
 assert 'dropbear' not in final,(view,final)
 checked.append({'path':view,'target':target,'resolved':final,**f})
assert len(checked)+len(deferred)==1051
overrides=[r for r in j['rows'] if r['policy']=='private-vendor-override']
assert {x['path'] for x in overrides}=={'/usr/sbin/ip','/usr/sbin/tc','/usr/sbin/service'}
for name in ['reboot','halt','poweroff','shutdown','init','telinit','switch_root','pivot_root']:
 assert any(x['path']=='/usr/sbin/'+name for x in deferred),name
result={'schema_version':1,'status':'passed-static-alias-closure','production_ready':False,
        'manifest':str(a.manifest),'manifest_sha256':sha(a.manifest),'projection_sha256':sha(projection),
        'checked_aliases':checked,'native_block_helper_required':deferred,'resolved_alias_count':len(checked),
        'explicit_private_vendor_overrides':overrides,'no_unknown_target':True,'no_vendor_program_executed':True,
        'namespace_mount_runtime_validation':'peer fixture still required; this report is path/type/hash analysis only',
        'builder_sha256':sha(Path(__file__))}
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'resolved':len(checked),'native_denial_helper':len(deferred),'unknown':0}))

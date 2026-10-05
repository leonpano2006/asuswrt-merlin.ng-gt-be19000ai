#!/usr/bin/env python3
"""Create a private executable ASUS ELF projection, without activation or vendor execution."""
import argparse, collections, hashlib, importlib.util, io, json, os, re, shutil, stat, struct, subprocess, tarfile
from pathlib import Path, PurePosixPath
R=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('audit',R/'scripts/audit-asus-closure.py');a=importlib.util.module_from_spec(s);s.loader.exec_module(a)
TRIPS={'armel':'arm-linux-gnueabi','arm64':'aarch64-linux-gnu'}
BASE=R/'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-armel15-b53-v2.tar'
STOCK=R/'build/stock-rootfs';OUT=R/'build/asus-runtime-projection'
GNU=re.compile(r'^(?:ld-linux[^/]*|lib(?:c|m|pthread|dl|rt|anl|util|resolv|nsl|crypt|BrokenLocale|thread_db|gcc_s|stdc\+\+|atomic|gomp)\.so(?:\..*)?|libnss_.*\.so(?:\..*)?)$')
EXCLUDE={'/bin/busybox':'native private ASUS BusyBox package owns shell/applets','/sbin/ldconfig':'Ubuntu libc-bin owns loader cache', '/usr/sbin/dropbear':'native OpenSSH owns SSH','/usr/bin/dropbearmulti':'native OpenSSH owns SSH; exclude its actual multicall ELF as well as legacy aliases'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,b,mode=0o644):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);p.chmod(mode)
def dump(p,x):write(p,(json.dumps(x,indent=2,sort_keys=True)+'\n').encode())
def strip_search(raw):
 e=a.ELFFile(io.BytesIO(raw));dyn=e.get_section_by_name('.dynamic')
 if not dyn:return raw,[]
 size=dyn['sh_entsize'];offset=dyn['sh_offset'];fmt='<iI' if e.elfclass==32 else '<qQ'
 entries=[raw[o:o+size] for o in range(offset,offset+dyn['sh_size'],size)]
 removed=[struct.unpack(fmt,b)[1] for b in entries if struct.unpack(fmt,b)[0] in (15,29)]
 if not removed:return raw,[]
 keep=[b for b in entries if struct.unpack(fmt,b)[0] not in (15,29)]
 result=bytearray(raw);result[offset:offset+dyn['sh_size']]=b''.join(keep)+bytes(size*len(removed))
 return bytes(result),removed

def main():
 p=argparse.ArgumentParser();p.add_argument('--label',default='v1');p.add_argument('--base',type=Path,default=BASE);p.add_argument('--rc-dir',type=Path,default=R/'build/asus-rc-recovery/linked');args=p.parse_args();
 global_base=args.base.resolve();rc_dir=args.rc_dir.resolve();assert re.fullmatch('[a-z0-9-]+',args.label)
 out=OUT/args.label;assert not out.exists(),'Preserve previous candidate';out.mkdir(parents=True)
 stage=out/'stage';stage.mkdir()
 entries,links=a.inventory_directory(STOCK)
 ubuntu,ulinks,text=a.inventory_tar(global_base)
 basepaths=set()
 with tarfile.open(global_base) as t:
  for x in t:basepaths.add(a.clean(x.name))
 report={'schema_version':1,'label':args.label,'production_ready':False,'activated':False,'vendor_code_executed':False,
 'base':{'path':str(global_base.relative_to(R)),'sha256':sha(global_base)},'source_pin':'9b25e55ca5c56a6f01d6a56264c0f6c47459ada0',
 'scope':'Private executable application/library projection; no service units, triggers, maintainer scripts or public command aliases.',
 'files':[],'excluded':[],'aliases':[],'search_path_sanitized':[],'public_alias_plan':[], 'collision_audit':[]}
 projected={};metadata={};targets={}
 def put(orig,target,raw,abi,kind,source,mode=0o644):
  if target in targets:
   assert targets[target]==hashlib.sha256(raw).hexdigest(),target
   projected[orig]=target;return
  assert a.resolve(target,ulinks) not in basepaths,'Ubuntu package collision '+target
  clean,removed=strip_search(raw)
  if removed:report['search_path_sanitized'].append({'source':orig,'old_rpath':entries[orig]['rpath'],'old_runpath':entries[orig]['runpath'],'method':'remove only DT_RPATH/DT_RUNPATH dynamic entries; executable instructions/data untouched','before_sha256':hashlib.sha256(raw).hexdigest(),'after_sha256':hashlib.sha256(clean).hexdigest()})
  write(stage/target.lstrip('/'),clean,mode);projected[orig]=target;targets[target]=hashlib.sha256(clean).hexdigest()
  v=a.elf_info(target,clean);metadata[target]=v
  report['files'].append({'source':source,'original':orig,'target':target,'abi':abi,'kind':kind,'source_sha256':hashlib.sha256(raw).hexdigest(),'sha256':targets[target],'mode':mode})
 for orig,v in sorted(entries.items()):
  abi=v['abi'];name=PurePosixPath(orig).name
  if abi not in TRIPS or orig in EXCLUDE or GNU.fullmatch(name):
   report['excluded'].append({'path':orig,'sha256':v['sha256'],'reason':EXCLUDE.get(orig,'GNU runtime supplied by coherent Ubuntu multiarch packages' if GNU.fullmatch(name) else 'foreign target architecture anomaly')});continue
  islib=orig.startswith(('/lib/','/lib64/','/usr/lib/','/usr/lib64/')) and ('.so' in name)
  raw=(STOCK/orig.lstrip('/')).read_bytes();source='build/stock-rootfs'+orig
  if orig=='/sbin/rc':source=str((rc_dir/'rc').relative_to(R));raw=(R/source).read_bytes();target='/usr/libexec/asus/rc'
  elif orig=='/usr/lib/libovpn.so':source=str((rc_dir/'libovpn.so').relative_to(R));raw=(R/source).read_bytes();target='/usr/lib/'+TRIPS[abi]+'/asus/'+name
  elif islib:
   root=next(x for x in ['/usr/lib64/','/usr/lib/','/lib64/','/lib/'] if orig.startswith(x));tail=orig[len(root):]
   target='/usr/lib/'+TRIPS[abi]+'/asus/'+tail
  else:target='/usr/libexec/asus/vendor'+orig
  put(orig,target,raw,abi,'library' if islib else 'application',source,0o644 if islib else 0o755)
 # All vendor basenames (including nested SONAMEs) are visible in the ABI-private library root.
 def alias(path,target,abi,origin):
  if path==target:return
  assert path not in targets,path
  p=stage/path.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True)
  relative=os.path.relpath(target,str(PurePosixPath(path).parent))
  if p.is_symlink():
   if os.readlink(p)==relative:return
   # Exact stock firmware ships two libuuid.so.1 implementations. Preserve
   # its /lib-before-/usr/lib lookup and retain the alternate under its real name.
   assert path.endswith(('/libuuid.so.1','/libuuid.so')) and os.readlink(p)=='libuuid.so.1.0.0' and relative=='libuuid.so.1.2',(path,os.readlink(p),relative,origin)
   report['collision_audit'].append({'path':path,'selected':'libuuid.so.1.0.0','alternate':'libuuid.so.1.2','reason':'exact stock /lib precedes /usr/lib; both originals retained by real basename'})
   return
  assert not p.exists(),path
  assert a.resolve(path,ulinks) not in basepaths,'Ubuntu collision '+path
  p.symlink_to(relative);report['aliases'].append({'path':path,'target':target,'link':relative,'abi':abi,'original':origin})
 for orig,target in list(projected.items()):
  v=entries[orig]
  if target.startswith('/usr/lib/'):
   for name in {PurePosixPath(orig).name,v['soname']} - {None}:
    alias('/usr/lib/'+TRIPS[v['abi']]+'/asus/'+name,target,v['abi'],orig)
 for orig,to in sorted(links.items()):
  real=a.resolve(orig,links)
  if real not in projected:continue
  target=projected[real];abi=entries[real]['abi']
  if orig.startswith(('/lib/','/lib64/','/usr/lib/','/usr/lib64/')):
   root=next(x for x in ['/usr/lib64/','/usr/lib/','/lib64/','/lib/'] if orig.startswith(x));dest='/usr/lib/'+TRIPS[abi]+'/asus/'+orig[len(root):]
  elif orig.startswith(('/bin/','/sbin/','/usr/bin/','/usr/sbin/')):dest='/usr/libexec/asus/vendor'+orig
  else:continue
  if orig=='/sbin/init':report['excluded'].append({'path':orig,'reason':'systemd remains the only PID1 executable; no vendor init alias'});continue
  alias(dest,target,abi,orig)
 # Private duplicate rc alias supports vendor PATH dispatch without replacing systemd init.
 alias('/usr/libexec/asus/vendor/sbin/rc','/usr/libexec/asus/rc','armel','/sbin/rc')
 for name in ['nvram','wl','jq','sqlite3','curl']:
  candidates=[(orig,target) for orig,target in projected.items() if orig.endswith('/'+name)]
  assert len(candidates)==1,(name,candidates)
  orig,target=candidates[0];alias('/usr/libexec/asus/collector-tools/'+name,target,'armel',orig)
 for orig,target in sorted(projected.items()):
  canon=a.resolve(orig,{'/bin':'usr/bin','/sbin':'usr/sbin','/lib':'usr/lib','/lib64':'usr/lib64'})
  collision=a.resolve(canon,ulinks) in basepaths
  report['public_alias_plan'].append({'original':orig,'usrmerge_path':canon,'private_target':target,'ubuntu_collision':collision,'installed':False})
 report['path_contract']={'library_path_literal':'/usr/$LIB/asus','preload_literal':'/usr/$LIB/leon-asus/libleon-rc-notify.so',
 'private_path':'/usr/libexec/asus/vendor/sbin:/usr/libexec/asus/vendor/usr/sbin:/usr/libexec/asus/vendor/bin:/usr/libexec/asus/vendor/usr/bin:/usr/sbin:/usr/bin',
 'limitations':['Absolute vendor application and plugin paths still require reviewed namespace/public aliases; package presence alone is not complete filesystem integration.','No global ld.so.conf, LD_PRELOAD or /bin/sh replacement.']}
 # Static recursive loader scope includes the replacement rc export table for libovpn.
 allmeta=dict(ubuntu);allmeta.update(metadata)
 alllinks=dict(ulinks);alllinks.update({x['path']:x['target'] for x in report['aliases']})
 lookup={}
 for path,v in allmeta.items():
  lookup[(v['abi'],str(PurePosixPath(path).parent),PurePosixPath(path).name)]=path
 for path,to in alllinks.items():
  real=a.resolve(path,alllinks)
  if real in allmeta:lookup[(allmeta[real]['abi'],str(PurePosixPath(path).parent),PurePosixPath(path).name)]=real
 def find(v,name):
  for d in ['/usr/lib/'+TRIPS[v['abi']]+'/asus','/usr/lib/'+TRIPS[v['abi']]]:
   if (v['abi'],d,name) in lookup:return lookup[v['abi'],d,name]
  return None
 edges=[];checks=[]
 for target,v in metadata.items():
  closure={target};todo=[target];miss=[]
  while todo:
   item=allmeta[todo.pop()]
   for name in item['needed']:
    provider=find(item,name)
    if not provider:miss.append({'consumer':item['path'],'needed':name});continue
    if provider not in closure:closure.add(provider);todo.append(provider)
  exports=set().union(*(allmeta[x]['_exports'] for x in closure))
  unresolved=[{'consumer':x,**i} for x in closure for i in allmeta[x]['_imports'] if not i['weak'] and ((i['name'],i['version']) not in exports if i['version'] else not any(n==i['name'] for n,_ in exports))]
  checks.append({'target':target,'missing_libraries':miss,'unresolved_symbols':unresolved,'closure':sorted(closure)})
  for name in v['needed']:
   pp=find(v,name);edges.append({'consumer':target,'needed':name,'provider':pp})
 report['static_closure']=checks;report['dependency_edges']=edges
 report['private_imports']=[{'consumer':t,**i} for t,v in metadata.items() for i in v['private_imports']]
 report['counts']={'files':len(report['files']),'aliases':len(report['aliases']),'rpath_sanitized':len(report['search_path_sanitized']),'excluded':len(report['excluded']),'missing_library_roots':sum(bool(x['missing_libraries']) for x in checks),'unresolved_symbol_roots':sum(bool(x['unresolved_symbols']) for x in checks),'vendor_glibc_private_imports':len(report['private_imports'])}
 report['previous_customizations']={'comparison':'build/asus-runtime-projection/stock-to-kernel9-ui1.json','rgb':'Five accepted sites move into rebuilt ledg.o; old duplicated rc not projected. Prior JFFS replacement hooks must be migrated/disabled before activation.','non_elf_resources':'Owned by separate BSP/UI resource package with reviewed kernel9-ui1 files.'}
 dump(out/'projection.json',report)
 write(out/'recipe-source/prepare-runtime-projection.py',Path(__file__).read_bytes())
 print(json.dumps({'path':str(out),'counts':report['counts']},indent=2))
if __name__=='__main__':main()

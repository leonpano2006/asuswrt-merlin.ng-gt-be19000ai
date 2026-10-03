#!/usr/bin/env python3
"""Start from pristine AI userspace; replace only matching open-source modules."""
from pathlib import Path
import argparse,shutil,subprocess,hashlib,json,stat,os
r=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser();p.add_argument('--version',type=int,required=True);a=p.parse_args();k=r/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19';root=r/f'build/candidate-rootfs-v{a.version}';stock=r/'build/stock-rootfs';assert not root.exists()
shutil.copytree(stock,root,symlinks=True);modroot=root/'lib/modules/4.19.294';orig={}
for f in modroot.rglob('*.ko'):
 assert f.name not in orig,f.name
 orig[f.name]=f
records=[]
built_in_zsmalloc='CONFIG_ZSMALLOC=y' in (k/'.config').read_text()
for f in sorted(k.rglob('*.ko')):
 if built_in_zsmalloc and f.relative_to(k)==Path('mm/zsmalloc.ko'):continue
 rel=f.relative_to(k);assert rel.parts[0] in ['lib','crypto','fs','mm','net','drivers'],rel
 dest=orig.get(f.name,modroot/'kernel'/rel);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(f,dest)
 records.append({'path':str(dest.relative_to(root)),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
assert len(records)==(133 if built_in_zsmalloc else 134),len(records)
if built_in_zsmalloc:
 builtin=modroot/'modules.builtin';lines=builtin.read_text().splitlines();name='kernel/mm/zsmalloc.ko'
 if name not in lines:builtin.write_text('\n'.join(lines+[name])+'\n')
order=modroot/'modules.order';old=order.read_text().splitlines();new=[str(f.relative_to(modroot)) for f in sorted(modroot.rglob('*.ko'))];order.write_text('\n'.join(old+[n for n in new if n not in old])+'\n')
subprocess.run(['depmod','-b',str(root),'-F',str(k/'System.map'),'4.19.294'],check=True)
def scan(root):
 out={}
 for f in root.rglob('*'):
  n=str(f.relative_to(root))
  if n=='lib/modules' or n.startswith('lib/modules/'):continue
  s=f.lstat();v=[s.st_mode,int(s.st_mtime)]
  if stat.S_ISREG(s.st_mode):v.append(hashlib.sha256(f.read_bytes()).hexdigest())
  if stat.S_ISLNK(s.st_mode):v.append(os.readlink(f))
  out[n]=v
 return out
assert scan(stock)==scan(root),'userspace changed'
image=r/f'build/rootfs-v{a.version}.zstd.squashfs';assert not image.exists()
subprocess.run(['mksquashfs',str(root),str(image),'-noappend','-all-root','-comp','zstd','-Xcompression-level','22','-b','524288','-processors','12','-no-progress'],check=True)
shutil.copyfile(image,r/'build/rootfs.zstd.squashfs')
(r/f'evidence/modules-v{a.version}.json').write_text(json.dumps(records,indent=2)+'\n')
(r/f'evidence/rootfs-v{a.version}.json').write_text(json.dumps({'sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'bytes':image.stat().st_size,'nonmodule_entries':len(scan(stock)),'nonmodule_differences':0},indent=2)+'\n')
print('Staged',len(records),'modules; nonmodule entries unchanged')

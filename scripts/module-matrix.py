#!/usr/bin/env python3
"""Load each module and dependencies in a fresh offline VM, stock vs candidate."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from collections import Counter
from elftools.elf.elffile import ELFFile
import gzip,hashlib,json,stat,subprocess,re,sys
r=Path(__file__).resolve().parents[1];out=r/'build/module-matrix';out.mkdir(exist_ok=True)
roots={'stock':r/'build/stock-rootfs','candidate':r/'build/candidate-rootfs'}
kernels={'stock':r/'inputs/stock-Image','candidate':r/'build/Image-v3'}
init=b'''#!/bin/busybox sh
export PATH=/bin
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
for arg in $(cat /proc/cmdline); do case "$arg" in lab_target=*) target=${arg#lab_target=};; esac; done
while read name; do
 /load_one "$name" "/modules/$name.ko" || break
done < /plans/$target
echo QEMU_MODULE_TEST_COMPLETE
poweroff -f
'''
plans={};paths={}
for version,root in roots.items():
 modules={p.stem.replace('-','_'):p for p in (root/'lib/modules').rglob('*.ko')}
 deps={}
 for n,p in modules.items():
  with p.open('rb') as f:
   sec=ELFFile(f).get_section_by_name('.modinfo');data=sec.data().split(b'\0')
  ds=next((x[8:].decode().split(',') for x in data if x.startswith(b'depends=')),[])
  deps[n]=[d.replace('-','_') for d in ds if d]
 # depmod resolves cross-directory dependencies that a separate M= build
 # cannot put in .modinfo until all other Module.symvers files are available.
 depfile=root/'lib/modules/4.19.294/modules.dep'
 for line in depfile.read_text().splitlines():
  path,rest=line.split(':',1);n=Path(path).stem.replace('-','_')
  if n in modules:deps[n]=[Path(x).stem.replace('-','_') for x in rest.split()]
 def plan(n,active=None):
  active=set() if active is None else active
  assert n not in active,n
  active.add(n);seq=[]
  for d in deps[n]:
   if d not in modules:raise ValueError((n,d))
   for item in plan(d,active.copy()):
    if item not in seq:seq.append(item)
  return seq+[n]
 plans[version]={n:plan(n) for n in modules};paths[version]=modules
 entries={d:(stat.S_IFDIR|0o755,b'',0,0) for d in ['bin','dev','proc','sys','tmp','modules','plans']}
 for n,p in {'bin/busybox':r/'build/busybox','load_one':r/'build/load_one'}.items():entries[n]=(stat.S_IFREG|0o755,p.read_bytes(),0,0)
 for n,p in modules.items():
  entries['modules/'+n+'.ko']=(stat.S_IFREG|0o444,p.read_bytes(),0,0)
  entries['plans/'+n]=(stat.S_IFREG|0o444,('\n'.join(plans[version][n])+'\n').encode(),0,0)
 entries.update({'QEMU_LAB_GUEST':(stat.S_IFREG|0o444,b'offline guest only\n',0,0),'init':(stat.S_IFREG|0o755,init,0,0),'dev/console':(stat.S_IFCHR|0o600,b'',5,1),'dev/null':(stat.S_IFCHR|0o666,b'',1,3),'TRAILER!!!':(0,b'',0,0)})
 buf=bytearray()
 for ino,(n,(m,d,ma,mi)) in enumerate(entries.items(),1):
  n=n.encode()+b'\0';f=[ino,m,0,0,2 if stat.S_ISDIR(m) else 1,0,len(d),0,0,ma,mi,len(n),0];buf+=b'070701'+''.join(f'{v:08x}' for v in f).encode()+n;buf+=b'\0'*(-len(buf)%4);buf+=d;buf+=b'\0'*(-len(buf)%4)
 (out/(version+'.cpio.gz')).write_bytes(gzip.compress(buf,compresslevel=1,mtime=0))
 (out/(version+'-manifest.json')).write_text(json.dumps({n:{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'load_plan':plans[version][n]} for n,p in modules.items()},indent=2)+'\n')
# Both original modules and added container/storage modules, one fresh VM per target.
targets=sys.argv[1:] or sorted(set(paths['stock'])|set(paths['candidate']))
def run(v,n):
 label='matrix-v4-'+v+'-'+n
 subprocess.run(['python3',str(r/'scripts/run-qemu.py'),'--label',label,'--kernel',str(kernels[v]),'--initrd',str(out/(v+'.cpio.gz')),'--target',n,'--timeout','20','--complete-marker','QEMU_MODULE_TEST_COMPLETE'],stdout=subprocess.DEVNULL)
 result=json.loads((r/'build/qemu'/label/'result.json').read_text());log=(r/'build/qemu'/label/'serial.log').read_text(errors='replace')
 matches=re.findall(r'LAB_MODULE_END (\S+) rc=(-?\d+) errno=(\d+) message=(.*)',log)
 target=next((x for x in matches if x[0]==n),None)
 state='loaded' if target and target[1]=='0' and not result['panic'] else 'load_error' if target else 'dependency_error' if matches and matches[-1][1]!='0' else 'panic' if result['panic'] else 'timeout_or_early_exit'
 record={'version':v,'target':n,'status':state,'module_results':matches,'panic':result['panic'],'kernel_sha256':result['kernel_sha256'],'guest_complete':result['guest_complete']}
 (out/(v+'-'+n+'.json')).write_text(json.dumps(record,indent=2)+'\n');return record
records=[];counts={v:Counter() for v in roots}
with ThreadPoolExecutor(max_workers=4) as pool:
 fs=[pool.submit(run,v,n) for n in targets for v in roots if n in paths[v]]
 for f in as_completed(fs):
  x=f.result();records.append(x);counts[x['version']][x['status']]+=1
  if len(records)%24==0:print(len(records),'/',len(fs),json.dumps(counts),flush=True)
lookup={(x['version'],x['target']):x for x in records}
regressions=[n for n in set(targets)&set(paths['stock'])&set(paths['candidate']) if lookup['stock',n]['status']=='loaded' and lookup['candidate',n]['status']!='loaded']
summary={'counts':counts,'regressions':regressions,'targets':len(targets),'vm_runs':len(records),'hardware_not_emulated':True}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
raise SystemExit(bool(regressions))

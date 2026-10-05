#!/usr/bin/env python3
"""Exercise only ledg.o against complete hardware/NVRAM mocks, never vendor rc."""
import hashlib,json,os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2];W=R/'build/asus-runtime-projection/ledg-proof';W.mkdir(exist_ok=True)
fixture=json.loads((R/'configs/ledg-node-qemu-fixture.json').read_text());(W/'nvram-fixture.h').write_text('static char *fixture[][2] = {\n'+',\n'.join('{'+json.dumps(k)+','+json.dumps(v)+'}' for k,v in fixture.items())+'\n};\n')
mock=(R/'scripts/ledg-qemu-mock.c').read_text()+'''\nvoid cled_set(int gpio,unsigned int a,unsigned int b,unsigned int c,unsigned int d){printf("MOCK_CLED %d %u %u %u %u\\n",gpio,a,b,c,d);}
void LEDGroupReset(int mode){printf("MOCK_GROUP_RESET %d\\n",mode);}
int remove(const char *p){printf("MOCK_REMOVE %s\\n",p);return 0;}
extern int ledg_main(int,char **);
int main(int argc,char **argv){return ledg_main(argc,argv);}
''';(W/'mock.c').write_text(mock)
proof=json.loads((R/'build/asus-rc-recovery/compile-result.json').read_text());cc=Path(proof['compiler']);sr=Path(proof['sysroot']);env=dict(os.environ,LD_LIBRARY_PATH=str(cc.parents[1]/'lib/aarch64-linux-gnu'))
flags=['--sysroot='+str(sr),'-isystem',str(sr/'usr/include/arm-linux-gnueabi'),'-isystem',str(sr/'usr/include'),'-B'+str(sr/'usr/lib/arm-linux-gnueabi')+'/', '-mcpu=cortex-a53','-mfloat-abi=softfp','-mfpu=crypto-neon-fp-armv8','-D_TIME_BITS=32','-D_FILE_OFFSET_BITS=32','-fno-builtin','-O2','-I'+str(W)]
objects={'original':R/'build/asus-rc-recovery/source/release/src/router/rc/prebuild/GT-BE19000AI/ledg.o','patched':W/'ledg-patched.o'}
commands=[]
for name,obj in objects.items():
 cmd=[str(cc),*flags,str(W/'mock.c'),str(obj),'-o',str(W/name)];subprocess.run(cmd,env=env,check=True);commands.append(cmd)
results=[]
for scheme in range(8):
 runs={}
 for name,role in [('original',0),('patched',1)]:
  q=subprocess.run(['qemu-arm','-L',str(sr),str(W/name)],env={**os.environ,'TEST_RE_MODE':str(role),'TEST_SCHEME':str(scheme)},text=True,capture_output=True,timeout=5)
  (W/f'{name}-{scheme}.log').write_text(q.stdout+q.stderr);assert q.returncode==0 and 'MOCK_DONE' in q.stdout,(name,scheme,q.stdout,q.stderr)
  runs[name]=q.stdout
 assert runs['original']==runs['patched'],scheme
 results.append({'scheme':scheme,'patched_node_matches_original_controller':True})
q=subprocess.run(['qemu-arm','-L',str(sr),str(W/'original')],env={**os.environ,'TEST_RE_MODE':'1','TEST_SCHEME':'4'},text=True,capture_output=True,timeout=5);assert q.returncode==0 and q.stdout!=(W/'original-4.log').read_text();(W/'negative-original-node.log').write_text(q.stdout)
report={'status':'passed','cases':results,'unmodified_node_cycle_differs':True,'commands':commands,'object_patch_report':'build/asus-runtime-projection/ledg-proof/patch.json','source_inputs':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),W/'mock.c',R/'scripts/ledg-qemu-mock.c',W/'nvram-fixture.h']},'scope':'Only exact ledg object + synthetic main + NVRAM/file/hardware/timer mocks. libc2.44 and GCC15.2. No vendor DSOs or rc/hardware/service starts; initial palette/channel/timer request only; physical output not retested.'}
(W/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':'passed','schemes':8,'negative_control':True}))

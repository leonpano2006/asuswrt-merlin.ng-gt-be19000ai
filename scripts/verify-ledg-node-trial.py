#!/usr/bin/env python3
from pathlib import Path
import json,subprocess
repo=Path(__file__).resolve().parents[1]
root=repo/'build'
work=root/'rgb-node-test'
fixture=json.loads((repo/'configs/ledg-node-qemu-fixture.json').read_text())
(work/'nvram-fixture.h').write_text('static char *fixture[][2] = {\n'+',\n'.join('{'+json.dumps(k)+','+json.dumps(v)+'}' for k,v in fixture.items())+'\n};\n')
subprocess.run(['clang','--target=arm-linux-gnueabi','-march=armv7-a','-mfloat-abi=softfp','-fPIC','-shared','-nostdlib','-fuse-ld=lld','-O2','-Wall','-Wextra','-Wno-unused-parameter','-Wno-builtin-requires-header','-I',str(work),str(repo/'scripts/ledg-qemu-mock.c'),'-o',str(work/'mock.so')],check=True)
base=['bwrap','--unshare-all','--ro-bind',str(root/'stock-rootfs'),'/','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind','/usr/bin/qemu-arm-static','/tmp/qemu','--ro-bind',str(root/'rgb-node-test'),'/tmp/test','--setenv','LD_LIBRARY_PATH','/lib:/usr/lib','/tmp/qemu','-E','LD_PRELOAD=/tmp/test/mock.so']
# root is build (not repository); all writes, NVRAM and timers are mocked.
cases=[]
for scheme in range(8):
 outputs={}
 for kind,role,exe in [('stock-controller','0','/sbin/rc'),('patched-node','1','/tmp/test/rc')]:
  c=subprocess.run(base+['-E','TEST_RE_MODE='+role,'-E','TEST_SCHEME='+str(scheme),'-0','ledg',exe],capture_output=True,text=True,timeout=10)
  assert c.returncode==0,(scheme,kind,c.stderr)
  assert 'MOCK_DONE' in c.stdout
  (root/'rgb-node-test'/f'{kind}-{scheme}.log').write_text(c.stdout+c.stderr)
  outputs[kind]=c.stdout
 assert outputs['stock-controller']==outputs['patched-node'],scheme
 cases.append({'scheme':scheme,'patched_node_matches_stock_controller':True})
r={'isolation':'Bubblewrap unshare-all, read-only rootfs, no router access; hardware/NVRAM/timer calls mocked.','cases':cases,'limitation':'Validates initial hardware command sequence and timer request, not physical LED output or long-running animation.'}
(root/'rgb-node-test/qemu-results.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2))

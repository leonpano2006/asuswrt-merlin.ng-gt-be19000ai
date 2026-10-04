#!/usr/bin/env python3
"""Integrate reviewed node fixes into a copy of the tested kernel6 rootfs."""
from pathlib import Path
import hashlib, json, os, shutil, stat, subprocess
R=Path(__file__).resolve().parents[1]
root=R/'build/rc1-rootfs'
assert root.is_dir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(R/'build/rootfs-v6.zstd.squashfs')=='78b8eb8761cc331531e0a0436b4293b05ee1b70fa371e2d6ab5f44d4fb5c7301'
assert sha(root/'sbin/rc')=='9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814'
assert sha(root/'usr/lib/libcodb.so')=='57d4f89d6bc82ce95a346f823c66b8a9d305ce98d40b4b83f0f17a7307d033fd'
def inventory():
 out={}
 for f in root.rglob('*'):
  s=f.lstat();row={'mode':stat.S_IMODE(s.st_mode),'kind':stat.S_IFMT(s.st_mode)}
  if f.is_symlink():row['target']=os.readlink(f)
  elif f.is_file():row['sha256']=sha(f)
  out[str(f.relative_to(root))]=row
 return out
baseline=inventory()
selected=json.loads((R/'configs/next-release-candidate.json').read_text())
assert selected['packaging_authorized'] is True
for row in selected['web_manifest']['files']:
 src=R/'build/node-web-fix'/row['path'];dst=root/'www'/row['path']
 assert sha(src)==row['patched_sha256'],str(src)
 assert sha(dst)==row['source_sha256'],str(dst)
 shutil.copyfile(src,dst)
# Keep the stock multicall PID1 executable. Only the ledg entry point uses this
# tested alternate copy, so all normal LED restarts inherit the same fix.
led=root/'usr/libexec/ledg-node';led.mkdir(parents=True)
shutil.copy2(R/'build/rgb-node-test/rc',led/'rc')
assert sha(led/'rc')=='630bf99efe7d014b55dda7e337bf43d80cd5d1f93514c30115b170a96d6e9567'
(led/'ledg').symlink_to('rc')
assert os.readlink(root/'sbin/ledg')=='rc'
(root/'sbin/ledg').unlink();(root/'sbin/ledg').symlink_to('../usr/libexec/ledg-node/ledg')
for name,files in [('node-history',['history.sh','collect.awk','schema.sql']),('ccr-status',['collect.sh','normalize.jq','network.jq','schema.sql'])]:
 dest=root/'usr/libexec'/name;dest.mkdir(parents=True)
 for f in files:shutil.copy2(R/'configs'/name/f,dest/f)
 script=dest/('history.sh' if name=='node-history' else 'collect.sh')
 s=script.read_text()
 if name=='ccr-status':
  assert s.count('"$base/curl.conf"')==3
  s=s.replace('"$base/curl.conf"','"$credential"')
  s=s.replace('run=/tmp/ccr-status','credential=/jffs/ccr-status/curl.conf\nrun=/tmp/ccr-status')
  s=s.replace('[ -r "$credential" ] &&','[ ! -e /jffs/ccr-status/disabled ] && [ -r "$credential" ] &&')
 else:
  s=s.replace('[ ! -e "$base/disabled" ] &&','[ ! -e /jffs/node-history/disabled ] && [ ! -e "$base/disabled" ] &&')
 script.write_text(s);script.chmod(0o755)
 subprocess.run(['sh','-n',str(script)],check=True)
meta={'release':'kernel6-ui1','target':'GT-BE19000AI BCM6813','kernel':'4.19.294 #6','ai_board_modified':False,'trial_only':True,'features':['reviewed-node-web-ui','ledg-node-animation','passive-local-history','ccr-direct-overview'],'excluded':['libcodb-source-rebuild-ABI-mismatch','scoped-service-restart-implementation','full-airiq-fft','sl1680-changes']}

start=root/'usr/libexec/be19000ai-candidate/start-services.sh';start.parent.mkdir(parents=True)
(start.parent/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
start.write_text('''#!/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
[ "$(nvram get productid)" = GT-BE19000AI ] || exit 0
[ "$(nvram get re_mode)" = 1 ] || exit 0
[ ! -e /jffs/node-web-fix/disabled ] || exit 0
/usr/libexec/node-history/history.sh start
/usr/libexec/ccr-status/collect.sh start
logger -t be19000ai-candidate 'kernel6-ui1 firmware services started'
''');start.chmod(0o755)
subprocess.run(['sh','-n',str(start)],check=True)
after=inventory()
changes=[{'path':p,'before':baseline.get(p),'after':after.get(p)} for p in sorted(set(baseline)|set(after)) if baseline.get(p)!=after.get(p)]
allowed={ 'www/'+x['path'] for x in selected['web_manifest']['files'] }
for row in changes:
 p=row['path'];assert p in allowed or p in ['sbin/ledg','etc/be19000ai-candidate.json','usr/libexec'] or p.startswith(('usr/libexec/ledg-node','usr/libexec/node-history','usr/libexec/ccr-status','usr/libexec/be19000ai-candidate')),p
assert all(not x['path'].startswith('lib/modules') for x in changes)
assert not list(root.rglob('curl.conf'))
report={'release':meta,'changed_entries':changes,'kernel_modules_unchanged':True,'pid1_rc_unchanged':True,'libcodb_retained':True,'credential_in_image':False,'startup_hook_sha256':sha(start)}
(R/'evidence/rc1/rootfs-changes.json').write_text(json.dumps(report,indent=2)+'\n')
image=R/'build/rootfs-rc1.zstd.squashfs';assert not image.exists()
subprocess.run(['mksquashfs',str(root),str(image),'-noappend','-all-root','-comp','zstd','-Xcompression-level','22','-b','524288','-processors','12','-no-progress'],check=True)
report.update({'rootfs_sha256':sha(image),'rootfs_bytes':image.stat().st_size})
(R/'evidence/rc1/rootfs-changes.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ['changed_entries']},indent=2))

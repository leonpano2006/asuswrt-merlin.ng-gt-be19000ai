#!/usr/bin/env python3
"""Keep reviewed kernel9 UI/telemetry resources and adapt their runtime guards."""
import argparse,hashlib,json,os,shutil,stat,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=ROOT/'build/asus-resource-projection'/a.label;out.mkdir(parents=True,exist_ok=False)
 inventory=ROOT/'build/asus-runtime-projection/stock-to-kernel9-ui1.json';difference=json.loads(inventory.read_text())
 base=ROOT/difference['modified'];bsp_report=ROOT/'reports/ubuntu26/asus-bsp-resource-ownership.json';bsp=json.loads(bsp_report.read_text());bsp_tree=ROOT/bsp['projection'];bsp_report=bsp_tree/'result.json';bsp=json.loads(bsp_report.read_text())
 assert sha(ROOT/bsp['patch']['path'])==bsp['patch']['sha256']
 payload=out/'payload';share=payload/'usr/share/asus/integration';share.mkdir(parents=True)
 for name in ['rom','etc-seed']:shutil.copytree(bsp_tree/name,share/name,symlinks=True)
 shutil.copytree(base/'www',share/'www',symlinks=True)
 for name in ['be19000ai-candidate','ccr-status','node-history']:
  shutil.copytree(base/'usr/libexec'/name,payload/'usr/libexec'/name,symlinks=True)
 accounts=[]
 for row in difference['changes']:
  path=row['path'];new=row['new']
  if path.startswith('/lib/modules/'):continue
  if path=='/usr/libexec':policy='Parent directory supplied by native package'
  elif path=='/sbin/ledg' or path.startswith('/usr/libexec/ledg-node'):policy='RGB fix ported into rebuilt rc by runtime ELF package; old rc intentionally not copied'
  elif path.startswith('/www/') or path.startswith(('/usr/libexec/be19000ai-candidate','/usr/libexec/ccr-status','/usr/libexec/node-history')):
   source=base/path.lstrip('/')
   if new['type']==stat.S_IFREG:assert sha(source)==new['sha256'],path
   policy='Exact reviewed content copied; only three script runtime guards and candidate metadata deliberately adapted below'
  else:raise AssertionError('Unaccounted prior change: '+path)
  accounts.append({**row,'migration_policy':policy})
 adapted=[]
 for rel in ['usr/libexec/be19000ai-candidate/start-services.sh','usr/libexec/node-history/history.sh','usr/libexec/ccr-status/collect.sh']:
  target=payload/rel;old=target.read_text();new=old
  assert new.count('PATH=/sbin:/bin:/usr/sbin:/usr/bin')==1
  new=new.replace('PATH=/sbin:/bin:/usr/sbin:/usr/bin','PATH=/usr/libexec/asus/collector-tools:/usr/libexec/asus/sh-applets:/usr/sbin:/usr/bin')
  new=new.replace('export PATH\n',"export PATH\n# Literal token expands independently in each ABI loader; vendor namespace only.\nLD_LIBRARY_PATH='/usr/$LIB/asus'\nexport LD_LIBRARY_PATH\n",1)
  oldguard=' [ "$(sha256sum /sbin/rc | cut -d \' \' -f 1)" = 9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814 ] &&'
  guard=' /usr/libexec/asus/bsp-ownership --require &&\n sha256sum -c /usr/share/asus/integration/rc.sha256 >/dev/null 2>&1 &&'
  if 'supported()' in new:
   assert new.count(oldguard)==1
   new=new.replace(oldguard,guard)
  else:
   new=new.replace('export LD_LIBRARY_PATH\n','export LD_LIBRARY_PATH\n/usr/libexec/asus/bsp-ownership --require || exit 125\nsha256sum -c /usr/share/asus/integration/rc.sha256 >/dev/null 2>&1 || exit 125\n',1)
   new=new.replace("'kernel9-ui1 firmware services started'","'Ubuntu26 ASUS UI telemetry services started'")
  target.write_text(new);subprocess.run(['/usr/bin/busybox','ash','-n',str(target)],check=True)
  adapted.append({'path':'/'+rel,'before_sha256':sha(base/rel),'after_sha256':sha(target),'policy':'Preserve collectors, disabled switches and CCR device-only credentials; bind new runtime identity and namespace'})
 manifest=payload/'usr/libexec/be19000ai-candidate/manifest.json';old_manifest=json.loads(manifest.read_text())
 manifest.write_text(json.dumps({'release':'ubuntu26-asus-integration-candidate','target':old_manifest['target'],'preserved_from':old_manifest,'activation':'native private ASUS namespace only; rc hash manifest required','hardware_tested':False},indent=2)+'\n')
 adapted.append({'path':'/usr/libexec/be19000ai-candidate/manifest.json','before_sha256':sha(base/'usr/libexec/be19000ai-candidate/manifest.json'),'after_sha256':sha(manifest),'policy':'Current candidate identity with original baseline provenance retained'})
 original_hook=ROOT/'build/kernel9-ui1-services-start'
 entry=payload/'usr/libexec/be19000ai-candidate/start-services.sh'
 hook='''#!/bin/sh
# Package presence selects Ubuntu permanently for this boot. Fail closed:
# never mount old web overlays or execute a stock rc under the new runtime.
if [ -e /usr/share/asus/integration/rc.sha256 ]; then
    /usr/libexec/asus/bsp-ownership --require || exit 125
    entry=/usr/libexec/be19000ai-candidate/start-services.sh
    [ "$(sha256sum "$entry" | cut -d ' ' -f 1)" = ENTRY_SHA ] || exit 125
    "$entry" >>/tmp/node-web-fix.log 2>&1 &
    exit 0
fi
'''.replace('ENTRY_SHA',sha(entry))+original_hook.read_text().split('\n',1)[1]
 (out/'services-start.migration-candidate').write_text(hook)
 subprocess.run(['/usr/bin/busybox','ash','-n',str(out/'services-start.migration-candidate')],check=True)
 mode_changes=[]
 for path in sorted(payload.rglob("*")):
  if path.is_symlink():continue
  before=stat.S_IMODE(path.stat().st_mode);after=before & ~0o022
  if before!=after:
   path.chmod(after);mode_changes.append({"path":"/"+str(path.relative_to(payload)),"before":before,"after":after})
 rows=[]
 for path in sorted(payload.rglob('*')):
  st=path.lstat();row={'path':'/'+str(path.relative_to(payload)),'mode':stat.S_IMODE(st.st_mode)}
  if path.is_symlink():row.update(type='symlink',target=os.readlink(path))
  elif path.is_dir():row.update(type='directory')
  else:
   raw=path.read_bytes();assert not raw.startswith(b'\x7fELF'),str(path)
   row.update(type='regular',size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
  rows.append(row)
 report={'status':'resource projection prepared; no installation, hooks or ASUS services executed','payload':str(payload.relative_to(ROOT)),
  'baseline':str(base.relative_to(ROOT)),'baseline_diff':{'path':str(inventory.relative_to(ROOT)),'sha256':sha(inventory)},
  'bsp_report':{'path':str(bsp_report.relative_to(ROOT)),'sha256':sha(bsp_report)},'prior_modified_resources':accounts,'deliberate_adaptations':adapted,
  'files':rows,'mode_changes':mode_changes,'private_mounts':{'/rom':'/usr/share/asus/integration/rom','/www':'/usr/share/asus/integration/www','private_etc_first_lower':'/usr/share/asus/integration/etc-seed'},
  'jffs_hook':{'candidate':str((out/'services-start.migration-candidate').relative_to(ROOT)),'sha256':sha(out/'services-start.migration-candidate'),'expected_current_hash':sha(original_hook),
   'policy':'Not installed. Later read-only verify exact current hook before atomic replacement; preserve old branch for stock firmware rollback. An unrecognized current hook requires merge, never overwrite.'},
  'dependencies':['Runtime package provides /usr/share/asus/integration/rc.sha256 for final /usr/libexec/asus/rc','Runtime collector-tools allowlist has only nvram,wl,jq,sqlite3,curl','Native namespace launcher binds private ROM/www and layers reviewed etc-seed before Ubuntu/etc','Existing /jffs/ccr-status/curl.conf remains on-device root0600; never copied into package','Existing re_upgrade=1 and jffs2_scripts=1 remain device-authorized NVRAM values, never replaced by package defaults'],
  'factory_tls_material':'ROM/seed retain firmware reference files; runtime HTTPS must continue using device-specific credentials through prepare_cert_in_etc, not claim factory material unique',
  'actual_asus_services_executed':False,'flash_allowed':False,'generator_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
 (ROOT/'reports/ubuntu26/asus-resource-projection.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'payload':report['payload'],'files':len(rows),'prior_changes_accounted':len(accounts),'adaptations':len(adapted)}))
if __name__=='__main__':main()

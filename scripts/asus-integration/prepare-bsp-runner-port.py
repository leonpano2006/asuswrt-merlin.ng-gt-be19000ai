#!/usr/bin/env python3
"""Replace only BCM launch calls with an ordered, bounded, status-aware runner."""
import argparse,difflib,hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=ROOT/'build/asus-bsp-runner'/('source-'+a.label);out.mkdir(parents=True,exist_ok=False)
 base=ROOT/'build/asus-device-ownership/v1/source/release/src/router/rc/init.c'
 report=json.loads((ROOT/'reports/ubuntu26/asus-device-ownership.json').read_text())
 assert sha(base)==next(row['after_sha256'] for row in report['changes'] if row['path'].endswith('/init.c'))
 old=base.read_text(errors='surrogateescape');new=old
 for action in ['start','stop']:
  needle='system("bcm_boot_launcher '+action+'");'
  assert new.count(needle)==2,(action,new.count(needle))
  new=new.replace(needle,'if (eval("/usr/libexec/asus/bsp-runner", "'+action+'")) {\n\t\tfprintf(stderr, "ASUS BSP '+action+' failed; inspect ASUS_BSP_STAGE diagnostics\\n");\n\t\t_exit(125);\n\t}')
 path='release/src/router/rc/init.c'
 patch='diff --git a/'+path+' b/'+path+'\n'+''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+path,tofile='b/'+path))
 output=ROOT/'patches/ubuntu26/asuswrt6/0015-asus-bsp-ordered-runner.patch';output.write_text(patch,errors='surrogateescape')
 target=out/path;target.parent.mkdir(parents=True);target.write_bytes(base.read_bytes())
 run=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(output)],cwd=out,capture_output=True,text=True)
 assert run.returncode==0,run.stdout+run.stderr
 proof={'patch':{'path':str(output.relative_to(ROOT)),'sha256':sha(output)},'base_sha256':sha(base),'after_sha256':sha(target),
  'apply_stdout':run.stdout,'fuzz':0,'source_pin':'9b25e55ca5c56a6f01d6a56264c0f6c47459ada0',
  'apply_order':'after0003–0011 and0013;0012 is ROM resources;0014 SSH touches different scope',
  'contract':'Nonzero start stops initialization. Stop runner attempts every original K step first, then rc exits125 so broker records incomplete drain.',
  'actual_asus_services_executed':False,'flash_allowed':False}
 (out/'result.json').write_text(json.dumps(proof,indent=2)+'\n')
 reportpath=ROOT/'reports/ubuntu26/asus-bsp-runner.json';record=json.loads(reportpath.read_text());record['rc_source_port']=proof;reportpath.write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps({'patch':str(output),'fuzz':0}))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Prove invalid activation evidence cannot create a guardian build directory."""
import hashlib,json,subprocess,sys,tempfile,uuid
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 out=R/'build/asus-trial-runtime/gate-rejection-v2';out.mkdir(exist_ok=False)
 work=Path(tempfile.mkdtemp(prefix='asus-gate-negative-'));cases=[]
 def reject(name,arguments):
  label='reject-'+uuid.uuid4().hex
  p=subprocess.run([sys.executable,str(R/'scripts/build-asus-trial-runtime.py'),'--label',label,*arguments],capture_output=True,text=True)
  assert p.returncode and not (R/'build/asus-trial-runtime'/label).exists(),name
  cases.append({'name':name,'passed':True,'build_directory_created':False,'exit_code':p.returncode})
 reject('enable_without_evidence',['--enable-deployment-gate'])
 bad=work/'invalid.json';bad.write_text('{}');reject('empty_evidence',['--enable-deployment-gate','--production-loop-report',str(bad)])
 bad.write_text(json.dumps({'passed':False}));reject('failed_evidence',['--enable-deployment-gate','--production-loop-report',str(bad)])
 reject('evidence_without_explicit_enable',['--production-loop-report',str(bad)])
 names=['production.c','trial-policy.c','trial-policy.h','trial-handoff.h','preflight.c','control-server.c','control-server.h','process-auth.c','local-health.c','health-worker.c','health-worker.h','sshd-state.h']
 fake={'passed':True,'production_loop_fixture_validation_passed':True,'all_six_scenarios_passed':True,'native_guardian_gate_enabled':False,'physical_watchdog_opened':False,'runtime_accepted':False,'automatic_commit_allowed':False,'errors':[],'cases':[{'case':n,'checks':{'ok':True}} for n in ['healthy-lan-expiry','healthy-ssh-argv','healthy-worker-hang','healthy-metadata-change','prearm-refuse','arm-failure']],'shared_production_sources':{n:'0'*64 for n in names}}
 bad.write_text(json.dumps(fake));reject('mismatching_production_source',['--enable-deployment-gate','--production-loop-report',str(bad)])
 for tool in ['build-asus-trial-runtime.py','export-asus-trial-guardian.py']:
  p=subprocess.run([sys.executable,'-O',str(R/'scripts'/tool),'--help'],capture_output=True,text=True)
  assert p.returncode and 'Optimized Python cannot verify' in p.stderr
  cases.append({'name':'optimized_python_rejected_'+tool,'passed':True,'exit_code':p.returncode})
 result={'passed':True,'cases':cases,'builder_sha256':sha(R/'scripts/build-asus-trial-runtime.py'),'test_sha256':sha(Path(__file__)),'hardware_accessed':False,'candidate_builds_created':False};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(cases),'path':str((out/'result.json').relative_to(R))}))
if __name__=='__main__':main()

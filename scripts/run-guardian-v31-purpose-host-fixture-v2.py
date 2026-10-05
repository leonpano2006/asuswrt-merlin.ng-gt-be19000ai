#!/usr/bin/env python3
"""One new protocol-only compile/run; preserve the25 passed v31 cases."""
import hashlib,json,os,re,shutil,signal,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
BASE=R/'build/asus-accepted-runtime/v31-focused-host-v1'
PRIOR=BASE/'isolated-execution-v2/result.json'
REPORT=R/'reports/ubuntu26/guardian-v31-accepted-this-boot-source-v2.json'
F=R/'scripts/asus-integration/accepted-guard/v31-fixture-protocol-only-v2.c'
S=R/'scripts/asus-integration/accepted-guard/v31-runtime'
OUT=R/'build/asus-accepted-runtime/v31-purpose-host-v2'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':p.relative_to(R).as_posix(),'sha256':sha(p)}
def save(p,value):
 with p.open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def run(argv,log,cwd,limit):
 with log.open('xb') as f:
  p=subprocess.Popen(argv,stdout=f,stderr=subprocess.STDOUT,cwd=cwd,start_new_session=True)
  try:return p.wait(timeout=limit),False
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGKILL);return p.wait(timeout=5),True

def main():
 assert sha(PRIOR)=='0844ca30bbd5c446de71fb3d97a895329e49eeea0da1825827319e2ace74390c'
 assert sha(REPORT)=='9662648aa3d712e675dec799b6fa80751c1f66b2fb043d5ee193d47e5ab2496e'
 assert sha(F)=='3123abe14ca291a7859d9cd26345271b6861b5133d5cfe09cc338332e2e9154e'
 first=json.loads((BASE/'result.json').read_text());prior=json.loads(PRIOR.read_text());report=json.loads(REPORT.read_text())
 assert first['compile_count']==1 and first['compile_returncode']==0
 assert prior['observed_passes']==first['expected_cases'][:25]
 assert sha(BASE/'isolated-execution-v2/fixture.log')==prior['log_sha256']
 assert 'purposes: Assertion `!mkdir(sandbox,0755)' in (BASE/'isolated-execution-v2/fixture.log').read_text()
 assert {p.name:sha(p) for p in S.iterdir()}==report['source_files']
 cases=re.findall(r'pass\("([a-z0-9-]+)"\)',F.read_text());assert cases==first['expected_cases'][25:] and len(cases)==14
 assert not OUT.exists() and not OUT.is_symlink()
 argv=first['compile_argv'].copy();argv[argv.index('source/fixture.c')]='source/protocol-only.c';argv[-1]='v31-purpose-fixture'
 command=['/usr/bin/mmdebstrap','--unshare-helper','/usr/bin/unshare','--mount','--pid','--fork','--mount-proc','--net','--uts',str(OUT/'v31-purpose-fixture'),'--protocol-only','sandbox']
 plan={'schema':1,'status':'protocol_only_source_plan','runner':ref(Path(__file__)),'fixture':ref(F),'source_report':ref(REPORT),'prior25_validation':ref(PRIOR),'prior25_log':ref(BASE/'isolated-execution-v2/fixture.log'),'source_inventory':report['source_files'],'compile_argv':argv,'namespace_argv':command,'expected_cases':cases,'expected_case_count':14,'reused_passed_case_count':25,'repeated_case_count':0,'setup_fix':'Host UID1000 output mode0755 was not writable by mapped UID0/subuid root. A distinct empty sticky1777 parent permits mapped root to create its own0755 private sandbox; no source/runtime security guard is relaxed.','coverage_limits':first['coverage_limits']}
 OUT.mkdir(parents=True,mode=0o755);(OUT/'source').mkdir(mode=0o755);shutil.copytree(S,OUT/'source/v31-runtime');shutil.copyfile(F,OUT/'source/protocol-only.c')
 parent=OUT/'sandbox-parent';parent.mkdir(mode=0o755);parent.chmod(0o1777)
 save(OUT/'plan.json',plan)
 result={**plan,'status':'started_outcome_unknown','compile_count':0,'fixture_run_count':0,'runtime_sources_modified':False,'device_accessed':False,'hardware_watchdog_opened':False,'old_tests_rerun':False,'firmware_built':False}
 try:
  result['compile_count']=1;code,timed=run(argv,OUT/'compile.log',OUT,45);result['compile_returncode']=code;result['compile_timed_out']=timed
  assert code==0 and not timed,'New protocol-only compile failed; no retry'
  result['binary']=ref(OUT/'v31-purpose-fixture');result['fixture_run_count']=1
  code,timed=run(command,OUT/'fixture.log',parent,30);result['fixture_returncode']=code;result['fixture_timed_out']=timed
  lines=(OUT/'fixture.log').read_text().splitlines();result['observed_passes']=[s[5:] for s in lines if s.startswith('PASS ')]
  assert code==0 and not timed,'Protocol-only invocation failed; no retry'
  assert result['observed_passes']==cases and lines.count('V31_PURPOSE_PROTOCOL_PASS cases=14')==1,'Exact14 new protocol cases required'
  result['status']='v31_purpose_protocol14_passed_prior25_reused'
 except Exception as exc:result.update(status='failed_evidence_retained_no_retry',error=str(exc))
 finally:
  result['logs']={p.name:ref(p) for p in [OUT/'compile.log',OUT/'fixture.log'] if p.exists()}
  result['runtime_sources_unchanged_after']={p.name:sha(p) for p in S.iterdir()}==report['source_files']
  save(OUT/'result.json',result)
 print(json.dumps({'result':ref(OUT/'result.json'),'status':result['status'],'compile_count':result['compile_count'],'fixture_run_count':result['fixture_run_count'],'expected_case_count':14}),flush=True)
 if (OUT/'fixture.log').exists():print((OUT/'fixture.log').read_text())
 if result['status']!='v31_purpose_protocol14_passed_prior25_reused':raise SystemExit(1)
if __name__=='__main__':main()

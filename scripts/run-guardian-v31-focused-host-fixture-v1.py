#!/usr/bin/env python3
"""One new host-native v31 predicate/callback and isolated purpose check only."""
import hashlib,json,os,re,shutil,signal,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/accepted-guard/v31-runtime'
F=R/'scripts/asus-integration/accepted-guard/v31-fixture-v1.c'
REPORT=R/'reports/ubuntu26/guardian-v31-accepted-this-boot-source-v2.json'
REPORT_SHA='9662648aa3d712e675dec799b6fa80751c1f66b2fb043d5ee193d47e5ab2496e'
OUT=R/'build/asus-accepted-runtime/v31-focused-host-v1'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':p.relative_to(R).as_posix(),'sha256':sha(p)}
def save(p,value):
 with p.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def run_once(argv,log,cwd,limit):
 with log.open('xb') as f:
  p=subprocess.Popen(argv,stdout=f,stderr=subprocess.STDOUT,cwd=cwd,start_new_session=True)
  try:return p.wait(timeout=limit),False
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGKILL);return p.wait(timeout=5),True

def main():
 assert sha(REPORT)==REPORT_SHA
 report=json.loads(REPORT.read_text())
 assert {p.name:sha(p) for p in S.iterdir()}==report['source_files']
 cases=re.findall(r'pass\("([a-z0-9-]+)"\)',F.read_text())
 assert len(cases)==len(set(cases)) and cases
 assert not OUT.exists() and not OUT.is_symlink()
 compiler=Path('/usr/bin/cc');assert compiler.exists()
 prefix=['/usr/bin/ccache'] if Path('/usr/bin/ccache').exists() else []
 flags=['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-D_TIME_BITS=64','-D_FILE_OFFSET_BITS=64','-fstack-protector-strong','-fno-strict-aliasing','-ffunction-sections','-fdata-sections','-Wl,--gc-sections']
 argv=prefix+[str(compiler),*flags,'source/fixture.c','source/v31-runtime/accepted-runtime.c','source/v31-runtime/trial-policy.c','source/v31-runtime/control-server.c','source/v31-runtime/process-auth.c','-o','v31-focused-fixture']
 # Existing mapped-root helper; new mount/PID/proc/network namespaces only.
 namespace=['/usr/bin/mmdebstrap','--unshare-helper','/usr/bin/unshare','--mount','--pid','--fork','--mount-proc','--net','--uts','./v31-focused-fixture','sandbox']
 plan={'schema':1,'status':'v31_focused_host_source_plan','runner':ref(Path(__file__)),'source_report':ref(REPORT),'fixture':ref(F),'source_inventory':report['source_files'],'compile_argv':argv,'host_compiler_resolved_path':str(compiler.resolve()),'compiler_version_probe':False,'namespace_argv':namespace,'expected_cases':cases,'expected_case_count':len(cases),'expected_compile_count':1,'expected_fixture_run_count':1,'compile_timeout_seconds':45,'fixture_outer_timeout_seconds':30,'scope':'Actual v31 cached predicate/callback and purpose control paths; current real mount-namespace auth and SO_PEERCRED. Pipe descriptor only; in-memory diagnostic stub. Guardian entry, metadata reads, health scheduling, hardware watchdog, deployment and old tests never executed.'}
 OUT.mkdir(parents=True,mode=0o755)
 (OUT/'source').mkdir(mode=0o755)
 shutil.copytree(S,OUT/'source/v31-runtime')
 shutil.copyfile(F,OUT/'source/fixture.c')
 save(OUT/'plan.json',plan)
 result={**plan,'status':'started_outcome_unknown','compile_count':0,'fixture_run_count':0,'runtime_sources_modified':False,'device_accessed':False,'hardware_watchdog_opened':False,'old_tests_rerun':False,'firmware_built':False,'coverage_limits':['Host GCC fixture does not validate the ARM deployment binary/toolchain.','Does not execute guardian main, worker scheduling, real metadata partitions, diagnostic storage or watchdog keepalive.','Does not test PID1/systemd responsiveness, physical networking, boot selection, permanent commit or rollback.','Control open-path and immutable-client peer checks are not exercised; ops4–6 use a private socket and current actual namespace/peer predicates.']}
 try:
  result['compile_count']=1
  code,timed=run_once(argv,OUT/'compile.log',OUT,45)
  result['compile_returncode']=code;result['compile_timed_out']=timed
  assert code==0 and not timed,'Sole compile failed; evidence retained, no retry'
  result['fixture_binary']=ref(OUT/'v31-focused-fixture')
  result['fixture_run_count']=1
  code,timed=run_once(namespace,OUT/'fixture.log',OUT,30)
  result['fixture_returncode']=code;result['fixture_timed_out']=timed
  lines=(OUT/'fixture.log').read_text().splitlines()
  result['observed_passes']=[line[5:] for line in lines if line.startswith('PASS ')]
  assert code==0 and not timed,'Sole isolated invocation failed; evidence retained, no retry'
  assert result['observed_passes']==cases,'Missing, repeated or reordered focused case'
  assert lines.count(f'V31_FOCUSED_ACCEPTANCE_PASS cases={len(cases)}')==1,'One complete success marker required'
  result['status']='v31_focused_cached_acceptance_and_purpose_passed'
 except Exception as exc:
  result.update(status='failed_evidence_retained_no_retry',error=str(exc))
 finally:
  result['logs']={p.name:ref(p) for p in [OUT/'compile.log',OUT/'fixture.log'] if p.exists()}
  result['source_unchanged_after']={p.name:sha(p) for p in S.iterdir()}==report['source_files']
  save(OUT/'result.json',result)
 print(json.dumps({'result':ref(OUT/'result.json'),'status':result['status'],'compile_count':result['compile_count'],'fixture_run_count':result['fixture_run_count'],'expected_case_count':len(cases)}),flush=True)
 if result['status']!='v31_focused_cached_acceptance_and_purpose_passed':raise SystemExit(1)
if __name__=='__main__':main()

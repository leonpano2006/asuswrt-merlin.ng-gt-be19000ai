#!/usr/bin/env python3
"""Plan by default; one authorized host compile/run of the real fixed PID1 parser."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess

R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/accepted-guard/v32-runtime'
F=R/'scripts/asus-integration/accepted-guard/v32-pid1-stat-fixture-v1.c'
REPORT=R/'reports/ubuntu26/guardian-v32-pid1-zero-time-source-v1.json'
REPORT_SHA='a7cc84a3ecebefd9522cadc693a0948c750d8eaf52af0f633c0b6163762e4ee1'
CORE_SHA='c8172b73b9e8db0e3e9a62d6a7ef379830fb3f90a8f05f92681f7ab8c12358ab'
FIXTURE_SHA='71038d81edf1006d670f1ae5a5787ef33bf9ab750b51030539c9cff381c4188d'
OUT=R/'build/asus-accepted-runtime/pid1-zero-time-fixture-v1'

def need(condition,reason):
 if not condition:raise RuntimeError(reason)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':p.relative_to(R).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size}
def save(p,value):
 with p.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def run_once(argv,log,cwd,limit):
 with log.open('xb') as f:
  process=subprocess.Popen(argv,stdout=f,stderr=subprocess.STDOUT,cwd=cwd,start_new_session=True)
  try:return process.wait(timeout=limit),False
  except subprocess.TimeoutExpired:
   os.killpg(process.pid,signal.SIGKILL);return process.wait(timeout=5),True
def plan():
 need(FIXTURE_SHA is not None,'Final fixture source pin pending')
 need(sha(REPORT)==REPORT_SHA and sha(S/'accepted-core.c')==CORE_SHA and sha(F)==FIXTURE_SHA,'Fixed source hash mismatch')
 report=json.loads(REPORT.read_bytes())
 need({p.name:sha(p) for p in S.iterdir()}==report['source_files'],'Exact 36-file source closure mismatch')
 need(report['changed_source_count']==1 and report['unchanged_source_count']==35 and report['process_auth_byte_identical'] and report['volume_function_and_checks_byte_identical'],'Narrow production delta required')
 text=(S/'accepted-core.c').read_text()
 for region in reversed(report['regions']):
  need(text.count(region['after'])==1,'Reverse region occurrence mismatch');text=text.replace(region['after'],region['before'])
 need(hashlib.sha256(text.encode()).hexdigest()==report['base_source_files']['accepted-core.c'],'Exact v31 reverse proof mismatch')
 cases=re.findall(r'(?:accepts|rejects|pass)\("([a-z0-9-]+)"',F.read_text())
 need(len(cases)==21 and len(set(cases))==21,'Exact 21 new parser cases required')
 argv=['/usr/bin/ccache','/usr/bin/cc','-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-D_TIME_BITS=64','-D_FILE_OFFSET_BITS=64','-fstack-protector-strong','-fno-strict-aliasing','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','source/fixture.c','-o','pid1-stat-fixture']
 return {'schema':1,'status':'fixed_pid1_zero_start_parser_source_plan','runner':ref(Path(__file__)),'source_report':ref(REPORT),'fixture':ref(F),'inputs':{'accepted_core':ref(S/'accepted-core.c'),'source_report':ref(REPORT),'fixture':ref(F)},'source_inventory':report['source_files'],'expected_cases':cases,'expected_case_count':21,'compile_argv':argv,'fixture_argv':['./pid1-stat-fixture'],'expected_compile_count':1,'expected_fixture_run_count':1,'compile_timeout_seconds':45,'fixture_outer_timeout_seconds':15,'compiler_version_probe':False,'isolated_namespace_required':False,'scope':'Only the actual accepted_parse_pid1_stat runs on synthetic bounded buffers; no proc file/volume/namespace/SSH/control/guardian/metadata/watchdog function is called.','old_25_and_14_cases_reused_not_rerun':report['old_proofs_reused_not_reexecuted'],'device_accessed':False}
def main():
 if not __debug__:raise RuntimeError('python -O is not permitted')
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute-plan-sha256');args=parser.parse_args()
 proposal=plan();gate=hashlib.sha256(json.dumps(proposal,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if args.execute_plan_sha256 is None:
  print(json.dumps({'plan':proposal,'plan_sha256':gate},sort_keys=True,indent=2));return
 need(args.execute_plan_sha256==gate,'Exact reviewed plan gate required')
 need(not OUT.exists() and not OUT.is_symlink(),'Exclusive output already exists; no automatic retry')
 need(Path('/usr/bin/cc').exists() and Path('/usr/bin/ccache').exists(),'Accepted host compile recipe unavailable')
 OUT.mkdir(parents=True,mode=0o755);(OUT/'source').mkdir(mode=0o755)
 shutil.copytree(S,OUT/'source/v32-runtime');shutil.copyfile(F,OUT/'source/fixture.c');save(OUT/'plan.json',proposal)
 need({p.name:sha(p) for p in (OUT/'source/v32-runtime').iterdir()}==proposal['source_inventory'] and sha(OUT/'source/fixture.c')==FIXTURE_SHA,'Compiled input inventory mismatch')
 result={**proposal,'status':'started_outcome_unknown','plan_sha256':gate,'compile_count':0,'fixture_run_count':0,'returncode':None,'runtime_sources_modified':False,'hardware_watchdog_opened':False,'old_tests_rerun':False,'firmware_built':False,'coverage_limits':['Host parser cases do not validate the new ARM binary or actual PID1 identity/namespace/systemd/volumes.','This does not run acceptance, guardian main, workers, metadata reads, hardware keepalive or physical boot.','The existing physical capture proves current v31 PID1 starttime0/core6; no new physical successor execution is claimed.']}
 try:
  result['compile_count']=1;code,timed=run_once(proposal['compile_argv'],OUT/'compile.log',OUT,45)
  result.update(compile_returncode=code,compile_timed_out=timed)
  need(code==0 and not timed,'Sole compile failed; retain evidence, no retry')
  result['fixture_binary']=ref(OUT/'pid1-stat-fixture')
  result['fixture_run_count']=1;code,timed=run_once(proposal['fixture_argv'],OUT/'fixture.log',OUT,15)
  result.update(returncode=code,fixture_returncode=code,fixture_timed_out=timed)
  lines=(OUT/'fixture.log').read_text().splitlines();result['observed_passes']=[line[5:] for line in lines if line.startswith('PASS ')]
  need(code==0 and not timed,'Sole fixture failed; retain evidence, no retry')
  need(result['observed_passes']==proposal['expected_cases'],'Missing/repeated/reordered parser case')
  need(lines.count('V32_PID1_STAT_PARSER_PASS cases=21')==1,'Exact success marker required')
  result['status']='pure_production_pid1_zero_start_parser_fixture_passed'
 except Exception as exc:result.update(status='failed_evidence_retained_no_retry',error=str(exc))
 finally:
  result['logs']={p.name:ref(p) for p in (OUT/'compile.log',OUT/'fixture.log') if p.exists()}
  result['source_unchanged_after']={p.name:sha(p) for p in S.iterdir()}==proposal['source_inventory'] and sha(F)==FIXTURE_SHA
  save(OUT/'result.json',result)
 print(json.dumps({'status':result['status'],'result':ref(OUT/'result.json'),'compile_count':result['compile_count'],'fixture_run_count':result['fixture_run_count']},sort_keys=True))
 if result['status']!='pure_production_pid1_zero_start_parser_fixture_passed':raise SystemExit(1)
if __name__=='__main__':main()

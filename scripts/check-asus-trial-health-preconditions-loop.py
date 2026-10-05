#!/usr/bin/env python3
"""Bind health precondition loop evidence using the explicit fixture completion markers.

The original run-qemu result and serial log remain unchanged. A caller omitted
the custom --complete-marker; its generic guest_complete flag is not this
fixture contract. Check the actual fixed markers plus every existing scenario
assertion, never rerun or rewrite a guest outcome to repair a host marker."""
import argparse,hashlib,json,re
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
 if not __debug__:raise RuntimeError('Assertions are mandatory; Python optimization is unsupported')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);p.add_argument('--native',default='native-v15');p.add_argument('--scenarios',nargs='+');p.add_argument('--case-result',action='append',default=[]);a=p.parse_args();assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
 overrides={}
 for item in a.case_result:
  case,path=item.split('=',1);assert case not in overrides;overrides[case]=(R/path).resolve()
 pivot=R/'build/ubuntu26-pivot-qemu'/a.label;pm=json.loads((pivot/'manifest.json').read_text());fixture=R/pm['production_loop_fixture']['manifest'];fm=json.loads(fixture.read_text())
 assert sha(fixture)==pm['production_loop_fixture']['manifest_sha256'];assert fm['fixture'] and not fm['hardware_adapter'] and not fm['deployment_gate_enabled'];assert fm['role']=='production-loop-fixture'
 assert sha(pivot/'initramfs.cpio.gz')==pm['initramfs_sha256'];assert sha(pivot/'firmware.sqfs')==pm['squashfs_sha256'];assert sha(pivot/pm['image_filename'])==pm['image_sha256'];assert pm['guardian_input']['sha256']==fm['guardian']['sha256']
 native=R/'build/asus-trial-runtime'/a.native;nm=json.loads((native/'manifest.json').read_text());ns={Path(x['path']).name:x['sha256'] for x in nm['sources']};fs={Path(x['path']).name:x['sha256'] for x in fm['sources']}
 shared=['production.c','trial-policy.c','trial-policy.h','trial-handoff.h','preflight.c','control-server.c','control-server.h','process-auth.c','local-health.c','health-worker.c','health-worker.h','sshd-state.h','diagnostic-state.c','diagnostic-state.h','boot-diagnostics.h']
 for name in shared:
  assert ns[name]==fs[name],name
  assert sha(native/'source-snapshot'/name)==ns[name],name
  assert sha(fixture.parent/'source-snapshot'/name)==fs[name],name
 assert sha(R/fm['guardian']['path'])==fm['guardian']['sha256']
 assert fm['diagnostic_build_id']==nm['diagnostic_build_id']
 header=fm['diagnostic_generated_header'];assert sha(R/header['path'])==header['sha256']
 assert (R/header['path']).read_text()=='#define LEON_DIAGNOSTIC_BUILD_ID '+json.dumps(nm['diagnostic_build_id'])+'\n'
 assert pm['production_loop_fixture']['diagnostic_initialization']['before_firmware_pid1_and_guardian_arm'] is True
 assert fs['production.c']==fm['production_loop_source_sha256'];assert nm['deployment_gate_enabled'] is False
 cases=[];errors=[]
 for case in a.scenarios or fm['cases']:
  assert case in fm['cases'];result=overrides.get(case,R/'build/qemu'/('ubuntu26-pivot-'+a.label+'-'+case)/'result.json');directory=result.parent;rr=json.loads(result.read_text());log=directory/'serial.log';text=log.read_text(errors='replace')
  marker=('LAB_TRIAL_LOOP_KERNEL10_COMPLETE' if case.startswith('healthy-') else 'QEMU_UBUNTU26_PIVOT_COMPLETE' if case=='prearm-refuse' else 'LEON_ROOT_EMERGENCY_FIXTURE_SINK stage=guardian-handoff code=0')
  completed=marker in text and not rr['panic']
  expected_stop=(rr['stop_reason']=='complete' or (rr['stop_reason']=='qemu_exit' and rr['exit_code']==0)) or (case=='arm-failure' and rr['stop_reason']=='timeout' and rr['exit_code']==0 and completed)
  checks={'complete_without_panic':completed,'expected_guest_stop':expected_stop,'exact_initramfs':rr['initramfs_sha256']==pm['initramfs_sha256'],'exact_kernel10':rr['kernel_sha256']==nm['kernel_identity']['image_sha256'],'exact_log':sha(log)==rr['log_sha256'],'no_nic':'-nic' in rr['command'] and rr['command'][rr['command'].index('-nic')+1]=='none','real_squashfs_pid1':'LAB_REAL_SQUASHFS_PID1_START' in text,'no_restore_failure':'LEON_ROOT_RESTORE_FAILED' not in text}
  if case.startswith('healthy-'):
   markers=fm['expected_markers']+['LAB_TRIAL_LOOP_ACTUAL_KERNEL_NOTES_PASS','LAB_TRIAL_LOOP_REAL_SSH_AND_LOCAL_REJECT_PASS','LAB_TRIAL_LOOP_HEALTHY_KEEPS_FEEDING_PASS','LAB_TRIAL_LOOP_IMMUTABLE_OWNER_QUERY_PASS']
   checks.update({marker:marker in text for marker in markers})
   checks.update(prepared_before_armed=0<=text.find('LEON_ROOT_GUARDIAN_PREPARED_UNARMED')<text.find('LEON_ROOT_GUARDIAN_ARMED'),armed_exact_40='LEON_ROOT_GUARDIAN_ARMED stage=guardian-handoff code=40' in text,real_systemd='systemd 259.5-' in text,actual_collector_all_bits='LAB_TRIAL_LOOP_COLLECT bits=7' in text,healthy_before_failure_before_reset=0<=text.find('LAB_TRIAL_LOOP_REAL_HEALTH_AND_SSH_ACK_PASS')<text.find('LAB_TRIAL_LOOP_FAILURE_LATCHED_PASS')<text.find('LAB_TRIAL_LOOP_RESET_SINK_PASS'),no_emergency_or_fallback='LEON_ROOT_EMERGENCY_RESET' not in text and 'LEON_ROOT_FALLBACK' not in text,no_failed_proof=bool(re.findall(r'LAB_TRIAL_LOOP_PROOF_EXIT_code=(\d+)',text)) and not any(int(n) for n in re.findall(r'LAB_TRIAL_LOOP_PROOF_EXIT_code=(\d+)',text)))
   if case=='healthy-lan-expiry':checks['lan_lease_reason']=bool(re.search(r'LAB_TRIAL_LOOP_STATE phase=3 failed=1 reason=6 ',text))
   if case=='healthy-ssh-argv':checks.update(real_running_wrong_config_injected=0<=text.find('LAB_TRIAL_LOOP_SSH_RESTART_INJECTION_BEGIN')<text.find('LAB_TRIAL_LOOP_LIVE_SSH_WRONG_ARGV_INJECTED')<text.find('LAB_TRIAL_LOOP_FAILURE_LATCHED_PASS'),no_competing_capture_timeout='LAB_TRIAL_LOOP_CAPTURE_ABORT' not in text[text.find('LAB_TRIAL_LOOP_SSH_RESTART_INJECTION_BEGIN'):text.find('LAB_TRIAL_LOOP_FAILURE_LATCHED_PASS')],ssh_and_dependent_lan_bits_lost='LAB_TRIAL_LOOP_COLLECT bits=1' in text,local_failure_reason=bool(re.search(r'LAB_TRIAL_LOOP_STATE phase=3 failed=1 reason=4 ',text)))
   if case=='healthy-worker-hang':checks.update(worker_injected_after_healthy=0<=text.find('LAB_TRIAL_LOOP_HEALTHY_KEEPS_FEEDING_PASS')<text.find('LAB_TRIAL_LOOP_WORKER_HANG_INJECTED')<text.find('LAB_TRIAL_LOOP_FAILURE_LATCHED_PASS'),worker_abnormal_evidence='LAB_TRIAL_LOOP_WORKER_EXIT' in text or 'LAB_TRIAL_LOOP_WORKER_KILL' in text,diagnostic_waitpid_status='LAB_TRIAL_LOOP_DIAGNOSTIC_WORKER_WAIT_STATUS_PASS' in text)
   if case=='healthy-metadata-change':checks.update(metadata_injected_after_healthy=0<=text.find('LAB_TRIAL_LOOP_HEALTHY_KEEPS_FEEDING_PASS')<text.find('LAB_TRIAL_LOOP_METADATA_RO_LOST_INJECTED')<text.find('LAB_TRIAL_LOOP_FAILURE_LATCHED_PASS'),metadata_recheck_failed='LAB_TRIAL_LOOP_METADATA_RECHECK_FAILED' in text)
  elif case=='prearm-refuse':checks.update(prearm_refused='LEON_ROOT_GUARDIAN_REFUSED_UNARMED' in text,never_armed='LAB_TRIAL_LOOP_MOCK_ARMED_40S_PASS' not in text,safe_vendor_fallback='LAB_VENDOR_FALLBACK_PID1_SQUASHFS_PASS' in text,no_emergency='LEON_ROOT_EMERGENCY_RESET' not in text)
  elif case=='arm-failure':checks.update(arm_failure='LAB_TRIAL_LOOP_ARM_FAILURE_INJECTED' in text,verified_sysrq_selected='LAB_TRIAL_LOOP_EMERGENCY_SINK path=verified-proc-sysrq-b' in text,no_vendor_exec_or_restored_root='LEON_ROOT_VENDOR_EXEC' not in text and 'LAB_VENDOR_FALLBACK_PID1_SQUASHFS_PASS' not in text,emergency_sink='LEON_ROOT_EMERGENCY_FIXTURE_SINK' in text)
  errors.extend({'case':case,'check':key} for key,value in checks.items() if not value)
  cases.append({'case':case,'checks':checks,'elapsed_seconds':rr['elapsed_seconds'],'result':ref(result),'serial':ref(log),'fixture_completion_marker':marker,'original_runner_generic_complete':rr['guest_complete'],'completion_evaluation':'Actual fixed fixture marker; original result/serial bytes preserved'})
 report={'schema_version':1,'status':'component_validated_with_explicit_synthetic_adapters' if not errors else 'failed','passed':not errors,'production_loop_fixture_validation_passed':not errors,'all_six_scenarios_passed':not errors and set(x['case'] for x in cases)==set(fm['cases']),'native_guardian_gate_enabled':False,'physical_watchdog_opened':False,'physical_reset_and_stock_fallback_proven':False,'ASUS_hardware_services_validated':False,'runtime_accepted':False,'automatic_commit_allowed':False,'router_accessed':False,'fixture':ref(fixture),'pivot':ref(pivot/'manifest.json'),'native_build':ref(native/'manifest.json'),'shared_production_sources':{name:fs[name] for name in shared},'timings_ms':fm['timings_ms'],'synthetic_seams':fm['synthetic_seams'],'cases':cases,'errors':errors,'limits':['Actual production control loop, worker, parser and native SSH session checks are exercised; board storage, ASUS backend and hardware watchdog/reset are explicit substitutes.','Kernel core may keep feeding a bootloader-started watchdog before userspace opens it. These results do not promise a 40-second reset for arbitrary pre-ARM hangs.','A bounded external SSH observer is required for trial only; permanent acceptance and physical functional tests remain separate.'],'checker':ref(Path(__file__))}
 out=R/'reports/ubuntu26'/('asus-trial-loop-'+a.label+'.json');assert not out.exists();out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'scenarios':len(cases),'errors':errors,'report':str(out.relative_to(R))},indent=2));raise SystemExit(bool(errors))
if __name__=='__main__':main()

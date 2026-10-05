#!/usr/bin/env python3
"""One guarded continuation after zero-child refusal and fresh read-only views."""
from pathlib import Path
import importlib.util,json,shutil,sys,hashlib
R=Path(__file__).resolve().parents[1]
BASE=R/'evidence/ubuntu26/trial-live/fourteenth-return-forensics-v1'
OUT=BASE/'resume-exclusive-upload-v2'
record=json.loads((BASE/'result.json').read_text())
assert record['status']=='refused_evidence_preserved_no_retry'
assert record['recovery_started'] is True and record['export_started'] is False
assert (BASE/'recover.stdout').read_bytes()==b''
assert (BASE/'recover.stderr').read_bytes()==b'LEON_RECOVERY_REFUSED stage=same-boot-and-stock-root started=0 reaped=0 timed_out=0 status=0 retries=0 mounted=false provisioned=false\n'
stock=json.loads((BASE/'stock-result.json').read_text());boot=stock['boot_id']
assert boot=='00000000-0000-4000-8000-000000000024'
for name in ('preflight-refusal-current-state-v1','preflight-refusal-p11-consumers-v1'):
 view=json.loads((BASE/name/'result.json').read_text());assert view['returncode']==0
current=(BASE/'preflight-refusal-current-state-v1/stdout').read_text()
assert current.startswith(boot+'\n/sbin/rc\n')
consumers=(BASE/'preflight-refusal-p11-consumers-v1/stdout').read_text()
assert consumers.startswith('BOOT='+boot+'\nHOLDERS\nSWAPS\n')
assert 'P11_MOUNT pid=' not in consumers and 'UNREADABLE_STILL_PRESENT pid=' not in consumers
assert '\nPROCESS_COUNT=179\n' in consumers
spec=importlib.util.spec_from_file_location('unchanged_v14_forensics',R/'scripts/forensics-v14-clean-return.py')
m=importlib.util.module_from_spec(spec)
source=Path(spec.origin).read_text()
old='/tmp/leon-clean-v14-';new='/tmp/leon-clean-v14-resume-v2-'
assert source.count(old)==1 and new not in source
patched=source.replace(old,new)
assert patched.replace(new,old)==source
exec(compile(patched,spec.origin,'exec'),m.__dict__)
prior_resume=json.loads((BASE/'resume-after-preflight-refusal-v1/result.json').read_text())
assert prior_resume['recovery_started'] is False and prior_resume['export_started'] is False
assert prior_resume['error']=='Step refused: recover-transfer rc=1; no retry'

OUT.mkdir(exist_ok=False)
for name in ('stock-result.json','stock-context.stdout'):
 shutil.copyfile(BASE/name,OUT/name)
(OUT/'continuation-basis.json').write_text(json.dumps({'schema':1,'reason':'zero-child frozen-helper refusal; fresh views show same stock boot, no persistent p11 consumer or unreadable process mount view','prior_refusal':str((BASE/'result.json').relative_to(R)),'prior_refusal_sha256':hashlib.sha256((BASE/'result.json').read_bytes()).hexdigest(),'prior_recovery_child_starts':0,'new_guarded_attempt_limit':1,'exclusive_remote_prefix_changed_only':True,'prior_resume_stopped_before_helper':True,'frozen_checks_unchanged':True,'exact_transient_predicate_not_identified':True},indent=2)+'\n')
m.OUT=OUT
sys.argv=[str(R/'scripts/forensics-v14-clean-return.py'),'recover-and-export']
m.main()

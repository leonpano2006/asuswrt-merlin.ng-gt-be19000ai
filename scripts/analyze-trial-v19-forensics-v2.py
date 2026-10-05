#!/usr/bin/env python3
"""Plan one V19 export analysis; pending export SHA blocks all analysis commands."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

R=Path(__file__).resolve().parents[1]
EXPORT=('evidence/ubuntu26/trial-live/nineteenth-return-forensics-v1/export.stdout','61450fbc376ef664d3d68ec4ff976a5e63ab5f080f8d4017179e0dff80e375fc')
RETURN_RECEIPT_PIN=('evidence/ubuntu26/trial-live/nineteenth-return-forensics-v1/result.json','b2e6ddc3b31e1d4ccd7f2b0dca8c57c9d363f28d7d5b15f1e3d44e0b9e9a80a8')
RETURN_RECEIPT=R/RETURN_RECEIPT_PIN[0]
V19_TEMPLATE=('scripts/analyze-trial-v19-forensics-v1.py','4ed21c2125b35e5fb7dbf3ed9b0fbb9309829548d51f6fcefc5102e0526f15ea')
PRIMARY_RESULT=('evidence/ubuntu26/trial-live/nineteenth-primary-readonly-v1/result.json','155a7f0d2d454629f6ab8cb756e1f27e001436cfbd2835d2849a6689fe03853c')
PRIMARY_STDOUT=('evidence/ubuntu26/trial-live/nineteenth-primary-readonly-v1/stdout','c50910dfd9e0b5257245b81bbc982074e2035a08d6a814ca2a263ed31c81dcf5')
NATIVE_BOOT='00000000-0000-4000-8000-000000000030'
PRIMARY_HOST_KEY='208b0e8d4a18194d0da78a722eed6b361ccce51f3a3643a9575c4f3c50c04db3'
BASE_TEMPLATE=('scripts/analyze-trial-v17-forensics-v1.py','d11d25288c66d78e603cd4e4dadaf284255eb7bfe5cbf600fefacc309c387d3e')
OUT=R/'evidence/ubuntu26/trial-live/nineteenth-forensics-analysis-v2'
BASE=('scripts/analyze-trial-v15-forensics-v1.py','cf5d8beb835335dfd3a9c09ead10de4ba755d0cbd1068ea1288616255348fd8d')
PARSER=('scripts/asus-integration/boot-diagnostics/parse.py','f3693a5ef4c2cd32f72a2b173c166daaa0a0de4b9b7ae3a5869ba1c944a99082')
V14=('evidence/ubuntu26/trial-live/fourteenth-return-forensics-v1/resume-exclusive-upload-v2/journal-inventory.json',
     '833163bfd5dca3b51d48443b9639474e700ef3d08515c1fcf6e18fe1b4388aea')
V15=('evidence/ubuntu26/trial-live/fifteenth-return-forensics-v1/journal-inventory.json',
     'e8dc4661c7410ab41e2d241960c042efb24ff47b8aad652e40df237edc5f7c4b')
V17=('evidence/ubuntu26/trial-live/seventeenth-forensics-analysis-v1/journal-inventory.json','f147f871d92bf4c34ebf9d3b89f46cd408c25ed0a10bcc7c03166d80799784a9')
V17_RESULT=('evidence/ubuntu26/trial-live/seventeenth-forensics-analysis-v1/result.json','76d5e2b7c3a88d51d44ed4882fc2ed5fe50f14f49341fd0b9277f1c2f6a474e5')
V18_TEMPLATE=('scripts/analyze-trial-v18-forensics-v1.py','3fb224149590397fee69b438ca664c7e79885997ed3bc3b9e7da159b8f127d43')
V18=('evidence/ubuntu26/trial-live/eighteenth-forensics-analysis-v1/journal-inventory.json','a9844277ce459a8e9659b59db1ec205c8f1a91cfac1a498b7b9cfe9a5d0d5cb1')
V18_RESULT=('evidence/ubuntu26/trial-live/eighteenth-forensics-analysis-v1/result.json','3f77d07ec1f0daddba9e72f41258b61e250cec95da9f425918cf0e6ff706fcb8')
V18_BOOT='00000000-0000-4000-8000-000000000015'
V17_BOOT='00000000-0000-4000-8000-000000000005'
V16_BOOT='00000000-0000-4000-8000-000000000023'
PRIOR_BOOTS={'00000000-0000-4000-8000-000000000036','00000000-0000-4000-8000-000000000021',V16_BOOT,V17_BOOT,V18_BOOT}
INHERITED_ARCHIVE='var/log/journal/70dbd0a4090e4fdc8a3d260f6a4b17a4/system@37b1875e3c7340cb804d23a5743bdba5-00000000000015b9-00065d085f622e1e.journal'
INHERITED_SHA='89639139abd91ebc3cbe48e969c39dcc853082b0a33e69a2640f4202b04c7b8a'

def require(value,why):
    if not value:raise RuntimeError(why)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def ref(path):
    require(path.is_file() and not path.is_symlink(),'Regular local input required: '+str(path))
    return {'path':path.relative_to(R).as_posix(),'sha256':sha(path),'bytes':path.stat().st_size}
def pinned(row):
    value=ref(R/row[0]);require(value['sha256']==row[1],'Pinned source/proof changed: '+row[0]);return value
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def prior_proofs():
    references=[pinned(V14),pinned(V15),pinned(V17)]
    v17_result_ref=pinned(V17_RESULT);v17_result=json.loads((R/V17_RESULT[0]).read_text())
    require(v17_result['status']=='new_v17_forensics_analysis_complete' and v17_result['candidate_boot']==V17_BOOT
            and v17_result['source']['sha256']==BASE_TEMPLATE[1], 'Actual completed V17 analyzer provenance')
    inventories=[json.loads((R/row[0]).read_text()) for row in (V14,V15,V17)]
    require(inventories[0]['candidate_boot']=='00000000-0000-4000-8000-000000000036'
            and inventories[1]['candidate_boot']=='00000000-0000-4000-8000-000000000021'
            and inventories[2]['candidate_boot']==V17_BOOT
            and len(inventories[2]['changed_verified'])==v17_result['new_journals_verified'],
            'Only actual V14/V15/V17 verification inventories may be reused')
    passed={}
    for reference,inventory in zip(references,inventories):
        for row in inventory['changed_verified']:
            require(row['returncode']==0,'Old verification was not successful')
            passed[row['sha256']]={'inventory':reference,'old_path':row['path'],'proof':'actual_prior_verify_returncode0'}
    require(all(INHERITED_ARCHIVE in j['unchanged_reused'] for j in inventories),
            'Common old archive must be an actual reused proof in V14/V15/V17')
    for row in (V14,V15,V17):
        old=R/row[0]
        require(sha(old.parent/'extracted'/INHERITED_ARCHIVE)==INHERITED_SHA,
                'Common old archive byte identity changed')
    passed[INHERITED_SHA]={'inventories':list(references),'old_path':INHERITED_ARCHIVE,
                         'proof':'actual_V14_V15_V17_inherited_verification_with_fixed_byte_identity'}
    references.append(v17_result_ref)
    v18_ref=pinned(V18);v18_result_ref=pinned(V18_RESULT)
    v18=json.loads((R/V18[0]).read_text());v18_result=json.loads((R/V18_RESULT[0]).read_text())
    require(v18_result['status']=='v18_forensics_analysis_complete_no_fresh_native_journal_proved'
            and v18_result['source']['sha256']==V18_TEMPLATE[1]
            and v18_result['new_journals_verified']==0 and v18_result['old_verifications_reused']==3
            and v18['changed_verified']==[] and len(v18['reused_proofs'])==3,
            'Actual completed V18 no-new-journal provenance must be preserved')
    require(set(v18['observed_diagnostic_boot_ids'])=={V17_BOOT,V18_BOOT}
            and v18['candidate_boot'] is None and v18['fresh_v18_diagnostic_boot_proved'] is False,
            'Mixed V18 producers must not be relabelled as a fresh V19 boot')
    reused_names=[];reused_digests=[]
    for row in v18['reused_proofs']:
        name=row['path'];digest=row['sha256']
        require(re.fullmatch(r'var/log/journal/[0-9a-f]{32}/system(?:@[0-9a-f-]+)?\.journal',name)
                and name not in reused_names and digest not in reused_digests,
                'Unique fixed V18 journal proof members required')
        require(digest in passed and row['prior_proof']==passed[digest],
                'V18 reused proof must match the already successful verification provenance')
        old=(R/V18[0]).parent/'extracted'/name
        require(ref(old)['sha256']==digest,'Actual V18 extracted journal bytes changed')
        reused_names.append(name);reused_digests.append(digest)
    require(set(reused_names)==set(v18['unchanged_reused']) and len(v18['unchanged_reused'])==3,
            'All three actual V18 reused journals must be byte-bound')
    for row in v18['reused_proofs']:
        passed[row['sha256']]={'inventory':v18_ref,'result':v18_result_ref,'old_path':row['path'],
                              'proof':'actual_V18_byte_identical_reuse_of_successful_prior_verification',
                              'prior_proof':row['prior_proof']}
    references.extend([v18_ref,v18_result_ref])
    return references,passed

def primary_proof():
    result_ref=pinned(PRIMARY_RESULT);stdout_ref=pinned(PRIMARY_STDOUT)
    result=json.loads((R/PRIMARY_RESULT[0]).read_text());raw=(R/PRIMARY_STDOUT[0]).read_bytes()
    require(result['returncode']==0 and result['ack_sent'] is False and result['settings_changed'] is False
            and result['source']=='192.168.100.35' and result['destination']=='192.168.100.15:22'
            and result['host_key_sha256_hex']==PRIMARY_HOST_KEY,
            'Actual successful authenticated read-only primary SSH receipt required')
    require(raw.startswith(('BOOT='+NATIVE_BOOT+'\nPID1=systemd\n').encode())
            and re.findall(rb'(?m)^BOOT=([^\n]+)$',raw)==[NATIVE_BOOT.encode()]
            and b'\n/dev/mmcblk0p11 ext4 ea8e47b8-c606-406c-b931-d2244d26ec55\n' in raw,
            'Hash-bound actual native boot/PID1/root output required')
    return {'result':result_ref,'stdout':stdout_ref,'boot_id':NATIVE_BOOT,
            'authenticated_primary_returncode':0,'diagnostic_freshness_claimed':False}

def prepare():
    require(__debug__,'Python -O forbidden')
    require(not OUT.exists() and not OUT.is_symlink(),'Exclusive V19 analysis output already exists')
    inputs={'baseline':pinned(BASE),'parser':pinned(PARSER),'frozen_v17_template':pinned(BASE_TEMPLATE),'frozen_v18_template':pinned(V18_TEMPLATE)}
    inputs['frozen_v19_v1_template']=pinned(V19_TEMPLATE)
    primary=primary_proof()
    old,passed=prior_proofs()
    ready=EXPORT[1] is not None and RETURN_RECEIPT_PIN[1] is not None
    export=receipt=None
    if ready:
        export=pinned(EXPORT);receipt=pinned(RETURN_RECEIPT_PIN)
        require(export['bytes']<=256*1024*1024,'Bounded raw export required')
        data=json.loads(RETURN_RECEIPT.read_text())
        require(data['status']=='clean_only_export_complete' and data['export_sha256']==EXPORT[1],
                'Actual complete clean-only export receipt must bind its bytes')
    plan={'schema':1,'status':'v19_forensics_analysis_v2_source_plan_only','source':ref(Path(__file__)),
          'inputs':inputs,'actual_primary_proof':primary,'export':export,'return_receipt':receipt,'pending_export_path':EXPORT[0],
          'ready_for_execution':ready,'output':OUT.relative_to(R).as_posix(),
          'reused_verification_inventories':old,'reusable_verified_digests':sorted(passed),
          'known_v16_native_boot':V16_BOOT,'v16_journal_previously_verified':False,
          'known_v17_native_boot':V17_BOOT,'v17_verification_reused_by_exact_digest':True,
          'known_v18_bootstrap_boot':V18_BOOT,'v18_all_three_journal_proofs_reused_by_exact_digest':True,
          'journal_boot_fixed_to_authenticated_actual_native_boot':NATIVE_BOOT,
          'fresh_bootstrap_if_present_must_match_authenticated_boot':True,
          'guardian_boot_must_match_authenticated_boot_independently':True,
          'missing_or_old_diagnostics_do_not_skip_actual_boot_journal_query':True,
          'verify_only_journals_without_exact_old_verified_byte_identity':True,
          'no_old_verification_reruns':True,'device_accessed':False,'builds_tests_QEMU':False,
          'no_fresh_diagnostic_or_journal_is_retained_without_v19_verification_claim':True,
          'old_v16_journal_query_not_repeated':True,'root_cause_inferred':False}
    return plan,passed

def analyze(plan,passed,gate):
    require(plan['ready_for_execution'] is True,'Actual export SHA pending; no extraction or journal command allowed')
    require(hashlib.sha256(canonical(plan)).hexdigest()==gate,'Exact reviewed local analysis plan required')
    OUT.mkdir(parents=True,exist_ok=False)
    result={**plan,'status':'analysis_started_outcome_unknown','approved_plan_sha256':gate}
    try:
        dest=OUT/'extracted';dest.mkdir()
        names=[];total=0
        with tarfile.open(R/EXPORT[0],'r:') as archive:
            for member in archive:
                name=member.name
                allowed=name in ('etc/leon/root-generation','etc/leon/trial-slot-proof','etc/leon/boot-diagnostics','metadata.txt')
                allowed|=bool(re.fullmatch(r'var/lib/leon-boot/diagnostics/[0-9a-f-]{36}\.root-init\.log',name))
                allowed|=bool(re.fullmatch(r'var/log/journal/[0-9a-f]{32}/system(?:@[0-9a-f-]+)?\.journal',name))
                require(allowed and name not in names and member.isfile() and not member.islnk(),'Fixed regular export member required')
                total+=member.size
                require(0<=member.size<=32*1024*1024 and total<=256*1024*1024 and len(names)<128,'Bounded export members required')
                path=dest/name;path.parent.mkdir(parents=True,exist_ok=True)
                with path.open('xb') as output:output.write(archive.extractfile(member).read())
                names.append(name)
        spec=importlib.util.spec_from_file_location('fixed_boot_diagnostic_parser',R/PARSER[0])
        parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
        parsed={'schema':1,'slots':[],'boot_ids':[],'diagnostic_file_status':'absent',
                'not_claimed':'SSH boot proof does not imply diagnostic producer freshness.'}
        if 'etc/leon/boot-diagnostics' in names:
            try:
                parsed=parser.parse((dest/'etc/leon/boot-diagnostics').read_bytes())
                parsed['diagnostic_file_status']='present_parsed'
            except ValueError as exc:
                parsed.update(diagnostic_file_status='invalid_length_or_structure',parse_error=str(exc))
        (OUT/'parsed.json').write_text(json.dumps(parsed,indent=2)+'\n')
        bootstrap=[row for row in parsed['slots'] if row['producer']==0 and row['status']=='valid']
        require(len(bootstrap)<=1,'Unique bootstrap diagnostic producer required')
        fresh_boot=bool(bootstrap and bootstrap[0]['boot_id'] not in PRIOR_BOOTS)
        require(not fresh_boot or bootstrap[0]['boot_id']==NATIVE_BOOT,
                'Fresh bootstrap producer must match independently authenticated actual V19 boot')
        boot=NATIVE_BOOT
        guardian=[row for row in parsed['slots'] if row['producer']==1 and row['status']=='valid']
        require(len(guardian)<=1,'Unique guardian diagnostic producer required')
        fresh_guardian=bool(guardian and guardian[0]['boot_id']==NATIVE_BOOT)
        single_boot=len(parsed['boot_ids'])==1 and all(row['status']=='valid' for row in parsed['slots'])
        producer_proof={'bootstrap':bootstrap[0] if bootstrap else None,
                        'guardian':guardian[0] if guardian else None,
                        'authenticated_actual_native_boot':NATIVE_BOOT,
                        'selected_fresh_bootstrap_boot':boot if fresh_boot else None,
                        'guardian_record_matches_authenticated_actual_boot':fresh_guardian,
                        'old_or_different_boot_guardian_not_claimed_fresh':not fresh_guardian}
        result.update(observed_diagnostic_boot_ids=parsed['boot_ids'],diagnostic_slots_valid_for_single_boot=single_boot,
                      diagnostic_producer_attribution=producer_proof,
                      fresh_v19_diagnostic_boot_proved=fresh_boot,
                      fresh_v19_guardian_diagnostic_boot_proved=fresh_guardian,
                      v19_journal_proved=False,v19_journal_lines=0)
        record={'candidate_boot':boot,'observed_diagnostic_boot_ids':parsed['boot_ids'],
                'fresh_v19_diagnostic_boot_proved':fresh_boot,
                'fresh_v19_guardian_diagnostic_boot_proved':fresh_guardian,
                'diagnostic_producer_attribution':producer_proof,
                'known_v16_native_boot':V16_BOOT,'v16_previously_verified':False,
                'known_v17_native_boot':V17_BOOT,'known_v18_bootstrap_boot':V18_BOOT,
                'changed_verified':[],'unchanged_reused':[],'reused_proofs':[]}
        env=dict(os.environ,TMPDIR='/tmp')
        journals=sorted((dest/'var/log/journal').rglob('*.journal'))
        for i,path in enumerate(journals):
            name=path.relative_to(dest).as_posix();digest=sha(path)
            if digest in passed:
                record['unchanged_reused'].append(name)
                record['reused_proofs'].append({'path':name,'sha256':digest,'prior_proof':passed[digest]})
                continue
            check=subprocess.run(['journalctl','--verify','--file='+str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env=env)
            (OUT/f'journal-verify-new-{i}.stdout').write_bytes(check.stdout)
            (OUT/f'journal-verify-new-{i}.stderr').write_bytes(check.stderr)
            record['changed_verified'].append({'path':name,'sha256':digest,'returncode':check.returncode})
            require(check.returncode==0,'New journal verification refused; no retry')
        (OUT/'journal-inventory.json').write_text(json.dumps(record,indent=2)+'\n')
        queries=[('monotonic',NATIVE_BOOT,True)]
        for label,identity,mandatory in queries:
            lines=subprocess.run(['journalctl','--directory='+str(dest/'var/log/journal'),'--boot='+identity.replace('-',''),
                                  '-o','short-monotonic','--no-pager'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env=env)
            (OUT/(label+'.txt')).write_bytes(lines.stdout);(OUT/(label+'.stderr')).write_bytes(lines.stderr)
            present=lines.returncode==0 and bool(re.search(rb'(?m)^\[\s*[0-9]+\.[0-9]+\]',lines.stdout))
            if mandatory:
                result['v19_journal_proved']=present
                focus=[line[:4096] for line in lines.stdout.splitlines() if
                       b'LEON_RESCUE' in line or b'leon-asus-rescue-link.service' in line or b'leon-asus-ssh-uplink-rescue' in line
                       or b'ASUS_NATIVE_PREPARE' in line or b'leon-asus-broker' in line or b'LEON_ROOT_' in line]
                raw=(b'\n'.join(focus[:256])+b'\n')[:256*1024]
                (OUT/'rescue-focused.txt').write_bytes(raw)
                result['v19_journal_lines']=len(lines.stdout.splitlines())
                result['rescue_focus_truncated']=len(focus)>256 or len(raw)==256*1024
            else:
                result['v16_journal_present_in_new_export']=present
                result['v16_journal_extraction_returncode']=lines.returncode
                result['v16_journal_previously_verified']=False
        proved=result['v19_journal_proved']
        result.update(status='new_v19_forensics_analysis_complete' if proved else 'v19_forensics_analysis_complete_no_fresh_native_journal_proved',
                      candidate_boot=NATIVE_BOOT,candidate_boot_basis='authenticated_primary_SSH_saved_result_and_stdout',members=len(names),
                      new_journal_count=len(record['changed_verified']),new_journals_verified=len(record['changed_verified']),
                      old_verifications_reused=len(record['unchanged_reused']),v16_journal_previously_verified=False,
                      diagnosis='Query the independently authenticated V19 boot; diagnostic producers remain separately attributed. Missing or old diagnostics do not prove fresh producers, and absent journal data does not establish a cause.')
    except Exception as exc:
        result.update(status='failed_analysis_evidence_retained_no_retry',error=str(exc));raise
    finally:
        (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result),flush=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only',action='store_true');group.add_argument('--execute-plan-sha256')
    args=parser.parse_args();plan,passed=prepare()
    gate=hashlib.sha256(canonical(plan)).hexdigest()
    if args.execute_plan_sha256 is None:print(json.dumps({'plan_sha256':gate,'plan':plan},indent=2))
    else:analyze(plan,passed,args.execute_plan_sha256)

if __name__=='__main__':main()

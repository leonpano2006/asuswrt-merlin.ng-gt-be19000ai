#!/usr/bin/env python3
"""Plan one V17 export analysis; pending export SHA blocks all analysis commands."""
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
EXPORT=('evidence/ubuntu26/trial-live/seventeenth-return-forensics-v1/export.stdout','7360d58cf2df8f16aa41743da5331741d24606d739d53c32b013cc7fe49d6a10')
RETURN_RECEIPT=R/'evidence/ubuntu26/trial-live/seventeenth-return-forensics-v1/result.json'
OUT=R/'evidence/ubuntu26/trial-live/seventeenth-forensics-analysis-v1'
BASE=('scripts/analyze-trial-v15-forensics-v1.py','cf5d8beb835335dfd3a9c09ead10de4ba755d0cbd1068ea1288616255348fd8d')
PARSER=('scripts/asus-integration/boot-diagnostics/parse.py','f3693a5ef4c2cd32f72a2b173c166daaa0a0de4b9b7ae3a5869ba1c944a99082')
V14=('evidence/ubuntu26/trial-live/fourteenth-return-forensics-v1/resume-exclusive-upload-v2/journal-inventory.json',
     '833163bfd5dca3b51d48443b9639474e700ef3d08515c1fcf6e18fe1b4388aea')
V15=('evidence/ubuntu26/trial-live/fifteenth-return-forensics-v1/journal-inventory.json',
     'e8dc4661c7410ab41e2d241960c042efb24ff47b8aad652e40df237edc5f7c4b')
V16_BOOT='00000000-0000-4000-8000-000000000023'
PRIOR_BOOTS={'00000000-0000-4000-8000-000000000036','00000000-0000-4000-8000-000000000021',V16_BOOT}
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
    references=[pinned(V14),pinned(V15)]
    inventories=[json.loads((R/row[0]).read_text()) for row in (V14,V15)]
    require(inventories[0]['candidate_boot']=='00000000-0000-4000-8000-000000000036'
            and inventories[1]['candidate_boot']=='00000000-0000-4000-8000-000000000021',
            'Only actual V14/V15 verification inventories may be reused')
    passed={}
    for reference,inventory in zip(references,inventories):
        for row in inventory['changed_verified']:
            require(row['returncode']==0,'Old verification was not successful')
            passed[row['sha256']]={'inventory':reference,'old_path':row['path'],'proof':'actual_prior_verify_returncode0'}
    require(all(INHERITED_ARCHIVE in j['unchanged_reused'] for j in inventories),
            'Common old archive must be an actual reused proof in both V14/V15')
    for row in (V14,V15):
        old=R/row[0]
        require(sha(old.parent/'extracted'/INHERITED_ARCHIVE)==INHERITED_SHA,
                'Common old archive byte identity changed')
    passed[INHERITED_SHA]={'inventories':references,'old_path':INHERITED_ARCHIVE,
                         'proof':'actual_V14_V15_inherited_verification_with_fixed_byte_identity'}
    return references,passed

def prepare():
    require(__debug__,'Python -O forbidden')
    require(not OUT.exists() and not OUT.is_symlink(),'Exclusive V17 analysis output already exists')
    inputs={'baseline':pinned(BASE),'parser':pinned(PARSER)}
    old,passed=prior_proofs()
    ready=EXPORT[1] is not None
    export=receipt=None
    if ready:
        export=pinned(EXPORT);receipt=ref(RETURN_RECEIPT)
        require(export['bytes']<=256*1024*1024,'Bounded raw export required')
        data=json.loads(RETURN_RECEIPT.read_text())
        require(data['status']=='clean_only_export_complete' and data['export_sha256']==EXPORT[1],
                'Actual complete clean-only export receipt must bind its bytes')
    plan={'schema':1,'status':'v17_forensics_analysis_source_plan_only','source':ref(Path(__file__)),
          'inputs':inputs,'export':export,'return_receipt':receipt,'pending_export_path':EXPORT[0],
          'ready_for_execution':ready,'output':OUT.relative_to(R).as_posix(),
          'reused_verification_inventories':old,'reusable_verified_digests':sorted(passed),
          'known_v16_native_boot':V16_BOOT,'v16_journal_previously_verified':False,
          'v17_native_boot_unknown_until_diagnostic_parse':True,
          'verify_only_journals_without_exact_old_verified_byte_identity':True,
          'no_old_verification_reruns':True,'device_accessed':False,'builds_tests_QEMU':False,
          'root_cause_inferred':False}
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
        require('etc/leon/boot-diagnostics' in names,'Actual boot diagnostics required')
        spec=importlib.util.spec_from_file_location('fixed_boot_diagnostic_parser',R/PARSER[0])
        parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
        parsed=parser.parse((dest/'etc/leon/boot-diagnostics').read_bytes())
        (OUT/'parsed.json').write_text(json.dumps(parsed,indent=2)+'\n')
        require(len(parsed['boot_ids'])==1 and all(row['status']=='valid' for row in parsed['slots']),'One valid diagnostic boot required')
        boot=parsed['boot_ids'][0]
        require(boot not in PRIOR_BOOTS,'No fresh V17 diagnostic boot proved; do not label a prior V14/V15/V16 boot as V17')
        record={'candidate_boot':boot,'known_v16_native_boot':V16_BOOT,'v16_previously_verified':False,
                'changed_verified':[],'unchanged_reused':[],'reused_proofs':[]}
        env=dict(os.environ,TMPDIR='/tmp')
        journals=sorted((dest/'var/log/journal').rglob('*.journal'))
        require(journals,'Journal members required')
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
        for label,identity,mandatory in [('monotonic',boot,True),('v16-monotonic',V16_BOOT,False)]:
            lines=subprocess.run(['journalctl','--directory='+str(dest/'var/log/journal'),'--boot='+identity.replace('-',''),
                                  '-o','short-monotonic','--no-pager'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env=env)
            (OUT/(label+'.txt')).write_bytes(lines.stdout);(OUT/(label+'.stderr')).write_bytes(lines.stderr)
            present=lines.returncode==0 and bool(re.search(rb'(?m)^\[\s*[0-9]+\.[0-9]+\]',lines.stdout))
            if mandatory:
                require(present,'Fresh V17 journal entries required')
                focus=[line[:4096] for line in lines.stdout.splitlines() if
                       b'LEON_RESCUE' in line or b'leon-asus-rescue-link.service' in line or b'leon-asus-ssh-uplink-rescue' in line]
                raw=(b'\n'.join(focus[:256])+b'\n')[:256*1024]
                (OUT/'rescue-focused.txt').write_bytes(raw)
                result['v17_journal_lines']=len(lines.stdout.splitlines())
                result['rescue_focus_truncated']=len(focus)>256 or len(raw)==256*1024
            else:
                result['v16_journal_present_in_new_export']=present
                result['v16_journal_extraction_returncode']=lines.returncode
                result['v16_journal_previously_verified']=False
        result.update(status='new_v17_forensics_analysis_complete',candidate_boot=boot,members=len(names),
                      new_journals_verified=len(record['changed_verified']),old_verifications_reused=len(record['unchanged_reused']),
                      diagnosis='Review new rescue-focused.txt dump kind/stage and socket activation; no automatic cause claim.')
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

#!/usr/bin/env python3
"""Read-only compare immutable guardian preflight hashes with a composed tar.

Does not extract or execute the candidate, provision identity, or enable a gate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

R=Path(__file__).resolve().parents[1]
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def ref(path):
    path=path.resolve()
    return {'path':str(path.relative_to(R)) if path.is_relative_to(R) else str(path),'sha256':sha(path)}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label',required=True)
    p.add_argument('--rootfs',type=Path,required=True)
    p.add_argument('--guardian-receipt',type=Path,required=True)
    a=p.parse_args();assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
    receipt=json.loads(a.guardian_receipt.read_text())
    assert receipt['status']=='built' and receipt['scope']=='candidate-device-policy'
    assert receipt['hardware_adapter'] and receipt['fixture'] is False
    manifest=R/receipt['build_manifest']['path'];assert sha(manifest)==receipt['build_manifest']['sha256']
    executable=R/receipt['executable']['path'];assert sha(executable)==receipt['executable']['sha256']
    header=a.guardian_receipt.parent/'identity-production.h'
    assert sha(header)==receipt['generated_identity_policy_sha256']
    rows=re.findall(r'^\{PFX "(/[^"\n]+)","([0-9a-f]{64})"\},$',header.read_text(),re.M)
    assert rows and len({path for path,_ in rows})==len(rows)
    checks=[]
    with tarfile.open(a.rootfs) as archive:
        index={}
        for member in archive:
            name=member.name.removeprefix('./').rstrip('/')
            assert not name.startswith('/') and '..' not in Path(name).parts
            assert name not in index,name
            index[name]=member
        for name,wanted in rows:
            member=index.get(name[1:]);actual=None
            metadata=bool(member and member.isfile() and member.uid==member.gid==0 and not member.mode&0o022)
            if member and member.isfile():
                with archive.extractfile(member) as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
            checks.append({'path':name,'expected_sha256':wanted,'actual_sha256':actual,'root_owned_regular_nonwritable':metadata,'passed':metadata and actual==wanted})
    errors=[row for row in checks if not row['passed']]
    out=R/'reports/ubuntu26'/('asus-trial-identity-map-'+a.label+'.json');assert not out.exists()
    report={'schema_version':1,'passed':not errors,'rootfs':ref(a.rootfs),'guardian_receipt':ref(a.guardian_receipt),'generated_identity_header':ref(header),'guardian':ref(executable),'deployment_gate_enabled':receipt['deployment_gate_enabled'],'count':len(checks),'checks':checks,'errors':errors,'executed_candidate':False,'device_accessed':False,'scope':'Only guardian table file identities and safe tar metadata; not physical slot, provisioned credentials, network or watchdog validation.','checker':ref(Path(__file__))}
    out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':not errors,'checked_files':len(checks),'errors':errors,'report':str(out)}))
    raise SystemExit(bool(errors))
if __name__=='__main__':main()

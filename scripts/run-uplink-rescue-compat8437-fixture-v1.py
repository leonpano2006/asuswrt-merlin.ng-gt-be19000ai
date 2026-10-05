#!/usr/bin/env python3
"""Plan only new raw SDK4.19 table8437 cases; compile/run only by exact gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/uplink-rescue'
SOURCE=('scripts/asus-integration/uplink-rescue/rescue-link-v5.c','3d980d63514c7e9dc0e4352a364a437c89afab7c12319530cb29832eb1a7f78e')
DELTA=('reports/ubuntu26/uplink-rescue-compat8437-v5-source-v1.json','678dd143ebb622d37475597a1a3638a5e1ba8e740496984dcf35e49a81ff673d')
ENV=('build/asus-native-build/v2/result.json','5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc')
RECIPE=('scripts/run-private-sh-link-fixture-v1.py','f4f1d05526eed60b2e6d7358b0ce9d896b09418cfbc77fd7e5922806aae98a4f')
TEMPLATE=('scripts/asus-integration/uplink-rescue/compat8437-route-fixture-v1.c','8542d940e446954cbc8cfa9aafb6b44968fdfe9a09823ed8153ecb694218fc0d')
OUT=R/'build/asus-uplink-rescue/compat8437-focused-fixture-v1'
WORK='uplink-rescue-compat8437-focused-fixture-v1'
CASES=['raw252-8437-disjoint-subnet-pass', 'raw252-8437-disjoint-host-pass', 'raw252-8437-self-overlap-refused', 'raw252-8437-peer-overlap-refused', 'raw252-8437-covering-prefix-refused', 'raw252-8437-default-refused', 'raw252-missing-full-table-refused', 'raw252-unknown-full-table-refused', 'raw252-full-table252-refused', 'raw254-full-table8437-conflict-refused', 'raw0-full-table8437-noncanonical-refused', 'raw252-duplicate-full-table-refused', 'raw252-conflicting-duplicate-table-refused', 'raw252-short-full-table-refused', 'raw252-8437-unknown-attribute-refused', 'raw252-8437-gateway-refused', 'raw252-8437-multipath-refused']
WORKER_TRANSFORMS=[
 {'old':'cp "$inputs/fixture.c" "$inputs/fixture-helpers.h" "$inputs/private-sh-link-update-v1.c.inc" "$root/work/@WORK@/"',
  'new':'cp "$inputs/fixture.c" "$inputs/rescue-link-v5.c" "$root/work/@WORK@/"'},
 {'old':'LEON_PRIVATE_SH_FIXTURE_COMPILE_STARTED','new':'LEON_COMPAT8437_FIXTURE_COMPILE_STARTED'},
 {'old':'fixture.c -o private-sh-fixture','new':'fixture.c -o compat8437-fixture'},
 {'old':'mkdir -m0700 sandbox\n','new':''},
 {'old':'LEON_PRIVATE_SH_FIXTURE_EXECUTION_STARTED','new':'LEON_COMPAT8437_FIXTURE_EXECUTION_STARTED'},
 {'old':'timeout 15 ./private-sh-fixture "$PWD/sandbox"','new':'timeout 15 ./compat8437-fixture'}]

def require(value,why):
    if not value:raise RuntimeError(why)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def ref(path):
    require(path.is_file() and not path.is_symlink(),'Regular local input required: '+str(path))
    return {'path':path.relative_to(R).as_posix(),'sha256':sha(path),'bytes':path.stat().st_size}
def pinned(row):
    value=ref(R/row[0]);require(value['sha256']==row[1],'Pinned input changed: '+row[0]);return value
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()

def prepare():
    require(__debug__,'Python -O forbidden')
    require(not OUT.exists() and not OUT.is_symlink(),'Immutable fixture output already exists')
    inputs={k:pinned(row) for k,row in [('production_source',SOURCE),('source_delta',DELTA),
                                      ('environment',ENV),('accepted_recipe',RECIPE),('template',TEMPLATE)]}
    env=json.loads((R/ENV[0]).read_text())
    require(env['status']=='prepared' and env['compiler']=='gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0'
            and env['libc']=='glibc 2.44','Accepted native environment required')
    delta=json.loads((R/DELTA[0]).read_text());source=(R/SOURCE[0]).read_text()
    require(delta['reverse_exact_old_source'] is True and delta['new_source']==inputs['production_source'],
            'Finalized production delta/source binding required')
    old_path=R/delta['old_source']['path'];require(ref(old_path)==delta['old_source'],'Frozen v4 source changed')
    reconstructed=old_path.read_text()
    for change in delta['transforms']:
        require(reconstructed.count(change['old'])==1,'Unique source transformation required')
        reconstructed=reconstructed.replace(change['old'],change['new'])
    require(reconstructed==source,'Additional production change refused')
    a=source.index('static int snapshot_until(');b=source.index('static int snapshot(',a)
    completion=source[a:b]
    mandatory='if(s->rules_mask!=7&&s->rules_mask!=15)'
    overlap='for(unsigned i=0;i<s->routes_n;++i)if(s->routes[i].table==8437&&!asus_8437_route_disjoint(&s->routes[i]))'
    require(completion.count(mandatory)==1 and completion.count(overlap)==1
            and completion.index(mandatory)<completion.index(overlap)<completion.rindex('return 0;'),
            'Production mandatory-rule and unconditional overlap gate must precede snapshot success')
    template=(R/TEMPLATE[0]).read_text()
    require(template.count('#define main rescue_daemon_entry')==1
            and template.count('#include "rescue-link-v5.c"')==1 and template.count('#undef main')==1,
            'Include the complete exact production source and rename daemon entry')
    require('__attribute__((constructor' not in source and '__attribute__((constructor' not in template,
            'No production entry through constructors')
    recipe=(R/RECIPE[0]).read_text()
    quote="'"*3
    found=re.findall("    worker=r"+quote+"(.*?)"+quote+r"\.replace\('@WORK@',WORK\)",recipe,re.S)
    require(len(found)==1,'One frozen accepted isolated worker literal required')
    worker=found[0]
    for change in WORKER_TRANSFORMS:
        require(worker.count(change['old'])==1,'Unique focused worker change required')
        worker=worker.replace(change['old'],change['new'])
    worker=worker.replace('@WORK@',WORK)
    files={'fixture.c':template.encode(),'rescue-link-v5.c':source.encode()}
    plan={'schema':1,'status':'pure_production_compat8437_fixture_source_plan_only','runner':ref(Path(__file__)),
          'inputs':inputs,'source_inventory':{name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()},
          'worker_sha256':hashlib.sha256(worker.encode()).hexdigest(),'worker_literal_transforms':WORKER_TRANSFORMS,
          'output':OUT.relative_to(R).as_posix(),'work':WORK,'expected_cases':CASES,'expected_case_count':len(CASES),
          'production_functions_called':['parse_route','asus_8437_route_disjoint'],
          'production_completion_gates_source_bound':{'mandatory_rule_masks':[7,15],
              'unconditional_table8437_overlap_gate':True,'gate_source_sha256':hashlib.sha256(completion.encode()).hexdigest()},
          'case_scope':'Only17 new raw-route cases; actual canonical252+8437 wire representation enters production parse_route before unchanged disjointness predicate. Old29 cases not rerun.',
          'expected_compile_count':1,'expected_fixture_run_count':1,'compile_count':0,'fixture_run_count':0,
          'device_accessed':False,'service_netlink_or_write_functions_executed':False,
          'no_old_tests_QEMU_kernel_or_environment_probes':True,
          'scope':'Mapped isolated userns root, isolated network/UTS namespace and native chroot; pure synthetic production parser/predicate calls only; 15s fixture deadline and180s outer bound.'}
    return plan,files,worker

def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group()
    g.add_argument('--plan-only',action='store_true');g.add_argument('--execute-plan-sha256');a=p.parse_args()
    plan,files,worker=prepare();gate=hashlib.sha256(canonical(plan)).hexdigest()
    if a.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256':gate,'plan':plan},indent=2));return
    require(a.execute_plan_sha256==gate,'Exact parent-reviewed execution plan SHA required')
    root=Path(json.loads((R/ENV[0]).read_text())['root'])
    require(not (root/'work'/WORK).exists() and not (root/'work'/WORK).is_symlink(),'Fresh isolated work label required')
    OUT.mkdir(parents=True);(OUT/'source').mkdir()
    inp=Path(tempfile.mkdtemp(prefix='leon-asus-compat8437-fixture-'));inp.chmod(0o755)
    for name,raw in files.items():
        (OUT/'source'/name).write_bytes(raw);(inp/name).write_bytes(raw);(inp/name).chmod(0o644)
    (OUT/'plan.json').write_bytes(canonical(plan));(OUT/'worker.sh').write_text(worker)
    (inp/'worker.sh').write_text(worker);(inp/'worker.sh').chmod(0o644)
    argv=['mmdebstrap','--unshare-helper','bash',str(inp/'worker.sh'),str(root),str(inp),os.readlink('/proc/self/ns/user')]
    result={**plan,'status':'fixture_started_outcome_unknown','approved_plan_sha256':gate,'namespace_command':argv}
    try:
        with (OUT/'worker.log').open('wb') as log:
            run=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=180)
        result['returncode']=run.returncode
        lines=(OUT/'worker.log').read_text().splitlines()
        result['compile_count']=lines.count('LEON_COMPAT8437_FIXTURE_COMPILE_STARTED')
        result['fixture_run_count']=lines.count('LEON_COMPAT8437_FIXTURE_EXECUTION_STARTED')
        require(run.returncode==0 and result['compile_count']==result['fixture_run_count']==1,'First compile/run failed; no retry')
        require(all(lines.count('LEON_COMPAT8437_CASE_PASS '+name)==1 for name in CASES),
                'Every genuine positive/negative case must pass once')
        require(lines.count('LEON_COMPAT8437_ALL_CASES_PASS count='+str(len(CASES)))==1,
                'One complete fixture success marker required')
        stage=root/'work'/WORK
        for name in ['compat8437-fixture','ccache-before.txt','ccache-after.txt']:
            shutil.copyfile(stage/name,OUT/name)
        result.update(status='pure_production_compat8437_fixture_passed',cases=[{'name':name,'pass':True} for name in CASES])
    except Exception as exc:
        result.update(status='failed_evidence_retained_no_retry',error=str(exc));raise
    finally:
        log=OUT/'worker.log'
        if log.exists():
            lines=log.read_text().splitlines()
            result['compile_count']=lines.count('LEON_COMPAT8437_FIXTURE_COMPILE_STARTED')
            result['fixture_run_count']=lines.count('LEON_COMPAT8437_FIXTURE_EXECUTION_STARTED')
        (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({'result':ref(OUT/'result.json'),'status':result['status']}),flush=True)

if __name__=='__main__':main()

#!/usr/bin/env python3
"""Plan one pure production rule/route fixture; compile/run only by exact gate."""
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
SOURCE=('scripts/asus-integration/uplink-rescue/rescue-link-v4.c','e289f45739a661705faf8b526e139514c7861e24557e4f59fa2346c9549874d4')
DELTA=('reports/ubuntu26/uplink-rescue-empty-asus-rule-v4-source-v1.json','a8192d7453f2d5474756869ac2d45ff8688caeb502d3e0e2e10931fcd2823849')
ENV=('build/asus-native-build/v2/result.json','5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc')
RECIPE=('scripts/run-private-sh-link-fixture-v1.py','f4f1d05526eed60b2e6d7358b0ce9d896b09418cfbc77fd7e5922806aae98a4f')
TEMPLATE=('scripts/asus-integration/uplink-rescue/rule-route-fixture-v1.c','7a6ffe6995452f6dbd65943999bb5250720f79610ebe36cac64b11cdc415c3c5')
OUT=R/'build/asus-uplink-rescue/rule-route-focused-fixture-v1'
WORK='uplink-rescue-rule-route-focused-fixture-v1'
CASES=['rules-default-three','rules-exact-fourth-20-8437','rules-duplicate-fourth-refused',
       'rules-wrong-table-refused','rules-wrong-priority-refused','rules-destination-selector-refused',
       'rules-source-selector-refused','rules-flags-refused','rules-wrong-action-refused',
       'rules-unknown-attribute-refused','rules-duplicate-attribute-refused','rules-missing-default-observed-mask11',
       'route-disjoint-subnet-pass','route-disjoint-host-pass','route-self-host-refused','route-peer-host-refused',
       'route-covering-subnet-refused','route-default-refused','route-covering-blackhole-refused',
       'route-covering-throw-refused','route-noncanonical-refused','route-missing-dst-refused',
       'route-prefix33-refused','route-unknown-refused','route-gateway-refused','route-multipath-refused',
       'route-source-prefix-refused','route-source-value-refused','route-tos-refused']
WORKER_TRANSFORMS=[
 {'old':'cp "$inputs/fixture.c" "$inputs/fixture-helpers.h" "$inputs/private-sh-link-update-v1.c.inc" "$root/work/@WORK@/"',
  'new':'cp "$inputs/fixture.c" "$inputs/rescue-link-v4.c" "$root/work/@WORK@/"'},
 {'old':'LEON_PRIVATE_SH_FIXTURE_COMPILE_STARTED','new':'LEON_ASUS_RULE_ROUTE_FIXTURE_COMPILE_STARTED'},
 {'old':'fixture.c -o private-sh-fixture','new':'fixture.c -o rule-route-fixture'},
 {'old':'mkdir -m0700 sandbox\n','new':''},
 {'old':'LEON_PRIVATE_SH_FIXTURE_EXECUTION_STARTED','new':'LEON_ASUS_RULE_ROUTE_FIXTURE_EXECUTION_STARTED'},
 {'old':'timeout 15 ./private-sh-fixture "$PWD/sandbox"','new':'timeout 15 ./rule-route-fixture'}]

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
    old_path=R/delta['old_source']['path'];require(ref(old_path)==delta['old_source'],'Frozen v3 source changed')
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
            and template.count('#include "rescue-link-v4.c"')==1 and template.count('#undef main')==1,
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
    files={'fixture.c':template.encode(),'rescue-link-v4.c':source.encode()}
    plan={'schema':1,'status':'pure_production_rule_route_fixture_source_plan_only','runner':ref(Path(__file__)),
          'inputs':inputs,'source_inventory':{name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()},
          'worker_sha256':hashlib.sha256(worker.encode()).hexdigest(),'worker_literal_transforms':WORKER_TRANSFORMS,
          'output':OUT.relative_to(R).as_posix(),'work':WORK,'expected_cases':CASES,'expected_case_count':len(CASES),
          'production_functions_called':['parse_rule','asus_8437_route_disjoint'],
          'production_completion_gates_source_bound':{'mandatory_rule_masks':[7,15],
              'unconditional_table8437_overlap_gate':True,'gate_source_sha256':hashlib.sha256(completion.encode()).hexdigest()},
          'missing_default_case':'Actual parser produces mask11; the unchanged production completion gate above source-checks refusal. No duplicate gate implementation.',
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
    inp=Path(tempfile.mkdtemp(prefix='leon-asus-rule-route-fixture-'));inp.chmod(0o755)
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
        result['compile_count']=lines.count('LEON_ASUS_RULE_ROUTE_FIXTURE_COMPILE_STARTED')
        result['fixture_run_count']=lines.count('LEON_ASUS_RULE_ROUTE_FIXTURE_EXECUTION_STARTED')
        require(run.returncode==0 and result['compile_count']==result['fixture_run_count']==1,'First compile/run failed; no retry')
        require(all(lines.count('LEON_ASUS_RULE_ROUTE_CASE_PASS '+name)==1 for name in CASES),
                'Every genuine positive/negative case must pass once')
        require(lines.count('LEON_ASUS_RULE_ROUTE_ALL_CASES_PASS count='+str(len(CASES)))==1,
                'One complete fixture success marker required')
        stage=root/'work'/WORK
        for name in ['rule-route-fixture','ccache-before.txt','ccache-after.txt']:
            shutil.copyfile(stage/name,OUT/name)
        result.update(status='pure_production_rule_route_fixture_passed',cases=[{'name':name,'pass':True} for name in CASES])
    except Exception as exc:
        result.update(status='failed_evidence_retained_no_retry',error=str(exc));raise
    finally:
        log=OUT/'worker.log'
        if log.exists():
            lines=log.read_text().splitlines()
            result['compile_count']=lines.count('LEON_ASUS_RULE_ROUTE_FIXTURE_COMPILE_STARTED')
            result['fixture_run_count']=lines.count('LEON_ASUS_RULE_ROUTE_FIXTURE_EXECUTION_STARTED')
        (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({'result':ref(OUT/'result.json'),'status':result['status']}),flush=True)

if __name__=='__main__':main()

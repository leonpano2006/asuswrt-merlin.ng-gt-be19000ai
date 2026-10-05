#!/usr/bin/env python3
"""Narrow, explicit evidence reuse for the UUID/diagnostic PID1 successor.

No build or device operation. Kernel, modules and container tests retain their
original image scope. Changed guardian bytes require their own exact-source
six-scenario proof; a new PID1 handoff report remains mandatory.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASELINE=ROOT/'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v2/manifest.json'
BASELINE_SHA='d7aa123ffab26890d5278080048bb19ecb58c88f9cbd96cebacda6427b6128da'
GUARDIAN_SHA='cf8a91cc2de7be670fa6dfeb57a782c12a14938ad134a0a14f4f3734fcfa9723'
POLICY=ROOT/'configs/ubuntu26/root-init-device-policy.json'
ADDITIONS={'lookup':'filesystem-uuid','emmc_cid':'00000000000000000000000000000001'}
CHANGED={'sbin/init','usr/libexec/leon-boot/manifest.json'}
SHARED={'production.c','trial-policy.c','trial-policy.h','trial-handoff.h','preflight.c','control-server.c','control-server.h','process-auth.c','local-health.c','health-worker.c','health-worker.h','sshd-state.h','diagnostic-state.c','diagnostic-state.h','boot-diagnostics.h'}
DIAGNOSTIC_SOURCE_CHANGES={
 'scripts/asus-integration/trial-guard/runtime/'+name for name in
 ['production.c','health-worker.c','health-worker.h','worker-test.c','diagnostic-state.c','diagnostic-state.h','local-health.c','process-auth.c']
}|{'scripts/asus-integration/boot-diagnostics/boot-diagnostics.h'}

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(path):return json.loads(path.read_text())
def record(path):return {'path':str(path.resolve().relative_to(ROOT)),'sha256':sha(path)}
def pinned(row):
 p=Path(row['path']);assert not p.is_absolute() and '..' not in p.parts
 p=ROOT/p;assert p.is_file() and not p.is_symlink() and sha(p)==row['sha256'];return p

def content(init_path,guardian_path=None):
 if not __debug__:raise RuntimeError('Python -O forbidden')
 assert sha(BASELINE)==BASELINE_SHA
 old=read(BASELINE);old_stage_path=pinned(old['stage_manifest']);old_stage=read(old_stage_path)
 old_guard_path=pinned(old['guardian_manifest']);guard=read(old_guard_path)
 assert sha(old_guard_path)==GUARDIAN_SHA and guard['deployment_gate_enabled'] is True
 pinned(guard['executable']);assert guard['full_production_loop_validation_passed']
 assert guard['hardware_adapter'] and not guard['fixture'] and not guard['flash_accepted']
 new_guard_path=guardian_path or old_guard_path
 new_guard=read(new_guard_path)
 changed_guard=new_guard_path.resolve()!=old_guard_path.resolve()
 if changed_guard:
  assert new_guard['scope']=='candidate-device-policy' and new_guard['deployment_gate_enabled'] is True
  assert new_guard['hardware_adapter'] and not new_guard['fixture'] and not new_guard['flash_accepted']
  assert new_guard['full_production_loop_validation_passed'] and new_guard['production_loop_evidence']
  exe=pinned(new_guard['executable']);build_path=pinned(new_guard['build_manifest']);build=read(build_path)
  if build['status']=='built_identity_only_successor':
   # Only fixed reviewed successors: unchanged loop sources, approved helper
   # digest rows and a fresh static guardian compile/refusal. Each verifier
   # pins its predecessor, helper bytes, focused proof and complete delta.
   if build_path.resolve()==ROOT/'build/asus-trial-runtime/native-v23-bsp-policy/manifest.json':
    verifier=ROOT/'scripts/build-asus-trial-identity-successor.py'
   elif build_path.resolve()==ROOT/'build/asus-trial-runtime/native-v24-bsp-license/manifest.json':
    verifier=ROOT/'scripts/build-asus-trial-bsp-license-successor.py'
   elif build_path.resolve()==ROOT/'build/asus-trial-runtime/native-v27-openssh-recovery/manifest.json':
    verifier=ROOT/'scripts/build-asus-trial-recovery-successor.py'
   else:
    raise AssertionError('Unknown fixed guardian identity successor')
   spec=importlib.util.spec_from_file_location('fixed_guardian_identity_successor',verifier)
   module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
   module.verify_successor(build_path)
   assert new_guard['identity_only_successor'] is True
   assert new_guard['identity_delta']==build['identity_delta']
   assert new_guard['baseline_guardian_receipt']==build['baseline_guardian_receipt']
   assert new_guard['generated_identity_policy_sha256']==sha(build_path.parent/'identity-production.h')
  else:
   assert build['status']=='built_readonly_fixture_tests_passed'
  assert build['deployment_gate_enabled'] is True
  assert build['full_production_loop_validation_passed'] and build['production_loop_evidence']==new_guard['production_loop_evidence']
  assert build['outputs'][exe.name]==new_guard['executable']['sha256']
  assert {x['path']:x['sha256'] for x in build['sources']}==new_guard['source_hashes']
  assert build['kernel_identity']['image_sha256']==old_stage['kernel_sha256']
  assert new_guard['root_init_policy_sha256']==sha(POLICY)
  assert new_guard['trial_handoff_sha256']==guard['trial_handoff_sha256']
  for name,digest in new_guard['source_hashes'].items():assert sha(ROOT/name)==digest
  for name,digest in guard['source_hashes'].items():
   if name not in DIAGNOSTIC_SOURCE_CHANGES:assert new_guard['source_hashes'][name]==digest,('unchanged guardian source',name)
  assert set(new_guard['source_hashes'])-set(guard['source_hashes'])<=DIAGNOSTIC_SOURCE_CHANGES
  by_name={Path(name).name:digest for name,digest in new_guard['source_hashes'].items()}
  assert len(by_name)==len(new_guard['source_hashes'])
  for row in new_guard['production_loop_evidence']:
   proof=read(pinned(row))
   assert proof['passed'] and proof['all_six_scenarios_passed'] and proof['production_loop_fixture_validation_passed']
   assert not proof['runtime_accepted'] and not proof['automatic_commit_allowed'] and not proof['errors']
   assert len(proof['cases'])==6 and all(all(c['checks'].values()) for c in proof['cases'])
   assert {c['case'] for c in proof['cases']}=={'healthy-lan-expiry','healthy-ssh-argv','healthy-worker-hang','healthy-metadata-change','prearm-refuse','arm-failure'}
   assert set(proof['shared_production_sources'])==SHARED
   for name,digest in proof['shared_production_sources'].items():assert by_name[name]==digest
   refs=[proof[k] for k in ['fixture','pivot','native_build','checker']]+[c[k] for c in proof['cases'] for k in ['result','serial']]
   for reference in refs:pinned(reference)
   tested=read(pinned(proof['native_build']));tested_sources={Path(x['path']).name:x['sha256'] for x in tested['sources']}
   assert tested['deployment_gate_enabled'] is False and tested['kernel_identity']['image_sha256']==old_stage['kernel_sha256']
   for name in SHARED:assert tested_sources[name]==by_name[name]
 old_policy=old_stage['inputs']['root_policy'];new_policy=read(POLICY)
 assert not any(k in old_policy for k in ADDITIONS)
 assert new_policy==dict(old_policy,**ADDITIONS),'Only UUID lookup and fixed physical CID may change policy'
 assert old_stage['root_policy_sha256']==guard['root_init_policy_sha256']
 new_init=read(init_path)
 assert new_init['status']=='built' and new_init['policy']==new_policy and new_init['policy_file_sha256']==sha(POLICY)
 assert new_init['guardian_required'] and new_init['static_no_interpreter']
 assert not new_init['emergency_fault_sink'] and not new_init['guardian_exec_failure_fixture'] and not new_init['mock_guardian_source_sha256']
 assert new_init['trial_handoff_sha256']==guard['trial_handoff_sha256']
 assert new_init['source_sha256']==sha(ROOT/'scripts/asus-integration/ubuntu-root-init.c')
 header=ROOT/'scripts/asus-integration/boot-diagnostics/boot-diagnostics.h'
 assert new_init['boot_diagnostics_sha256']==sha(header)
 identity={'source_sha256':new_init['source_sha256'],'boot_diagnostics_sha256':sha(header),
           'trial_handoff_sha256':new_init['trial_handoff_sha256'],'policy_sha256':sha(POLICY),
           'builder_sha256':sha(ROOT/'scripts/build-ubuntu26-root-init.py')}
 assert new_init['diagnostic_build_identity']==identity
 assert new_init['diagnostic_build_id']==hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 assert new_init['outputs']['boot-diagnostics.h']==sha(header)
 generated=init_path.parent/'ubuntu-root-build-id.h'
 assert sha(generated)==new_init['outputs'][generated.name]
 assert generated.read_text()=='#define ROOT_DIAG_BUILD_SHA256 "'+new_init['diagnostic_build_id']+'"\n'
 init=init_path.parent/'ubuntu-root-init';assert sha(init)==new_init['outputs']['ubuntu-root-init']
 for k in ['qemu_result','qemu_inputs']:pinned(old[k])
 return {'schema':1,'status':'narrow_bootstrap_evidence_reuse','baseline_firmware':record(BASELINE),
  'baseline_stage':record(old_stage_path),'baseline_guardian':record(old_guard_path),'guardian':record(new_guard_path),'guardian_changed':changed_guard,'new_root_init':record(init_path),
  'new_root_init_sha256':sha(init),'old_policy_sha256':old_stage['root_policy_sha256'],
  'new_policy':new_policy,'new_policy_sha256':sha(POLICY),'policy_additions':ADDITIONS,
  'kernel_sha256':old_stage['kernel_sha256'],'module_inventory_sha256':old_stage['module_inventory_sha256'],
  'qemu_result':old['qemu_result'],'qemu_inputs':old['qemu_inputs'],
  'allowed_changed_inventory_paths':sorted(CHANGED|({'usr/libexec/leon-boot/trial-guardian'} if changed_guard else set())),
  'reused_scope':['Frozen guardian protocol/policy; changed executable has separate new six-scenario evidence.' if changed_guard else 'Frozen v17 guardian executable/protocol and its original six-scenario evidence.','Exact kernel10 and 181-module inventory.','Container and zstd/userspace-hash test on the original device-enabled-v3 image; not a new-image container run.'],
  'new_required_scope':['Actual successor SquashFS PID1 entry and same-source adapted systemd handoff with new root-init helper.','Exact baseline/successor inventory comparison against the explicit allowed path list.'],
  'not_claimed':['Physical boot success or physical watchdog recovery.','Runtime08 or accepted guardian integration.','New-image container execution or new Broadcom hardware tests.'],
  'physical_trial_accepted':False,'automatic_boot_commit':False,'builder_sha256':sha(Path(__file__))}

def load(path):
 saved=read(path);init=pinned(saved['new_root_init']);guardian=pinned(saved['guardian']);assert saved==content(init,guardian),'Reuse receipt differs from current pinned inputs';return saved

def validate_stager(path,init_path,guardian_path):
 reuse=load(path);assert record(init_path)==reuse['new_root_init'] and record(guardian_path)==reuse['guardian'];return reuse

def validate_stage(path,stage_path,guardian_path):
 reuse=load(path);stage=read(stage_path);old=read(pinned(reuse['baseline_stage']))
 assert record(guardian_path)==reuse['guardian']
 assert stage['bootstrap_evidence_reuse']==record(path)
 assert stage['inputs']['bootstrap_evidence_reuse_sha256']==sha(path)
 assert stage['inputs']['root_init_manifest_sha256']==reuse['new_root_init']['sha256']
 assert stage['inputs']['root_init_sha256']==reuse['new_root_init_sha256']
 assert stage['root_policy_sha256']==reuse['new_policy_sha256'] and stage['inputs']['root_policy']==reuse['new_policy']
 for key in ['kernel_sha256','module_inventory_sha256','module_count','base_rootfs_sha256']:
  assert stage[key]==old[key],key
 # Hook path changes per staging label while its exact bytes must remain.
 assert stage['unapplied_jffs_hook']['sha256']==old['unapplied_jffs_hook']['sha256']
 before,after=old['inventory'],stage['inventory']
 changes={name for name in before.keys()|after.keys() if before.get(name)!=after.get(name)}
 assert changes==set(reuse['allowed_changed_inventory_paths']),changes
 assert after['sbin/init']['sha256']==reuse['new_root_init_sha256']
 new_guard=read(guardian_path)
 assert stage['inputs']['guardian_sha256']==new_guard['executable']['sha256'] and stage['inputs']['guardian_manifest_sha256']==sha(guardian_path)
 assert after['usr/libexec/leon-boot/trial-guardian']['sha256']==new_guard['executable']['sha256']
 for key in ['private_fsck_manifest_sha256','guardian_deployment_gate_enabled','kernel_sha256','trial_only','automatic_boot_commit']:
  assert stage['inputs'][key]==old['inputs'][key],key
 return reuse,old

def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--new-root-init-manifest',type=Path,required=True);p.add_argument('--new-guardian-receipt',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 assert not a.output.exists();result=content(a.new_root_init_manifest.resolve(),a.new_guardian_receipt.resolve() if a.new_guardian_receipt else None);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(record(a.output)))
if __name__=='__main__':main()

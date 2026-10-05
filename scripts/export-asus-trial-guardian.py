#!/usr/bin/env python3
"""Export an explicitly gated static guardian receipt for offline SquashFS staging."""
import argparse,hashlib,json,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 if not __debug__:raise RuntimeError("Optimized Python cannot verify the deployment evidence gate")
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native',type=Path,required=True);a=p.parse_args();n=a.native.resolve();m=n/'manifest.json';record=json.loads(m.read_text());assert record['status']=='built_readonly_fixture_tests_passed' and isinstance(record['deployment_gate_enabled'],bool)
 gate=record['deployment_gate_enabled'];evidence=record.get('production_loop_evidence',[])
 if gate:
  assert record['full_production_loop_validation_passed'] and evidence
  for item in evidence:assert sha(R/item['path'])==item['sha256']
 exe=n/'guardian-integrated';assert sha(exe)==record['outputs']['guardian-integrated'];elf=subprocess.check_output(['readelf','-h','-l','-d',str(exe)],text=True);assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
 policy=R/'configs/ubuntu26/root-init-device-policy.json';profile=json.loads(policy.read_text());assert profile['scope']=='candidate-device-policy' and profile['guardian']['required'] and not profile['flash_accepted'];assert profile['generation'].strip() in (n/'identity-production.h').read_text()
 sources={x['path']:x['sha256'] for x in record['sources']};handoff='scripts/asus-integration/trial-guard/trial-handoff.h';assert sources[handoff]==sha(R/handoff)
 result={'schema_version':1,'status':'built','scope':'candidate-device-policy','hardware_adapter':True,'fixture':False,'deployment_gate_enabled':gate,'root_init_policy_sha256':sha(policy),'trial_handoff_sha256':sources[handoff],'executable':{'path':str(exe.relative_to(R)),'sha256':sha(exe)},'build_manifest':{'path':str(m.relative_to(R)),'sha256':sha(m)},'source_snapshot':str((n/'source-snapshot').relative_to(R)),'source_hashes':sources,'generated_identity_policy_sha256':sha(n/'identity-production.h'),'static_no_interpreter_or_needed':True,'empty_environment_refusal_sha256':sha(n/'guardian-empty-env.log'),'hardware_adapter_executed':False,'hardware_watchdog_opened':False,'physical_reset_proven':False,'full_production_loop_validation_passed':record.get('full_production_loop_validation_passed',False),'production_loop_evidence':evidence,'runtime_accepted':False,'flash_accepted':False,'staging_meaning':('Explicit gate enabled after exact-source full production-loop fixture proof; no device hardware has been exercised. Board preflight, device-local identity and fresh slot proof remain mandatory before arming.' if gate else 'Immutable deployment gate fixedfalse; PID1 invocation refuses before preflight or watchdog access. Offline composition only.'),'critical_identity_scope':'Exact kernel10/module files, rc07 containing0019, frozen native broker/launcher/systemd/OpenSSH files, and validated trial-control0.1 clients. Final integration must audit the composed file map.','exporter_sha256':sha(Path(__file__))}
 if 'diagnostic_build_id' in record:
  result['diagnostic_build_id']=record['diagnostic_build_id'];result['diagnostic_store']=record['diagnostic_store']
 out=n/'guardian-receipt.json';assert not out.exists();out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'receipt':str(out.relative_to(R)),'sha256':sha(out),'binary':result['executable']},indent=2))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Bind the already passed installer to exact frozen inputs; no test reruns."""
import hashlib
import json
from pathlib import Path

R=Path(__file__).resolve().parents[1]
OUT=R/'build/asus-ssh-recovery/install-v1'
BASE=R/'build/ubuntu26-bsp-update/native-v2'
REPORT=R/'reports/ubuntu26/openssh-recovery-installer-sealed-v1.json'
PINS={
 'build/asus-ssh-recovery/install-v1/manifest.json':'455fdb8227329b2b1a0dc6ef2ed442d43817280880ee8b1efee5db858e462669',
 'build/ubuntu26-bsp-update/native-v2/manifest.json':'3f993744f1586f29d255ca190eb1d2e06b1205ac959a9a266a41521b85a4322a',
 'reports/ubuntu26/asus-openssh-recovery-focused-v2.json':'e3d35906037500a99bb97a9354857d031bc46f9e1ba1306cf2688ec2e97ea720',
 'build/asus-ssh-recovery/recovery-source-v1/manifest.json':'d099f76ef25894bc4bcd20126168f5637c5b62d8265f8675429d5051f755081f',
 'evidence/ubuntu26/management-backup/ubuntu-host-ed25519.pub':'3457059d21603fe0d2f0971b1475c35625679c3511f3bcc073c8765ac6829bd2',
 'evidence/ubuntu26/device-identity-live/identity-v8-first.txt':'2808496c1eb8fff2586b0a47ac9bce3d87f217da1d977bcc47b9199bfae473a4',
}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def ref(path):return {'path':str(path.relative_to(R)),'sha256':sha(path)}
def read(path):return json.loads(path.read_text())
def verify():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 for name,digest in PINS.items():
  path=R/name;assert path.is_file() and not path.is_symlink() and sha(path)==digest,name
 manifest=read(OUT/'manifest.json');base=read(BASE/'manifest.json')
 for item in [manifest['builder'],*manifest['sources'],*manifest['outputs'],*manifest['payloads'],manifest['native_build_environment']]:
  path=R/item['path'];assert path.is_file() and not path.is_symlink() and sha(path)==item['sha256'],str(path)
 expected={}
 for item in base['sources']:
  path=R/item['path'];assert sha(path)==item['sha256']
  name='hardware-provision.c' if item['path']=='build/ubuntu26-hardware-order/native-v1/source/provision.c' else path.name
  assert name not in expected;expected[name]=item['sha256']
 expected['bsp-payload.h']=base['embedded_payload_header']['sha256']
 for item in base['required_bsp_resources']:
  name='resources/'+Path(item['path']).name
  assert name not in expected or expected[name]==item['sha256'];expected[name]=item['sha256']
 actual={str(path.relative_to(BASE/'source')):sha(path) for path in (BASE/'source').rglob('*') if path.is_file()}
 assert actual==expected,'Complete frozen baseline source inventory'
 expected['bsp-provision.c']=expected.pop('provision.c')
 snapshot=OUT/'source'
 for name,digest in expected.items():assert sha(snapshot/name)==digest,('copied guard',name)
 final={str(path.relative_to(snapshot)):sha(path) for path in snapshot.rglob('*') if path.is_file()}
 assert final==manifest['frozen_source_inventory']
 native_root=Path(read(R/manifest['native_build_environment']['path'])['root'])
 for name,digest in final.items():assert sha(native_root/'work/recovery-install-v1'/name)==digest,('compiled input',name)
 proof=read(R/'reports/ubuntu26/asus-openssh-recovery-focused-v2.json')
 assert proof['status']=='focused_no_nic_qemu_pass_physical_acceptance_pending'
 package=read(R/'build/asus-ssh-recovery/recovery-source-v1/manifest.json')
 assert manifest['recovery_package']==package['package']|{} or manifest['recovery_package']['sha256']==package['package']['sha256']
 # Package metadata adds version/architecture; payload identity is the same.
 assert manifest['recovery_package']['path']==package['package']['path']
 for item in package['sources']:assert sha(R/item['path'])==item['sha256']
 assert (OUT/'fixture.log').read_text().splitlines()[-1]=='RECOVERY_INSTALL_CASES 15'
 assert sum(line.startswith('PASS ') for line in (OUT/'fixture.log').read_text().splitlines())==15
 return {'schema':1,'status':'installer_exact_inputs_sealed_and_focused_evidence_reused',
         'installer_manifest':ref(OUT/'manifest.json'),'installer':manifest['installer'],
         'fixed_input_pins':PINS,'copied_frozen_guard_inventory':expected,
         'compiled_input_snapshot_exact':True,'changed_transaction_cases_reused':15,
         'runtime_source_peer':'candidate_recovery_guardian: no concrete transaction/auth bypass finding',
         'peer_build_binding_gaps_resolved':'Complete copied and compiled frozen guard comparison plus fixed package/proof/host/enrollment pins; no rebuild or test repeat.',
         'verifier':ref(Path(__file__)),'device_operated':False,'physical_acceptance':False}
def main():
 result=verify();assert not REPORT.exists();REPORT.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'report':ref(REPORT),'installer':result['installer']}))
if __name__=='__main__':main()

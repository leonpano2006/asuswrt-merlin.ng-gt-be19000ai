#!/usr/bin/env python3
"""Build an ISOLATED accepted-current-boot successor, disabled by default.
Explicit enabling requires exact-source loop and independent peer evidence.
No original runtime sources, rootfs or physical devices are edited.
"""
import argparse,hashlib,json,re,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1];S=R/'scripts/asus-integration/accepted-guard/runtime';BASE=R/'build/asus-trial-runtime/native-v17-enabled'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def evidence_ref(row):
 p=(R/row['path']).resolve();assert p.is_relative_to(R) and sha(p)==row['sha256'];return p
def enable_evidence(report,peer,source_records):
 r=json.loads(report.read_text());p=json.loads(peer.read_text())
 assert r['status']=='accepted_current_boot_loop_validated_with_explicit_adapters' and r['passed'] is True
 assert r['checks'] and all(v is True for v in r['checks'].values()) and not r['errors']
 assert r['production_gate_enabled'] is False and r['router_accessed'] is False
 for name in ['native_build','fixture','pivot','result','serial','checker']:evidence_ref(r[name])
 npath=evidence_ref(r['native_build']);n=json.loads(npath.read_text())
 fpath=evidence_ref(r['fixture']);f=json.loads(fpath.read_text())
 assert f['role']=='accepted-loop-fixture' and f['fixture'] and not f['hardware_adapter']
 evidence_ref(f['guardian'])
 current={row['build_name']:row['sha256'] for row in source_records}
 native={row['build_name']:row['sha256'] for row in n['sources']}
 assert current==native,'Successor sources differ from tested native build'
 for row in n['sources']:
  evidence_ref(row);assert sha(npath.parent/'source'/row['build_name'])==row['sha256']
 for row in f['sources']:
  evidence_ref(row);assert sha(fpath.parent/'source-snapshot'/Path(row['path']).name)==row['sha256']
 for row in f['files']:assert sha(R/row['source'])==row['sha256']
 assert p['status']=='source_peer_review_passed' and not p['findings']
 assert evidence_ref(p['manifest'])==npath
 for row in p['reviewed']:evidence_ref(row)
 assert {Path(x['path']).name for x in p['reviewed']} >= {'production.c','control-server.c','accepted-runtime.c','accepted-core.c','accept-client.c','control-client.c'}
 return {'report':{'path':str(report.relative_to(R)),'sha256':sha(report)},'peer':{'path':str(peer.relative_to(R)),'sha256':sha(peer)}}
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--enable-deployment-gate',action='store_true');p.add_argument('--accepted-loop-report',type=Path);p.add_argument('--source-peer-report',type=Path);a=p.parse_args();assert re.fullmatch('[a-z0-9-]+',a.label)
 assert bool(a.enable_deployment_gate)==bool(a.accepted_loop_report and a.source_peer_report),'Explicit enabling requires both reports'
 receipt=BASE/'guardian-receipt.json';assert sha(receipt)=='cf8a91cc2de7be670fa6dfeb57a782c12a14938ad134a0a14f4f3734fcfa9723'
 baseline=json.loads(receipt.read_text());bm=json.loads(evidence_ref(baseline['build_manifest']).read_text())
 base_names=['guardian.c','trial-policy.c','trial-policy.h','trial-handoff.h','watchdog-adapter.c','preflight.c','preflight.h','sha256-compat.h','process-auth.c','process-auth.h','local-health.c','local-health.h','health-worker.c','health-worker.h','sshd-state.h']
 files=[BASE/'source-snapshot'/n for n in base_names]+[BASE/'sha256.c',BASE/'identity-production.h']+sorted(S.glob('*.[ch]'));record=[]
 for f in files:
  if f.is_relative_to(BASE):
   if f.name=='identity-production.h':expected=baseline['generated_identity_policy_sha256']
   elif f.name=='sha256.c':expected=bm['outputs']['sha256.c']
   else:
    matches=[digest for path,digest in baseline['source_hashes'].items() if Path(path).name==f.name];assert len(matches)==1;expected=matches[0]
   assert sha(f)==expected,f
  record.append({'path':str(f.relative_to(R)),'sha256':sha(f),'build_name':'identity-policy.h' if f.name=='identity-production.h' else f.name})
 proof=enable_evidence(a.accepted_loop_report.resolve(),a.source_peer_report.resolve(),record) if a.enable_deployment_gate else None
 w=R/'build/asus-accepted-runtime'/a.label;w.mkdir(parents=True,exist_ok=False);snapshot=w/'source';snapshot.mkdir();tmp=Path(tempfile.mkdtemp(prefix='leon-accepted-runtime-'));tmp.chmod(0o755)
 for f in files:
  assert f.is_file();name='identity-policy.h' if f.name=='identity-production.h' else f.name
  assert not (snapshot/name).exists();shutil.copyfile(f,snapshot/name);shutil.copyfile(f,tmp/name)
 root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 script=r'''set -euo pipefail
root="$1";input="$2";label="$3";gate="$4"
mount --make-rprivate /
mkdir -m0755 "$root/work/accepted-runtime-$label"
cp "$input"/*.[ch] "$root/work/accepted-runtime-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" "$gate" <<'BUILD'
set -euo pipefail
cd "/work/accepted-runtime-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-misleading-indentation -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -fno-strict-aliasing -static-pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" -DLEON_TRIAL_RUNTIME_LINKED -DLEON_TRIAL_DEPLOYMENT_ENABLED="$2" guardian.c trial-policy.c watchdog-adapter.c production.c preflight.c sha256.c control-server.c process-auth.c local-health.c health-worker.c accepted-runtime.c accepted-core.c -o guardian-accepted
ccache gcc-16 "${flags[@]}" accept-client.c control-client.c process-auth.c -o trial-accept
ccache gcc-16 "${flags[@]}" test-runtime.c control-server.c accepted-runtime.c -o test-runtime
./test-runtime >test.log 2>&1
env -i ./guardian-accepted --pre-systemd >nondevice.log 2>&1 && exit 1 || test "$?" = 125
grep -Fx LEON_TRIAL_REFUSED_NOT_PID1_CHILD nondevice.log
./trial-accept --accept-this-boot --expected-boot-id 00000000-0000-4000-8000-000000000000 >client-refusal.log 2>&1 && exit 1 || test "$?" = 125
readelf -h -l -d guardian-accepted >elf.txt
gcc-16 --version >compiler.txt
BUILD
'''
 (tmp/'build.sh').write_text(script)
 with (w/'build.log').open('w') as f:run=subprocess.run(['mmdebstrap','--unshare-helper','bash',str(tmp/'build.sh'),str(root),str(tmp),a.label,str(int(a.enable_deployment_gate))],stdout=f,stderr=subprocess.STDOUT)
 stage=root/f'work/accepted-runtime-{a.label}'
 for name in ['guardian-accepted','trial-accept','test-runtime','test.log','nondevice.log','client-refusal.log','elf.txt','compiler.txt']:
  if (stage/name).is_file():shutil.copyfile(stage/name,w/name)
 if not run.returncode:
  for name in ['guardian-accepted','trial-accept','test-runtime']:(w/name).chmod(0o755)
  assert 'INTERP' not in (w/'elf.txt').read_text() and '(NEEDED)' not in (w/'elf.txt').read_text()
 result={'status':'built_focused_offline_tests_passed' if not run.returncode else 'build_failed','returncode':run.returncode,'sources':record,'baseline_receipt':{'path':str(receipt.relative_to(R)),'sha256':sha(receipt)},'outputs':{f.name:sha(f) for f in w.iterdir() if f.is_file()},'builder_sha256':sha(Path(__file__)),'deployment_enabled':a.enable_deployment_gate,'enable_switch_available':True,'accepted_loop_evidence':proof,'critical_identity_scope':'Frozen runtime07 identity only; runtime08 composition must generate and independently check its new exact identity table before staging.','device_accessed':False,'frozen_sources_modified':False,'rootfs_modified':False,'permanent_boot_commit':False,'contract':'Explicit native root current-boot acceptance; same guardian/FD; COMMITTED2 preserved; after acceptance core-only checks, no external ACK or service collector.'}
 (w/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(w/'manifest.json');raise SystemExit(run.returncode)
if __name__=='__main__':main()

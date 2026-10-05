#!/usr/bin/env python3
"""Build native trial guardian; enabling requires exact-source full-loop proof."""
import argparse,hashlib,json,re,shutil,struct,subprocess,tempfile,uuid,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/trial-guard/runtime'
K=R/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def elf_notes(p):
 b=p.read_bytes();assert b[:6]==b'\x7fELF\x02\x01';off=struct.unpack_from('<Q',b,40)[0];ents,count,index=struct.unpack_from('<HHH',b,58)
 entries=[struct.unpack_from('<IIQQQQIIQQ',b,off+i*ents) for i in range(count)];names=entries[index];strings=b[names[4]:names[4]+names[5]]
 hits=[x for x in entries if strings[x[0]:].split(b'\0',1)[0]==b'.notes'];assert len(hits)==1;x=hits[0];return b[x[4]:x[4]+x[5]]
def main():
 if not __debug__:raise RuntimeError("Optimized Python cannot verify the deployment evidence gate")
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);p.add_argument('--enable-deployment-gate',action='store_true');p.add_argument('--production-loop-report',type=Path);a=p.parse_args();assert re.fullmatch('[a-zA-Z0-9_-]+',a.label)
 evidence=[]
 if a.enable_deployment_gate:
  assert a.production_loop_report,'--enable-deployment-gate requires --production-loop-report'
  report=a.production_loop_report.resolve();acceptance=json.loads(report.read_text())
  assert acceptance['passed'] and acceptance['production_loop_fixture_validation_passed'] and acceptance['all_six_scenarios_passed']
  assert acceptance['native_guardian_gate_enabled'] is False and acceptance['physical_watchdog_opened'] is False
  assert acceptance['runtime_accepted'] is False and acceptance['automatic_commit_allowed'] is False
  assert {c['case'] for c in acceptance['cases']}=={'healthy-lan-expiry','healthy-ssh-argv','healthy-worker-hang','healthy-metadata-change','prearm-refuse','arm-failure'} and len(acceptance['cases'])==6 and not acceptance['errors']
  assert all(all(c['checks'].values()) for c in acceptance['cases'])
  assert set(acceptance['shared_production_sources'])=={'production.c','trial-policy.c','trial-policy.h','trial-handoff.h','preflight.c','control-server.c','control-server.h','process-auth.c','local-health.c','health-worker.c','health-worker.h','sshd-state.h','diagnostic-state.c','diagnostic-state.h','boot-diagnostics.h'}
  for name,digest in acceptance['shared_production_sources'].items():
   options=[S/name,S.parent/name,R/'scripts/asus-integration/openssh'/name,R/'scripts/asus-integration/boot-diagnostics'/name]
   actual=[f for f in options if f.is_file()];assert len(actual)==1 and sha(actual[0])==digest,('production source changed after loop proof',name)
  references=[acceptance[k] for k in ['fixture','pivot','native_build','checker']]+[case[k] for case in acceptance['cases'] for k in ['result','serial']]
  for item in references:assert sha(R/item['path'])==item['sha256'],item['path']
  base=json.loads((R/acceptance['native_build']['path']).read_text());assert base['kernel_identity']['image_sha256']==sha(R/'build/Image-v10')
  evidence=[{'path':str(report.relative_to(R)),'sha256':sha(report)}]
 else:assert a.production_loop_report is None,'Loop acceptance is required only for explicit gate activation'
 w=R/'build/asus-trial-runtime'/a.label;w.mkdir(parents=True,exist_ok=False)
 tmp=Path(tempfile.mkdtemp(prefix='asus-trial-runtime-'));tmp.chmod(0o755)
 files=sorted(S.glob('*.[ch]'))+[S.parent/name for name in ['trial-policy.h','trial-policy.c','trial-handoff.h','watchdog-adapter.c','guardian.c']]+[R/'scripts/asus-integration/openssh/sshd-state.h',R/'scripts/asus-integration/boot-diagnostics/boot-diagnostics.h']
 snapshots=[]
 (w/'source-snapshot').mkdir()
 for f in files:
  shutil.copyfile(f,tmp/f.name);shutil.copyfile(tmp/f.name,w/'source-snapshot'/f.name);snapshots.append({'path':str(f.relative_to(R)),'sha256':sha(tmp/f.name)})
 diagnostic_id=hashlib.sha256(json.dumps(snapshots,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 (tmp/'diagnostic-build.h').write_text('#define LEON_DIAGNOSTIC_BUILD_ID '+json.dumps(diagnostic_id)+'\n')
 source=K/'lib/sha256.c';raw=source.read_text();new=re.sub(r'#include <(?:linux/(?:bitops|sha256|string)\.h|asm/byteorder\.h)>\n','',raw)
 assert raw.count('#include ')==4 and '#include' not in new
 (tmp/'sha256.c').write_text('#include "sha256-compat.h"\n'+new)
 notes=elf_notes(K/'vmlinux');(tmp/'kernel-notes').write_bytes(notes)
 modules=json.loads((R/'reports/kernel10/modules-stage.json').read_text())['file_sha256']
 table={}
 for name,digest in modules.items():
  path=R/'build/kernel10-module-root/lib/modules/4.19.294'/name;assert sha(path)==digest;table['/usr/lib/modules/4.19.294/'+name]=digest
 # Pin the exact no-vendor-wdtd rc07 and native service/identity executables.
 # Apply the final reviewed startup package over the frozen runtime06 base.
 # Pin by archive receipt as well as staged bytes, so a newer unit cannot be
 # silently checked against the previous candidate's policy.
 candidate=R/'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-asus-runtime06-integration-sealed-b53-v1.tar'
 names=['usr/libexec/asus/'+n for n in ['rc-broker','etc-launch','storage-owner','bsp-ownership','bsp-runner','startup-prepare']]+['usr/lib/systemd/systemd','usr/bin/systemctl','usr/sbin/sshd','usr/lib/openssh/sshd-session','usr/lib/systemd/system/leon-asus-broker.service']
 with tarfile.open(candidate) as archive:
  indexed={m.name.removeprefix('./'):m for m in archive}
  for name in names:
   member=indexed[name];assert member.isfile() and member.uid==0 and not(member.mode&0o022)
   table['/'+name]=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
 startup_dir=R/'build/asus-startup/package-v5'
 startup=json.loads((startup_dir/'manifest.json').read_text())
 assert startup['package']['version']=='0.7+asus3006.102.9'
 assert sha(R/startup['package']['path'])==startup['package']['sha256']
 overlays=[]
 for item in startup['archive']:
  path=item['path']
  if path not in table:continue
  assert item['type']=='regular' and not(item['mode']&0o022)
  staged=startup_dir/'root'/path.lstrip('/')
  assert sha(staged)==item['sha256']
  overlays.append({'path':path,'previous_sha256':table[path],'sha256':item['sha256']})
  table[path]=item['sha256']
 assert table['/usr/lib/systemd/system/leon-asus-broker.service']=='d7647d69ef6726fe53184a36d47272ae665883dc2eeada4c29ba380c48892829'
 rc=R/'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-v4/linked/rc'
 assert sha(rc)=='af9b497f7791d75031772c894d17f886ba99dbac687262d9933133aa65a752fe'
 table['/usr/libexec/asus/rc']=sha(rc)
 for name in ['trial-health','trial-ack']:table['/usr/libexec/leon-asus/'+name]=sha(R/'build/asus-trial-runtime/native-v8'/name)
 watchdog_policy=R/'build/ubuntu26-trial-activation/package-v1/root/usr/lib/systemd/system.conf.d/90-leon-trial-watchdog.conf'
 table['/usr/lib/systemd/system.conf.d/90-leon-trial-watchdog.conf']=sha(watchdog_policy)
 # Keep the physically deployed BSP fixes while recompiling changed health
 # logic. Only this immutable file table is reused; enabling still requires
 # all six loop scenarios against the current C sources above.
 identity_base=R/'build/asus-trial-runtime/native-v24-bsp-license'
 identity_manifest=identity_base/'manifest.json'
 assert sha(identity_manifest)=='0b8cc0a5e5a71b54f0d31afa75cb85e98383a6760ab973cfcca96053b4dae666'
 identity_meta=json.loads(identity_manifest.read_text())
 identity_header=identity_base/'identity-production.h'
 assert sha(identity_header)==identity_meta['outputs']['identity-production.h']
 identity_rows=re.findall(r'^\{PFX "([^"]+)","([0-9a-f]{64})"\},$',identity_header.read_text(),re.M)
 identity_table=dict(identity_rows)
 assert len(identity_rows)==len(identity_table)==208 and set(identity_table)==set(table)
 fixed_helpers={
  '/usr/libexec/asus/etc-launch':R/'build/ubuntu26-bsp-license/native-v1/etc-launch',
  '/usr/libexec/asus/bsp-runner':R/'build/ubuntu26-bsp-license/native-v1/bsp-runner',
  '/usr/libexec/asus/bsp-ownership':R/'build/ubuntu26-bsp-policy/native-v1/bsp-ownership',
 }
 for name,digest in identity_table.items():
  if name in fixed_helpers:assert sha(fixed_helpers[name])==digest
  else:assert table[name]==digest,('unapproved identity change',name)
 table=identity_table
 storage=[(7,1028096,204800,'b2779970-ea82-4aec-96ed-816e1aac53a0'),(8,1232896,40960,'b33c1d3a-f5a1-4beb-b0fe-edfdecba957d'),(9,1273856,409600,'7575e860-48ee-493e-bb5b-a1ca270b8512'),(10,1683456,25165824,'d6754055-3be0-4b1d-8dc4-3c3bb8493fbe')]
 version=re.search(r'^#define UTS_VERSION "(.*)"$',(K/'include/generated/compile.h').read_text(),re.M)[1]
 common=['/* Generated immutable identity policy; production provisioning incomplete. */','#define TRIAL_KERNEL_RELEASE "4.19.294"','#define TRIAL_KERNEL_VERSION '+json.dumps(version),'#define TRIAL_KERNEL_NOTES_SHA256 '+json.dumps(hashlib.sha256(notes).hexdigest()),'#define TRIAL_BOOT_ROOT "/dev/mmcblk0p4"','struct trial_file {const char *path,*sha256;};','struct trial_storage_identity {unsigned number; unsigned long long start,sectors; unsigned char uuid[16];};','static const struct trial_storage_identity trial_storage[]={']
 for n,start,sectors,id in storage:common.append('{%d,%d,%d,{%s}},'%(n,start,sectors,','.join('0x%02x'%x for x in uuid.UUID(id).bytes)))
 common+=['};']
 # The immutable board generation is pinned. A fresh postflash token is
 # separately required; no token is manufactured by this builder.
 production=common+['#define TRIAL_ROOT_GENERATION "be19000ai-ubuntu26-kernel10-systemd-v1"','#define TRIAL_STOCK_KERNEL_SHA256 "ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256"','#define TRIAL_STOCK_ROOTFS_SHA256 "51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465"','static const struct trial_file trial_files[]={']
 for name,digest in sorted(table.items()):production.append('{PFX '+json.dumps(name)+','+json.dumps(digest)+'},')
 production+=['};'];(tmp/'identity-production.h').write_text('\n'.join(production)+'\n')
 fixture=common+['#define TRIAL_ROOT_GENERATION "isolated-fixture"','#define TRIAL_STOCK_KERNEL_SHA256 '+json.dumps(hashlib.sha256(b'fixture-stock-kernel').hexdigest()),'#define TRIAL_STOCK_ROOTFS_SHA256 '+json.dumps(hashlib.sha256(b'fixture-stock-rootfs').hexdigest()),'static const struct trial_file trial_files[]={','{PFX "/usr/lib/modules/4.19.294/fixture.ko",'+json.dumps(hashlib.sha256(b'fixture-module\n').hexdigest())+'},','};'];(tmp/'identity-fixture.h').write_text('\n'.join(fixture)+'\n')
 shutil.copyfile(R/'evidence/ubuntu26/boot-metadata/20261004-v1/metadata1.bin',tmp/'metadata.bin')
 (tmp/'fixture-input.json').write_text(json.dumps({'kernel_version':version,'storage':storage,'fixture_root':'/work/trial-runtime-'+a.label+'/fixture-root'}))
 script=r'''set -euo pipefail
root="$1"; input="$2"; label="$3"; gate="$4"
mount --make-rprivate /
mkdir -m 0755 "$root/work/trial-runtime-$label"
cp "$input"/* "$root/work/trial-runtime-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" "$gate" <<'BUILD'
set -euo pipefail
cd "/work/trial-runtime-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -static-pie -Wl,-z,relro,-z,now)
cp identity-production.h identity-policy.h
ccache gcc-16 "${flags[@]}" -DLEON_TRIAL_PREFLIGHT_MAIN preflight.c sha256.c -o trial-preflight-candidate
cp identity-fixture.h identity-policy.h
ccache gcc-16 "${flags[@]}" -DLEON_TRIAL_PREFLIGHT_MAIN -DLEON_TRIAL_FIXTURE_ROOT='"'"$PWD"'/fixture-root"' preflight.c sha256.c -o trial-preflight-fixture
ccache gcc-16 "${flags[@]}" ack-client.c control-client.c process-auth.c -o trial-ack
ccache gcc-16 "${flags[@]}" health-client.c control-client.c process-auth.c -o trial-health
ccache gcc-16 "${flags[@]}" -DLEON_TRIAL_SSH_FIXTURE server-fixture.c control-server.c process-auth.c -o trial-server-fixture
ccache gcc-16 "${flags[@]}" -c control-server.c process-auth.c
cp identity-production.h identity-policy.h
ccache gcc-16 "${flags[@]}" -DLEON_TRIAL_RUNTIME_LINKED -DLEON_TRIAL_DEPLOYMENT_ENABLED="$2" guardian.c trial-policy.c watchdog-adapter.c production.c preflight.c sha256.c control-server.c process-auth.c local-health.c health-worker.c diagnostic-state.c -o guardian-integrated
env -i ./guardian-integrated --pre-systemd > guardian-empty-env.log 2>&1 && exit 1 || test "$?" = 125
grep -Fx LEON_TRIAL_REFUSED_NOT_PID1_CHILD guardian-empty-env.log
readelf -h -l -d guardian-integrated > guardian-elf.txt
cp identity-fixture.h identity-policy.h
ccache gcc-16 "${flags[@]}" adapter-test.c preflight.c sha256.c control-client.c process-auth.c -o adapter-test
./adapter-test > adapter-test.log 2>&1
ccache gcc-16 "${flags[@]}" capture-test.c preflight.c sha256.c trial-policy.c -o capture-test
./capture-test > capture-test.log 2>&1
ccache gcc-16 "${flags[@]}" worker-test.c health-worker.c -o worker-test
./worker-test > worker-test.log 2>&1
gcc-16 --version > compiler.txt
readelf -h -l -d trial-preflight-candidate > elf.txt
BUILD
python3 "$input/fixture-test.py" "$root" "/work/trial-runtime-$label" > "$root/work/trial-runtime-$label/fixture-test.log" 2>&1
'''
 (tmp/'build.sh').write_text(script)
 for file in ['fixture-test.py']:shutil.copyfile(S/file,tmp/file)
 root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 with (w/'build.log').open('w') as log:run=subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(tmp/'build.sh'),str(root),str(tmp),a.label,'1' if a.enable_deployment_gate else '0'],stdout=log,stderr=subprocess.STDOUT)
 stage=root/('work/trial-runtime-'+a.label)
 record={'status':'build_failed','returncode':run.returncode,'hardware_accessed':False,'router_accessed':False,'deployment_gate_enabled':a.enable_deployment_gate,'production_policy_provisioned':False,'runtime_accepted':False,'sources':snapshots+[{'path':str((S/'fixture-test.py').relative_to(R)),'sha256':sha(S/'fixture-test.py')}],'sha256_source':{'path':str(source.relative_to(R)),'sha256':sha(source),'transformation':'Only replace four Linux includes with GPL userspace type shim; use fno-strict-aliasing'},'kernel_identity':{'image_sha256':sha(R/'build/Image-v10'),'vmlinux_sha256':sha(K/'vmlinux'),'notes_sha256':hashlib.sha256(notes).hexdigest(),'version':version,'module_files':len(modules),'critical_files':len(table)-len(modules),'base_rootfs_sha256':sha(candidate)},'boot_policy_scope':'Exact GPT schema COMMITTED2/VALID1,2/SEQ0..999 with root0600 fresh full-metadata and pinned full stock-slot hashes token required. No token supplied/deployment.'}
 record['production_loop_evidence']=evidence
 record['diagnostic_build_id']=diagnostic_id
 record['diagnostic_store']={'path':'/etc/leon/boot-diagnostics','bytes':16384,'producer':1,'writer_timeout_ms':3000,'heartbeat_ms':1000,'precreated_required':True,'diagnostic_storage_io_in_child':True,'periodic_metadata_io_in_separate_bounded_worker':True,'metadata_worker_timeout_ms':6500,'other_main_loop_io_all_bounded':False}
 record['full_production_loop_validation_passed']=bool(evidence)
 record['hardware_watchdog_opened']=False
 record['physical_reset_proven']=False
 record['flash_accepted']=False
 record['critical_file_overlays']={'startup_manifest':str((startup_dir/'manifest.json').relative_to(R)),'startup_manifest_sha256':sha(startup_dir/'manifest.json'),'files':overlays}
 record['critical_identity_baseline']={'path':str(identity_manifest.relative_to(R)),'sha256':sha(identity_manifest),'generated_header_sha256':sha(identity_header),'scope':'Only208immutablefilehashrows; no oldhealthlogic or loopproof reused','fixed_helpers':[{'path':str(path.relative_to(R)),'sha256':sha(path)} for path in fixed_helpers.values()]}
 for name in ['trial-preflight-candidate','trial-preflight-fixture','trial-ack','trial-health','trial-server-fixture','guardian-integrated','adapter-test','adapter-test.log','fixture-test.log','compiler.txt','elf.txt','identity-production.h','identity-fixture.h','sha256.c','guardian-empty-env.log','guardian-elf.txt','worker-test','worker-test.log','capture-test','capture-test.log']:
  if (stage/name).is_file():shutil.copyfile(stage/name,w/name)
 if not run.returncode:
  for name in ['trial-preflight-candidate','trial-preflight-fixture','trial-ack','trial-health','trial-server-fixture','guardian-integrated','adapter-test']:(w/name).chmod(0o755)
  assert 'INTERP' not in (w/'elf.txt').read_text();record['status']='built_readonly_fixture_tests_passed'
 record['outputs']={f.name:sha(f) for f in w.iterdir() if f.is_file()};(w/'manifest.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'status':record['status'],'path':str(w),'code':run.returncode}));raise SystemExit(run.returncode)
if __name__=='__main__':main()

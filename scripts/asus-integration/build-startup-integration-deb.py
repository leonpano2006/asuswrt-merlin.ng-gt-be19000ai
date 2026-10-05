#!/usr/bin/env python3
"""Upgrade inert integration resources with explicit native startup wiring."""
import argparse,hashlib,io,json,os,shutil,stat,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
NAME='leon-asus-integration'
VERSION='0.7+asus3006.102.9'
EPOCH=1791072000
FINAL_RC='af9b497f7791d75031772c894d17f886ba99dbac687262d9933133aa65a752fe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--native',type=Path,required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-startup'/('package-'+a.label);out.mkdir(parents=True,exist_ok=False)
 prior=R/'build/asus-native-integration/v4/manifest.json';old=json.loads(prior.read_text());assert old['package']['version']=='0.2+asus3006.102.9'
 native=json.loads((a.native/'result.json').read_text());assert native['status']=='built'
 for row in native['outputs']:assert sha(R/row['path'])==row['sha256']
 base=R/'build/asus-native-integration/v4/root'
 for row in old['archive']:
  if row['type']=='regular':assert sha(base/row['path'].lstrip('/'))==row['sha256'],row['path']
 root=out/'root';shutil.copytree(base,root,symlinks=True)
 inputs=[]
 def copy(source,target,mode):
  destination=root/target.lstrip('/');destination.parent.mkdir(parents=True,exist_ok=True)
  shutil.copyfile(source,destination);destination.chmod(mode)
  inputs.append({'path':str(source),'target':target,'sha256':sha(source)})
 for name in ['startup-prepare','etc-launch','rc-broker','rcctl','command-denied','device-event']:
  copy(a.native/name,'/usr/libexec/asus/'+name,0o755)
 for unit in sorted((R/'configs/ubuntu26/asus-startup-units').iterdir()):copy(unit,'/usr/lib/systemd/system/'+unit.name,0o644)
 control=root/'DEBIAN'
 (control/'control').write_text(f'''Package: {NAME}
Version: {VERSION}
Architecture: arm64
Section: admin
Priority: optional
Maintainer: BE19000AI local integration <local@invalid>
Depends: libc6 (>= 2.44), systemd (>= 259), udev, util-linux, mount, e2fsprogs, kmod, leon-asus-shell (= 0.2+asus3006.102.9), leon-asus-notify:arm64 (= 0.2+leonb53.1), leon-asus-notify:armel (= 0.2+leonb53.1), leon-asus-runtime-armel (= 0.7), leon-asus-runtime-arm64 (= 0.7), leon-asus-command-map (= 0.3), leon-asus-resolver (= 0.2+asus3006.102.9), leon-asus-openssh-control (= 0.4+leonb53.1), leon-bcm-kernel-modules (= 4.19.294-10+leonb53.1)
Description: Inactive BE19000AI ASUS integration with native startup wiring
 Explicit native storage/device preparation and ordered broker supervision.
 ASUS account, command and resource projections are private to its mount
 namespace. Installation does not enable units, migrate credentials, edit
 JFFS hooks, load modules or activate Broadcom hardware services.
''')
 docs=root/'usr/share/doc'/NAME
 (docs/'README').write_text('''Inactive startup candidate; no maintainer scripts, triggers, presets or enablement.
The explicit graph is four native UUID mount units -> leon-asus-prepare.service
-> leon-asus-broker.service -> private resource/command/etc launcher -> ASUS rc.
Preparation stays in PID1 mount namespace, loads the packaged overlay module,
creates reviewed static nodes with systemd-tmpfiles, publishes runtime-only udev
aliases and prepares a revocable storage-owner proof. Each command is bounded.
The broker is native systemd's MainPID; only the launcher creates a mount namespace.
The launcher validates all BSP/storage/device prerequisites before any rc instruction.
Type=notify readiness comes from rc through its broker; it is not hardware health.
The native SSH control socket must be listening before the broker starts; this
does not enable ssh.service or migrate its login identity. Stopping only signals
the broker first and drains the ASUS cgroup; it does not stop native OpenSSH or
its control socket. Stop of prerequisites first drains the broker,
then revokes the storage proof. Mount teardown stays with native systemd units.
No whole-machine reboot, flash erase, format, trial commit or SL reboot is invoked
by these integration helpers. Explicit vendor commands retain separate policy.
JFFS hook migration remains a reviewed offline candidate, not an installed hook.
All earlier reviewed Web/AI/Docker/RGB/CCR/telemetry resource bytes are retained.
Runtime ELF identity is provided by the exact runtime0.7 rc.sha256 package file.
Hardware acceptance, management identity, healthy networking
and the boot trial guard must be integrated before an actual device launch.
Synthetic kernel10 tests use RAM filesystems and a mock backend; they cannot
establish ASUS hardware functionality and never execute real ASUS rc/services.
''')
 receipt={'previous_integration_manifest':str(prior.relative_to(R)),'previous_integration_manifest_sha256':sha(prior),
  'native_build_manifest':str(a.native/'result.json'),'native_build_manifest_sha256':sha(a.native/'result.json'),
  'expected_runtime_rc_sha256':FINAL_RC,'inputs':inputs,
  'stop_patch_sha256':sha(R/'patches/ubuntu26/asuswrt6/0017-asus-managed-stop-ownership.patch'),
  'internal_emmc_patch_sha256':sha(R/'patches/ubuntu26/asuswrt6/0018-asus-internal-emmc-ownership.patch')}
 (docs/'source-manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
 for path in [root,*root.rglob('*')]:
  if path.is_symlink():continue
  if path.is_dir():path.chmod(0o755)
  elif path.parent==control:path.chmod(0o644)
  else:path.chmod(stat.S_IMODE(path.stat().st_mode)&~0o022)
  os.utime(path,(EPOCH,EPOCH),follow_symlinks=False)
 sums=[]
 for path in sorted(root.rglob('*')):
  if path.is_file() and not path.is_symlink() and 'DEBIAN' not in path.relative_to(root).parts:
   sums.append(hashlib.md5(path.read_bytes()).hexdigest()+'  '+str(path.relative_to(root)))
 (control/'md5sums').write_text('\n'.join(sums)+'\n');(control/'md5sums').chmod(0o644);os.utime(control/'md5sums',(EPOCH,EPOCH))
 env={**os.environ,'SOURCE_DATE_EPOCH':str(EPOCH)};builds=[]
 for number in [1,2]:
  path=out/f'{NAME}_{VERSION}_arm64.build{number}.deb'
  subprocess.run(['dpkg-deb','--root-owner-group','-Zzstd','-z6','--build',str(root),str(path)],check=True,env=env,stdout=subprocess.DEVNULL);builds.append(path)
 assert sha(builds[0])==sha(builds[1])
 package=out/f'{NAME}_{VERSION}_arm64.deb';shutil.copyfile(builds[0],package)
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(package)]))) as tar:
  members={x.name.removeprefix('./') for x in tar.getmembers()};assert members<={'','.','control','conffiles','md5sums'},members
 archive=[]
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(package)]))) as tar:
  for entry in tar.getmembers():
   path=entry.name.removeprefix('./');assert entry.uid==entry.gid==0 and (entry.issym() or not entry.mode&0o022),path
   assert not path.startswith(('etc/systemd/system/','usr/lib/systemd/system-preset/','usr/lib/tmpfiles.d/','usr/lib/udev/rules.d/')),path
   row={'path':'/'+path,'mode':entry.mode,'type':'directory' if entry.isdir() else 'symlink' if entry.issym() else 'regular'}
   if entry.isfile():row['sha256']=hashlib.sha256(tar.extractfile(entry).read()).hexdigest()
   if entry.issym():row['target']=entry.linkname
   archive.append(row)
 report={'status':'reproducible_inactive_startup_integration_package','package':{'name':NAME,'version':VERSION,'architecture':'arm64','path':str(package.relative_to(R)),'sha256':sha(package)},
 'two_builds_identical':True,'control_members':sorted(members),'archive':archive,'inputs':receipt,
 'unit_graph':['data.mount+jffs.mount+ai.mount+mnt-defaults.mount','leon-asus-storage.target','leon-asus-prepare.service (native PID1 mount namespace)','leon-asus-ssh.socket (native control prerequisite, no ssh.service activation)','leon-asus-broker.service (native MainPID)','etc-launch (private mount namespace; direct child PID retained)','rc (same PID as launcher)'],
 'automatic_activation':False,'maintainer_scripts':False,'actual_asus_services_executed':False,'flash_allowed':False,
 'not_yet_proven':['Final package apt install with runtime0.7/command-map0.3/modules/notify0.2/resolver0.2/openssh-control0.4','Actual Broadcom service initialization or hardware acceptance','Watchdog trial ownership and native DNS network reachability'],
 'builder_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');(R/'reports/ubuntu26/asus-startup-integration-package.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'package':str(package),'sha256':sha(package),'activation':False}))
if __name__=='__main__':main()

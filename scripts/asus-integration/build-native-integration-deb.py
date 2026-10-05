#!/usr/bin/env python3
"""Package the tested native helpers/resources without activating any service."""
import argparse,hashlib,io,json,os,shutil,stat,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
EPOCH=1791072000
NAME='leon-asus-integration'
VERSION='0.2+asus3006.102.9'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-native-integration'/a.label;out.mkdir(parents=True,exist_ok=False)
 root=out/'root';source=R/'build/asus-resource-projection/v3';manifest=json.loads((source/'manifest.json').read_text())
 for row in manifest['files']:
  path=source/'payload'/row['path'].lstrip('/')
  if row['type']=='regular':assert sha(path)==row['sha256'],row['path']
  elif row['type']=='symlink':assert os.readlink(path)==row['target']
 shutil.copytree(source/'payload',root,symlinks=True)
 inputs=[{'path':str((source/'manifest.json').relative_to(R)),'sha256':sha(source/'manifest.json')}]
 def copy(src,dest,mode):
  target=root/dest.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,target);target.chmod(mode)
  inputs.append({'path':str(src.relative_to(R)),'target':dest,'sha256':sha(src)})
 for binary,name in [('resource-launch','etc-launch'),('bsp-ownership','bsp-ownership'),('device-event','device-event')]:
  copy(R/'build/asus-bsp-resources/native-v4'/binary,'/usr/libexec/asus/'+name,0o755)
 copy(R/'build/asus-bsp-resources/native-v5/bsp-runner','/usr/libexec/asus/bsp-runner',0o755)
 copy(R/'build/asus-private-etc/native-v2/storage-owner','/usr/libexec/asus/storage-owner',0o755)
 for name in ['asus-bcm-devices.conf','70-asus-mmc-aliases.rules']:
  copy(R/'build/asus-bsp-resources/v7'/name,'/usr/share/asus/integration/'+name,0o644)
 for unit in sorted((R/'configs/ubuntu26/asus-storage-units').iterdir()):copy(unit,'/usr/lib/systemd/system/'+unit.name,0o644)
 for source_name,target in [('asus-storage-ownership.be19000ai-verified.conf','storage-ownership.conf'),('asus-bsp-storage-ownership.be19000ai-verified.conf','bsp-storage-ownership.conf')]:
  copy(R/'configs/ubuntu26'/source_name,'/etc/asus/'+target,0o600)
 copy(source/'services-start.migration-candidate','/usr/share/asus/integration/services-start.migration-candidate',0o644)
 for name in ['rom','www','data','jffs','ai','mnt/defaults','mnt/nvram']:(root/name).mkdir(parents=True,exist_ok=True)
 control=root/'DEBIAN';control.mkdir()
 (control/'control').write_text(f'''Package: {NAME}
Version: {VERSION}
Architecture: arm64
Section: admin
Priority: optional
Maintainer: BE19000AI local integration <local@invalid>
Depends: libc6 (>= 2.44), systemd (>= 259), udev, util-linux, mount, e2fsprogs, leon-asus-shell (= 0.2+asus3006.102.9), leon-asus-notify:arm64 (= 0.1+leonb53.1), leon-asus-notify:armel (= 0.1+leonb53.1), leon-asus-runtime-armel (= 0.4), leon-asus-runtime-arm64 (= 0.4)
Description: Inactive native BE19000AI ASUS integration candidate
 Private namespace launcher, verified storage ownership, bounded boot runner,
 event-only device adapter and reviewed kernel9 UI resources. This package
 installs no service activation, credentials or flash operation. Hardware
 acceptance and an explicit guarded activation remain separate.
''')
 (control/'conffiles').write_text('/etc/asus/storage-ownership.conf\n/etc/asus/bsp-storage-ownership.conf\n')
 docs=root/'usr/share/doc'/NAME;docs.mkdir(parents=True)
 (docs/'README').write_text('''Inactive BCM-side integration candidate only. No postinst/prerm/postrm/triggers exist.
The .mount units are not enabled. No manager unit or activation target is installed.
Device tmpfiles and udev alias rules remain under /usr/share/asus/integration and
are NOT installed into automatic /usr/lib/tmpfiles.d or /usr/lib/udev/rules.d.
An explicit native activation must create nodes through systemd-tmpfiles, expose
reviewed aliases, activate verified UUID mounts, then run storage-owner --prepare
in the native PID1 mount namespace before launching etc-launch under the broker.
JFFS services-start is only a migration candidate with the expected old hash in
resource manifest. Never overwrite an unrecognized current hook. No JFFS file,
NVRAM setting or private CCR credential is installed or copied by this package.
Native Ubuntu/OpenSSH account databases stay outside the ASUS private namespace.
ROM/web resources are bound read-only only when the launcher is explicitly run.
The resource namespace/BSP prerequisite fixture passed in kernel10 with RAM-only
filesystems and inert device nodes. Actual ASUS/Broadcom services did not execute;
these results do not establish that this candidate can be flashed or activated.
''')
 receipt={'resources_manifest_sha256':sha(source/'manifest.json'),'bsp_kernel10_checked_sha256':sha(R/'build/asus-resource-projection/qemu-v1/checked.json'),
  'runner_synthetic_report_sha256':sha(R/'build/asus-bsp-runner/v4/result.json'),'final_runtime_rc_sha256':'c2f2a761ec3411a14277d2d2b929edff75e43f64c92a6bc892f5de11c517f8ff','inputs':inputs}
 (docs/'source-manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
 root.chmod(0o755);os.utime(root,(EPOCH,EPOCH))
 for path in sorted(root.rglob('*')):
  if path.is_symlink():continue
  if path.is_dir():path.chmod(0o755)
  elif path.parent==control:path.chmod(0o644)
  else:path.chmod(stat.S_IMODE(path.stat().st_mode)&~0o022)
  os.utime(path,(EPOCH,EPOCH),follow_symlinks=False)
 env={**os.environ,'SOURCE_DATE_EPOCH':str(EPOCH)};packages=[]
 for index in [1,2]:
  target=out/f'{NAME}_{VERSION}_arm64.build{index}.deb'
  subprocess.run(['dpkg-deb','--root-owner-group','-Zzstd','-z6','--build',str(root),str(target)],check=True,env=env,stdout=subprocess.DEVNULL)
  packages.append(target)
 assert sha(packages[0])==sha(packages[1]),'Non-reproducible package archive'
 final=out/f'{NAME}_{VERSION}_arm64.deb';shutil.copyfile(packages[0],final)
 control_tar=subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(final)])
 with tarfile.open(fileobj=io.BytesIO(control_tar)) as tar:
  members={m.name.removeprefix('./'):m for m in tar.getmembers()}
  assert set(members)<={'','.','control','conffiles'},members
 data_tar=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(final)])
 archive=[]
 with tarfile.open(fileobj=io.BytesIO(data_tar)) as tar:
  for entry in tar.getmembers():
   name=entry.name.removeprefix('./')
   assert entry.uid==0 and entry.gid==0,(name,entry.uid,entry.gid)
   assert not entry.mode&0o022 or entry.issym(),(name,oct(entry.mode))
   assert not (name.startswith(('usr/lib/tmpfiles.d/','usr/lib/udev/rules.d/','etc/systemd/system/')) or name in ['sbin/init','usr/lib/systemd/system/leon-asus-broker.service'])
   row={'path':'/'+name,'mode':entry.mode,'type':'directory' if entry.isdir() else 'symlink' if entry.issym() else 'regular'}
   if entry.isfile():row['sha256']=hashlib.sha256(tar.extractfile(entry).read()).hexdigest()
   if entry.issym():row['target']=entry.linkname
   archive.append(row)
 report={'status':'built_reproducible_inactive_native_integration_deb','package':{'path':str(final.relative_to(R)),'sha256':sha(final),'name':NAME,'version':VERSION,'architecture':'arm64'},
  'two_builds_identical':True,'control_members':sorted(members),'archive':archive,'inputs':receipt,
  'resource_count':len(manifest['files']),'protected_accounts':'No native passwd/shadow/group/gshadow or NSS/loader config is packaged','automatic_activation':False,'maintainer_scripts':False,'flash_allowed':False,'actual_asus_services_executed':False,
  'not_yet_verified':['apt install/remove/reinstall of this integration package with exact final runtime0.4 dependencies','Final manager/broker unit, node provisioning and udev activation wiring','Read-only current JFFS hook hash before any deployment'],'builder_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');(R/'reports/ubuntu26/asus-native-integration-package.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'package':str(final),'sha256':sha(final),'archive_entries':len(archive),'activation':False}))
if __name__=='__main__':main()

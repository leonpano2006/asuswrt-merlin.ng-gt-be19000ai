#!/usr/bin/env python3
"""Real kernel10 package install + constructor-free ASUS runtime loader proof."""
import argparse,gzip,hashlib,importlib.util,io,json,stat,struct,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
PROOF=r'''#!/bin/sh
set -eu
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
D=/usr/libexec/leon-lab/asus-runtime
trap 'code=$?; echo LAB_ASUS_RUNTIME_EXIT_code=$code' EXIT
sha256sum /usr/lib/systemd/systemd /usr/lib/aarch64-linux-gnu/libc.so.6 /usr/lib/arm-linux-gnueabi/libc.so.6 /usr/sbin/sshd > /run/asus-runtime-native-before
dpkg-query -W -f='${binary:Package}\t${Version}\n' > /run/asus-runtime-packages-before
apt-get -y --no-install-recommends install "$D"/*.deb
dpkg --audit > /run/asus-runtime-dpkg-audit
test ! -s /run/asus-runtime-dpkg-audit
apt-get check
# dpkg preserves existing directory modes. Apply the same exact old packaging
# regression migration as the offline composer, never a recursive chmod.
while IFS= read -r path; do
 mode=$(stat -c '%a:%u:%g' "$path")
 case "$mode" in 775:0:0) chmod 0755 "$path" ;; 755:0:0) : ;; *) echo "Unexpected directory mode: $path $mode"; exit 1 ;; esac
done < "$D/directory-repairs"
sha256sum -c "$D/files.sha256" > /run/asus-runtime-installed-hashes
sha256sum /usr/lib/systemd/systemd /usr/lib/aarch64-linux-gnu/libc.so.6 /usr/lib/arm-linux-gnueabi/libc.so.6 /usr/sbin/sshd > /run/asus-runtime-native-after
cmp /run/asus-runtime-native-before /run/asus-runtime-native-after
for arch in armel arm64; do test "$(dpkg-query -W -f='${Version}' leon-asus-runtime-$arch)" = __VERSION__; done
test ! -e /etc/ld.so.preload
test ! -e /run/asus/systemd-managed
test "$(stat -c '%a:%u:%g' /usr/share/asus/integration/rc.sha256)" = 644:0:0
sha256sum -c /usr/share/asus/integration/rc.sha256
find /usr/libexec/asus /usr/lib/arm-linux-gnueabi/asus /usr/lib/aarch64-linux-gnu/asus /usr/share/asus /usr/share/leon-asus-runtime /etc/asus /usr/lib/arm-linux-gnueabi/leon-asus /usr/lib/aarch64-linux-gnu/leon-asus /usr/share/doc/leon-gcc15-runtime /usr/share/leon-bcm-rootfs \( -type f -o -type d \) \( -perm /022 -o ! -user root -o ! -group root \) -print > /run/asus-runtime-bad-permissions
if test -s /run/asus-runtime-bad-permissions; then cat /run/asus-runtime-bad-permissions; exit 1; fi
test "$(stat -c '%a:%u:%g' /etc/asus/storage-ownership.conf)" = 600:0:0
test "$(stat -c '%a:%u:%g' /etc/asus/bsp-storage-ownership.conf)" = 600:0:0
for unit in ai.mount data.mount jffs.mount mnt-defaults.mount leon-asus-storage.target; do
 test "$(systemctl is-active "$unit" || :)" = inactive
 if test "$unit" = leon-asus-storage.target; then expected=static; else expected=disabled; fi
 state=$(systemctl is-enabled "$unit" || :)
 echo "LAB_ASUS_INERT_UNIT=$unit:$state"
 test "$state" = "$expected"
done
echo LAB_ASUS_RUNTIME_PACKAGE_MODES_AND_INERT_INTEGRATION_PASS
echo LAB_ASUS_RUNTIME_DEB_INSTALL_NATIVE_UNCHANGED_PASS
# Both ABIs must independently expand the same scoped loader token.
/lib/ld-linux.so.3 --list-diagnostics > /run/asus-armel-loader
/lib/ld-linux-aarch64.so.1 --list-diagnostics > /run/asus-native-loader
grep -qx 'dl_dst_lib="lib/arm-linux-gnueabi"' /run/asus-armel-loader
grep -qx 'dl_dst_lib="lib/aarch64-linux-gnu"' /run/asus-native-loader
# Remove the disposable guest cache only for explicit cold-path validation.
mv /etc/ld.so.cache /run/asus-ld.so.cache
gcc-16 -O2 -Wall -Wextra "$D/loader-runner.c" -o /run/asus-loader-runner
/run/asus-loader-runner "$D/jobs" __COUNT__
mv /run/asus-ld.so.cache /etc/ld.so.cache
test ! -e /etc/ld.so.preload
test ! -e /run/asus/systemd-managed
for unit in systemd-journald.service systemd-udevd.service dbus.service; do systemctl is-active --quiet "$unit"; done
echo LAB_ASUS_RUNTIME_KERNEL10_COMPLETE
'''
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--projection',type=Path,required=True);p.add_argument('--package-report',type=Path);p.add_argument('--integration-manifest',type=Path,required=True);p.add_argument('--extra-manifest',type=Path,action='append',default=[]);p.add_argument('--label',required=True);p.add_argument('--with-notify',action='store_true');p.add_argument('--controls-plan',type=Path,default=R/'build/asus-runtime-projection/v3/loader-controls-v1/plan.json');a=p.parse_args();a.projection=a.projection.resolve();pr=json.loads(a.projection.read_text());w=a.projection.parent/('qemu-'+a.label);assert not w.exists();w.mkdir()
 label='asus-runtime-base-'+a.label;rootfs=R/pr['base']['path'];assert sha(rootfs)==pr['base']['sha256']
 subprocess.run(['python3',str(R/'scripts/prepare-ubuntu26-qemu.py'),'--rootfs',str(rootfs),'--mode','systemd','--systemd-full-boot','--output-label',label],check=True,stdout=subprocess.DEVNULL)
 spec=importlib.util.spec_from_file_location('cpio',R/'scripts/asus-integration/prepare-private-etc-qemu.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 base=R/'build/ubuntu26-rootfs'/('ubuntu26-'+label+'.cpio.gz');rows=m.parse(gzip.decompress(base.read_bytes()));index={x[0]:x for x in rows};ino=max(x[1][0] for x in rows)+1
 def add(name,data,mode=0o644,kind=stat.S_IFREG):
  nonlocal ino
  assert name not in index
  row=[name,[ino,kind|mode,0,0,2 if kind==stat.S_IFDIR else 1,0,len(data),0,0,0,0,len(name.encode())+1,0],data];ino+=1;rows.insert(-1,row);index[name]=row
 d='usr/libexec/leon-lab/asus-runtime';add(d,b'',0o755,stat.S_IFDIR)
 files={x['target']:x for x in pr['files']};jobs=[]
 for row in pr['static_closure']:
  if row['missing_libraries'] or row['unresolved_symbols']:continue
  item=files[row['target']];raw=(a.projection.parent/'stage'/item['target'].lstrip('/')).read_bytes()
  if raw[4]==1:off=struct.unpack_from('<I',raw,28)[0];size,num=struct.unpack_from('<HH',raw,42)
  else:off=struct.unpack_from('<Q',raw,32)[0];size,num=struct.unpack_from('<HH',raw,54)
  if item['kind']=='application' and not any(struct.unpack_from('<I',raw,off+i*size)[0]==3 for i in range(num)):continue
  jobs.append([item['abi'],item['kind'],item['target'],'-'])
 plugins=json.loads((a.projection.parent/'plugin-plan.json').read_text())
 for row in plugins['plans']:
  item=files[row['owner']];jobs.append([item['abi'],item['kind'],item['target'],row['target']])
 assert len(jobs)>600,len(jobs)
 add(d+'/loader-runner.c',(R/'scripts/asus-integration/runtime-loader-runner.c').read_bytes())
 package_report_path=a.package_report or a.projection.parent/'packages.json'
 package_report=json.loads(package_report_path.read_text())
 integration=json.loads(a.integration_manifest.read_text());assert integration['automatic_activation']==False
 packages=package_report['packages']+[integration['package']];package_files={};directory_repairs=set()
 for manifest in a.extra_manifest:
  extra=json.loads(manifest.read_text());packages.extend(extra['packages'] if 'packages' in extra else [extra['package']])
 for item in packages:
  path=R/item['path'];assert sha(path)==item['sha256'];add(d+'/'+path.name,path.read_bytes())
  raw=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(path)])
  with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
   for member in archive:
    name=member.name.removeprefix('./')
    if member.isdir() and member.mode==0o755 and item.get('name') in ['leon-asus-notify','leon-gcc15-runtime','leon-bcm-rootfs-config']:
     prior=index.get(name)
     if prior and prior[1][1]&0o7777==0o775:
      assert prior[1][2]==prior[1][3]==0
      directory_repairs.add('/'+name)
    if member.isfile():
     target='/'+member.name.removeprefix('./')
     content=archive.extractfile(member).read();digest=hashlib.sha256(content).hexdigest()
     if target in package_files:assert package_files[target]==digest,target
     package_files[target]=digest
     # Also trace new native integration/SSH/startup helper executables, without
     # executing their entry point. Metadata-only GNU updates need no new scope.
     if target.startswith('/usr/libexec/asus/') and target not in files and content.startswith(b'\x7fELF'):
      if content[4]==1:off=struct.unpack_from('<I',content,28)[0];size,num=struct.unpack_from('<HH',content,42);abi='armel'
      else:off=struct.unpack_from('<Q',content,32)[0];size,num=struct.unpack_from('<HH',content,54);abi='arm64'
      if any(struct.unpack_from('<I',content,off+i*size)[0]==3 for i in range(num)):jobs.append([abi,'application',target,'-'])
 if a.with_notify:
  for job in jobs:job[3]='/usr/$LIB/leon-asus/libleon-rc-notify.so'+(':'+job[3] if job[3]!='-' else '')
 add(d+'/jobs',(''.join('|'.join(x)+'\n' for x in jobs)).encode())
 add(d+'/directory-repairs',(''.join(path+'\n' for path in sorted(directory_repairs))).encode())
 add(d+'/files.sha256',(''.join(digest+'  '+target+'\n' for target,digest in sorted(package_files.items()))).encode())
 plan=json.loads(a.controls_plan.read_text());inputs=Path(plan['plugins']).parent
 for name in ['canary','unresolved.so']:add(d+'/'+name,(inputs/name).read_bytes(),0o755 if name=='canary' else 0o644)
 versions={x['version'] for x in package_report['packages']};assert len(versions)==1
 proof=PROOF.replace('__COUNT__',str(len(jobs))).replace('__VERSION__',next(iter(versions)));add(d+'/proof',proof.encode(),0o755)
 original=index['usr/libexec/leon-lab/full-boot-proof']
 start=original[2].index(b'apt-get -y install /root/leon-rootfs-probe.deb')
 end=original[2].index(b'for unit in multi-user.target',start)
 original[2]=original[2][:start]+original[2][end:]
 needle=b'echo passed > /run/leon-full-boot-ok';assert original[2].count(needle)==1;original[2]=original[2].replace(needle,('/'+d+'/proof\n').encode()+needle)
 unit=index['etc/systemd/system/leon-full-boot.service'];assert b'TimeoutStartSec=90' in unit[2];unit[2]=unit[2].replace(b'TimeoutStartSec=90',b'TimeoutStartSec=240')
 data=bytearray()
 for name,fields,payload in rows:
  n=name.encode()+b'\0';fields[6]=len(payload);fields[11]=len(n);data+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;data+=bytes(-len(data)%4);data+=payload;data+=bytes(-len(data)%4)
 path=w/'initramfs.cpio.gz';path.write_bytes(gzip.compress(data,compresslevel=1,mtime=0));(w/'proof.sh').write_text(proof)
 report={'scope':'No-NIC kernel10 systemd PID1: install inert runtime and native integration debs, actual ARMEL/native loader traces and synthetic controls. No vendor main/constructor, hardware/network/AI service activation.','production_ready':False,'scoped_production_notify':a.with_notify,'kernel':'build/Image-v10','rootfs':str(rootfs.relative_to(R)),'rootfs_sha256':sha(rootfs),'projection_sha256':sha(a.projection),'packages':packages,'package_report_sha256':sha(package_report_path),'integration_manifest_sha256':sha(a.integration_manifest),'installed_regular_file_hashes':len(package_files),'jobs':jobs,'unreferenced_orphan':plugins['unresolved'],'base_fixture_sha256':sha(base),'initramfs':str(path.relative_to(R)),'initramfs_sha256':sha(path),'builder_sha256':sha(Path(__file__)),'expected_markers':['LAB_ASUS_RUNTIME_PACKAGE_MODES_AND_INERT_INTEGRATION_PASS','LAB_ASUS_RUNTIME_DEB_INSTALL_NATIVE_UNCHANGED_PASS',f'LAB_ASUS_RUNTIME_ALL_LOADER_SCOPES_PASS_count={len(jobs)}','LAB_ASUS_RUNTIME_NO_MAIN_CTORS_AND_NEGATIVE_CONTROL_PASS','LAB_ASUS_RUNTIME_KERNEL10_COMPLETE','QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE']}
 (w/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'initramfs':report['initramfs'],'jobs':len(jobs)}))
if __name__=='__main__':main()

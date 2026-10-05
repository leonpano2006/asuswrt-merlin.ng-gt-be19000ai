#!/usr/bin/env python3
"""Verify dual-ABI notify archives and close the kernel10 namespace evidence."""
import hashlib,importlib.util,io,json,os,re,subprocess,tarfile,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1];W=R/'build/asus-notify-packages/v1';Q=R/'build/qemu/asus-notify-kernel10-v1'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(p):return json.loads(p.read_text())
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def write(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
 spec=importlib.util.spec_from_file_location('elf_audit',R/'scripts/build-asus-libcrypt-compat.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 manifest=read(W/'manifest.json');native=m.inspect_elf(W/'arm64/libleon-rc-notify.so');old=m.inspect_elf(R/'build/asus-native-helpers/v3/libleon-rc-notify.so')
 assert native['exports']==old['exports'] and native['imports']==old['imports']
 for source in manifest['source_inputs']:assert sha(R/source['path'])==source['sha256']
 docs=[];packageproof=[]
 for p in manifest['packages']:
  archive=R/p['path'];assert sha(archive)==p['sha256']
  control=subprocess.check_output(['dpkg-deb','-f',str(archive)],text=True)
  assert '\nMulti-Arch: same\n' in control and '\nVersion: 0.1+leonb53.1\n' in control
  data=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(archive)]);rows=[];doc={}
  with tarfile.open(fileobj=io.BytesIO(data)) as tf:
   for f in tf:
    n=f.name.removeprefix('./');assert not n.startswith('etc/') and 'systemd' not in n and not f.isdev();assert f.uid==f.gid==0
    row={'path':n,'mode':oct(f.mode),'uid':f.uid,'gid':f.gid}
    if f.isfile():row['sha256']=hashlib.sha256(tf.extractfile(f).read()).hexdigest()
    if n.startswith('usr/share/doc/'):doc[n]=row
    rows.append(row)
  docs.append(doc)
  elf=m.inspect_elf(W/p['architecture']/'libleon-rc-notify.so')
  assert elf['machine']==('EM_ARM' if p['architecture']=='armel' else 'EM_AARCH64') and not elf['rpath_runpath']
  if p['architecture']=='armel':assert elf['float_abi_flags']==0x200
  assert set(elf['exports'])==set(native['exports']) and not any(s.endswith('@GLIBC_PRIVATE') for s in elf['imports'])
  with tempfile.TemporaryDirectory(prefix='notify-repack-') as temp:
   same=Path(temp)/'same.deb';subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','--build',str(W/('stage-'+p['architecture'])),str(same)],env={**os.environ,'SOURCE_DATE_EPOCH':str(manifest['source_date_epoch'])},stdout=subprocess.DEVNULL,check=True);assert sha(same)==p['sha256']
  packageproof.append({'package':p,'control':control,'elf':elf,'data_members':rows,'deterministic_repack_same_sha256':True})
 assert docs[0]==docs[1]
 fixture=read(R/'build/asus-notify-packages/qemu-v1/manifest.json');result=read(Q/'result.json');candidate=read(R/'reports/ubuntu26/asus-notify-candidate.json')
 assert result['exit_code']==0 and result['guest_complete'] and not result['panic']
 assert result['log_sha256']==sha(Q/'serial.log') and result['kernel_sha256']==sha(R/'build/Image-v10')
 assert result['initramfs_sha256']==fixture['initramfs_sha256']==sha(R/fixture['initramfs'])
 assert fixture['packages_manifest_sha256']==sha(W/'manifest.json')
 assert candidate['status']=='built' and candidate['apt_install_dpkg_reinstall_passed'] and not candidate['global_preload_installed']
 rootfs=R/candidate['rootfs_tar'];assert sha(rootfs)==candidate['rootfs_sha256']==fixture['rootfs_sha256']
 text=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',(Q/'serial.log').read_text(errors='replace')).replace('\r','');lines=text.splitlines()
 assert all(marker in lines for marker in fixture['expected_markers'])
 assert lines.count('NOTIFY_AND_ORDINARY_SIGNAL_PASS')==14
 assert lines.count('MISSING_BROKER_FAIL_CLOSED_PASS')==2
 assert lines.count('LAB_NOTIFY_OUTSIDE_NO_PRELOAD_PASS')==4
 assert 'LAB_NOTIFY_QEMU_EXIT_code=0' in lines
 report={'schema_version':1,'status':'passed_dual_abi_private_preload_component','component_runtime_validated':True,'full_asus_runtime_accepted':False,'production_ready':False,
 'scope':'Exact paired Ubuntu multiarch packages coinstalled. ARMEL GCC15.2/time64 and native GCC16/time64 helpers automatically loaded by literal /usr/$LIB/leon-asus/libleon-rc-notify.so exclusively inside the real private-/etc launcher namespace.',
 'package_manifest':ref(W/'manifest.json'),'packages':packageproof,'rootfs':ref(rootfs),'shared_documentation_identical':True,'native_v3_exports_imports_identical':True,'global_preload_installed':False,'services_enabled':False,
 'isolated_install':{'new_packages':candidate['new_or_changed_packages'],'existing_custom_versions_unchanged':len(candidate['custom_package_versions_preserved']),'protected_hashes':candidate['native_protected_file_hashes'],'worker_result':ref(R/'build/asus-notify-packages/gnu-systemd-openssh-armel15-notify-b53-v1/worker-result.json'),'worker_log':ref(R/'build/asus-notify-packages/gnu-systemd-openssh-armel15-notify-b53-v1/worker.log'),'apt_install_passed':True,'exact_archive_reinstall_passed':True,'dpkg_audit_clean':True},
 'qemu':{'result':ref(Q/'result.json'),'serial_log':ref(Q/'serial.log'),'fixture_manifest':ref(R/'build/asus-notify-packages/qemu-v1/manifest.json'),'kernel':ref(R/'build/Image-v10'),'elapsed_seconds':result['elapsed_seconds'],'markers':fixture['expected_markers'],'positive_notify_call_count':14,'missing_broker_count':2,'outside_namespace_no_preload_count':4,'private_preload_LIB_correct_for_both_ABIs':True,'all_helpers_time_t_off_t_64':True,'no_host_disk_or_nic':True},
 'boundaries':['Broker in this fixture is a benign root-owned SOCK_SEQPACKET protocol server; existing production-broker lifecycle evidence remains separate.','Calls reuse notify-caller.c and notify-fixture.c; proprietary libshared and ASUS daemons are not executed here.','No global preload entry or service unit is installed. Production launcher will activate the shim only in its private namespace.','ASUS hardware/full runtime acceptance and deployment remain pending.'],
 'router_access':False,'host_ssh_modified':False,'flash_performed':False,'checker':ref(Path(__file__))}
 rp=R/'reports/ubuntu26/asus-notify-multiarch.json';write(rp,report)
 candidate.update(target_kernel_runtime_validated=True,runtime_validation_report=str(rp.relative_to(R)),full_asus_runtime_accepted=False);write(R/'reports/ubuntu26/asus-notify-candidate.json',candidate)
 frozen={'schema_version':1,'packages':manifest['packages'],'rootfs':ref(rootfs),'runtime_report':ref(rp),'scope':'Installed inactive dual-ABI notify packages; private namespace runtime validated; no full ASUS/deployment acceptance'}
 fp=W/'validated-manifest.json';assert not fp.exists();write(fp,frozen)
 print(json.dumps({'status':report['status'],'manifest':ref(fp),'report':ref(rp),'rootfs':ref(rootfs)},indent=2))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Close the ARMEL package acceptance record using exact isolated/QEMU evidence."""
import hashlib,json,re,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1];W=R/'build/ubuntu26-armel-runtime-gcc15';Q=R/'build/qemu/ubuntu26-kernel10-armel15-v2'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(p):return json.loads(p.read_text())
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def write(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
 result=read(Q/'result.json');fixture=read(W/'armel15-kernel10-v2/manifest.json');candidate=read(R/'reports/ubuntu26/armel-runtime-candidate.json');audit=read(R/'reports/ubuntu26/armel-runtime-package-audit.json');packages=read(W/'packages.json')['packages']
 assert result['guest_complete'] and not result['panic'] and result['exit_code']==0
 assert result['kernel_sha256']==sha(R/'build/Image-v10')
 assert result['log_sha256']==sha(Q/'serial.log')
 assert result['initramfs_sha256']==fixture['initramfs_sha256']==sha(R/fixture['initramfs'])
 log=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',(Q/'serial.log').read_text(errors='replace')).replace('\r','');lines=log.splitlines()
 missing=[s for s in fixture['expected_markers'] if s not in lines]
 missing += [s for s in fixture['expected_prefix_markers'] if not any(x.startswith(s) for x in lines)]
 assert not missing,missing
 assert audit['static_package_abi_audit_passed'] and candidate['status']=='built' and candidate['apt_install_dpkg_reinstall_passed']
 rootfs=R/candidate['rootfs_tar'];assert sha(rootfs)==candidate['rootfs_sha256']==fixture['rootfs_sha256'];assert candidate['base_unchanged'] and candidate['signed_sources_unchanged']
 for p in packages:assert sha(R/p['path'])==p['sha256']
 cpp=audit['legacy_gcc_runtime_exports']['libstdc++.so.6'];crypt=audit['vendor_armel_libcrypt'];nativecrypt=audit['native_libcrypt_allowlisted_upgrade']
 switches={}
 for name in ['libgcc_s.so.1','libstdc++.so.6.0.34']:
  p=W/'package-stage/leon-gcc15-runtime/usr/lib/arm-linux-gnueabi'/name
  text=subprocess.check_output(['readelf','-p','.GCC.command.line',str(p)],text=True)
  for flag in ['15.2.0','-mtune=cortex-a53','-march=armv8-a+crc+crypto','-mfloat-abi=softfp']:assert flag in text
  switches[name]={'sha256':sha(p),'recorded_compiler_switches':text}
 report={'schema_version':1,'status':'component_runtime_validated','runtime_component_validation_passed':True,'full_asus_runtime_accepted':False,'production_ready':False,
 'scope':'Ubuntu-format ARMEL GNU/libcrypt packages coinstalled with the native Ubuntu candidate; kernel10 runtime ABI and native OpenSSH regression. ASUS manager, Wi-Fi, switch, hardware and persistent-root integration are separate unproven deployment gates.',
 'packages':packages,'rootfs':ref(rootfs),'base_candidate_preserved':{'path':candidate['base_rootfs'],'sha256':candidate['base_sha256'],'unchanged':candidate['base_unchanged']},
 'compiler_policy':ref(R/'configs/ubuntu26/compiler-policy.json'),'gcc15_source_authentication':ref(W/'gcc15-source-authentication.json'),'gcc15_compiler_authentication':ref(W/'gcc15-bootstrap-authentication.json'),
 'build_evidence':[ref(W/(phase+'-build.json')) for phase in ['glibc','gcc-runtime','libcrypt-armel','libcrypt-arm64']],
 'probe_build':ref(W/'probe-build.json'),'package_audit':ref(R/'reports/ubuntu26/armel-runtime-package-audit.json'),'recorded_gcc_runtime_flags':switches,
 'isolated_install':{'worker_result':ref(W/'gnu-systemd-openssh-armel15-b53-v2/worker-result.json'),'worker_log':ref(W/'gnu-systemd-openssh-armel15-b53-v2/worker.log'),'apt_solver_no_removals':True,'apt_install_passed':True,'exact_archive_dpkg_reinstall_passed':True,'apt_dependency_check_passed':True,'dpkg_audit_clean':True,'custom_native_versions_unchanged':len(candidate['custom_package_versions_preserved']),'native_protected_file_hashes':candidate['native_protected_file_hashes'],'sole_native_package_upgrade':'libcrypt1:arm64 1:4.5.1-1 -> 1:4.5.1-1+leonb53.1','signed_ubuntu_sources_unchanged':True},
 'abi':{'armel':'EABI5 softfp; armv8-a+crypto+crc tuned Cortex-A53','loader_LIB':{'armel':'lib/arm-linux-gnueabi','arm64':'lib/aarch64-linux-gnu'},'usrmerge':True,'new_code_time_t_and_off_t_bits':64,'legacy_time32_probe_passed':True,'vendor_crypt_exports_retained':crypt['old_exports'],'vendor_crypt_private_imports':False,'native_crypt_export_changes':len(nativecrypt['export_changes']),'libstdcxx_reviewed_missing_weak_inline_exports':len(cpp['missing_exports']),'libstdcxx_reviewed_binding_changes':len(cpp['incompatible_exports']),'libstdcxx_consumer_paths':[x['path'] for x in cpp['current_cpp_consumers']],'vendor_static_literal_scan_files':cpp['literal_lookup_scan_files'],'external_plugin_compatibility_claimed':False,'armhf_built':False},
 'qemu':{'result':ref(Q/'result.json'),'serial_log':ref(Q/'serial.log'),'fixture_manifest':ref(W/'armel15-kernel10-v2/manifest.json'),'kernel':ref(R/'build/Image-v10'),'initramfs':ref(R/fixture['initramfs']),'elapsed_seconds':result['elapsed_seconds'],'exit_code':0,'guest_complete':True,'panic':False,'markers_verified':fixture['expected_markers'],'prefix_markers_verified':fixture['expected_prefix_markers'],'guest_network':'-nic none; SSH loopback only, no forwarding','native_openssh_full_regression_passed':True},
 'harness_repairs':[{'evidence':str((W/'gnu-systemd-openssh-armel15-b53-v1/worker-result.json').relative_to(R)),'issue':'apt local-file --reinstall requested missing native Multi-Arch same archives; ordinary apt install had passed. Exact five archive dpkg reinstall plus apt check used instead, without native sibling replacement.'},{'evidence':str((R/'build/qemu/ubuntu26-kernel10-armel15-v1/result.json').relative_to(R)),'issue':'First fixture omitted cpio parent directory for ARMEL probes. No runtime file was found; fixed fixture directory entry, retained candidate and packages unchanged.'}],
 'limitations':['Full upstream glibc/GCC/libxcrypt test suites not run.','libstdc++ has the exact reviewed GCC10-to-GCC15 delta. Current vendor imports resolve; no general external plugin ABI claim.','ASUS full userspace services/hardware and writable persistent root not yet accepted.','Formal SSH login identity not migrated; no root empty password, no production account keys included.','ARMEL GCC16 batch remains quarantined; these target packages are GCC15.2.'],
 'host_packages_modified':False,'host_ssh_modified':False,'router_access':False,'flash_performed':False,'checker':ref(Path(__file__))}
 report_path=R/'reports/ubuntu26/armel-runtime-kernel10.json';write(report_path,report)
 candidate.update(target_kernel_runtime_validated=True,runtime_validation_report=str(report_path.relative_to(R)),production_ready=False,full_asus_runtime_accepted=False)
 write(R/'reports/ubuntu26/armel-runtime-candidate.json',candidate)
 frozen={'schema_version':1,'label':'armel-gcc15-runtime-kernel10-validated-v1','packages':packages,'rootfs':ref(rootfs),'runtime_report':ref(report_path),'scope':'Component-only local integration candidate; no ASUS full runtime/deployment approval','compiler_policy':ref(R/'configs/ubuntu26/compiler-policy.json')}
 manifest=W/'validated-manifest.json';assert not manifest.exists(),'Do not overwrite the frozen accepted manifest';write(manifest,frozen)
 print(json.dumps({'runtime_component_validation_passed':True,'full_asus_runtime_accepted':False,'report':ref(report_path),'manifest':ref(manifest),'rootfs':ref(rootfs),'verified_exact_markers':len(fixture['expected_markers'])},indent=2))
if __name__=='__main__':main()

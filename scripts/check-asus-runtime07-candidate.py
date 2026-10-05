#!/usr/bin/env python3
"""Bind exact runtime07 composition, target-loader, sealing and independent modes evidence."""
import hashlib,json,re
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(name):return json.loads((R/name).read_text())
def ref(name):return {'path':name,'sha256':sha(R/name)}
def main():
 names={
 'composition':'build/asus-runtime-projection/gnu-systemd-openssh-asus-runtime07-integration-b53-v1/build.json',
 'hostkey_seal':'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-asus-runtime07-integration-sealed-b53-v1.hostkey-seal.json',
 'fixture':'build/asus-runtime-projection/v7/qemu-asus-runtime07-kernel10-v1/manifest.json',
 'qemu':'build/qemu/asus-runtime07-kernel10-v2/result.json',
 'serial':'build/qemu/asus-runtime07-kernel10-v2/serial.log',
 'source_preflight':'reports/ubuntu26/asus-runtime07-preflight.json',
 'projection':'build/asus-runtime-projection/v7/projection.json',
 'independent_installed_modes':'reports/ubuntu26/installed-modes-integration07-sealed-v1.json',
 'openssh_component':'reports/ubuntu26/asus-openssh-applied-state-v1.json'}
 c,s,f,q,m,ssh=[read(names[k]) for k in ['composition','hostkey_seal','fixture','qemu','independent_installed_modes','openssh_component']]
 assert c['status']=='built' and not c['returncode'] and c['base_unchanged'] and c['apt_install_and_dpkg_reinstall']
 for k in ['protected_native_files_unchanged','existing_package_versions_unchanged_except_approved_metadata','signed_sources_unchanged','no_global_preload','no_service_activation']:assert c[k],k
 assert not c['package_collision_audit']['unapproved_non_directory_collisions']
 assert len(c['packages'])==16 and c['installed_entries_checked']==4666
 signatures=lambda rows:sorted((x['path'],x['sha256']) for x in rows)
 assert signatures(c['packages'])==signatures(f['packages'])
 for p in c['packages']:assert sha(R/p['path'])==p['sha256']
 assert q['guest_complete'] and not q['panic'] and q['stop_reason']=='complete'
 assert q['kernel_sha256']==sha(R/'build/Image-v10') and q['initramfs_sha256']==f['initramfs_sha256']
 log=(R/names['serial']).read_text();assert sha(R/names['serial'])==q['log_sha256']
 for marker in f['expected_markers']:assert marker in log,marker
 scope=re.search(r'LAB_ASUS_RUNTIME_ALL_LOADER_SCOPES_PASS_count=(\d+) elapsed=([0-9.]+)',log);assert scope and int(scope[1])==len(f['jobs'])==643
 assert s['input']['sha256']==c['rootfs_sha256'] and s['all_other_file_bytes_and_metadata_unchanged'] and len(s['removed_files'])==6
 rootfs=dict(s['output']);rootfs['bytes']=(R/rootfs['path']).stat().st_size;assert sha(R/rootfs['path'])==rootfs['sha256']
 assert m['rootfs']['sha256']==rootfs['sha256'] and len(m['installed_packages'])==181
 for key in ['critical_group_or_world_writable','critical_unowned','writable_executables','custom_setuid_files']:assert not m[key],key
 assert any(p['sha256']==ssh['package']['sha256'] and p['name']=='leon-asus-openssh-control' for p in c['packages'])
 checks={'installed_entries':c['installed_entries_checked'],'installed_packages':181,'installed_tar_entries':m['entry_count'],'loader_scopes':643,'loader_seconds':float(scope[2]),'qemu_seconds':q['elapsed_seconds'],'canary_no_vendor_main_or_constructors':True,'negative_undefined_symbol_control':True,'protected_native_files_unchanged':True,'existing_versions_preserved_except_approved_metadata':True,'no_global_preload':True,'no_service_activation':True,'critical_writable_or_unowned':0,'writable_executables':0,'custom_setuid':0,'mode_migrations':c['explicit_legacy_directory_mode_migrations']}
 result={'schema_version':1,'status':'passed_offline_composition_and_kernel10_loader_preflight','production_ready':False,'flash_allowed':False,'runtime_version':'0.7','rootfs':rootfs,'base':{'rootfs':{'path':c['base_rootfs'],'sha256':c['base_sha256']},'manifest':ref('build/asus-notify-packages/v1/validated-manifest.json')},'packages':c['packages'],'evidence':{k:ref(v) for k,v in names.items()},'checks':checks,'scope':'Exact same 16 package hashes installed on the immutable base in an isolated namespace and under kernel10/systemd PID1. ARMEL/native loader traces, owner/plugin scopes and synthetic canaries only; no actual ASUS main, constructors, hardware initialization or watchdog arm. Sealed tar differs from composed tar only by six hash-identified prototype SSH key files. Separate SSH component evidence covers real guest loopback login and policy management with synthetic identity.',
 'pending':['Independent immutable guardian critical-file table check against the final archive-composed root.','Final signed local archive package overlay and activated trial root composition by the parent task.','Device-local account and unique host-key provisioning, fresh postflash slot proof and observer trust.','Guarded physical storage/kernel trial and actual Broadcom Wi-Fi/AiMesh/AI/peripheral acceptance.'],
 'preserved_harness_error':{'path':'build/qemu/asus-runtime07-kernel10-v1/result.json','reason':'Wrong completion-marker argument. Guest log contains all positive markers and exit0, but wrapper guest_complete=false. A new unchanged-fixture v2 run completed with the correct full marker.'},'checker':ref(str(Path(__file__).resolve().relative_to(R)))}
 target=R/'build/asus-runtime-projection/v7/validated-manifest.json';assert not target.exists();target.write_text(json.dumps(result,indent=2)+'\n')
 report={k:result[k] for k in ['schema_version','status','production_ready','flash_allowed','runtime_version','rootfs','checks','evidence','scope','pending']};report['manifest']=ref(str(target.relative_to(R)))
 report_path=R/'reports/ubuntu26/asus-runtime07-candidate.json';assert not report_path.exists();report_path.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':result['status'],'manifest':ref(str(target.relative_to(R))),'rootfs':rootfs},indent=2))
if __name__=='__main__':main()

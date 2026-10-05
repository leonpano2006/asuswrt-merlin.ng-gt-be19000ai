#!/usr/bin/env python3
"""Check immutable package, candidate and target-kernel SSH component evidence."""
import argparse,hashlib,io,json,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(p):return json.loads(p.read_text())
def evidence(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
 p=argparse.ArgumentParser();p.add_argument('--fixture',required=True);p.add_argument('--qemu',required=True);a=p.parse_args()
 w=R/'build/asus-ssh-integration';np=w/'native-v3/manifest.json';n=load(np);cp=w/'gnu-systemd-openssh-control-b53-v4/build.json';c=load(cp);fp=w/a.fixture/'manifest.json';f=load(fp);rp=R/'build/qemu'/a.qemu/'result.json';q=load(rp);log=rp.parent/'serial.log'
 assert q['guest_complete'] and not q['panic'] and q['exit_code'] in (0,-15)
 assert sha(log)==q['log_sha256'] and q['initramfs_sha256']==f['initramfs_sha256'] and sha(R/f['initramfs'])==f['initramfs_sha256']
 assert q['kernel_sha256']==sha(R/'build/Image-v10')
 assert c['status']=='built' and c['returncode']==0 and c['base_unchanged'] and c['signed_sources_unchanged'] and c['apt_install_dpkg_reinstall_passed']
 assert sha(R/c['rootfs_tar'])==c['rootfs_sha256']==f['rootfs_sha256']
 assert sha(np)==f['native_manifest_sha256'] and sha(w/'clients-v1/manifest.json')==f['client_manifest_sha256']
 text=log.read_text(errors='replace');markers={m:m in text for m in f['expected_markers']};assert all(markers.values()),markers
 assert 'LAB_SSH_CONTROL_EXIT_code=0' in text
 package=R/n['package']['path'];assert sha(package)==n['package']['sha256']
 for item in n['sources']:assert sha(R/item['path'])==item['sha256']
 raw=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(package)]);files=[]
 with tarfile.open(fileobj=io.BytesIO(raw)) as t:
  for m in t:
   name=m.name.removeprefix('./');assert not m.isdev() and not m.issym() and not m.islnk();assert m.uid==0 and m.gid==0
   if m.isdir():assert not m.mode&0o022;continue
   assert m.isfile() and name.startswith('usr/') and not m.mode&0o022
   content=t.extractfile(m).read();files.append({'path':name,'mode':oct(m.mode),'sha256':hashlib.sha256(content).hexdigest()})
   if name=='usr/libexec/leon-asus/ssh-control':assert hashlib.sha256(content).hexdigest()==n['binaries']['native-control']
 assert len(files)==5
 controls=subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(package)])
 with tarfile.open(fileobj=io.BytesIO(controls)) as t:assert {m.name.removeprefix('./') for m in t if m.isfile()}=={'control','md5sums'}
 with tarfile.open(R/c['rootfs_tar']) as t:
  present={m.name.removeprefix('./'):m for m in t}
  for item in files:
   m=present[item['path']];assert m.uid==0 and m.gid==0 and oct(m.mode)==item['mode'] and hashlib.sha256(t.extractfile(m).read()).hexdigest()==item['sha256']
  assert not any(x.startswith('var/lib/leon-asus-ssh') or x.startswith('home/MastermixStudios') or ('etc/systemd/system/' in x and 'leon-asus-ssh' in x) for x in present)
  passwd=t.extractfile(present['etc/passwd']).read();assert b'\nMastermixStudios:' not in b'\n'+passwd
 seal_path=R/'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-control-sealed-b53-v2.hostkey-seal.json'
 seal=load(seal_path);assert seal['input']['sha256']==c['rootfs_sha256'] and seal['all_other_file_bytes_and_metadata_unchanged'] and len(seal['removed_files'])==6
 assert sha(R/seal['output']['path'])==seal['output']['sha256']
 mode_path=R/'reports/ubuntu26/installed-modes-ssh-sealed-v2.json';modes=load(mode_path)
 assert modes['rootfs']['sha256']==seal['output']['sha256']
 source=load(w/'source-audit/manifest.json')
 for item in source['files']:assert sha(R/item['saved'])==item['sha256']
 official=[];metadata=(cp.parent/'official-source-metadata.txt').read_text()
 paragraphs=[]
 for block in metadata.split('\n\n'):
  fields={line.split(': ',1)[0]:line.split(': ',1)[1] for line in block.splitlines() if ': ' in line and not line[0].isspace()};paragraphs.append(fields)
 for deb in sorted((cp.parent/'official-archives').glob('*.deb')):
  fields=subprocess.check_output(['dpkg-deb','-f',str(deb),'Package','Version','Architecture'],text=True)
  info=dict(line.split(': ',1) for line in fields.splitlines());match=[x for x in paragraphs if all(x.get(k)==v for k,v in info.items()) and x.get('SHA256')==sha(deb)];assert match,info
  official.append({**info,**evidence(deb),'ubuntu_metadata_sha256_matches':True,'filename':match[0]['Filename']})
 assert {d['Package'] for d in official}=={'sudo','sudo-common'}
 d={'schema_version':1,'status':'component_validated_inactive_candidate','component_runtime_validation_passed':True,'runtime_accepted':False,'production_ready':False,'runtime_acceptance_scope':'Actual native Ubuntu ssh.service, synthetic single-account identity, IPv4/IPv6 guest loopback and ARMEL/native request transport under target kernel10. Full ASUS userspace, physical LAN/WAN policy and real device identity cutover remain unaccepted.','package':n['package'],'package_payload':files,'package_installs_services_enabled':False,'package_creates_accounts_or_host_keys':False,'candidate':{'path':c['rootfs_tar'],'sha256':c['rootfs_sha256'],'base_unchanged':c['base_unchanged'],'custom_versions_preserved':c['custom_package_versions_preserved'],'new_packages':c['new_or_changed_packages'],'apt_install_reinstall_passed':True,'protected_native_files':c['native_protected_file_hashes'],'formal_identity_migrated':False,'contains_prototype_host_keys_must_be_sealed':True},'sealed_candidate':{'archive':seal['output'],'report':evidence(seal_path),'all_non_key_bytes_and_metadata_unchanged':True,'device_keys_generated':False},'installed_mode_peer_audit':{'report':evidence(mode_path),'inherited_critical_paths':modes['critical_count'],'inherited_packages_requiring_metadata_fix':['leon-asus-notify 0.1','leon-gcc15-runtime 15.2.0-0leonb53.1','leon-bcm-rootfs-config 0.2'],'ssh_control_package_violations':0,'writable_executables':len(modes['writable_executables'])},'official_packages':official,'source_pin':source['source_pin'],'source_audit_inputs':source['files'],'source_findings':{'sshd_enable_values':{'0':'disabled','2':'LAN only','1':'LAN and WAN; rejected by native helper'},'web_apply':'Advanced_System_Content.asp invokes restart_time; services.c time handler stop/starts sshd. Explicit sshd handler also retained.','identity_sync':'setup_passwd hook sends only selected private getspnam crypt hash, never plaintext NVRAM password or an entire account database.','generic_stop':'0014 stop_sshd ignores generic stop while sshd_enable is nonzero. Overall broker shutdown stop_services path needs independent native ownership policy; coordinated with startup agent.','legacy_window':'sshd_rwb is a Dropbear receive-window parameter without a claimed native mapping.','ipv6':'Vendor firewall opens WAN IPv6 SSH only when sshd_enable==1. Native helper enumerates br0 IPv4+IPv6 addresses, explicit binds and per-prefix AllowUsers; physical firewall integration still requires real deployment validation.'},'identity_policy':{'name':'MastermixStudios','uid':'Native useradd allocated ordinary UID >=1000; persisted marker; no UID0 vendor alias copied.','privileges':'sudo group; official default sudo policy requiring password; no NOPASSWD override.','password_storage':'Validated existing crypt encoding, atomic selected shadow entry under lckpwdf; all unrelated entries preserved.','allowed_hash_formats':['DES','MD5 crypt','SHA256 crypt','SHA512 crypt','yescrypt j9T'],'unsupported_hash_policy':'Unsupported formats or excessive configured rounds fail closed; no password algorithm silently converted.','authorized_keys':'ASUS keys kept in separate owned file; native home authorized_keys remains an additional source.','host_keys':'Explicit native device initialization only; refuses existing unmarked keys, uses no-overwrite links and fsync before marker; idempotent retry preserves existing marked keys. No automatic local Dropbear conversion is implemented.'},'request_boundary':{'socket_type':'UNIX SOCK_SEQPACKET','request_bytes':3440,'reply_bytes':16,'peer':'root SO_PEERCRED and exact approved rc inode','namespace':'native PID1 mount namespace and native /etc identity','scope':'fixed apply/identity operations and exact username; no shell command transport','timeout_limit':'Normal request and subprocess execution have alarms plus systemd RuntimeMaxSec. Uninterruptible kernel I/O cannot be given a hard userspace deadline.'},'qemu':{'result':evidence(rp),'serial_log':evidence(log),'fixture':evidence(fp),'kernel_sha256':q['kernel_sha256'],'initramfs_sha256':q['initramfs_sha256'],'elapsed_seconds':q['elapsed_seconds'],'expected_markers':markers,'command':q['command'],'fixture_seams':'Approved executable path and LAN interface overridden to synthetic test client and lo; production helper used unchanged for device key initialization. Two ABI fixture clients are fresh builds. No QEMU NIC, forwarding, host block device or hardware passthrough.'},'quarantined_package_versions':['0.1+leonb53.1: pre-fsync fix and noncanonical staging modes','0.2+leonb53.1: staging umask leaked group-writable metadata; binaries not a permission bypass, archive not accepted'],'historical_failures':[{'result':'build/qemu/asus-openssh-control-kernel10-v1/result.json','cause':'Fixture lacked parent directory for injected client; device key ownership tests passed.'},{'result':'build/qemu/asus-openssh-control-kernel10-v3/result.json','cause':'Generic initramfs builder skipped tar root metadata; StrictModes correctly refused unsafe default /. Input rootfs / is 0755 root:root; fixed by preserving exact tar metadata, never by disabling StrictModes.'}],'additional_fixture_failure':{'result':'build/qemu/asus-openssh-control-kernel10-v4/result.json','cause':'Synthetic askpass reset generated an empty answer due to nested printf formatting. Fixed fixture with literal heredoc and exact-output guard; PAM and crypt policy unchanged.'},'evidence':{'native_build':evidence(np),'candidate_build':evidence(cp),'clients_build':evidence(w/'clients-v1/manifest.json'),'official_archive_metadata':evidence(cp.parent/'official-source-metadata.txt'),'rc_patch':evidence(R/'patches/ubuntu26/asuswrt6/0014-asus-native-openssh-control.patch')},'remaining_before_deployment':['Merge the parent-owned metadata-only repairs for inherited notify/GCC15/rootfs-config packages and rerun the installed mode audit.','Use the hash-guarded sealer on the final assembled rootfs (a separate sealed candidate is already provided), then provision or explicitly migrate device-local identity without exporting private keys.','Activate control socket only as part of reviewed native startup ordering after storage and current approved rc inode are present.','Migrate real selected admin identity locally and validate exact original credential/hash format without printing or packaging credentials.','Verify physical br0 addresses, IPv4/IPv6 LAN/WAN firewall and ASUS Web apply end-to-end on guarded device trial.','Complete full ASUS service and closed-blob integration acceptance.'],'router_access':False,'real_passwords_read':False,'host_ssh_changed':False,'checker_sha256':sha(Path(__file__))}
 path=R/'reports/ubuntu26/asus-openssh-control.json';path.write_text(json.dumps(d,indent=2)+'\n')
 validated=w/'validated-manifest.json';validated.write_text(json.dumps({'schema_version':1,'status':d['status'],'package':n['package'],'candidate':{'path':c['rootfs_tar'],'sha256':c['rootfs_sha256']},'report':evidence(path),'sealed_candidate':{'archive':seal['output'],'report':evidence(seal_path)},'qemu_result':evidence(rp),'qemu_log':evidence(log),'production_ready':False},indent=2)+'\n')
 print(json.dumps({'status':d['status'],'report':str(path),'markers':len(markers),'package':n['package'],'candidate_sha256':c['rootfs_sha256']},indent=2))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Native-owned resolver bridge; explicit startup only, no listener or hook."""
import argparse,hashlib,io,json,os,shutil,stat,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
NAME='leon-asus-resolver';VERSION='0.3+asus3006.102.9';EPOCH=1791072000
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 if not __debug__:raise RuntimeError('Optimized Python disables required package checks')
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--native',type=Path,required=True);p.add_argument('--unit-validation',type=Path,required=True);a=p.parse_args()
 validation=json.loads(a.unit_validation.read_text())
 assert validation['schema']==1 and validation['status'] in ('passed','failed')
 for entry in validation['unit_files']:assert sha(R/entry['path'])==entry['sha256']
 assert sha(R/validation['log']['path'])==validation['log']['sha256']
 assert sha(R/validation['script']['path'])==validation['script']['sha256']
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-resolver'/('package-'+a.label);out.mkdir(parents=True,exist_ok=False);root=out/'root';root.mkdir()
 native=json.loads((a.native/'result.json').read_text());assert native['status']=='built'
 source=R/'scripts/asus-integration/resolver-export.c'
 assert next(x['sha256'] for x in native['inputs'] if x['path'].endswith('/resolver-export.c'))==sha(source)
 evidence=R/'evidence/ubuntu26/native-network/20261004-v1/capture.txt'
 assert sha(evidence)=='01909ed45fd657ef34db97a95abdb5dfdf223bf848c35958905ea0d29c7442ed'
 tests=R/'build/asus-resolver/test-v2/result.json';test=json.loads(tests.read_text());assert test['source_sha256']==sha(source)
 def copy(src,target,mode):
  dest=root/target;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest);dest.chmod(mode)
 copy(a.native/'resolver-export','usr/libexec/asus/resolver-export',0o755)
 copy(R/'configs/ubuntu26/asus-native-dns.be19000ai-verified.conf','etc/asus/native-dns.conf',0o600)
 for unit in sorted((R/'configs/ubuntu26/asus-resolver-units').iterdir()):copy(unit,'usr/lib/systemd/system/'+unit.name,0o644)
 for name,target in [('etc/resolv.conf','/run/asus/native-resolv.conf'),('usr/share/asus/integration/etc-seed/resolv.conf','/tmp/resolv.conf')]:
  path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.symlink_to(target)
 control=root/'DEBIAN';control.mkdir()
 (control/'control').write_text(f'''Package: {NAME}
Version: {VERSION}
Architecture: arm64
Section: admin
Priority: optional
Maintainer: BE19000AI local integration <local@invalid>
Depends: libc6 (>= 2.44), systemd (>= 259)
Description: Native-owned ASUS upstream resolver bridge
 Publishes only numeric nameservers allowed by a root-owned policy. The
 current verified LAN upstream is 192.168.100.1. No DNS listener, service
 enablement or maintainer script is installed. Native resolver bootstrap
 and updates require explicit unit activation from the ASUS target.
''')
 (control/'conffiles').write_text('/etc/asus/native-dns.conf\n')
 doc=root/'usr/share/doc'/NAME;doc.mkdir(parents=True)
 (doc/'README').write_text('''The previous candidate carried a copied 127.0.0.53 stub without a running
systemd-resolved daemon. This package deliberately replaces that unowned
/etc/resolv.conf with a native-owned link to /run/asus/native-resolv.conf.
Before explicit bootstrap this runtime link is dangling; inactive installation
does not establish working DNS. Offline apt tests require no external DNS.
Bootstrap publishes the read-only verified current CCR2216 upstream192.168.100.1.
The path unit reacts to ASUS /tmp/resolv.conf updates. ASUS owns its private
/etc/resolv.conf link to that source; it cannot overwrite native /etc through it.
The actual ASUS source is root-owned mode0666, so content is untrusted even
though the owner is root: only numeric addresses in /etc/asus/native-dns.conf
are accepted, no shell/options/search text. New upstreams require a reviewed
policy update. Empty disconnect updates retain the last policy-authorized
output; malformed/unapproved input fails without replacing it. Atomic rename
prevents native readers seeing truncation. No port53 listener or networkd is
started and dnsmasq continues to own its ASUS DNS role. Current LAN has no IPv6
address/route; IPv6 numeric parsing is fixture-tested, not live-network-proven.
Search domains and VPN split DNS are not mirrored by this numeric-only policy.
Successor0.2 opens input nonblocking so FIFO paths fail immediately at fstat,
instead of waiting for the systemd unit timeout. Regular-file parsing is unchanged.
No maintainer script, activation symlink or preset is included. DNS reachability
through actual br0/CCR2216 remains a hardware acceptance gate.
''')
 for path in [root,*root.rglob('*')]:
  if path.is_symlink():continue
  if path.is_dir():path.chmod(0o755)
  elif path.parent==control:path.chmod(0o644)
  else:path.chmod(stat.S_IMODE(path.stat().st_mode)&~0o022)
  os.utime(path,(EPOCH,EPOCH))
 outputs=[]
 for number in [1,2]:
  path=out/f'{NAME}_{VERSION}_arm64.build{number}.deb'
  subprocess.run(['dpkg-deb','--root-owner-group','-Zzstd','-z6','--build',str(root),str(path)],check=True,stdout=subprocess.DEVNULL,env={**os.environ,'SOURCE_DATE_EPOCH':str(EPOCH)});outputs.append(path)
 assert sha(outputs[0])==sha(outputs[1])
 final=out/f'{NAME}_{VERSION}_arm64.deb';shutil.copyfile(outputs[0],final)
 archive=[]
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(final)]))) as tar:
  for entry in tar.getmembers():
   assert entry.uid==entry.gid==0 and (entry.issym() or not entry.mode&0o022),entry.name
   name=entry.name.removeprefix('./');assert not name.startswith(('etc/systemd/system/','usr/lib/systemd/system-preset/'))
   row={'path':'/'+name,'mode':entry.mode,'type':'directory' if entry.isdir() else 'symlink' if entry.issym() else 'regular'}
   if entry.issym():row['target']=entry.linkname
   if entry.isfile():row['sha256']=hashlib.sha256(tar.extractfile(entry).read()).hexdigest()
   archive.append(row)
 report={'status':'reproducible_inactive_native_resolver_package','package':{'name':NAME,'version':VERSION,'architecture':'arm64','path':str(final.relative_to(R)),'sha256':sha(final)},
 'archive':archive,'two_builds_identical':True,'automatic_activation':False,'maintainer_scripts':False,'native_dns_working_claim':False,
 'authorized_base_replacement':{'path':'/etc/resolv.conf','before':'regular file copied systemd-resolved stub nameserver127.0.0.53 without daemon','after_type':'symlink','after_target':'/run/asus/native-resolv.conf','classification':'functional native DNS ownership change, not metadata-only'},
 'private_source_link':'/usr/share/asus/integration/etc-seed/resolv.conf -> /tmp/resolv.conf','initial_upstream':'192.168.100.1',
 'evidence':{'path':str(evidence.relative_to(R)),'sha256':sha(evidence)},'offline_tests':{'path':str(tests.relative_to(R)),'sha256':sha(tests),'cases':len(test['cases'])},
 'inputs':{'native_build_sha256':sha(a.native/'result.json'),'exporter_source_sha256':sha(source),'exporter_binary_sha256':sha(a.native/'resolver-export')},
 'inactive_state':'Runtime native resolv symlink remains dangling before explicit bootstrap; package installation alone does not provide network connectivity.',
 'actual_network_tested':False,'actual_asus_services_executed':False,'flash_allowed':False,'builder_sha256':sha(Path(__file__))}
 baseline_path=R/'build/asus-resolver/package-v3/manifest.json';baseline=json.loads(baseline_path.read_text())
 previous={x['path']:x for x in baseline['archive']};current={x['path']:x for x in archive}
 assert previous.keys()==current.keys()
 changes=[{'path':name,'before':previous[name],'after':current[name]} for name in previous if previous[name]!=current[name]]
 assert [x['path'] for x in changes]==['/usr/lib/systemd/system/leon-asus-resolver.path'],changes
 assert report['inputs']['exporter_binary_sha256']==baseline['inputs']['exporter_binary_sha256']
 report.update(previous_package_manifest={'path':str(baseline_path.relative_to(R)),'sha256':sha(baseline_path)},
  exact_payload_changes=changes,exporter_bytes_unchanged=True,
  unit_validation={'path':str(a.unit_validation.relative_to(R) if a.unit_validation.is_absolute() else a.unit_validation),'sha256':sha(a.unit_validation),'status':validation['status'],'returncode':validation['returncode']},
  unit_validation_passed=validation['status']=='passed',
  install_tested=False,device_update_allowed=False,
  successor_scope='0.3 fixes resolver.path ordering only. Package data differs solely in that unit; no service activation or device update is performed.')
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
 summary=R/'reports/ubuntu26/asus-native-resolver-ordering-package-v1.json'
 with summary.open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'package':str(final),'sha256':sha(final),'activation':False}))
if __name__=='__main__':main()

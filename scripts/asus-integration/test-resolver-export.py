#!/usr/bin/env python3
"""Strict DNS exporter tests on disposable ordinary files, with no DNS traffic."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-resolver'/('test-'+a.label);out.mkdir(parents=True,exist_ok=False)
 policy=out/'policy';source=out/'source';runtime=out/'runtime';runtime.mkdir(mode=0o755)
 binary=out/'resolver-export-fixture';src=R/'scripts/asus-integration/resolver-export.c'
 subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-DLEON_DNS_TEST_FIXTURE=1',
  '-DLEON_DNS_POLICY="'+str(policy)+'"','-DLEON_DNS_SOURCE="'+str(source)+'"','-DLEON_DNS_DIRECTORY="'+str(runtime)+'"',str(src),'-o',str(binary)],check=True)
 policy.write_text('ASUS_NATIVE_DNS_V1\nnameserver 192.168.100.1\nnameserver 2001:db8::53\n');policy.chmod(0o600)
 rows=[];output=runtime/'native-resolv.conf'
 def run(name,mode,expected,unchanged=False):
  before=sha(output) if output.exists() else None
  result=subprocess.run([str(binary),mode],capture_output=True,text=True,timeout=3)
  assert result.returncode==expected,(name,result)
  if unchanged:assert sha(output)==before,name
  rows.append({'case':name,'mode':mode,'exit':result.returncode,'stderr':result.stderr.strip(),'output_unchanged':unchanged})
 run('verified-bootstrap','--bootstrap',0)
 assert output.stat().st_mode&0o777==0o644
 source.write_text('nameserver 192.168.100.1\nnameserver 192.168.100.1\n');source.chmod(0o666)
 run('asus-world-writable-source-known-address-only','--update',0)
 assert output.read_text().count('nameserver')==1
 source.write_text('nameserver 2001:0db8:0000:0000:0000:0000:0000:0053 # equivalent\n')
 run('ipv6-canonical-allowlist','--update',0)
 assert '2001:db8::53' in output.read_text()
 for name,text,expected in [('empty-disconnect-retains-policy','',0),('unapproved-public-dns','nameserver 8.8.8.8\n',125),
  ('dead-stub-rejected','nameserver 127.0.0.53\n',125),('hostname-rejected','nameserver evil.invalid\n',125),
  ('options-not-imported','nameserver 192.168.100.1\noptions rotate\n',125),('shell-text-rejected','nameserver $(touch PWNED)\n',125),
  ('embedded-NUL','nameserver 192.168.100.1\0ignored\n',125),('oversized-source','#'+'x'*5000,125)]:
  source.write_text(text);run(name,'--update',expected,True)
 source.unlink();source.symlink_to(policy);run('source-symlink-rejected','--update',125,True);source.unlink()
 os.mkfifo(source,0o666);run('source-FIFO-immediately-rejected','--update',125,True);source.unlink()
 source.write_text('nameserver 192.168.100.1\n');os.link(source,out/'hardlink');run('source-hardlink-rejected','--update',125,True);(out/'hardlink').unlink()
 policy.chmod(0o666);run('policy-writable-rejected','--bootstrap',125,True);policy.chmod(0o600)
 target=out/'victim';target.write_text('untouched\n');output.unlink();output.symlink_to(target)
 run('output-symlink-rejected','--bootstrap',125,True);assert target.read_text()=='untouched\n'
 assert not (out/'PWNED').exists()
 report={'status':'strict_numeric_allowlist_atomic_export_tests_pass','source_sha256':sha(src),'binary_sha256':sha(binary),'cases':rows,
 'fixture_overrides':'Only test paths/expected UID/native PID1 namespace check are overridden. Production parse/metadata/publication logic is identical.',
 'network_traffic':False,'daemon_started':False,'actual_asus_services_executed':False,'checker_sha256':sha(Path(__file__))}
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'cases':len(rows),'output':str(out)}))
if __name__=='__main__':main()

#!/bin/bash
set -euo pipefail
exec python3 - <<'PY'
import pathlib,subprocess,json,os,socket,stat,hashlib
P=pathlib.Path
target='GT-BE19000AI-6B50'
old='be19000ai-bcm'
boot=P('/proc/sys/kernel/random/boot_id').read_text().strip()
assert boot=='00000000-0000-4000-8000-000000000025', 'Boot changed; re-evaluate before apply'
assert socket.gethostname()==old, 'Hostname changed; do not overwrite concurrent work'
assert P('/etc/hostname').read_bytes()==(old+'\n').encode()
hosts=P('/etc/hosts').read_bytes()
assert b'127.0.1.1 GT-BE19000AI-6B50 be19000ai-bcm\n' in hosts
assert not P('/etc/hostname').is_symlink()
backup=P('/var/backups/leon-hostname-20261010-v1')
backup.mkdir(mode=0o700,exist_ok=False)
for name in ['hostname','hosts','machine-info']:
 p=P('/etc')/name
 if p.exists():
  dest=backup/name
  fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as f:f.write(p.read_bytes());f.flush();os.fsync(f.fileno())
out={'before':old,'desired':target,'backup':str(backup),'boot_id':boot}
try:
 p=subprocess.run(['hostnamectl','--static','--transient','set-hostname',target],capture_output=True,timeout=15)
 assert p.returncode==0,p.stderr.decode()
 assert P('/etc/hostname').read_text().strip()==target, 'Persistent name differs'
 assert socket.gethostname()==target, 'Runtime name differs'
 assert P('/etc/hosts').read_bytes()==hosts, 'Hosts changed unexpectedly'
 assert P('/proc/sys/kernel/random/boot_id').read_text().strip()==boot
 out['after']=socket.gethostname()
 out['persistent']=P('/etc/hostname').read_text().strip()
 out['hosts_preserved']=True
 out['network_or_container_restart']=False
 out['result']='PASS'
except Exception:
 # Restore the exact prior file and runtime name if this narrow apply fails.
 subprocess.run(['hostnamectl','--static','--transient','set-hostname',old],capture_output=True,timeout=15)
 raise
# Read only selected ASUS identity fields. Never dump all NVRAM.
out['asus_identity']={}
for k in ['lan_hostname','computer_name','productid']:
 try:
  p=subprocess.run(['/usr/bin/asus','nvram','get',k],capture_output=True,timeout=5)
  out['asus_identity'][k]={'rc':p.returncode,'value':p.stdout.decode(errors='replace').strip()[:128]}
 except subprocess.TimeoutExpired:out['asus_identity'][k]={'timeout':True}
# Targeted, bounded substitute for rg, which is absent on this router.
matches=[]
for root in ['/etc/profile.d','/etc/systemd/system','/usr/local/sbin']:
 for p in P(root).rglob('*'):
  if p.is_symlink() or not p.is_file():continue
  if p.stat().st_size>131072:continue
  try:lines=p.read_text().splitlines()
  except (UnicodeError,OSError):continue
  for n,line in enumerate(lines,1):
   if any(s in line for s in ['hostnamectl','/etc/hostname','sethostname']):
    matches.append({'path':str(p),'line':n,'text':line[:300]})
    if len(matches)>=40:break
  if len(matches)>=40:break
 if len(matches)>=40:break
out['hostname_rules']=matches
print(json.dumps(out,indent=2))
PY

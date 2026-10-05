#!/usr/bin/env python3
"""Fixed sequential stock2-to-p11 overlay using existing enrolled key on .51.

Default prints the concrete deployment plan only. --execute transfers and
runs the three separately guarded, pinned installers; it never selects a
slot, flashes firmware, reboots, commits or exports a private key.
"""
import argparse
import hashlib
import importlib.util
import json
import shlex
import subprocess
from pathlib import Path

R=Path(__file__).resolve().parents[1]
BOOT='00000000-0000-4000-8000-000000000014'
METADATA='f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
ROWS=[
 ('build/asus-ssh-recovery/install-v1/install-recovery','d9cc63fb12062add7a135b2d212058e1f3645efcab5b57651b2e55204723848e','--install-native-recovery'),
 ('build/ubuntu26-cfe-defaults-update/native-v2/rc/updater','5060c0c910d262f30a1f587361c8aa158115cb5dc4a8707ea03382545a333c35','--update-fixed-asus-helper'),
 ('build/ubuntu26-cfe-defaults-update/native-v2/etc-launch/updater','255139340d39ff2a885ad524d6399e9f37cb143ee847abd25d25a1a9cb9fcb46','--update-fixed-asus-helper'),
]
PINS={
 'reports/ubuntu26/openssh-recovery-installer-sealed-v1.json':'72a0abb4943559678427d458d4c66623d1bf4ca4e90f2d9cc668aa20e57d9174',
 'build/ubuntu26-cfe-defaults-update/native-v2/manifest.json':'b80b1958d8e6b415a633034d92239cf2540d189704970b22aa63b9a109e326b3',
 'reports/ubuntu26/cfe-defaults-updaters-source-binding-native-v2.json':'3452512ab073c5f52c369c1181d9823546aaf4b6462b9c47dd5972db8f29d71e',
 'build/asus-trial-runtime/native-v27-openssh-recovery/guardian-receipt.json':'60d009ea9c0a2a5b0b376ad620bdb499593ca99bffaabc48f3c0b6272b1847b3',
}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def transport(command):
 hop=shlex.join(['dbclient','-T','-i','/root/.ssh/netpanel','-o','BatchMode=yes','-o','PasswordAuthentication=no','-o','StrictHostKeyChecking=yes','MastermixStudios@192.168.100.15',command])
 return ['/usr/bin/ssh','-T','-b','192.168.100.35','-o','BatchMode=yes','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=6','-o','ServerAliveInterval=5','root@192.168.100.51','exec '+hop]
def plan():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 for name,digest in PINS.items():
  path=R/name;assert path.is_file() and not path.is_symlink() and sha(path)==digest,name
 spec=importlib.util.spec_from_file_location('sealed_recovery_installer',R/'scripts/seal-openssh-recovery-installer.py')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.verify()
 result=[]
 for name,digest,flag in ROWS:
  p=R/name;assert p.is_file() and not p.is_symlink() and sha(p)==digest
  result.append({'local':name,'sha256':digest,'bytes':p.stat().st_size,'target_temporary':'/tmp/leon-p11-'+digest[:16],
                 'command_flag':flag,'boot_uuid':BOOT,'metadata_sha256':METADATA})
 return {'schema':1,'status':'protected_deployment_plan','order':result,
         'transport':'Existing .51 netpanel private key stays on .51; both pinned SSH hops use no password.',
         'roots':'Current stock2 squashfs p6; only enrolled Ubuntu p11 privately mounted by each guarded executable.',
         'future_native_account_uid':1000,'rebooted':False,'boot_metadata_written':False,'firmware_flashing':False,'git_commit_or_push':False,
         'limits':['No multi-file atomicity; stop on any installer failure and retain its output for review.',
                   'Guard rejects if exact original stock2 boot UUID or metadata/device/filesystem prerequisites changed.',
                   'After successful native boot, install staged recovery .deb with native apt/dpkg; account, password and host keys remain unchanged.']}
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true');args=parser.parse_args()
 data=plan()
 if not args.execute:
  print(json.dumps(data,indent=2));return
 out=R/'evidence/ubuntu26/device-cfe-recovery-live/install-v1';out.mkdir(parents=True,exist_ok=False)
 for row in data['order']:
  local=R/row['local'];remote=row['target_temporary'];digest=row['sha256']
  # Exclusive temporary transfer, then full hash before executable mode. The
  # guarded native entrypoint rechecks all hardware facts independently.
  command='set -eu; umask 077; test ! -e '+shlex.quote(remote)+'; test ! -L '+shlex.quote(remote)+'; set -C; cat > '+shlex.quote(remote)+'; set +C; set -- $(sha256sum '+shlex.quote(remote)+'); test "$1" = '+shlex.quote(digest)+'; chmod 700 '+shlex.quote(remote)
  label=Path(row['local']).parent.name+'-'+Path(row['local']).name
  with local.open('rb') as stream:
   upload=subprocess.run(transport(command),stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
  (out/(label+'-transfer.stdout')).write_bytes(upload.stdout);(out/(label+'-transfer.stderr')).write_bytes(upload.stderr)
  if upload.returncode:raise RuntimeError('Transfer refused or incomplete: '+label+'; inspect retained evidence, do not rerun blindly')
  call=shlex.join([remote,row['command_flag'],METADATA,BOOT])
  apply=subprocess.run(transport('exec '+call),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=330)
  (out/(label+'-apply.stdout')).write_bytes(apply.stdout);(out/(label+'-apply.stderr')).write_bytes(apply.stderr)
  print(json.dumps({'step':row['local'],'returncode':apply.returncode,'stdout':apply.stdout.decode(errors='replace'),'stderr':apply.stderr.decode(errors='replace')}),flush=True)
  if apply.returncode:raise RuntimeError('Protected installer refused: '+label+'; no next step executed')
  row['applied']=True
 data['status']='three_guarded_overlays_installed_physical_boot_pending'
 (out/'result.json').write_text(json.dumps(data,indent=2)+'\n')
 print(json.dumps({'status':data['status'],'evidence':str(out.relative_to(R))}))
if __name__=='__main__':main()

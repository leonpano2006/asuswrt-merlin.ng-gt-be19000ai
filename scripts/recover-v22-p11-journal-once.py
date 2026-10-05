#!/usr/bin/env python3
"""Recover journal once only when the new authenticated stock2 p11 needs it."""
import argparse,ast,hashlib,json,shlex,struct,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
M='f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
S=R/'evidence/ubuntu26/trial-live/twentysecond-stock2-return-v1/stock-result.json'
H=R/'build/ubuntu26-diagnostic-recovery/native-v1/recover-p11'
HS='c735fcfd50085974aa97761f1cec2726b97d3e8d32d3aa0efe2144cbd9701596'
T=R/'scripts/deploy-cfe-recovery-p11.py'
def sha(p):assert p.is_file() and not p.is_symlink();return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--stock-sha256',required=True);p.add_argument('--expected-boot',required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
 assert __debug__ and sha(S)==a.stock_sha256
 d=json.loads(S.read_text());assert d['status']=='authenticated_new_stock2_return' and d['boot_id']==a.expected_boot and d['metadata_sha256']==M and d['reset_reason']=='34'
 assert sha(H)==HS and sha(T)=='db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7'
 O=R/'evidence/ubuntu26/trial-live/twentysecond-p11-journal-recovery-v1'
 if not a.execute:print(json.dumps({'status':'source_plan_only','boot':a.expected_boot,'stock_sha256':a.stock_sha256,'one_preen_only_if_dirty':True,'no_export_no_selection_no_reboot':True}));return
 O.mkdir(parents=True,mode=0o700,exist_ok=False)
 nodes=[n for n in ast.parse(T.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='transport'];assert len(nodes)==1
 ns={'__builtins__':{},'shlex':shlex};exec(compile(ast.Module(body=nodes,type_ignores=[]),str(T)+':transport-only','exec'),ns)
 guard='set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = '+shlex.quote(a.expected_boot)+'; '
 def call(label,cmd,data=None,limit=30):
  r=subprocess.run(ns['transport'](guard+cmd),input=data,stdin=subprocess.DEVNULL if data is None else None,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=limit)
  (O/(label+'.stdout')).write_bytes(r.stdout);(O/(label+'.stderr')).write_bytes(r.stderr);assert r.returncode==0,(label,r.returncode);return r.stdout
 record={'boot_id':a.expected_boot,'stock_receipt_sha256':a.stock_sha256,'preen_count':0,'no_export':True,'boot_selected':False,'rebooted':False,'source_sha256':sha(Path(__file__))}
 try:
  sb=call('superblock-before','test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; exec /bin/busybox dd if=/dev/mmcblk0p11 bs=1024 skip=1 count=1')
  assert len(sb)==1024 and sb[56:58]==b'\x53\xef' and sb[104:120].hex()=='ea8e47b8c606406cb931d2244d26ec55'
  state=struct.unpack_from('<H',sb,58)[0];errors=struct.unpack_from('<I',sb,404)[0];needs=bool(struct.unpack_from('<I',sb,96)[0]&4);orphan=struct.unpack_from('<I',sb,232)[0]
  record['superblock_before']={'state':state,'error_count':errors,'needs_recovery':needs,'last_orphan':orphan};assert errors==0
  if state!=1 or needs or orphan:
   remote='/tmp/leon-v22-journal-'+HS[:16]
   call('helper-transfer','umask 077; test ! -e '+remote+'; test ! -L '+remote+'; set -C; cat > '+remote+'; set +C; test "$(sha256sum '+remote+' | cut -d " " -f 1)" = '+HS+'; chmod 700 '+remote,H.read_bytes(),180)
   record['preen_count']=1
   response=json.loads(call('recover','exec '+shlex.join([remote,'--recover-p11',M,a.expected_boot]),limit=330))
   assert response['status']=='p11_preen_completed_and_frozen_clean_gates_passed' and response['boot_id']==a.expected_boot and response['metadata_sha256']==M and response['child_starts']==1 and response['retries']==0
   record['recovery']=response
  record['status']='clean_p11_ready_no_export'
 except Exception as e:record['status']='refused_evidence_retained_no_retry';record['error_type']=type(e).__name__;raise
 finally:(O/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)
if __name__=='__main__':main()

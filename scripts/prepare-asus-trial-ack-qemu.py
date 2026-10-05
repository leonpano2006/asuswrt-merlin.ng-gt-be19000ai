#!/usr/bin/env python3
"""Extend the already validated no-NIC SSH fixture with real session ACK proof."""
import argparse,gzip,hashlib,json,stat
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def parse(data):
 rows=[];pos=0
 while pos<len(data):
  assert data[pos:pos+6]==b'070701';fields=[int(data[pos+6+i*8:pos+14+i*8],16) for i in range(13)];name=data[pos+110:pos+110+fields[11]-1].decode();pos=(pos+110+fields[11]+3)&~3;payload=data[pos:pos+fields[6]];pos=(pos+fields[6]+3)&~3;rows.append([name,fields,payload])
  if name=='TRAILER!!!':break
 return rows
PROOF=r'''
stage=trial-ack-start
A=/usr/libexec/leon-asus/trial-ack
H2=/usr/libexec/leon-asus/trial-health
/usr/libexec/leon-lab/trial-server-fixture > "$R/trial-server.log" 2>&1 &
trial_server=$!
for n in $(seq 1 50); do test -S /run/leon-trial/control && break; sleep .1; done
test -S /run/leon-trial/control
trap 'rc=$?; echo LAB_TRIAL_ACK_EXIT_code=$rc stage=$stage; cat "$R/trial-server.log"; if test "$rc" != 0; then ps -ef; fi' EXIT
# Root/direct admin invocations lack an authenticated sshd-session ancestry.
if "$A" --challenge > "$R/root-ack.json" 2>/dev/null; then exit 1; fi
if runuser -u MastermixStudios -- "$A" --challenge > "$R/local-ack.json" 2>/dev/null; then exit 1; fi
# A fake marker or a live socket does not prove physical watchdog ownership.
if "$H2" --assert-armed; then exit 1; fi
echo LAB_TRIAL_ACK_LOCAL_AND_UNARMED_REJECT_PASS
stage=trial-ack-fresh-session
key_ssh 127.0.0.1 "$A --challenge" > "$R/challenge.json"
sed 's/,"expires_in_ms":20000//' "$R/challenge.json" > "$R/ack.json"
key_ssh 127.0.0.1 "$A --ack" < "$R/ack.json" > "$R/accepted.json"
grep -q '"accepted":true' "$R/accepted.json"
if key_ssh 127.0.0.1 "$A --ack" < "$R/ack.json" > "$R/replay.json" 2>/dev/null; then exit 1; fi
echo LAB_TRIAL_ACK_REAL_IPV4_SESSION_AND_REPLAY_PASS
stage=trial-ack-ipv6
key_ssh ::1 "$A --challenge" > "$R/challenge6.json"
sed 's/,"expires_in_ms":20000//' "$R/challenge6.json" > "$R/ack6.json"
key_ssh ::1 "$A --ack" < "$R/ack6.json" > "$R/accepted6.json"
grep -q '"accepted":true' "$R/accepted6.json"
echo LAB_TRIAL_ACK_REAL_IPV6_SESSION_PASS
stage=trial-ack-same-session
if key_ssh 127.0.0.1 "$A --challenge | sed 's/,\"expires_in_ms\":20000//' | $A --ack" > "$R/same.json" 2>/dev/null; then exit 1; fi
echo LAB_TRIAL_ACK_SAME_TCP_REJECT_PASS
stage=trial-ack-endpoint-change
key_ssh 127.0.0.1 "$A --challenge" > "$R/challenge-other.json"
sed 's/,"expires_in_ms":20000//' "$R/challenge-other.json" > "$R/other.json"
if key_ssh ::1 "$A --ack" < "$R/other.json" > "$R/other-result.json" 2>/dev/null; then exit 1; fi
echo LAB_TRIAL_ACK_ENDPOINT_CHANGE_REJECT_PASS
stage=trial-ack-expired
key_ssh 127.0.0.1 "$A --challenge" > "$R/challenge-old.json"
sed 's/,"expires_in_ms":20000//' "$R/challenge-old.json" > "$R/old.json"
sleep 21
if key_ssh 127.0.0.1 "$A --ack" < "$R/old.json" > "$R/old-result.json" 2>/dev/null; then exit 1; fi
echo LAB_TRIAL_ACK_EXPIRED_CHALLENGE_REJECT_PASS
kill "$trial_server"
wait "$trial_server" || :
cat "$R/trial-server.log"
echo LAB_TRIAL_ACK_KERNEL10_COMPLETE
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--native',required=True,type=Path);a=p.parse_args();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 w=R/'build/asus-trial-runtime'/a.label;w.mkdir(parents=True,exist_ok=False);base=R/'build/asus-ssh-integration/qemu-v5/initramfs.cpio.gz';rows=parse(gzip.decompress(base.read_bytes()));byname={r[0]:r for r in rows}
 target=byname['usr/libexec/leon-lab/openssh-proof'];needle=b'echo LAB_SSH_CONTROL_KEY_LOGIN_AND_REJECT_PASS';assert target[2].count(needle)==1;target[2]=target[2].split(needle)[0]+needle+PROOF.encode()+b'\necho LAB_SSH_CONTROL_KERNEL10_COMPLETE\n'
 unit=byname['etc/systemd/system/leon-full-boot.service'];unit[2]=unit[2].replace(b'TimeoutStartSec=130',b'TimeoutStartSec=160')
 ino=max(row[1][0] for row in rows)+1
 for name,file in [('usr/libexec/leon-asus/trial-ack','trial-ack'),('usr/libexec/leon-asus/trial-health','trial-health'),('usr/libexec/leon-lab/trial-server-fixture','trial-server-fixture')]:
  assert name not in byname;payload=(a.native/file).read_bytes();fields=[ino,stat.S_IFREG|0o755,0,0,1,0,len(payload),0,0,0,0,len(name)+1,0];ino+=1;rows.insert(-1,[name,fields,payload])
 out=bytearray()
 for name,fields,payload in rows:
  n=name.encode()+b'\0';fields[6]=len(payload);fields[11]=len(n);out+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;out+=b'\0'*(-len(out)%4);out+=payload;out+=b'\0'*(-len(out)%4)
 artifact=w/'initramfs.cpio.gz';artifact.write_bytes(gzip.compress(out,compresslevel=1,mtime=0));(w/'proof.sh').write_text(PROOF)
 report={'status':'prepared_no_nic_fixture','base':str(base.relative_to(R)),'base_sha256':sha(base),'native_manifest':str(a.native/'manifest.json'),'native_manifest_sha256':sha(a.native/'manifest.json'),'initramfs_sha256':sha(artifact),'expected_markers':[x.split('echo ',1)[1] for x in PROOF.splitlines() if x.startswith('echo LAB_')],'fixture_only':True,'real_hardware_armed':False,'production_services_changed':False,'builder_sha256':sha(Path(__file__))};(w/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(str(artifact))
if __name__=='__main__':main()

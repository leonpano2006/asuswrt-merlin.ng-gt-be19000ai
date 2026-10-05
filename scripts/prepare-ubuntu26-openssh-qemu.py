#!/usr/bin/env python3
"""Build an offline kernel10 OpenSSH/systemd fixture; no NIC or host forwarding."""
import argparse,gzip,hashlib,json,stat,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
PROOF=r'''#!/bin/sh
set -eu
B=/usr/libexec/leon-lab/busybox
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
stage=network-guard
trap 'rc=$?; echo LAB_OPENSSH_EXIT_code=$rc stage=$stage; if test "$rc" != 0; then systemctl status ssh.service ssh.socket --no-pager || :; journalctl -u ssh.service --no-pager -n 35 || :; fi' EXIT
# This BCM kernel creates tunnel/IFB virtual interfaces even with no QEMU NIC.
# Reject any hardware interface or globally addressed/default-routed network.
for link in /sys/class/net/*; do test ! -e "$link/device"; done
test -z "$(ip -o address show scope global)"
test -z "$(ip route show default)"
ip link set lo up
stage=test-identity
mkdir -p /run/leon-ssh
chmod 700 /run/leon-ssh
test ! -e /home/sshlab
useradd -m -u 1000 -s /bin/sh -p '*' sshlab
mkdir -p /home/sshlab/.ssh
chmod 700 /home/sshlab/.ssh
ssh-keygen -q -t ed25519 -N '' -f /run/leon-ssh/identity
ssh-keygen -q -t ed25519 -N '' -f /run/leon-ssh/denied
cp /run/leon-ssh/identity.pub /home/sshlab/.ssh/authorized_keys
chmod 600 /home/sshlab/.ssh/authorized_keys
chown -R sshlab:sshlab /home/sshlab/.ssh
mkdir -p /run/sshd
sshd -t
stage=effective-config
sshd -T > /run/leon-ssh/effective
for expected in 'port 2222' 'listenaddress 127.0.0.1:2222' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'permitemptypasswords no' 'authenticationmethods publickey' 'usepam yes'; do
 grep -qx "$expected" /run/leon-ssh/effective
done
echo LAB_OPENSSH_EFFECTIVE_CONFIG_PASS
stage=service-start
if dpkg-query -W -f='STATUS_FIELD' dropbear 2>/dev/null | grep -q installed; then exit 1; fi
if $B pidof dropbear; then exit 1; fi
systemctl stop ssh.socket
systemctl start ssh.service
systemctl is-active --quiet ssh.service
if systemctl is-active --quiet ssh.socket; then exit 1; fi
ss -H -ltnp > /run/leon-ssh/listeners
cat /run/leon-ssh/listeners
test "$(wc -l < /run/leon-ssh/listeners)" -eq 1
grep -q '127.0.0.1:2222' /run/leon-ssh/listeners
awk '{print "[127.0.0.1]:2222 "$1" "$2}' /etc/ssh/ssh_host_ed25519_key.pub > /run/leon-ssh/known_hosts
ssh_lab() {
 timeout -s KILL 20 ssh -F /dev/null -p 2222 -i /run/leon-ssh/identity -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/leon-ssh/known_hosts -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=5 sshlab@127.0.0.1 "$@"
}
test "$(ssh_lab 'id -u')" = 1000
echo LAB_OPENSSH_LOOPBACK_KEY_AUTH_PASS
stage=negative-key
if timeout -s KILL 10 ssh -F /dev/null -p 2222 -i /run/leon-ssh/denied -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/leon-ssh/known_hosts -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=5 sshlab@127.0.0.1 true >/run/leon-ssh/denied.log 2>&1; then exit 1; fi
grep -q 'Permission denied (publickey)' /run/leon-ssh/denied.log
echo LAB_OPENSSH_UNAUTHORIZED_KEY_REJECTED
stage=sftp
printf 'guest-only-sftp-roundtrip\n' > /run/leon-ssh/upload
printf 'put /run/leon-ssh/upload upload\nget upload /run/leon-ssh/download\nrm upload\n' > /run/leon-ssh/batch
timeout -s KILL 20 sftp -F /dev/null -P 2222 -i /run/leon-ssh/identity -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/leon-ssh/known_hosts -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -b /run/leon-ssh/batch sshlab@127.0.0.1
cmp /run/leon-ssh/upload /run/leon-ssh/download
echo LAB_OPENSSH_SFTP_PASS
stage=service-restart
before=$(systemctl show ssh.service -p MainPID --value)
test "$before" -gt 1
systemctl restart ssh.service
after=$(systemctl show ssh.service -p MainPID --value)
test "$after" -gt 1
test "$before" != "$after"
test "$(ssh_lab 'printf SSH_RESTART_OK')" = SSH_RESTART_OK
echo LAB_OPENSSH_SYSTEMD_RESTART_PASS
stage=service-stop
systemctl stop ssh.service
if systemctl is-active --quiet ssh.service; then exit 1; fi
ss -H -ltn > /run/leon-ssh/listeners-after-stop
test ! -s /run/leon-ssh/listeners-after-stop
echo LAB_OPENSSH_SYSTEMD_STOP_PASS
dpkg --audit > /run/leon-ssh/dpkg-audit
test ! -s /run/leon-ssh/dpkg-audit
echo LAB_OPENSSH_KERNEL10_COMPLETE
'''
PROOF=PROOF.replace('STATUS_FIELD','${db:Status-Status}')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def parse(data):
 rows=[];pos=0
 while pos<len(data):
  assert data[pos:pos+6]==b'070701'
  fields=[int(data[pos+6+i*8:pos+14+i*8],16) for i in range(13)]
  name=data[pos+110:pos+110+fields[11]-1].decode()
  pos=(pos+110+fields[11]+3)&~3;payload=data[pos:pos+fields[6]];pos=(pos+fields[6]+3)&~3
  rows.append([name,fields,payload])
  if name=='TRAILER!!!':break
 return rows
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rootfs',required=True,type=Path);p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 w=R/'build/ubuntu26-openssh'/a.label;assert not w.exists();w.mkdir(parents=True)
 base_label='openssh-base-'+a.label
 subprocess.run(['python3',str(R/'scripts/prepare-ubuntu26-qemu.py'),'--rootfs',str(a.rootfs),'--mode','systemd','--systemd-full-boot','--output-label',base_label],check=True)
 base=R/'build/ubuntu26-rootfs'/('ubuntu26-'+base_label+'.cpio.gz')
 rows=parse(gzip.decompress(base.read_bytes()));byname={row[0]:row for row in rows}
 name='usr/libexec/leon-lab/full-boot-proof';old=byname[name][2];assert old.count(b'echo passed > /run/leon-full-boot-ok')==1
 byname[name][2]=old.replace(b'echo passed > /run/leon-full-boot-ok',b'/usr/libexec/leon-lab/openssh-proof\necho passed > /run/leon-full-boot-ok')
 ino=max(row[1][0] for row in rows)+1
 def add(n,data,mode):
  nonlocal ino
  assert n not in byname;fields=[ino,stat.S_IFREG|mode,0,0,1,0,len(data),0,0,0,0,len(n.encode())+1,0];ino+=1;rows.insert(-1,[n,fields,data])
 add('usr/libexec/leon-lab/openssh-proof',PROOF.encode(),0o755)
 add('etc/ssh/sshd_config.d/00-00-loopback-lab.conf',b'Port 2222\nListenAddress 127.0.0.1\nAddressFamily inet\nUseDNS no\nLogLevel VERBOSE\n',0o644)
 out=bytearray()
 for name,fields,data in rows:
  n=name.encode()+b'\0';fields[6]=len(data);fields[11]=len(n)
  out+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
 path=w/'initramfs.cpio.gz';path.write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
 (w/'openssh-proof.sh').write_text(PROOF)
 report={'rootfs':str(a.rootfs),'rootfs_sha256':sha(a.rootfs),'base_fixture':str(base.relative_to(R)),'base_fixture_sha256':sha(base),'initramfs':str(path.relative_to(R)),'initramfs_sha256':sha(path),'proof_sha256':sha(w/'openssh-proof.sh'),'scope':'No-NIC QEMU fixture, guest loopback only. Runtime-generated disposable nonroot account and keys never enter candidate tar.','guest_loopback_port':2222,'production_login_identity_changed':False,'generic_builder_modified':False,'expected_markers':['LAB_OPENSSH_EFFECTIVE_CONFIG_PASS','LAB_OPENSSH_LOOPBACK_KEY_AUTH_PASS','LAB_OPENSSH_UNAUTHORIZED_KEY_REJECTED','LAB_OPENSSH_SFTP_PASS','LAB_OPENSSH_SYSTEMD_RESTART_PASS','LAB_OPENSSH_SYSTEMD_STOP_PASS','LAB_OPENSSH_KERNEL10_COMPLETE','QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE'],'builder_sha256':sha(Path(__file__))}
 (w/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()

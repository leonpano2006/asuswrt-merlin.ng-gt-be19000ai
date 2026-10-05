#!/usr/bin/env python3
"""Build an offline kernel10 OpenSSH/systemd fixture; no NIC or host forwarding."""
import argparse,gzip,hashlib,json,stat,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
PROOF=(R/'scripts/asus-integration/openssh/proof.sh').read_text()
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
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rootfs',required=True,type=Path);p.add_argument('--label',required=True);p.add_argument('--native',required=True,type=Path);p.add_argument('--clients',required=True,type=Path);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 w=R/'build/asus-ssh-integration'/a.label;assert not w.exists();w.mkdir(parents=True)
 base_label='ssh-control-base-'+a.label
 subprocess.run(['python3',str(R/'scripts/prepare-ubuntu26-qemu.py'),'--rootfs',str(a.rootfs),'--mode','systemd','--systemd-full-boot','--output-label',base_label],check=True)
 base=R/'build/ubuntu26-rootfs'/('ubuntu26-'+base_label+'.cpio.gz')
 rows=parse(gzip.decompress(base.read_bytes()));byname={row[0]:row for row in rows}
 name='usr/libexec/leon-lab/full-boot-proof';old=byname[name][2];assert old.count(b'echo passed > /run/leon-full-boot-ok')==1
 byname[name][2]=old.replace(b'echo passed > /run/leon-full-boot-ok',b'/usr/libexec/leon-lab/openssh-proof\necho passed > /run/leon-full-boot-ok')
 ino=max(row[1][0] for row in rows)+1
 def add(n,data,mode):
  nonlocal ino
  assert n not in byname;fields=[ino,(stat.S_IFDIR|0o755) if mode is None else (stat.S_IFREG|mode),0,0,1,0,len(data),0,0,0,0,len(n.encode())+1,0];ino+=1;row=[n,fields,data];rows.insert(-1,row);byname[n]=row
 # Linux initramfs root retains its default mode unless '.' is explicitly
 # archived. Preserve the input tar's real root metadata for StrictModes.
 with tarfile.open(a.rootfs) as tar:root_meta=tar.getmember('.')
 assert root_meta.isdir() and root_meta.uid==0 and root_meta.gid==0 and root_meta.mode==0o755
 if '.' not in byname:add('.',b'',None)
 byname['.'][1][1]=stat.S_IFDIR|root_meta.mode;byname['.'][1][2:4]=[root_meta.uid,root_meta.gid]
 byname['etc/systemd/system/leon-full-boot.service'][2]=byname['etc/systemd/system/leon-full-boot.service'][2].replace(b'TimeoutStartSec=90',b'TimeoutStartSec=160')
 add('usr/libexec/leon-lab/openssh-proof',PROOF.encode(),0o755)
 add('usr/libexec/leon-lab/ssh-control',b'',None)
 add('usr/libexec/leon-lab/ssh-control/request',(a.clients/'request-arm64').read_bytes(),0o755)
 add('usr/libexec/leon-lab/ssh-control/request-armel',(a.clients/'request-armel').read_bytes(),0o755)
 add('usr/libexec/leon-lab/ssh-control/fixture-control',(a.native/'fixture-control').read_bytes(),0o755)
 unit='usr/lib/systemd/system/leon-asus-ssh@.service';assert unit in byname
 byname[unit][2]=byname[unit][2].replace(b'/usr/libexec/leon-asus/ssh-control --request',b'/usr/libexec/leon-lab/ssh-control/fixture-control --request')
 # The installed production helper remains byte-identical and is used for
 # device identity provisioning; only the control peer/LAN seam uses lo.

 out=bytearray()
 for name,fields,data in rows:
  n=name.encode()+b'\0';fields[6]=len(data);fields[11]=len(n)
  out+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
 path=w/'initramfs.cpio.gz';path.write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
 (w/'openssh-proof.sh').write_text(PROOF)
 report={'rootfs':str(a.rootfs),'rootfs_sha256':sha(a.rootfs),'base_fixture':str(base.relative_to(R)),'base_fixture_sha256':sha(base),'initramfs':str(path.relative_to(R)),'initramfs_sha256':sha(path),'proof_sha256':sha(w/'openssh-proof.sh'),'scope':'No-NIC QEMU fixture, guest loopback only. Runtime-generated disposable nonroot account and keys never enter candidate tar.','guest_loopback_port':2222,'root_directory_metadata_preserved':{'uid':root_meta.uid,'gid':root_meta.gid,'mode':oct(root_meta.mode)},'fixture_service_timeout_seconds':160,'production_login_identity_changed':False,'generic_builder_modified':False,'expected_markers':[line.split('echo ',1)[1] for line in PROOF.splitlines() if line.startswith('echo LAB_')]+['QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE'],'client_manifest_sha256':sha(a.clients/'manifest.json'),'native_manifest_sha256':sha(a.native/'manifest.json'),'builder_sha256':sha(Path(__file__))}
 (w/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()

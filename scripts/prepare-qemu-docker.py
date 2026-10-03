#!/usr/bin/env python3
"""Build an offline RAM-only Docker guest using this candidate's modules."""
from pathlib import Path
import stat,gzip,json,hashlib,argparse
r=Path(__file__).resolve().parents[1];b=r/'build';p=argparse.ArgumentParser();p.add_argument('--version',type=int,default=5);a=p.parse_args();root=b/f'candidate-rootfs-v{a.version}'
entries={d:(stat.S_IFDIR|0o755,b'',0,0) for d in ['bin','proc','sys','dev','tmp','mnt','modules','docker','etc','var','firmware']}
files={'bin/busybox':b/'busybox','load_one':b/'load_one','btrfs.img':b/'blank-btrfs.img','image.tar':b/'image.tar','rootfs.img':b/'rootfs.zstd.squashfs'}
for n in ['docker','dockerd','containerd','containerd-shim-runc-v2','runc','docker-init']:files['docker/'+n]=b/'docker-tools'/n
zsmalloc_builtin=not list((root/'lib/modules').rglob('zsmalloc.ko'))
for n in ['tfat','tntfs','thfsplus','raid6_pq','xor','btrfs','exportfs','overlay','zsmalloc']:
 if n=='zsmalloc' and zsmalloc_builtin:continue
 ps=list((root/'lib/modules').rglob(n+'.ko'));assert len(ps)==1,(n,ps);files['modules/'+n+'.ko']=ps[0]
for n,p in files.items():entries[n]=(stat.S_IFREG|0o755,p.read_bytes(),0,0)
init=(r/'scripts/docker-guest-init.sh').read_text()
needle='mkdir -p /dev/pts /dev/shm /var/run /sys/fs/cgroup'
init=init.replace(needle,'''test -b /dev/loop7 || mknod /dev/loop7 b 7 7
losetup /dev/loop7 /rootfs.img || exit 1
mount -t squashfs -o ro /dev/loop7 /firmware || exit 1
(cd /firmware && sha256sum -c /userspace.sha256 > /tmp/userspace-check.log) || exit 1
echo LAB_ROOTFS_PASS zstd_mount_and_all_userspace_hashes
umount /firmware || exit 1
losetup -d /dev/loop7 || exit 1
rm /rootfs.img || exit 1
/load_one zsmalloc /modules/zsmalloc.ko || exit 1
echo zsmalloc > /sys/module/zswap/parameters/zpool || exit 1
echo Y > /sys/module/zswap/parameters/enabled || exit 1
'''+needle)
if zsmalloc_builtin:
 init=init.replace('/load_one zsmalloc /modules/zsmalloc.ko || exit 1',"dmesg | grep -q 'zswap: loaded using pool zstd/zsmalloc' || exit 1\necho LAB_ZSWAP_BOOT_POOL_PASS")
 init=init.replace('echo zsmalloc > /sys/module/zswap/parameters/zpool || exit 1','test \"$(cat /sys/module/zswap/parameters/zpool)\" = zsmalloc || exit 1')
 init=init.replace('echo Y > /sys/module/zswap/parameters/enabled || exit 1','test \"$(cat /sys/module/zswap/parameters/enabled)\" = Y || exit 1')
entries['init']=(stat.S_IFREG|0o755,init.encode(),0,0)
manifest=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(root))+'\n' for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink() and not str(p.relative_to(root)).startswith('lib/modules/'))
entries['userspace.sha256']=(stat.S_IFREG|0o644,manifest.encode(),0,0)
config=json.loads((r/'configs/docker-guest.json').read_text());config.update({'data-root':'/mnt/docker','log-level':'info'})
for n,data in {'daemon.json':json.dumps(config).encode(),'etc/passwd':b'root:x:0:0:root:/root:/bin/sh\n','etc/group':b'root:x:0:\n','etc/os-release':b'ID=be19000ai-qemu\n','QEMU_LAB_GUEST':b'offline guest only\n'}.items():entries[n]=(stat.S_IFREG|0o644,data,0,0)
entries.update({'run':(stat.S_IFLNK|0o777,b'var/run',0,0),'dev/console':(stat.S_IFCHR|0o600,b'',5,1),'dev/null':(stat.S_IFCHR|0o666,b'',1,3),'TRAILER!!!':(0,b'',0,0)})
out=bytearray()
for ino,(n,(m,d,ma,mi)) in enumerate(entries.items(),1):
 n=n.encode()+b'\0';f=[ino,m,0,0,2 if stat.S_ISDIR(m) else 1,0,len(d),0,0,ma,mi,len(n),0]
 out+=b'070701'+''.join(f'{v:08x}' for v in f).encode()+n;out+=b'\0'*(-len(out)%4);out+=d;out+=b'\0'*(-len(out)%4)
p=b/'docker-candidate.cpio.gz';p.write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
record={n:{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for n,p in files.items()}
(r/'evidence/qemu-inputs.json').write_text(json.dumps(record,indent=2)+'\n');print(p,p.stat().st_size)

#!/usr/bin/env python3
"""Offline QEMU fixture only; does not install any host/router userspace."""
from pathlib import Path
import stat,gzip,json,subprocess
r=Path(__file__).resolve().parents[1];b=r/'build/resource6'
init='''#!/bin/busybox sh
export PATH=/docker:/bin
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
fail(){ echo LAB_ROOTLESS_FAILED; tail -90 /tmp/rootless.log; poweroff -f; }
trap fail EXIT
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount --make-rprivate /
mount -t tmpfs tmpfs /sys/fs/cgroup
for c in cpu,cpuacct cpuset memory devices freezer pids blkio; do
 mkdir /sys/fs/cgroup/$c
 mount -t cgroup -o $c $c /sys/fs/cgroup/$c
done
mkdir -p /dev/pts /dev/shm /var/run/user/1000 /view /home/test
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
chown 1000:1000 /var/run/user/1000 /home/test
chmod 700 /var/run/user/1000 /home/test
mount -t tmpfs -o size=650m tmpfs /view
cp -a /bin /docker /etc /lib /home /var /rootless.json /image.tar /phase2 /view/
mkdir /view/dev /view/proc /view/sys /view/tmp
chmod 1777 /view/tmp
ln -s var/run /view/run
mount --move /dev /view/dev
mount --move /proc /view/proc
mount --move /sys /view/sys
exec switch_root /view /bin/sh /phase2
/bin/su -l test -s /bin/sh -c 'export PATH=/docker:/bin; export XDG_RUNTIME_DIR=/run/user/1000; export DOCKERD_ROOTLESS_ROOTLESSKIT_NET=none; export DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=none; export DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false; exec /docker/dockerd-rootless.sh --config-file=/rootless.json' > /tmp/rootless.log 2>&1 &
runner_pid=$!
for i in $(seq 1 45); do DOCKER_HOST=unix:///run/user/1000/docker.sock docker info >/tmp/rootless-info 2>&1 && break; sleep 1; done
cat /tmp/rootless-info
DOCKER_HOST=unix:///run/user/1000/docker.sock docker info --format '{{json .SecurityOptions}}' | grep rootless
# Verify outside user namespace: daemon remains owned by host UID 1000.
found=0
for p in /proc/[0-9]*/comm; do
 if [ "$(cat "$p" 2>/dev/null)" = dockerd ]; then
  awk '$1=="Uid:" {if($2!=1000 || $3!=1000) exit 1; print "LAB_ROOTLESS_UID",$2,$3}' "${p%comm}status" || exit 1
  found=1
 fi
done
test "$found" = 1
export DOCKER_HOST=unix:///run/user/1000/docker.sock
docker import /image.tar rootless-lab:local
docker run --rm --network none rootless-lab:local /bin/sh -c 'test "$(id -u)" = 0; echo isolated >/test; test "$(cat /test)" = isolated; /memload 8 0'
echo LAB_ROOTLESS_PASS actual_docker_daemon_uid1000_container_exec_and_write
kill "$runner_pid" || :
trap - EXIT
echo QEMU_ROOTLESS_COMPLETE
poweroff -f
'''
phase2_start=init.index('/bin/su -l test')
phase2="#!/bin/sh\nexport PATH=/docker:/bin\nfail(){ echo LAB_ROOTLESS_FAILED; tail -90 /tmp/rootless.log; poweroff -f; }\ntrap fail EXIT\nset -e\n"+init[phase2_start:]
init=init[:phase2_start]
entries={n:(stat.S_IFDIR|0o755,b'',0,0) for n in ['bin','docker','etc','dev','proc','sys','tmp','var','home','lib','lib/aarch64-linux-gnu']}
def add(n,p,mode=0o755):entries[n]=(stat.S_IFREG|mode,Path(p).read_bytes(),0,0)
add('bin/busybox',r/'build/busybox')
for n in ['docker','dockerd','containerd','containerd-shim-runc-v2','runc','docker-init']:add('docker/'+n,r/'build/docker-tools'/n)
for n in ['rootlesskit','dockerd-rootless.sh']:add('docker/'+n,b/n)
for n in ['newuidmap','newgidmap']:add('bin/'+n,'/usr/bin/'+n,0o4755)
for n in ['libaudit.so.1','libselinux.so.1','libc.so.6','libcap-ng.so.0','libpcre2-8.so.0']:add('lib/aarch64-linux-gnu/'+n,'/lib/aarch64-linux-gnu/'+n)
add('lib/ld-linux-aarch64.so.1','/lib/ld-linux-aarch64.so.1')
add('image.tar',r/'build/image.tar',0o644)
config={'data-root':'/home/test/docker','exec-root':'/run/user/1000/exec','pidfile':'/run/user/1000/dockerd.pid','hosts':['unix:///run/user/1000/docker.sock'],'group':'test','storage-driver':'vfs','features':{'containerd-snapshotter':False},'bridge':'none','iptables':False,'ip6tables':False,'ip-forward':False,'ip-masq':False,'userland-proxy':False}
files={'init':init,'phase2':phase2,'etc/passwd':'root:x:0:0:root:/root:/bin/sh\ntest:x:1000:1000:Test:/home/test:/bin/sh\n','etc/group':'root:x:0:\ntest:x:1000:\n','etc/subuid':'test:100000:65536\n','etc/subgid':'test:100000:65536\n','etc/nsswitch.conf':'passwd: files\ngroup: files\n','rootless.json':json.dumps(config),'QEMU_LAB_GUEST':'offline guest only\n'}
for n,data in files.items():entries[n]=(stat.S_IFREG|(0o755 if n=='init' else 0o644),data.encode(),0,0)
entries['run']=(stat.S_IFLNK|0o777,b'var/run',0,0)
entries['TRAILER!!!']=(0,b'',0,0);out=bytearray()
for ino,(n,(m,d,uid,gid)) in enumerate(entries.items(),1):
 name=n.encode()+b'\0';f=[ino,m,uid,gid,2 if stat.S_ISDIR(m) else 1,0,len(d),0,0,0,0,len(name),0]
 out+=b'070701'+''.join(f'{v:08x}' for v in f).encode()+name;out+=b'\0'*(-len(out)%4);out+=d;out+=b'\0'*(-len(out)%4)
p=b/'rootless-test.cpio.gz';p.write_bytes(gzip.compress(out,compresslevel=1,mtime=0));print(p,p.stat().st_size)

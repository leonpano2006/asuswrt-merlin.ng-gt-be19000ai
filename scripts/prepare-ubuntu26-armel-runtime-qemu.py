#!/usr/bin/env python3
"""Extend the no-NIC OpenSSH fixture with real ARMEL runtime ABI probes."""
import argparse,gzip,hashlib,importlib.util,json,stat,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/'build/ubuntu26-armel-runtime-gcc15'
PROOF=r'''#!/bin/sh
set -eu
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
D=/usr/libexec/leon-lab/armel-runtime
/lib/ld-linux.so.3 --list-diagnostics > /run/armel-loader-diagnostics
/lib/ld-linux-aarch64.so.1 --list-diagnostics > /run/native-loader-diagnostics
grep -qx 'dl_dst_lib="lib/arm-linux-gnueabi"' /run/armel-loader-diagnostics
grep -qx 'dl_dst_lib="lib/aarch64-linux-gnu"' /run/native-loader-diagnostics
echo ARMEL_RUNTIME_MULTIARCH_LOADER_PASS
"$D/time32-probe"
"$D/time64-probe" --expect-supported --qemu-regression
"$D/crypt-probe"
"$D/crypt-legacy-probe"
/lib/ld-linux.so.3 --list "$D/cxx-probe" > /run/armel-cxx-loader-list
cat /run/armel-cxx-loader-list
for soname in libgcc_s.so.1 libstdc++.so.6; do
 path=$(awk -v name="$soname" '$1==name {print $3}' /run/armel-cxx-loader-list)
 test -n "$path"
 canonical=$(readlink -f "$path")
 case "$canonical" in /usr/lib/arm-linux-gnueabi/*) ;; *) exit 1 ;; esac
done
"$D/cxx-probe" "$D/libcxx-probe.so"
echo ARMEL_RUNTIME_CANONICAL_RESOLUTION_PASS
test "$(dpkg-query -W -f='${Version}' leon-gcc15-runtime:armel)" = 15.2.0-0leonb53.1
test "$(dpkg-query -W -f='${Version}' libstdc++6:arm64)" = 16.2.0-3ubuntu1+leonb53.1
test "$(dpkg-query -W -f='${Version}' libgcc-s1:arm64)" = 16.2.0-3ubuntu1+leonb53.1
for abi in armel arm64; do
 test "$(dpkg-query -W -f='${Version}' libc6:$abi)" = 2.44-1ubuntu1+leonb53.1
 test "$(dpkg-query -W -f='${Version}' libcrypt1:$abi)" = 1:4.5.1-1+leonb53.1
done
dpkg --audit > /run/armel-runtime-dpkg-audit
test ! -s /run/armel-runtime-dpkg-audit
echo ARMEL_RUNTIME_PACKAGE_COHERENCE_PASS
echo ARMEL_RUNTIME_KERNEL10_COMPLETE
'''
MARKERS=['ARMEL_RUNTIME_MULTIARCH_LOADER_PASS',
 'GLIBC_TIME64_NANOSLEEP_EINTR_PASS','GLIBC_RAW_PSELECT_TIME64_EINTR_COPYBACK_PASS',
 'GLIBC_RAW_PPOLL_TIME64_EINTR_COPYBACK_PASS','GLIBC_RAW_FUTEX_TIME64_STOP_CONT_RESTART_PASS',
 'GLIBC_TIME64_VM_CLOCK_2100_RESTORED_PASS','GLIBC_TIME64_TIMER_SUPPORTED',
 'LAB_ASUS_LIBCRYPT_DES_MD5_TIME64_PASS','LAB_ASUS_LIBCRYPT_POISON_INITIALIZED_ONLY_PASS',
 'LAB_ASUS_LIBCRYPT_GLIBC24_OBSOLETE_ABI_PASS','ARMEL_GCC15_CXX_TLS_THREAD_DSO_UNWIND_PASS',
 'ARMEL_RUNTIME_CANONICAL_RESOLUTION_PASS','ARMEL_RUNTIME_PACKAGE_COHERENCE_PASS','ARMEL_RUNTIME_KERNEL10_COMPLETE',
 'LAB_OPENSSH_EFFECTIVE_CONFIG_PASS','LAB_OPENSSH_LOOPBACK_KEY_AUTH_PASS','LAB_OPENSSH_UNAUTHORIZED_KEY_REJECTED',
 'LAB_OPENSSH_SFTP_PASS','LAB_OPENSSH_SYSTEMD_RESTART_PASS','LAB_OPENSSH_SYSTEMD_STOP_PASS',
 'LAB_OPENSSH_KERNEL10_COMPLETE','QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rootfs',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args()
    assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
    out=W/a.label;assert not out.exists();out.mkdir()
    script=R/'scripts/prepare-ubuntu26-openssh-qemu.py'
    subprocess.run(['python3',str(script),'--rootfs',str(a.rootfs),'--label',a.label+'-base'],check=True)
    spec=importlib.util.spec_from_file_location('ssh_fixture',script);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    base=R/'build/ubuntu26-openssh'/(a.label+'-base')/'initramfs.cpio.gz'
    rows=module.parse(gzip.decompress(base.read_bytes()));lookup={x[0]:x for x in rows}
    proof=lookup['usr/libexec/leon-lab/full-boot-proof']
    needle=b'echo passed > /run/leon-full-boot-ok';assert proof[2].count(needle)==1
    proof[2]=proof[2].replace(needle,b'/usr/libexec/leon-lab/armel-runtime-proof\n'+needle)
    ino=max(x[1][0] for x in rows)+1
    def add(name,data,mode):
        nonlocal ino
        assert name not in lookup
        rows.insert(-1,[name,[ino,stat.S_IFREG|mode,0,0,1,0,len(data),0,0,0,0,len(name.encode())+1,0],data]);ino+=1
    add('usr/libexec/leon-lab/armel-runtime-proof',PROOF.encode(),0o755)
    directory='usr/libexec/leon-lab/armel-runtime'
    assert directory not in lookup
    rows.insert(-1,[directory,[ino,stat.S_IFDIR|0o755,0,0,2,0,0,0,0,0,0,len(directory.encode())+1,0],b'']);ino+=1
    files=[]
    for file in sorted((W/'probes').iterdir()):
        add('usr/libexec/leon-lab/armel-runtime/'+file.name,file.read_bytes(),0o755)
        files.append({'path':str(file.relative_to(R)),'sha256':sha(file)})
    data=bytearray()
    for name,fields,payload in rows:
        encoded=name.encode()+b'\0';fields[6]=len(payload);fields[11]=len(encoded)
        data+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+encoded;data+=b'\0'*(-len(data)%4)
        data+=payload;data+=b'\0'*(-len(data)%4)
    result=out/'initramfs.cpio.gz';result.write_bytes(gzip.compress(data,compresslevel=1,mtime=0))
    (out/'armel-runtime-proof.sh').write_text(PROOF)
    report={'rootfs':str(a.rootfs),'rootfs_sha256':sha(a.rootfs),'base_fixture_sha256':sha(base),
            'initramfs':str(result.relative_to(R)),'initramfs_sha256':sha(result),'probes':files,
            'expected_markers':MARKERS,'expected_prefix_markers':['ARMEL_LEGACY_TIME32_PASS '],
            'scope':'No-NIC QEMU runtime ABI tests plus complete native OpenSSH regression; no ASUS service or router activation.',
            'builder_sha256':sha(Path(__file__))}
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()

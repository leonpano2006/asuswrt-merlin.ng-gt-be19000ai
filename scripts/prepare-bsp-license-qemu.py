#!/usr/bin/env python3
"""Only the new RO license projection in kernel10, RAM files and no NIC."""
import gzip,hashlib,json,stat
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
PROOF=r'''#!/busybox sh
set -eu
B=/busybox
trap 'code=$?; echo LAB_LICENSE_PROJECTION_EXIT_code=$code; /busybox poweroff -f' EXIT
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
echo QEMU_LAB_INIT_REACHED
$B insmod /test/exportfs.ko
$B insmod /test/overlay.ko
$B mount -t tmpfs -o mode=0755 tmpfs /rom
$B mkdir -p /rom/etc/licenses
$B cp /test/licenses/* /rom/etc/licenses/
$B chmod 0755 /rom/etc/licenses
$B mount -t tmpfs -o mode=0755 tmpfs /fixture
$B mkdir -p /fixture/lower/licenses /fixture/upper /fixture/work
/test/projection-fixture
echo LAB_LICENSE_PROJECTION_COMPLETE
'''
def main():
    assert __debug__
    out=R/'build/ubuntu26-bsp-license/qemu-projection-v1';out.mkdir(parents=True,exist_ok=False)
    native=R/'build/ubuntu26-bsp-license/native-v1';fixture=native/'license-projection-fixture'
    manifest=json.loads((native/'manifest.json').read_text());assert manifest['status']=='bsp_license_helpers_built'
    sources=[(R/'build/busybox','busybox',0o755),(fixture,'test/projection-fixture',0o755),
             (R/'build/kernel10-module-root/lib/modules/4.19.294/kernel/fs/exportfs/exportfs.ko','test/exportfs.ko',0o644),
             (R/'build/kernel10-module-root/lib/modules/4.19.294/kernel/fs/overlayfs/overlay.ko','test/overlay.ko',0o644)]
    licenses=R/'build/asus-native-integration/v4/root/usr/share/asus/integration/rom/etc/licenses'
    for path in sorted(licenses.iterdir()):assert path.is_file() and not path.is_symlink();sources.append((path,'test/licenses/'+path.name,0o644))
    assert len(sources)==9
    raw=bytearray();ino=1
    def add(name,payload,mode):
        nonlocal ino
        names=name.encode()+b'\0';fields=[ino,mode,0,0,1,0,len(payload),0,0,0,0,len(names),0];ino+=1
        raw.extend(b'070701'+''.join('%08x'%x for x in fields).encode()+names);raw.extend(b'\0'*(-len(raw)%4));raw.extend(payload);raw.extend(b'\0'*(-len(raw)%4))
    for name in ['proc','sys','dev','rom','etc','etc/licenses','fixture','test','test/licenses']:add(name,b'',stat.S_IFDIR|0o755)
    for path,name,mode in sources:add(name,path.read_bytes(),stat.S_IFREG|mode)
    add('init',PROOF.encode(),stat.S_IFREG|0o755);add('TRAILER!!!',b'',0)
    initrd=out/'initramfs.cpio.gz';initrd.write_bytes(gzip.compress(raw,compresslevel=1,mtime=0));(out/'proof.sh').write_text(PROOF)
    proof={'schema':1,'status':'prepared_new_projection_case','initramfs':ref(initrd),'sources':[{'source':ref(path),'target':name} for path,name,mode in sources],
           'source_launcher':ref(R/'scripts/asus-integration/private-resource-launch.c'),'source_fixture':ref(R/'scripts/asus-integration/license-projection-fixture.c'),
           'expected_markers':['LAB_LICENSE_BIND_IDENTITY_BYTES_RO_PASS files=5','LAB_LICENSE_NATIVE_ETC_UNCHANGED_PASS','LAB_LICENSE_PROJECTION_COMPLETE','LAB_LICENSE_PROJECTION_EXIT_code=0'],
           'builder':ref(Path(__file__)),'scope':'One new exact production helper function, RAM tmpfs+overlay, original packaged license bytes. No ASUS backend/driver/crypto/physical block devices or networking. No prior suites repeated.'}
    (out/'manifest.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps({'initramfs':ref(initrd)}))
if __name__=='__main__':main()

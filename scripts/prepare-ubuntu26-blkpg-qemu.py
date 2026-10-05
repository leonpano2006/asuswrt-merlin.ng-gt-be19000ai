#!/usr/bin/env python3
"""Minimal kernel10 RAM-loop fixture; production device helper is not included."""
import argparse,gzip,hashlib,importlib.util,json,re,stat,struct,subprocess,zlib
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.resolve().relative_to(R)),'sha256':sha(p)}
spec=importlib.util.spec_from_file_location('gpt',R/'scripts/prepare-ubuntu26-gpt-candidate.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
PROOF=r'''#!/busybox sh
set -eu
B=/busybox
export PATH=/bin
$B mkdir -p /proc /sys /dev /run /hold /bin
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
$B mount -t tmpfs -o size=256m,mode=0755 tmpfs /run
stage=start
trap 'code=$?; echo LAB_BLKPG_EXIT_code=$code stage=$stage; /busybox poweroff -f' EXIT
echo QEMU_LAB_INIT_REACHED
printf '00000000000000000000000000000001\n' > /fixture-cid
chmod() { $B chmod "$@"; }
chmod 0644 /fixture-cid
seed() {
 $B rm -f /run/disk
 $B dd if=/dev/zero of=/run/disk bs=512 count=0 seek="$1" 2>/dev/null
 $B dd if="/$2-primary" of=/run/disk bs=512 conv=notrunc 2>/dev/null
 $B dd if="/$2-backup" of=/run/disk bs=512 seek=61226463 conv=notrunc 2>/dev/null
}
new_gpt() {
 $B dd if=/new-backup of=/dev/loop0 bs=512 seek=61226463 conv=notrunc 2>/dev/null
 $B dd if=/new-primary of=/dev/loop0 bs=512 conv=notrunc 2>/dev/null
 $B sync
}
assert_no_p11() { test ! -e /sys/class/block/loop0/loop0p11; }
refuse() {
 if /add-p11-loop-fixture --add-p11 > /run/result 2>/run/error; then echo UNEXPECTED_SUCCESS;exit 1; fi
 test ! -s /run/result
 $B grep -F "$1" /run/error
}
snapshot() {
 for n in 1 2 3 4 5 6 7 8 9 10; do
  printf '%s ' "$n"
  $B cat /sys/class/block/loop0/loop0p$n/start /sys/class/block/loop0/loop0p$n/size /sys/class/block/loop0/loop0p$n/dev
 done
}
stage=old-table-refusal
seed 61226496 old
$B dd if=/p7.ext4 of=/run/disk bs=512 seek=1028096 conv=notrunc 2>/dev/null
$B losetup /dev/loop0 /run/disk
refuse candidate-gpt-bytes
assert_no_p11
echo LAB_BLKPG_OLD_GPT_REFUSED_PASS
stage=mounted-partition
$B dd if=/dev/loop0p7 of=/run/p7-initial bs=512 count=131072 2>/dev/null
$B cmp /p7.ext4 /run/p7-initial
echo LAB_BLKPG_P7_INITIAL_SEED_EXACT_PASS
$B rm /run/p7-initial
$B mount -t ext4 -o ro /dev/loop0p7 /hold
snapshot > /run/parts-before
$B dd if=/dev/loop0p7 of=/run/p7-before bs=512 count=131072 2>/dev/null
$B sha256sum /p7.ext4 /run/p7-before
if ! $B cmp /p7.ext4 /run/p7-before; then
 echo LAB_BLKPG_MOUNT_CHANGED_BASELINE_BEFORE_HELPER
 $B cmp -l /p7.ext4 /run/p7-before | $B head -12
fi
new_gpt
stage=identity-negative
printf '00000000000000000000000000000000\n' > /fixture-cid
refuse fixture-cid
assert_no_p11
printf '00000000000000000000000000000001\n' > /fixture-cid
$B dd if=/bad-backup of=/dev/loop0 bs=512 seek=61226463 conv=notrunc 2>/dev/null
refuse candidate-gpt-bytes
assert_no_p11
new_gpt
$B mv /dev/loop0 /dev/loop0-real
$B ln -s loop0-real /dev/loop0
refuse open-fixed-disk
$B rm /dev/loop0
$B mv /dev/loop0-real /dev/loop0
if /add-p11-loop-fixture --add-p11 /dev/anything; then exit 1; fi
assert_no_p11
echo LAB_BLKPG_CID_GPT_SYMLINK_ARGUMENT_REFUSALS_PASS
stage=add-while-p7-mounted
/add-p11-loop-fixture --add-p11 > /run/result
$B grep -F '"p11":"added-exact"' /run/result
test "$($B cat /sys/class/block/loop0/loop0p11/start)" = 26849280
test "$($B cat /sys/class/block/loop0/loop0p11/size)" = 25165824
test "$($B cat /sys/class/block/loop0/loop0p11/dev)" = 7:11
snapshot > /run/parts-after
$B cmp /run/parts-before /run/parts-after
$B grep -F '/dev/loop0p7 /hold ext4 ro,' /proc/mounts
$B dd if=/dev/loop0 of=/run/primary bs=512 count=34 2>/dev/null
$B dd if=/dev/loop0 of=/run/backup bs=512 skip=61226463 count=33 2>/dev/null
$B cmp /new-primary /run/primary
$B cmp /new-backup /run/backup
$B dd if=/dev/loop0p7 bs=512 count=131072 2>/dev/null | $B sha256sum > /run/p7-after
$B sha256sum /run/p7-before | $B cut -d' ' -f1 > /run/p7-before-hash
$B cut -d' ' -f1 /run/p7-after > /run/p7-after-hash
$B cmp /run/p7-before-hash /run/p7-after-hash
echo LAB_BLKPG_ADD_WITH_EXISTING_MOUNT_GPT_PAYLOAD_UNCHANGED_PASS
stage=already-present
/add-p11-loop-fixture --add-p11 > /run/result
$B grep -F 'already-present-exact-no-op' /run/result
echo LAB_BLKPG_EXISTING_EXACT_NOOP_PASS
$B umount /hold
$B rm /run/p7-before
$B losetup -d /dev/loop0
stage=wrong-existing-p11
seed 61226496 wrong
$B losetup /dev/loop0 /run/disk
test "$($B cat /sys/class/block/loop0/loop0p11/start)" = 26851328
new_gpt
refuse existing-partitions
test "$($B cat /sys/class/block/loop0/loop0p11/start)" = 26851328
echo LAB_BLKPG_WRONG_EXISTING_EXTENT_UNCHANGED_PASS
$B losetup -d /dev/loop0
stage=unexpected-p12
seed 61226496 extra
$B losetup /dev/loop0 /run/disk
test -e /sys/class/block/loop0/loop0p12
new_gpt
refuse existing-partitions
test -e /sys/class/block/loop0/loop0p12
echo LAB_BLKPG_UNEXPECTED_PARTITION_REFUSED_PASS
$B losetup -d /dev/loop0
stage=wrong-capacity
seed 61226497 new
$B losetup /dev/loop0 /run/disk
refuse disk-geometry
echo LAB_BLKPG_WRONG_CAPACITY_REFUSED_PASS
$B losetup -d /dev/loop0
echo LAB_BLKPG_KERNEL10_COMPLETE
'''
def variant(primary,backup,kind):
 outputs=[]
 for index,data in enumerate([primary,backup]):
  data=bytearray(data);ho=512 if index==0 else len(data)-512;head=g.header(data,ho);array,off=g.entries(data,head,0 if index==0 else 61226463);array=bytearray(array)
  if kind=='wrong':struct.pack_into('<Q',array,10*128+32,26851328)
  elif kind=='extra':
   array[11*128:12*128]=array[10*128:11*128];array[11*128+16]^=1;struct.pack_into('<QQ',array,11*128+32,52017152,52019199)
  else:raise AssertionError(kind)
  data[off:off+len(array)]=array;g.patch_header(data,head,array);outputs.append(bytes(data))
 return outputs

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);p.add_argument('--native',type=Path,required=True);a=p.parse_args();assert re.fullmatch('[a-zA-Z0-9_-]+',a.label)
 native=json.loads((a.native/'manifest.json').read_text());binary=a.native/'add-p11-loop-fixture';assert sha(binary)==native['variants']['add-p11-loop-fixture']['sha256']
 out=R/'build/ubuntu26-blkpg-qemu'/a.label;out.mkdir(parents=True,exist_ok=False)
 p7=out/'p7.ext4'
 with p7.open('xb') as f:f.truncate(64*1024*1024)
 with (out/'mke2fs.log').open('w') as log:subprocess.run(['mke2fs','-t','ext4','-F','-b','4096','-I','256','-m','0','-O','none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum','-E','lazy_itable_init=0,lazy_journal_init=0','-U','1178f2c7-fc87-424a-93b0-4236822e54fa',str(p7)],check=True,stdout=log,stderr=subprocess.STDOUT)
 primary=(R/'build/ubuntu26-gpt-candidate/v1/primary.bin').read_bytes();backup=(R/'build/ubuntu26-gpt-candidate/v1/backup.bin').read_bytes()
 files={'busybox':(R/'build/busybox').read_bytes(),'add-p11-loop-fixture':binary.read_bytes(),'init':PROOF.encode(),'p7.ext4':p7.read_bytes(),'old-primary':(R/'evidence/ubuntu26/emmc-primary-gpt.bin').read_bytes(),'old-backup':(R/'evidence/ubuntu26/emmc-backup-gpt.bin').read_bytes(),'new-primary':primary,'new-backup':backup}
 bad=bytearray(backup);bad[-512+24]^=1;files['bad-backup']=bytes(bad)
 for kind in ['wrong','extra']:
  x,y=variant(primary,backup,kind);files[kind+'-primary']=x;files[kind+'-backup']=y
 data=bytearray();ino=1
 def add(name,payload,mode):
  nonlocal ino
  names=name.encode()+b'\0';fields=[ino,mode,0,0,1,0,len(payload),0,0,0,0,len(names),0];ino+=1
  data.extend(b'070701'+''.join('%08x'%x for x in fields).encode()+names);data.extend(b'\0'*(-len(data)%4));data.extend(payload);data.extend(b'\0'*(-len(data)%4))
 for name in ['proc','sys','dev','run','hold','bin']:add(name,b'',stat.S_IFDIR|0o755)
 for name,payload in files.items():add(name,payload,stat.S_IFREG|(0o755 if name in ['init','busybox','add-p11-loop-fixture'] else 0o644))
 add('TRAILER!!!',b'',0)
 initrd=out/'initramfs.cpio.gz';initrd.write_bytes(gzip.compress(data,compresslevel=1,mtime=0));(out/'proof.sh').write_text(PROOF)
 report={'schema_version':1,'status':'prepared_ram_loop_fixture','native':ref(a.native/'manifest.json'),'initramfs':ref(initrd),'proof':ref(out/'proof.sh'),'busybox':ref(R/'build/busybox'),'regular_p7_image':ref(p7),'expected_markers':[line.split('echo ',1)[1] for line in PROOF.splitlines() if line.startswith('echo LAB_')],'extra_kernel_arguments':'loop.max_part=15','device_binary_included':False,'production_device_opened':False,'gpt_host_device_written':False,'scope':'Only guest RAM loop block device. Fixture setup rewrites GPT on that synthetic loop; helper itself opens read-only and only issues BLKPG_ADD_PARTITION.'}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'initramfs':str(initrd.relative_to(R)),'markers':len(report['expected_markers'])}))
if __name__=='__main__':main()

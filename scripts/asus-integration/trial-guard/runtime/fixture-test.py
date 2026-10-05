#!/usr/bin/env python3
import json,struct,subprocess,uuid,zlib,sys,os,hashlib
from pathlib import Path
root=Path(sys.argv[1]);work=sys.argv[2];os.chdir(str(root)+work);policy=json.loads(Path('fixture-input.json').read_text());r=Path(str(root)+policy['fixture_root']);r.mkdir(mode=0o755)
def put(name,value):
 p=r/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value.encode() if isinstance(value,str) else value);p.chmod(0o644);return p
put('proc/sys/kernel/random/boot_id','12345678-1234-1234-1234-123456789abc\n');put('proc/sys/kernel/osrelease','4.19.294\n');put('proc/sys/kernel/version',policy['kernel_version']+'\n');put('sys/kernel/notes',Path('kernel-notes').read_bytes());put('etc/leon/root-generation','isolated-fixture\n');put('usr/lib/modules/4.19.294/fixture.ko','fixture-module\n');put('proc/cmdline','console=ttyAMA0 root=/dev/mmcblk0p4 rootwait\n');put('proc/bootstate/reset_reason','0');(r/'var').mkdir(mode=0o755)
for n in [1,2]:
 put(f'dev/mmcblk0p{n}',Path('metadata.bin').read_bytes());put(f'sys/dev/block/179:{n}/ro','1\n');put(f'sys/dev/block/179:{n}/size','512\n');put(f'sys/dev/block/179:{n}/uevent',f'MAJOR=179\nMINOR={n}\nPARTNAME=metadata{n}\n')
for n,start,sectors,id in policy['storage']:
 b=bytearray(2048);b[1024+56:1024+58]=b'\x53\xef';b[1024+104:1024+120]=uuid.UUID(id).bytes;put(f'dev/mmcblk0p{n}',b);put(f'sys/dev/block/179:{n}/start',f'{start}\n');put(f'sys/dev/block/179:{n}/size',f'{sectors}\n')
for n,start,sectors,data in [(5,516096,102400,b'fixture-stock-kernel'),(6,618496,409600,b'fixture-stock-rootfs')]:
 put(f'dev/mmcblk0p{n}',data);put(f'sys/dev/block/179:{n}/start',f'{start}\n');put(f'sys/dev/block/179:{n}/size',f'{sectors}\n')
def proof_for_metadata(data):
 digest=hashlib.sha256(data).hexdigest();kernel=hashlib.sha256(b'fixture-stock-kernel').hexdigest();rootfs=hashlib.sha256(b'fixture-stock-rootfs').hexdigest()
 put('etc/leon/trial-slot-proof',f'LEON_TRIAL_SLOT_V1\ngeneration isolated-fixture\nmetadata_sha256 {digest}\nstock_kernel_sha256 {kernel}\nstock_rootfs_sha256 {rootfs}\n').chmod(0o600)
proof_for_metadata(Path('metadata.bin').read_bytes())
cases=[]
def run(name,good=False):
 p=subprocess.run(['chroot',str(root),work+'/trial-preflight-fixture'],capture_output=True,text=True,timeout=16);assert p.returncode==(0 if good else 125),(name,p.returncode,p.stderr);cases.append(name);print('LAB_TRIAL_PREFLIGHT_'+name+'_PASS')
def mutate(name,path,value):
 p=r/path;original=p.read_bytes();mode=p.stat().st_mode&0o777;put(path,value).chmod(mode);run(name);put(path,original).chmod(mode)
run('VALID_READONLY_REFERENCE',True)
mutate('WRONG_KERNEL','proc/sys/kernel/version','wrong\n');mutate('WRONG_KERNEL_NOTES','sys/kernel/notes',b'wrong');mutate('WRONG_GENERATION','etc/leon/root-generation','wrong\n');mutate('MODULE_CHANGED','usr/lib/modules/4.19.294/fixture.ko','changed\n');mutate('WRONG_BOOT_ROOT','proc/cmdline','root=/dev/mmcblk0p6\n');mutate('DUPLICATE_BOOT_ROOT','proc/cmdline','root=/dev/mmcblk0p4 root=/dev/mmcblk0p4\n');mutate('ACTIVATE_OTHER_SLOT','proc/bootstate/reset_reason','1');mutate('UNKNOWN_BOOT_REASON','proc/bootstate/reset_reason','ffffffff');mutate('ACTIVATE_WITH_PHASE','proc/bootstate/reset_reason','131');mutate('UNKNOWN_PHASE','proc/bootstate/reset_reason','174');mutate('METADATA_RW','sys/dev/block/179:1/ro','0\n');mutate('METADATA_LABEL','sys/dev/block/179:2/uevent','PARTNAME=untrusted\n')
p=r/'dev/mmcblk0p1';b=bytearray(p.read_bytes());b[12]^=1;mutate('CRC_CORRUPT','dev/mmcblk0p1',b)
b=bytearray(p.read_bytes());b[13]^=1;struct.pack_into('<I',b,8,zlib.crc32(b[12:264]));mutate('OTHER_COMMIT_VALID_CRC','dev/mmcblk0p1',b)
b=bytearray(p.read_bytes());b[4096]=1;mutate('COPIES_DIFFER','dev/mmcblk0p2',b)
for n,*_ in policy['storage']:
 b=bytearray((r/f'dev/mmcblk0p{n}').read_bytes());b[1128]^=1;mutate(f'UUID_P{n}',f'dev/mmcblk0p{n}',b)
mutate('STORAGE_BOUNDS','sys/dev/block/179:10/size','1\n');put('var/gpt_modified.txt','1');run('GPT_MODIFIED');(r/'var/gpt_modified.txt').unlink()
p=r/'usr/lib/modules/4.19.294/fixture.ko';p.chmod(0o666);run('WRITABLE_MODULE');p.chmod(0o644)
p=r/'proc/bootstate/reset_reason';p.rename(p.with_name('saved'));p.symlink_to('saved');run('SYMLINK_REASON');p.unlink();p.with_name('saved').rename(p)
mutate('STOCK_KERNEL_CHANGED','dev/mmcblk0p5',b'wrong');mutate('STOCK_ROOTFS_CHANGED','dev/mmcblk0p6',b'wrong');mutate('TOKEN_WRONG','etc/leon/trial-slot-proof','wrong\n');put('proc/bootstate/reset_reason','134');run('OBSERVED_REASON_134',True);run('RESTORED_REFERENCE',True)
original=Path('metadata.bin').read_bytes()
for name,seq,expected in [('SEQ_AFTER_FLASH','6,4',True),('SEQ_WRAP','0,999',True),('SEQ_TOO_LARGE','1000,4',False),('SEQ_NEGATIVE','-1,4',False),('SEQ_NONCANONICAL','06,4',False)]:
 b=bytearray(original);b[12:264]=bytes(252);fields=('COMMITTED=2\0VALID=1,2\0SEQ='+seq+'\0').encode();b[12:12+len(fields)]=fields;struct.pack_into('<I',b,8,zlib.crc32(b[12:264]));put('dev/mmcblk0p1',b);put('dev/mmcblk0p2',b);proof_for_metadata(b);run(name,expected)
put('dev/mmcblk0p1',original);put('dev/mmcblk0p2',original);proof_for_metadata(original)
print(json.dumps({'cases':len(cases),'all_passed':True,'hardware_accessed':False}))

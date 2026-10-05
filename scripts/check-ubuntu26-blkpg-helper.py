#!/usr/bin/env python3
"""Bind the fixed native helper to its exact kernel10 RAM-loop acceptance."""
import hashlib,json,re
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def ref(name):return {'path':name,'sha256':sha(R/name)}
def main():
 paths={'native':'build/ubuntu26-blkpg-helper/v1/manifest.json','fixture':'build/ubuntu26-blkpg-qemu/v3/manifest.json','qemu':'build/qemu/ubuntu26-blkpg-p11-v2/result.json','serial':'build/qemu/ubuntu26-blkpg-p11-v2/serial.log','source_review':'reports/ubuntu26/blkpg-source-review.json'}
 values={k:json.loads((R/v).read_text()) for k,v in paths.items() if k not in ('serial','source_review')}
 n,f,q=[values[k] for k in ('native','fixture','qemu')];log=(R/paths['serial']).read_text()
 assert n['status']=='built_static_native_variants_not_executed' and not n['device_binary_executed']
 assert f['native']['sha256']==sha(R/paths['native'])
 for entry in n['variants'].values():assert sha(R/entry['path'])==entry['sha256']
 assert q['guest_complete'] and not q['panic'] and q['kernel_sha256']==sha(R/'build/Image-v10')
 assert q['initramfs_sha256']==f['initramfs']['sha256'] and q['log_sha256']==sha(R/paths['serial'])
 for marker in f['expected_markers']:assert marker in log,marker
 assert 'LAB_BLKPG_EXIT_code=0' in log and not f['device_binary_included']
 assert log.index('LAB_BLKPG_MOUNT_CHANGED_BASELINE_BEFORE_HELPER')<log.index('"p11":"added-exact"')
 assert all(x in log for x in ['45100   0  20','45137   0   4'])
 evidence={k:ref(v) for k,v in paths.items() if (R/v).exists()}
 result={'schema_version':1,'status':'fixed_helpers_compiled_loop_variant_validated_on_kernel10','production_ready':False,'device_execution_authorized_by_this_report':False,'evidence':evidence,'variants':n['variants'],'expected_device':{'path':'/dev/mmcblk0','major':179,'minor':0,'cid':'00000000000000000000000000000001','bytes':61226496*512,'logical_sector':512,'p11_start_sector':26849280,'p11_sectors':25165824},'native_api':'64-bit native struct blkpg_partition / struct blkpg_ioctl_arg; fixed production and fixture identities selected at compile time, no runtime arbitrary-device parameter.','file_descriptor':'O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK; exclusive advisory flock before inspection.','mutation':'Only BLKPG_ADD_PARTITION pno11. No write/pwrite/GPT/PMBR/payload/slot writes, BLKRRPART, delete or resize operation in helper source.','checks':['Exact full reviewed candidate primary and backup GPT bytes, including unchanged PMBR and all original entries.','Exact disk CID, major/minor, capacity, logical block size and sysfs whole-disk identity.','Exact p1–10 kernel start/size/number/dev, no unknown p12+; repeat immediately before ioctl.','Existing exact p11 returns no-op; wrong existing p11 extent fails closed.','After ADD, verify p11 exact boundary/minor, p1–10 unchanged, and both GPT copies unchanged.'],
 'qemu':{'seconds':q['elapsed_seconds'],'markers':f['expected_markers'],'disk':'Only /dev/loop0 backed by a sparse file in guest RAM; no NIC or host block device.','kernel_arguments':'loop.max_part=15','busy_partition':'p7 ext4 remained mounted read-only throughout successful ADD and no-op.','payload_proof':'Initial 64MiB p7 seed matched. Mount itself changed two bytes before helper execution; the complete 64MiB post-mount/pre-ADD snapshot equaled the post-ADD snapshot.','mount_phase_difference_offsets_one_based':[45100,45137],'negative_cases':['old GPT','wrong CID','corrupt backup GPT','symlink fixed device path','extra CLI device argument','wrong existing p11 start','unexpected p12','wrong whole-disk capacity']},
 'limits':['Production eMMC helper binary was compiled but never executed; physical hardware remains unvalidated.','BLKPG add_partition receives info=NULL: no GPT PARTNAME/PARTUUID is generated until a full later GPT scan. Immediate success uses sysfs start/size/dev only.','An external transaction must serialize unrelated firmware disk writers; advisory flock alone cannot guarantee that.','A failure after successful ADD may leave the correct p11 present; caller must inspect and may re-run for exact no-op, never blindly delete/recreate.','Fixture GPT writes are setup operations on the guest RAM loop only and are not helper behavior.','Original stock slot2 boot, durable backups and all separate GPT provisioning gates remain required before a physical change.'],
 'first_fixture_failure':{'path':'build/qemu/ubuntu26-blkpg-p11-v1/result.json','reason':'Compared post-mount payload to pre-mount seed. New v2 fixture locates the two changed bytes before helper execution, then verifies complete payload equality across ADD without changing helper bytes.'},'checker':ref(str(Path(__file__).resolve().relative_to(R)))}
 out=R/'build/ubuntu26-blkpg-helper/v1/validated-manifest.json';assert not out.exists();out.write_text(json.dumps(result,indent=2)+'\n')
 report=dict(result);report['manifest']=ref(str(out.relative_to(R)));(R/'reports/ubuntu26/blkpg-helper.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':result['status'],'manifest':ref(str(out.relative_to(R)))},indent=2))
if __name__=='__main__':main()

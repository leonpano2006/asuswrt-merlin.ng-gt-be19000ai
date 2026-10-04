#!/usr/bin/env python3
"""Repack only rootfs in the verified, signed kernel6 trial package."""
from pathlib import Path
import json,hashlib
from fitlib import images,repack,sha
R=Path(__file__).resolve().parents[1]
base=R/'build/GT-BE19000AI_3006_102.9_leon-kernel6_TRIAL.pkgtb'
b=base.read_bytes();assert sha(b)=='3eaf5b50b1e9d70d4dd08006f616f32c4d332f45959bd5396b9e362d21781fb6'
root=R/'build/rootfs-rc1.zstd.squashfs';payload=root.read_bytes()
stage=json.loads((R/'evidence/rc1/rootfs-changes.json').read_text())
assert sha(payload)==stage['rootfs_sha256']
qemu=json.loads((R/'build/qemu/rc1-integrated-final/result.json').read_text())
assert qemu['guest_complete'] and not qemu['panic']
assert qemu['kernel_sha256']=='807318115f76789e20d7d3ebfeff8cf22a5c19959ac1ecedf1d33dc96eff93ce'
inputs=json.loads((R/'evidence/rc1/qemu-inputs.json').read_text());assert inputs['rootfs.img']['sha256']==sha(payload)
assert 'LAB_ROOTFS_PASS zstd_mount_and_all_userspace_hashes' in qemu['lab_lines']
old=images(b);name='/images/emmc_squashfs';assert name in old
out,changes=repack(b,{name:payload});new=images(out)
for n,(_,data) in old.items():
 if n!=name:assert new[n][1]==data,n
assert new[name][1]==payload
bootname='/images/bootfs_6813_a0+';boot=new[bootname][1]
assert sha(boot)=='3f921031bec7b1425f556822ded72a712a879ec98afb7054c1c016fa407364a0'
assert len(payload)<209715200 and len(boot)<52428800
path=R/'build/GT-BE19000AI_3006_102.9_leon-kernel6-ui1_TRIAL.pkgtb';assert not path.exists();path.write_bytes(out)
record={'image':path.name,'sha256':sha(out),'bytes':len(out),'kernel_sha256':qemu['kernel_sha256'],'bootfs_sha256':sha(boot),'bootfs_bytes':len(boot),'rootfs_sha256':sha(payload),'rootfs_bytes':len(payload),'signed_bootfs_identical_to_verified_kernel6':True,'has_loader_update':False,'ai_board_modified':False,'kernel_modules_unchanged':True,'qemu_validated':True,'hardware_validated':False,'trial_only':True,'permanent_commit_allowed':False,'rootfs_changes':'evidence/rc1/rootfs-changes.json','known_exclusions':stage['release']['excluded'],'outer':changes}
(R/'evidence/rc1/image-manifest.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items() if k!='outer'},indent=2))

#!/usr/bin/env python3
"""Fixed kernel11/guardian33 successor of actual V23; pure plan by default.
An exact plan gate permits one exclusive root copy/pack/new LZO decode/sign/readback.
No compiler, old fixture replay, target execution, flash, selection or device IO.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/ubuntu26-bootstrap/device-scoped-udev-guardian32-v23'
STAGE = R / 'build/ubuntu26-bootstrap/device-kernel11-guardian33-v24'
WORK = R / 'build/ubuntu26-firmware/kernel11-ubuntu26-trial-v24-device-bpf-guardian33'
IMAGE = R / 'build/GT-BE19000AI_3006_102.9_leon-kernel11-ubuntu26-trial-v24-device-bpf-guardian33_TRIAL.pkgtb'
HELPER = {'path': 'scripts/pack-ubuntu26-guardian29-successor-v1.py', 'sha256': 'c941c29fa7f7edf39607f0cd13fbcb6c5b0e9123fc3473e25c8fff60bbfd7e6d'}
BASE_PACKER = {'path': 'scripts/pack-ubuntu26-guardian32-v23.py', 'sha256': '31660990e163d925a5d1ec02e88c370f04418499563ebab6740cfa0ba33453fb'}
BASE_FW = {'path': 'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v23-accepted-this-boot-guardian32/manifest.json', 'sha256': '0078fd28b41d1d7fa79c17a816813f419df94bbdd0666021f4d9273e1800f0a6'}
BASE_IMAGE = {'path': 'build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v23-accepted-this-boot-guardian32_TRIAL.pkgtb', 'sha256': '5a9233f2aa13a473daebc612f4d29654cf06fed90638e25266f38331e1e47fbd', 'bytes': 89073364}
BASE_STAGE = {'path': str((BASE/'manifest.json').relative_to(R)), 'sha256': 'd5ea8cd254cf3078c0294ee29bbeba48f5acc4e08c8f955a98cfc33b09d602c7'}
BASE_ROOT = {'path': str((BASE/'bootstrap.zstd.squashfs').relative_to(R)), 'sha256': '7ae270b468099fd566df31b2f292b880d0c066126f7f69007341e3df47320528', 'bytes': 76578816}
BASE_META = {'path': str((BASE/'root/usr/libexec/leon-boot/manifest.json').relative_to(R)), 'sha256': '0509693fca65c2ad46452aa3e258e3a51c4bb9ac185b4b95d42e23bb33cdea0c'}
VERIFIER = {'path': 'scripts/build-asus-guardian33-kernel11-native.py', 'sha256': '7a572af945fb47a07ea931c4d5f5d60a2d8969f1433d4c0ae1e28fd9c203431b'}
GUARD_MANIFEST = {'path': 'build/asus-trial-runtime/native-v33-kernel11-identity/manifest.json', 'sha256': 'a1d034cb56444162c24debc905a61fadf59d4a1072e0c1f0718d98151b41d155'}
GUARD_RECEIPT = {'path': 'build/asus-trial-runtime/native-v33-kernel11-identity/guardian-receipt.json', 'sha256': 'ffebfcc7c4338742a56624fd2af35fa0319a17e21742ff707e8f5dd4521cc90b'}
GUARD = {'path': 'build/asus-trial-runtime/native-v33-kernel11-identity/guardian-integrated', 'sha256': '24d5743457e3fb9717b3acca783ecf314121f6a5191a7dc61a44afc586f063b4'}
GUARD_SOURCE = {'path': 'reports/ubuntu26/guardian33-kernel11-identity-source-v1.json', 'sha256': '54de51e7e2b045d4d32792b253a4cb6265aa73d9f2aa0db0854b2b7586c474d6'}
KERNEL = {'path': 'build/kernel11-device-bpf/attempt1/Image', 'sha256': '7d0be9c9c719291e52cf8994221d3c6267185a27e9b5bd4079f40d9bf21a21ed', 'bytes': 13049864}
VMLINUX = {'path': 'build/kernel11-device-bpf/attempt1/vmlinux', 'sha256': '688e64dd67cc7bd14bcd0fa5764994d32ae44e713d30aa9459381e90f14290f9'}
ABI = {'path': 'build/kernel11-device-bpf/abi/result.json', 'sha256': '994c98af57ed5b0c395851fcef62239d4a5c5787a5865dd1be3eb98f2ff98a84'}
QEMU = {'path': 'build/qemu/kernel11-device-bpf-docker-v2/result.json', 'sha256': 'd01bee2acf64ecdd2a64c33adbc1ef9bbc844981fc17d0c6203ebfc3710954fc'}
MODULES = {'path': 'reports/kernel10/modules-stage.json', 'sha256': 'c222eb7e211f080a4160ece4ef4b418cf8fbb683603b9b735238f423751e1636'}
DECODER = {'path': 'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v11-cfe-factory-r2/decoder', 'sha256': 'c11c168e5d69fb1dfd1efadf77b1ed71b1b8e71673914d0e09655f25e4630d32', 'bytes': 71064}
DECODER_SOURCE = {'path': 'build/uboot-lzo/decoder.c', 'sha256': '0ad508e435f0674dbf9e577df7bafcfd34be2134ed8c83eb9ced77a74ae781c2'}
DECODER_ANCESTRY = {'path': 'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v11-cfe-factory-r2/manifest.json', 'sha256': 'a779c3806be2cb92304d6ff700d8ff167fe2ce5027e86b84710ccd3e89ccfc72'}
KEY = R / 'source/release/src-rt-5.04behnd.4916/targets/keys/demo/GEN3/Krot-fld.pem'
PUBLIC_DER_SHA = '8450c64281c9d0206dff844ae174fbe5e0ee805309368a02c4d54df5723643c0'
EXTRA_TOOLS = {'openssl': {'path': '/usr/bin/openssl', 'sha256': '77268ab5d3ec14a6e479c526d431bb193354b8ee3d9006ca03d40029b142d5e5'},
               'lzop': {'path': '/usr/bin/lzop', 'sha256': '08c62a7e7b78c4081ebc1c142f84225e2b8f7b0390e77b25273f1d9a115fa029'}}
MARKERS = ['LAB_DOCKER_CGROUP_V2_PASS pid1_rehomed_controllers_enabled', 'LAB_DOCKER_CGROUP_V2_PASS actual_unified_cgroupfs_daemon',
           'LAB_DOCKER_CGROUP_V2_PASS normal_container_cpu_memory_pids', 'DEVICE_OPEN_DENIED errno=1 major=7 minor=0',
           'LAB_DOCKER_CGROUP_V2_PASS device_read_open_eperm', 'DEVICE_OPEN_ALLOWED errno=0 major=7 minor=0',
           'LAB_DOCKER_CGROUP_V2_PASS explicit_device_read_open_allowed', 'QEMU_DOCKER_CGROUP_V2_COMPLETE']
META_FIELDS = {'kernel_sha256','guardian_sha256','guardian_manifest_sha256','bootstrap_evidence_reuse_sha256'}
PAYLOADS = {}
PACK = None


def require(ok,why):
    if not ok: raise RuntimeError(why)


def digest(data): return hashlib.sha256(data).hexdigest()


def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def fixed(item):
    require(item['sha256'] is not None,'Pending actual guardian/QEMU pin blocks before outputs/signing')
    p=Path(item['path']);require(not p.is_absolute() and '..' not in p.parts,'Fixed relative input')
    data=PACK.read_regular(R/p);require(digest(data)==item['sha256'] and ('bytes' not in item or len(data)==item['bytes']),'Pinned input changed: '+str(p));return data


def ref(path): return {'path':str(path.relative_to(R)),'sha256':digest(PACK.read_regular(path)),'bytes':path.stat().st_size}


def jref(item): return json.loads(fixed(item))


def module(item,name):
    fixed(item);spec=importlib.util.spec_from_file_location(name,R/item['path']);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod


def load_helpers():
    global PACK
    # This pinned ancestor supplies pure no-follow reads/tree/listing/FIT helpers only.
    p=R/HELPER['path'];require(p.is_file() and not p.is_symlink() and digest(p.read_bytes())==HELPER['sha256'],'Frozen helper source')
    spec=importlib.util.spec_from_file_location('v15_readonly_helpers_for_kernel11_v24',p);PACK=importlib.util.module_from_spec(spec);spec.loader.exec_module(PACK)


def generated(name,value):
    data=(json.dumps(value,indent=2)+'\n').encode();PAYLOADS[name]=data
    return {'path':str((WORK/name).relative_to(R)),'sha256':digest(data),'bytes':len(data)}


def repack_fixed(fit,old,replacements):
    new,record=fit.repack(old,replacements);_,_,locations=fit.fdt(old)
    if ('','timestamp') in locations:
        pos,size=locations[('','timestamp')];data=bytearray(new);data[pos:pos+size]=old[pos:pos+size];new=bytes(data)
    return new,record


def inputs():
    global PAYLOADS
    require(__debug__,'Python -O forbidden')
    require(all(x['sha256'] is not None for x in (GUARD_MANIFEST,GUARD_RECEIPT,GUARD,QEMU)),'Pending actual compile/targeted QEMU; no plan/action')
    PAYLOADS={};fixed(BASE_PACKER);baseline=jref(BASE_STAGE);firmware=jref(BASE_FW);old=fixed(BASE_IMAGE);root=fixed(BASE_ROOT);oldmeta=jref(BASE_META)
    require(baseline['status']=='staged_guardian32_v23_signed_bootfs_successor_local_only' and baseline['module_count']==181
            and baseline['module_inventory_sha256']==MODULES['sha256'] and firmware['stage_manifest']['sha256']==BASE_STAGE['sha256']
            and firmware['image']['sha256']==BASE_IMAGE['sha256'] and baseline['inputs']==oldmeta and baseline['rootfs']['sha256']==BASE_ROOT['sha256'],'Actual V23 baseline receipts')
    fixed(MODULES);PACK.validate_tree(BASE/'root',baseline['inventory'])
    verifier=module(VERIFIER,'kernel11_guardian33_pure_verifier');guardian=verifier.verify_successor(R/GUARD_MANIFEST['path']);receipt=jref(GUARD_RECEIPT);fixed(GUARD);fixed(GUARD_SOURCE)
    require(guardian['identity_only_successor'] is True and guardian['identity_delta']['changed_rows']==0 and guardian['identity_delta']['unchanged_rows']==213
            and guardian['identity_header_sha256']=='5fdc4366c0f7ea248e35ef175351f73de9c00745f7b0947d65cbfd8ee21fe42c'
            and guardian['source_report']==GUARD_SOURCE and guardian['kernel_identity']['image_sha256']==KERNEL['sha256']
            and guardian['guardian_compile_count']==1 and guardian['accept_client_compile_count']==0 and guardian['accept_client_reused'] is True
            and guardian['full_production_loop_validation_passed'] is False and guardian['physical_boot_validated'] is False,'Narrow compiled guardian33 contract')
    require({k:receipt['executable'][k] for k in GUARD}==GUARD and {k:receipt['build_manifest'][k] for k in GUARD_MANIFEST}==GUARD_MANIFEST
            and receipt['deployment_gate_enabled'] is True and receipt['hardware_adapter'] is True and receipt['static_no_interpreter_or_needed'] is True
            and receipt['fixture'] is False and receipt['runtime_accepted'] is False and receipt['flash_accepted'] is False and receipt['metadata_committed']==2,'Trusted unaccepted guardian33 receipt')
    fixed(KERNEL);fixed(VMLINUX);abi=jref(ABI);require(abi['pass'] is True and abi['candidate_vmlinux_sha256']==VMLINUX['sha256'],'Actual protected ABI PASS')
    qemu=jref(QEMU)
    require(qemu['status']=='offline_cgroup_v2_docker_fixture_passed' and qemu['run_count']==1 and set(qemu['checks'])==set(MARKERS)
            and all(qemu['checks'].values()) and qemu['returncode']==0 and qemu['kernel_fault_markers']==[]
            and {k:qemu['inputs']['kernel'][k] for k in KERNEL}==KERNEL
            and qemu['device_accessed'] is False and qemu['physical_network_accessed'] is False,'Actual targeted kernel11 QEMU proof')
    for row in (*qemu['inputs'].values(),qemu['archive'],qemu['serial_log']):
        if isinstance(row,dict) and 'path' in row and 'sha256' in row: fixed(row)
    fixed(DECODER);fixed(DECODER_SOURCE);decoder_ancestry=jref(DECODER_ANCESTRY)
    require(decoder_ancestry['uboot_lzo_exact_kernel_match'] is True and decoder_ancestry['uboot_decoder_source_sha256']==DECODER_SOURCE['sha256'],'Saved decoder ancestry scope')
    fit=module(PACK.FITLIB,'kernel11_v24_frozen_fitlib');images=fit.images(old)
    require(set(images)=={PACK.BOOT_NODE,PACK.ROOT_NODE} and images[PACK.ROOT_NODE][1]==root and digest(images[PACK.BOOT_NODE][1])==firmware['outer']['bootfs_sha256'],'Full V23 image component binding')
    oldboot=images[PACK.BOOT_NODE][1];header,nodes,_=fit.fdt(oldboot)
    require(oldboot[header:header+4]==b'STIF' and len(oldboot[header+4:header+260])==256 and nodes['/images/kernel']['compression']==b'lzo\0','Canonical signed LZO FIT')
    _,outer_nodes,_=fit.fdt(old);config=outer_nodes['/configurations/'+fit.string(outer_nodes['/configurations']['default'])]
    require('loader' not in config and not any('signature' in n for n in outer_nodes),'No loader/outer signature update')
    require(oldmeta['root_init_sha256']=='7572b4aa58a9ab5bf0475dc9d92dc805c6d089e807faeff022b0c30e281aedd2'
            and oldmeta['root_policy']['generation']=='be19000ai-ubuntu26-kernel10-systemd-v1\n' and oldmeta['automatic_boot_commit'] is False,'Frozen root-init/generation/COMMITTED2 scope')
    reuse={'schema':1,'status':'kernel11_guardian33_bootstrap_reuse_plan','baseline_firmware':BASE_FW,'baseline_image':BASE_IMAGE,'baseline_stage':BASE_STAGE,
           'new_guardian_manifest':GUARD_MANIFEST,'new_guardian_receipt':GUARD_RECEIPT,'new_guardian':GUARD,'new_guardian_source':GUARD_SOURCE,
           'kernel':KERNEL,'vmlinux':VMLINUX,'abi':ABI,'targeted_qemu':QEMU,'decoder':DECODER,'decoder_source':DECODER_SOURCE,'decoder_ancestry':DECODER_ANCESTRY,
           'scope':['V23 root-init/policy/generation/fsck/handoff/vendor rc/loader/web and all181 module bytes remain exact.',
                    'Only guardian and boot manifest leaves change; guardian runtime36 and213 file identities are unchanged.',
                    'New kernel11 LZO payload is decoded once using saved decoder, then new boot FIT signature is created/verified.',
                    'Old guardian39+21 and previous image/QEMU proofs keep original hashes; only targeted kernel11 QEMU is new.',
                    'QEMU uses frozen Docker29.8.0/runc1.5.1; installed Docker29.8.2 and real ASUS hardware remain separate physical gates.'],
           'permanent_boot_selection':False,'physical_boot_validated':False}
    reuse_ref=generated('reuse-plan.json',reuse);metadata=copy.deepcopy(oldmeta)
    metadata.update(kernel_sha256=KERNEL['sha256'],guardian_sha256=GUARD['sha256'],guardian_manifest_sha256=GUARD_RECEIPT['sha256'],bootstrap_evidence_reuse_sha256=reuse_ref['sha256'])
    require({k for k in oldmeta.keys()|metadata.keys() if oldmeta.get(k)!=metadata.get(k)}==META_FIELDS,'Exactly four metadata hash fields')
    meta_ref=generated('boot-manifest.expected.json',metadata);expected=copy.deepcopy(baseline['inventory']);delta=[]
    for n,d in [(PACK.GUARD_PATH,GUARD['sha256']),(PACK.META_PATH,meta_ref['sha256'])]:
        before=copy.deepcopy(expected[n]);mode=0o755 if n==PACK.GUARD_PATH else 0o644
        require(before['kind']==stat.S_IFREG and before['mode']==mode and (BASE/'root'/n).lstat().st_nlink==1,'Frozen changed single-link leaf')
        expected[n]={**before,'sha256':d};delta.append({'path':n,'before':before,'after':expected[n]})
    require({n for n in expected if expected[n]!=baseline['inventory'][n]}==PACK.CHANGES,'Exactly two bootstrap leaves')
    tools={**PACK.TOOLS,**EXTRA_TOOLS}
    for item in tools.values(): require(digest(PACK.read_regular(Path(item['path'])))==item['sha256'] and os.access(item['path'],os.X_OK),'Pinned host tool')
    plan={'schema':1,'status':'kernel11_guardian33_v24_pack_plan_only','builder':ref(Path(__file__)),'frozen_helpers':HELPER,'baseline_packer':BASE_PACKER,
          'baseline_firmware':BASE_FW,'baseline_image':BASE_IMAGE,'baseline_stage':BASE_STAGE,'baseline_rootfs':BASE_ROOT,'old_boot_manifest':BASE_META,
          'guardian_verifier':VERIFIER,'guardian_manifest':GUARD_MANIFEST,'guardian_receipt':GUARD_RECEIPT,'guardian':GUARD,'guardian_source':GUARD_SOURCE,
          'kernel':KERNEL,'vmlinux':VMLINUX,'abi':ABI,'targeted_qemu':QEMU,'decoder':DECODER,'decoder_source':DECODER_SOURCE,'decoder_ancestry':DECODER_ANCESTRY,
          'tools':tools,'tool_environment':PACK.TOOL_ENV,'signing_key_path':str(KEY.relative_to(R)),'signing_public_der_sha256':PUBLIC_DER_SHA,
          'expected_boot_manifest':metadata,'changed_boot_manifest_fields':sorted(META_FIELDS),'changed_paths':sorted(PACK.CHANGES),'expected_root_inventory_delta':delta,
          'baseline_inventory_sha256':digest(canonical(baseline['inventory'])),'expected_inventory_sha256':digest(canonical(expected)),
          'generated_payloads':{'reuse_plan':reuse_ref,'boot_manifest':meta_ref},'future_outputs':{'stage':str(STAGE.relative_to(R)),'work':str(WORK.relative_to(R)),'image':str(IMAGE.relative_to(R))},
          'mksquashfs_argv':[tools['mksquashfs']['path'],str(STAGE/'root'),str(STAGE/'bootstrap.zstd.squashfs'),'-noappend','-all-root','-comp','zstd','-Xcompression-level','22','-b','524288','-processors','12','-no-progress'],
          'original_timestamps_preserved':True,'archive_inode_count':4372,'packed_uid_gid_all_zero':True,'guardian_compile_in_packer':0,'decoder_compile_count':0,
          'decoder_new_kernel_run_count':1,'decoder_old_kernel_run_count':0,'new_signature_count':1,'old_tests_replayed':False,
          'hardware_validated':False,'flash_accepted':False,'device_modified':False,'automatic_boot_commit':False,'failure_retained_no_retry':True,'reuse_scope':reuse['scope']}
    return plan,baseline,expected,firmware,fit,old,oldboot


def command(argv,log,input_data=None,output=None,timeout=300):
    PACK.absent(log)
    if output is not None: PACK.absent(output)
    with log.open('xb') as stream:
        if output is None:
            proc=subprocess.run(argv,cwd=R,env=PACK.TOOL_ENV,input=input_data,stdout=stream,stderr=subprocess.STDOUT,timeout=timeout)
        else:
            with output.open('xb') as out:
                proc=subprocess.run(argv,cwd=R,env=PACK.TOOL_ENV,input=input_data,stdout=out,stderr=stream,timeout=timeout);out.flush();os.fsync(out.fileno())
        stream.flush();os.fsync(stream.fileno())
    require(proc.returncode==0,'Sole host command failed: '+argv[0])
    value={'argv':argv,'returncode':proc.returncode,'log':ref(log)}
    if output is not None: value['stdout_file']=ref(output)
    return value


def artifact_check(verified):
    plan,baseline,expected,firmware,fit,old,oldboot=verified
    PACK.validate_tree(STAGE/'root',expected);PACK.validate_tree(WORK/'packed-readback',expected)
    data=PACK.read_regular(STAGE/'bootstrap.zstd.squashfs');listing=PACK.packed_metadata(PACK.read_regular(STAGE/'packed-inventory.txt').decode(),expected)
    require(data[:4]==b'hsqs' and struct.unpack_from('<I',data,12)[0]==524288 and struct.unpack_from('<H',data,20)[0]==6 and len(data)<200*1024**2,'Packed zstd/block root')
    require(PACK.read_regular(WORK/'decoded-Image')==fixed(KERNEL),'New decoder exact kernel bytes')
    compressed=PACK.read_regular(WORK/'kernel.lzo');newboot=PACK.read_regular(WORK/'bootfs.itb')
    rebuilt,inner=repack_fixed(fit,oldboot,{'/images/kernel':compressed});header,_,_=fit.fdt(rebuilt)
    signature=PACK.read_regular(WORK/'signature');require(len(signature)==256,'RSA2048 signature bytes')
    rebuilt=rebuilt[:header+4]+signature+rebuilt[header+260:]
    require(rebuilt==newboot and PACK.read_regular(WORK/'header')==newboot[:header]
            and PACK.read_regular(WORK/'old-header')==oldboot[:header] and PACK.read_regular(WORK/'old-signature')==oldboot[header+4:header+260],'Exact header/signature FIT reconstruction')
    oldinner,newinner=fit.images(oldboot),fit.images(newboot);require(oldinner.keys()==newinner.keys() and newinner['/images/kernel'][1]==compressed,'Inner kernel replacement')
    require(all(newinner[n][1]==oldinner[n][1] for n in oldinner if n!='/images/kernel'),'All nonkernel inner payload bytes exact')
    packed,outer=repack_fixed(fit,old,{PACK.BOOT_NODE:newboot,PACK.ROOT_NODE:data});require(PACK.read_regular(IMAGE)==packed,'Exact whole two-payload firmware readback')
    public=PACK.read_regular(WORK/'public.der');require(digest(public)==PUBLIC_DER_SHA,'Actual signing public key')
    require(PACK.read_regular(STAGE/'services-start.candidate')==PACK.read_regular(BASE/'services-start.candidate'),'Unapplied hook exact')
    return {'bootfs_sha256':digest(newboot),'bootfs_bytes':len(newboot),'rootfs_sha256':digest(data),'rootfs_bytes':len(data),
            'kernel_payload_sha256':digest(compressed),'nonkernel_boot_payloads_unchanged':True,'has_loader_update':False,
            'original_timestamps_preserved':True,'new_signature_verified':True,'original_signature_verified':True,
            'signing_public_der_sha256':PUBLIC_DER_SHA,'uboot_lzo_exact_kernel_match':True,'packed_metadata':listing,'inner':inner,'outer':{'bootfs_sha256':digest(newboot),'rootfs_sha256':digest(data),'bootfs_bytes':len(newboot),'rootfs_bytes':len(data),'entire_signed_bootfs_byte_identical':False,'new_signature_operation':True,'repack_record':outer}}


def execute(verified,gate,key):
    plan,baseline,expected,firmware,fit,old,oldboot=verified
    require(digest(canonical(plan))==gate,'Exact reviewed plan SHA required')
    require(key is not None and str(key)==str(KEY) and KEY.is_file() and not KEY.is_symlink(),'Exact existing signing key path required only for execute')
    for p in (STAGE,WORK,IMAGE): PACK.absent(p);require(p.parent.is_dir() and not p.parent.is_symlink(),'Exclusive output parent')
    STAGE.mkdir(mode=0o755);WORK.mkdir(mode=0o755);commands=[]
    try:
        for n,data in PAYLOADS.items(): PACK.create_file(WORK/n,data,0o444)
        commands.append(command([plan['tools']['cp']['path'],'-a','--',str(BASE/'root'),str(STAGE/'root')],WORK/'copy-stage.log'))
        PACK.validate_tree(STAGE/'root',baseline['inventory'])
        for n,data,mode in [(PACK.GUARD_PATH,fixed(GUARD),0o755),(PACK.META_PATH,PAYLOADS['boot-manifest.expected.json'],0o644)]:
            path=STAGE/'root'/n;info=path.lstat();require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==mode,'Copied fixed leaf')
            with path.open('wb') as stream: stream.write(data);stream.flush();os.fsync(stream.fileno())
            path.chmod(mode)
        PACK.validate_tree(STAGE/'root',expected);PACK.create_file(STAGE/'services-start.candidate',PACK.read_regular(BASE/'services-start.candidate'),0o755)
        commands.append(command(plan['mksquashfs_argv'],WORK/'mksquashfs.log',timeout=600))
        root=STAGE/'bootstrap.zstd.squashfs';commands.append(command([plan['tools']['unsquashfs']['path'],'-lln',str(root)],STAGE/'packed-inventory.txt'))
        previous=os.umask(0)
        try: commands.append(command([plan['tools']['unsquashfs']['path'],'-no-progress','-processors','12','-d',str(WORK/'packed-readback'),str(root)],WORK/'packed-readback.log'))
        finally: os.umask(previous)
        PACK.validate_tree(WORK/'packed-readback',expected)
        header,_,_=fit.fdt(oldboot);PACK.create_file(WORK/'old-header',oldboot[:header]);PACK.create_file(WORK/'old-signature',oldboot[header+4:header+260])
        openssl=plan['tools']['openssl']['path'];commands.append(command([openssl,'pkey','-in',str(KEY),'-pubout','-out',str(WORK/'public.pem')],WORK/'public-pem.log'))
        commands.append(command([openssl,'pkey','-pubin','-in',str(WORK/'public.pem'),'-outform','DER'],WORK/'public-der.log',output=WORK/'public.der'))
        require(digest(PACK.read_regular(WORK/'public.der'))==PUBLIC_DER_SHA,'Unexpected signing public DER')
        verify=[openssl,'dgst','-sha256','-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:-1','-verify',str(WORK/'public.pem')]
        commands.append(command(verify+['-signature',str(WORK/'old-signature'),str(WORK/'old-header')],WORK/'old-signature-verify.log'))
        commands.append(command([plan['tools']['lzop']['path'],'-9','-c'],WORK/'lzop.log',input_data=fixed(KERNEL),output=WORK/'kernel.lzo'))
        commands.append(command([str(R/DECODER['path']),str(WORK/'kernel.lzo'),str(WORK/'decoded-Image')],WORK/'decoder.log'))
        require(PACK.read_regular(WORK/'decoded-Image')==fixed(KERNEL),'BSP decoder exact new kernel match')
        newboot,inner=repack_fixed(fit,oldboot,{'/images/kernel':PACK.read_regular(WORK/'kernel.lzo')});newheader,_,_=fit.fdt(newboot)
        require(newheader==header and newboot[header:header+4]==b'STIF','Unchanged inner header/STIF shape');PACK.create_file(WORK/'header',newboot[:header])
        require(inputs()[0]==plan,'Inputs changed before signature publication')
        commands.append(command([openssl,'dgst','-sign',str(KEY),'-sha256','-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:-1','-out',str(WORK/'signature'),str(WORK/'header')],WORK/'sign.log'))
        signature=PACK.read_regular(WORK/'signature');require(len(signature)==256,'Fixed signature length');newboot=newboot[:header+4]+signature+newboot[header+260:]
        commands.append(command(verify+['-signature',str(WORK/'signature'),str(WORK/'header')],WORK/'new-signature-verify.log'))
        PACK.create_file(WORK/'bootfs.itb',newboot);packed,outer=repack_fixed(fit,old,{PACK.BOOT_NODE:newboot,PACK.ROOT_NODE:PACK.read_regular(root)})
        require(len(newboot)<50*1024**2,'Bounded bootfs payload');PACK.create_file(IMAGE,packed)
        actual=artifact_check(verified);require(inputs()[0]==plan,'Source inputs changed during pack')
        stage={'schema_version':1,'status':'staged_kernel11_guardian33_v24_local_only','builder':ref(Path(__file__)),'execution_plan_sha256':gate,
               'baseline_stage':BASE_STAGE,'guardian_manifest':GUARD_MANIFEST,'guardian_receipt':GUARD_RECEIPT,'inputs':plan['expected_boot_manifest'],
               'rootfs':ref(root),'inventory':expected,'changed_entries':plan['expected_root_inventory_delta'],'packed_metadata':actual['packed_metadata'],
               'packed_listing':ref(STAGE/'packed-inventory.txt'),'packed_readback_inventory_sha256':digest(canonical(expected)),
               'module_count':181,'module_inventory_sha256':baseline['module_inventory_sha256'],'unapplied_jffs_hook':ref(STAGE/'services-start.candidate'),
               'root_init_rebuilt':False,'hardware_validated':False,'flash_accepted':False,'device_modified':False,'automatic_boot_commit':False}
        PACK.write_json(STAGE/'manifest.json',stage)
        result={'schema_version':1,'status':'kernel11_guardian33_v24_locally_signed_not_flash_accepted','builder':ref(Path(__file__)),'execution_plan_sha256':gate,
                'image':ref(IMAGE),'stage_manifest':ref(STAGE/'manifest.json'),'guardian_manifest':GUARD_MANIFEST,'guardian_receipt':GUARD_RECEIPT,
                'baseline_signed_firmware':BASE_FW,'baseline_signed_image':BASE_IMAGE,'kernel_sha256':KERNEL['sha256'],'vmlinux_sha256':VMLINUX['sha256'],
                'kernel_abi':ABI,'targeted_qemu':QEMU,'module_count':181,'unapplied_jffs_hook':stage['unapplied_jffs_hook'],**actual,
                'commands':commands,'decoder':DECODER,'decoder_source':DECODER_SOURCE,'decoder_ancestry':DECODER_ANCESTRY,
                'reuse_plan':plan['generated_payloads']['reuse_plan'],'root_init_rebuilt':False,'kernel_rebuilt':False,'decoder_compiled':False,
                'decoder_new_kernel_run_count':1,'decoder_old_kernel_run_count':0,'new_signature_operation':True,'new_signature_count':1,
                'private_signing_key_read_by_openssl_only':True,'new_targeted_kernel_qemu_performed':True,'new_exact_firmware_qemu_performed':False,
                'old_tests_replayed':False,'hardware_validated':False,'flash_accepted':False,'device_modified':False,'trial_only':True,'automatic_boot_commit':False,
                'limits':plan['reuse_scope']}
        PACK.write_json(WORK/'plan.json',plan);PACK.write_json(WORK/'manifest.json',result);verify_outputs()
        print(json.dumps({'status':result['status'],'image':result['image'],'manifest':ref(WORK/'manifest.json'),'stage_manifest':ref(STAGE/'manifest.json')}),flush=True)
    except Exception as exc:
        if not (WORK/'failure.json').exists(): PACK.write_json(WORK/'failure.json',{'status':'failed_pack_evidence_retained_no_retry','builder':ref(Path(__file__)),'approved_plan_sha256':gate,
            'error':str(exc),'completed_commands':commands,'device_accessed':False,'old_tests_replayed':False})
        raise


def verify_outputs():
    """Pure file-read proof of the actual newly signed artifact; no tools run."""
    if PACK is None: load_helpers()
    verified=inputs();plan,baseline,expected,firmware,fit,old,oldboot=verified;gate=digest(canonical(plan))
    stage=jref(ref(STAGE/'manifest.json'));result=jref(ref(WORK/'manifest.json'));actual=artifact_check(verified)
    require(stage['status']=='staged_kernel11_guardian33_v24_local_only' and result['status']=='kernel11_guardian33_v24_locally_signed_not_flash_accepted'
            and stage['builder']==result['builder']==plan['builder'] and stage['execution_plan_sha256']==result['execution_plan_sha256']==gate,'Fixed actual source/plan/status')
    require(jref(ref(WORK/'plan.json'))==plan and stage['inventory']==expected and stage['inputs']==plan['expected_boot_manifest']
            and stage['changed_entries']==plan['expected_root_inventory_delta'] and stage['packed_readback_inventory_sha256']==digest(canonical(expected)),'Exact packed inventory/metadata')
    require(stage['rootfs']==ref(STAGE/'bootstrap.zstd.squashfs') and stage['packed_listing']==ref(STAGE/'packed-inventory.txt')
            and stage['packed_metadata']==actual['packed_metadata'] and result['stage_manifest']==ref(STAGE/'manifest.json') and result['image']==ref(IMAGE),'Actual artifact receipt hashes')
    for k,v in actual.items(): require(result[k]==v,'Actual FIT/decoder/signature reconstruction: '+k)
    for n,data in PAYLOADS.items(): require(PACK.read_regular(WORK/n)==data,'Exact generated local payload: '+n)
    for row in result['commands']:
        require(row['returncode']==0 and ref(R/row['log']['path'])==row['log'],'Actual sole host command log')
        if 'stdout_file' in row: require(ref(R/row['stdout_file']['path'])==row['stdout_file'],'Actual command stdout file')
    expected_argv=[[plan['tools']['cp']['path'],'-a','--',str(BASE/'root'),str(STAGE/'root')],plan['mksquashfs_argv'],
                   [plan['tools']['unsquashfs']['path'],'-lln',str(STAGE/'bootstrap.zstd.squashfs')],
                   [plan['tools']['unsquashfs']['path'],'-no-progress','-processors','12','-d',str(WORK/'packed-readback'),str(STAGE/'bootstrap.zstd.squashfs')],
                   [plan['tools']['openssl']['path'],'pkey','-in',str(KEY),'-pubout','-out',str(WORK/'public.pem')],
                   [plan['tools']['openssl']['path'],'pkey','-pubin','-in',str(WORK/'public.pem'),'-outform','DER']]
    verify=[plan['tools']['openssl']['path'],'dgst','-sha256','-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:-1','-verify',str(WORK/'public.pem')]
    expected_argv += [verify+['-signature',str(WORK/'old-signature'),str(WORK/'old-header')],[plan['tools']['lzop']['path'],'-9','-c'],
                      [str(R/DECODER['path']),str(WORK/'kernel.lzo'),str(WORK/'decoded-Image')],
                      [plan['tools']['openssl']['path'],'dgst','-sign',str(KEY),'-sha256','-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:-1','-out',str(WORK/'signature'),str(WORK/'header')],
                      verify+['-signature',str(WORK/'signature'),str(WORK/'header')]]
    require([x['argv'] for x in result['commands']]==expected_argv,'Exactly four archive commands, two public exports, two signature verifies, one compression/decode/sign')
    require(result['kernel_sha256']==KERNEL['sha256'] and result['kernel_abi']==ABI and result['targeted_qemu']==QEMU
            and result['guardian_manifest']==GUARD_MANIFEST and result['guardian_receipt']==GUARD_RECEIPT and result['module_count']==181,'Current kernel/guardian/ABI/QEMU closure')
    for report in (stage,result): require(all(report[k] is False for k in ('root_init_rebuilt','hardware_validated','flash_accepted','device_modified','automatic_boot_commit')),'No physical/permanent acceptance claim')
    require(result['decoder_compiled'] is False and result['decoder_new_kernel_run_count']==1 and result['decoder_old_kernel_run_count']==0
            and result['new_signature_operation'] is True and result['new_signature_count']==1 and result['old_tests_replayed'] is False
            and result['new_exact_firmware_qemu_performed'] is False,'Truthful narrow packaging actions')
    require({p.name for p in STAGE.iterdir()}=={'root','bootstrap.zstd.squashfs','services-start.candidate','packed-inventory.txt','manifest.json'},'Exact stage inventory')
    known={'reuse-plan.json','boot-manifest.expected.json','copy-stage.log','mksquashfs.log','packed-readback.log','packed-readback','old-header','old-signature',
           'public.pem','public.der','public-pem.log','public-der.log','old-signature-verify.log','lzop.log','kernel.lzo','decoder.log','decoded-Image','header','signature','sign.log',
           'new-signature-verify.log','bootfs.itb','plan.json','manifest.json'}
    require({p.name for p in WORK.iterdir()}==known,'Exact new packaging output inventory');return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group();group.add_argument('--execute-plan-sha256');group.add_argument('--verify-only',action='store_true');parser.add_argument('--key',type=Path);args=parser.parse_args()
    load_helpers();verified=inputs();plan=verified[0];gate=digest(canonical(plan))
    if args.execute_plan_sha256: execute(verified,args.execute_plan_sha256,args.key)
    elif args.verify_only:
        require(args.key is None,'No key for pure verifier');result=verify_outputs();print(json.dumps({'status':'kernel11_guardian33_v24_file_verification_passed','manifest':ref(WORK/'manifest.json'),'image':result['image']}))
    else:
        require(args.key is None,'Default plan does not inspect signing key');print(json.dumps({'status':'source_only_no_output_written','execution_plan_sha256':gate,'plan':plan},indent=2))


if __name__=='__main__': main()

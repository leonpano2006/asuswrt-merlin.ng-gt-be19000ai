#!/usr/bin/env python3
"""Two fixed file replacements using the already tested guarded transaction."""
import hashlib,json,re,shutil,subprocess,tarfile,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
BASE=R/'build/ubuntu26-bsp-update/native-v2'
NATIVE=R/'build/ubuntu26-bsp-license/native-v1'
OUT=R/'build/ubuntu26-bsp-license/update-v1'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def source_bindings(previous):
    expected={}
    for row in previous['sources']:
        relative=Path(row['path']);assert not relative.is_absolute() and '..' not in relative.parts
        original=R/relative
        assert original.is_file() and not original.is_symlink() and sha(original)==row['sha256']
        name='hardware-provision.c' if row['path']=='build/ubuntu26-hardware-order/native-v1/source/provision.c' else original.name
        assert name not in expected;expected[name]=row['sha256']
    payload=previous['embedded_payload_header']
    assert payload['path']==str((BASE/'source/bsp-payload.h').relative_to(R))
    expected['bsp-payload.h']=payload['sha256']
    for row in previous['required_bsp_resources']:
        name='resources/'+Path(row['path']).name
        assert name not in expected or expected[name]==row['sha256']
        expected[name]=row['sha256']
    actual={}
    for path in (BASE/'source').rglob('*'):
        assert not path.is_symlink()
        if path.is_dir():continue
        assert path.is_file()
        actual[path.relative_to(BASE/'source').as_posix()]=sha(path)
    assert actual==expected
    environment=previous['native_build_environment']
    assert environment['path']=='build/asus-native-build/v2/result.json' and sha(R/environment['path'])==environment['sha256']
    return expected
def main():
    if not __debug__:raise RuntimeError('Python -O forbidden')
    assert sha(BASE/'manifest.json')=='3f993744f1586f29d255ca190eb1d2e06b1205ac959a9a266a41521b85a4322a'
    assert sha(NATIVE/'manifest.json')=='8adeac0ec59260ab8b41d26d5043ebf716b387458423635eeb0deafbc522a0ec'
    previous=json.loads((BASE/'manifest.json').read_text());new=json.loads((NATIVE/'manifest.json').read_text())
    assert new['status']=='bsp_license_helpers_focused_checks_passed'
    bindings=source_bindings(previous)
    OUT.mkdir(parents=True,exist_ok=False)
    inputs=Path(tempfile.mkdtemp(prefix='bsp-license-update-'));inputs.chmod(0o755)
    source=(BASE/'source/provision.c').read_text()
    # Preserve every device, mount and transaction instruction. Only the fixed
    # leaf names/digests, embedded bytes and CLI/result label change per build.
    old_definition='#define BSP_OLD_SHA "f51beb4faf20bac73df894a7752b385a06436967d782e3c264e48416e24ddbc9"'
    assert source.count(old_definition)==1
    for key in ['transaction_log_reused','transaction_evidence_reused','reused_guard_and_preservation']:
        row=previous[key];assert sha(R/row['path'])==row['sha256']
    root07=R/'build/ubuntu26-rootfs/ubuntu26-bcm-asus-runtime07-archive-sealed-v1.tar'
    members={}
    with tarfile.open(root07,'r:') as tar:
        for item in tar:
            name=item.name.removeprefix('./')
            if name not in ['usr/libexec/asus/etc-launch','usr/libexec/asus/bsp-runner']:continue
            assert name not in members and item.isfile() and item.uid==item.gid==0 and item.mode==0o755
            members[name]=hashlib.sha256(tar.extractfile(item).read()).hexdigest()
    assert len(members)==2
    variants=[]
    for name in ['etc-launch','bsp-runner']:
        old=new['old_binaries'][name];binary=new['binaries'][name]
        assert sha(R/old['path'])==old['sha256'] and sha(R/binary['path'])==binary['sha256']
        assert members['usr/libexec/asus/'+name]==old['sha256']
        stage=inputs/name;shutil.copytree(BASE/'source',stage)
        generated=source.replace('#define BSP_NAME "bsp-ownership"','#define BSP_NAME '+json.dumps(name))
        generated=generated.replace('#define BSP_TEMP "bsp-ownership.leon-update"','#define BSP_TEMP '+json.dumps(name+'.leon-update'))
        generated=generated.replace(old_definition,'#define BSP_OLD_SHA '+json.dumps(old['sha256']))
        generated=generated.replace('--update-bsp-ownership','--update-fixed-asus-helper').replace('bsp_ownership_updated','fixed_asus_helper_updated')
        assert generated!=source
        for function in ['bsp_parent','bsp_file','bsp_update']:
            pattern=r'static int '+function+r'\([^\n]*\) \{.*?\n\}'
            assert re.findall(pattern,generated,re.S)==re.findall(pattern,source,re.S)
        # Check all remaining bytes by reversing the five literal substitutions.
        restored=generated.replace('#define BSP_NAME '+json.dumps(name),'#define BSP_NAME "bsp-ownership"').replace('#define BSP_TEMP '+json.dumps(name+'.leon-update'),'#define BSP_TEMP "bsp-ownership.leon-update"')
        restored=restored.replace('#define BSP_OLD_SHA '+json.dumps(old['sha256']),old_definition).replace('--update-fixed-asus-helper','--update-bsp-ownership').replace('fixed_asus_helper_updated','bsp_ownership_updated')
        assert restored==source
        (stage/'provision.c').write_text(generated)
        payload=(R/binary['path']).read_bytes();assert 64<=len(payload)<=16*1024*1024
        header='#define BSP_NEW_SHA '+json.dumps(binary['sha256'])+'\nstatic const unsigned char bsp_payload[]={\n'
        header+='\n'.join(','.join('0x%02x'%byte for byte in payload[i:i+16])+',' for i in range(0,len(payload),16))+'\n};\n'
        (stage/'bsp-payload.h').write_text(header)
        snapshot=OUT/name/'source';shutil.copytree(stage,snapshot)
        variants.append({'name':name,'old_binary':old,'new_binary':binary,'source':ref(snapshot/'provision.c'),'payload_header':ref(snapshot/'bsp-payload.h'),'unchanged_transaction_functions':True,'only_five_literal_substitutions':True})
    env=R/'build/asus-native-build/v2/result.json';root=Path(json.loads(env.read_text())['root'])
    worker=r'''set -euo pipefail
root="$1"; inputs="$2"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/bsp-license-update-v1"
cp -r "$inputs"/. "$root/work/bsp-license-update-v1/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now)
for name in etc-launch bsp-runner; do
 cd "/work/bsp-license-update-v1/$name"
 ccache gcc-16 "${flags[@]}" provision.c slot-proof.c sha256.c -o updater
 ./updater --invalid > badargs.stdout 2>badargs.stderr && exit 1 || test "$?" = 64
 test ! -s badargs.stdout && test ! -s badargs.stderr
 ./updater --update-fixed-asus-helper aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 11111111-2222-3333-4444-555555555555 >nondevice.stdout 2>nondevice.stderr && exit 1 || test "$?" = 1
 test ! -s nondevice.stdout
 grep -Fx 'LEON_BSP_UPDATE_REFUSED stage=stock-root-and-native-namespace temporary_created=0 published=0 retained_for_review=true' nondevice.stderr
 readelf -h -l -d updater > elf.txt
done
BUILD
'''
    (inputs/'build.sh').write_text(worker)
    with (OUT/'build.log').open('w') as log:subprocess.run(['mmdebstrap','--unshare-helper','bash',str(inputs/'build.sh'),str(root),str(inputs)],stdout=log,stderr=subprocess.STDOUT,check=True)
    for row in variants:
        stage=root/'work/bsp-license-update-v1'/row['name'];out=OUT/row['name']
        for name in ['updater','elf.txt','badargs.stdout','badargs.stderr','nondevice.stdout','nondevice.stderr']:
            shutil.copyfile(stage/name,out/name);(out/name).chmod(0o755 if name=='updater' else 0o644)
        assert 'INTERP' not in (out/'elf.txt').read_text() and 'AArch64' in (out/'elf.txt').read_text()
        row['updater']=ref(out/'updater');row['outputs']=[ref(out/name) for name in ['updater','elf.txt','badargs.stdout','badargs.stderr','nondevice.stdout','nondevice.stderr']]
    record={'schema':1,'status':'two_fixed_helper_updaters_built_exact_transaction_reused','variants':variants,'baseline':ref(BASE/'manifest.json'),'new_helpers':ref(NATIVE/'manifest.json'),
            'reused_transaction_evidence':previous['transaction_evidence_reused'],'reused_transaction_log':previous['transaction_log_reused'],'transaction_cases_reused':15,'resource_cases_reused':5,
            'fresh_checks':'Each static ELF, invalid args64, nondevice refusal1; exact five literal substitutions and exact unchanged three transaction function bodies.',
            'root07_member_hashes':members,'builder':ref(Path(__file__)),'frozen_source_bindings':bindings,'device_operated':False,'boot_metadata_changed':False,'git_commit_or_push':False,
            'usage':'Each fixed updater --update-fixed-asus-helper <fresh metadata SHA> <current stock2 boot UUID>; one target per binary. Sequential atomic file replacements, no claim of atomic pair publication.',
            'limits':['Admin overlay; dpkg package database not updated.','Unchanged frozen storage guard, token/diagnostic/resolver/hardware/private-insmod preservation checks retained.','No target execution, flash, boot selection, reboot or commit in updater.']}
    (OUT/'manifest.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'manifest':ref(OUT/'manifest.json'),'updaters':[{k:row[k] for k in ['name','updater']} for row in variants]}))
if __name__=='__main__':main()

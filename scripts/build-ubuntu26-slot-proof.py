#!/usr/bin/env python3
"""Build fixed-device static slot proof helper; test synthetic files only."""
import argparse,hashlib,json,re,shutil,subprocess,tempfile,uuid
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/slot-proof'
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def ref(path):return {'path':str(path.relative_to(R)),'sha256':sha(path)}
def main():
    if not __debug__:raise RuntimeError('optimized Python would disable fixed source policy gates')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);a=p.parse_args()
    assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
    out=R/'build/ubuntu26-slot-proof'/a.label;out.mkdir(parents=True,exist_ok=False)
    inputs=Path(tempfile.mkdtemp(prefix='ubuntu26-slot-proof-'));inputs.chmod(0o755)
    snapshot=out/'source-snapshot';snapshot.mkdir(mode=0o755)
    manifest=R/'build/ubuntu26-gpt-candidate/v1/manifest.json'
    assert sha(manifest)=='60d2b71c6ed8560c311b4b3bd458a09868a025439a22776e08b3beef533c6a12'
    plan=json.loads(manifest.read_text());parts=plan['existing_entries_preserved_byte_for_byte']+[{'number':11,'start':26849280,'end':52015103}]
    fs={7:('b2779970-ea82-4aec-96ed-816e1aac53a0','/data'),8:('b33c1d3a-f5a1-4beb-b0fe-edfdecba957d','/tmp/mnt/defaults'),9:('7575e860-48ee-493e-bb5b-a1ca270b8512','/jffs'),10:('d6754055-3be0-4b1d-8dc4-3c3bb8493fbe','/ai'),11:('ea8e47b8-c606-406c-b931-d2244d26ec55','')}
    lines=['/* Fixed GPT candidate; no fresh metadata digest is embedded. */','#ifndef LEON_SLOT_DEVICE_POLICY_H','#define LEON_SLOT_DEVICE_POLICY_H','#include <stdint.h>',
        '#define SLOT_PRIMARY_GPT_SHA "a3d196fc60df1a2bec67518dfed09e6221a28174ef46b52960a01b01ad618c43"',
        '#define SLOT_BACKUP_GPT_SHA "6ab2bc3a8ad5ff4d500cce84fe202e1ecef818c3da2455db095621e1fc87f86a"',
        'struct slot_partition {uint64_t start,sectors;const char *mountpoint;unsigned char uuid[16];};','static const struct slot_partition slot_parts[]={']
    for entry in parts:
        n=entry['number'];raw=uuid.UUID(fs[n][0]).bytes if n in fs else bytes(16);mount=fs.get(n,('',''))[1]
        lines.append('{UINT64_C(%d),UINT64_C(%d),%s,{%s}},'%(entry['start'],entry['end']-entry['start']+1,json.dumps(mount),','.join(hex(x) for x in raw)))
    lines+=['};','#endif'];(out/'slot-device-policy.h').write_text('\n'.join(lines)+'\n')
    sources=[S/n for n in ['slot-proof.h','slot-proof.c','device.c','fixture.c','p11-clear-view.h','clear-view-fixture.c']]+[R/'scripts/asus-integration/trial-guard/runtime/sha256-compat.h',R/'build/asus-trial-runtime/native-v15/sha256.c',out/'slot-device-policy.h']
    for source in sources:shutil.copyfile(source,inputs/source.name);shutil.copyfile(source,snapshot/source.name)
    root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
    worker=r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/slot-proof-$label"
cp "$inputs"/*.[ch] "$root/work/slot-proof-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/slot-proof-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -static-pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" slot-proof.c device.c sha256.c -o slot-proof-device
ccache gcc-16 "${flags[@]}" -DLEON_SLOT_TEST slot-proof.c fixture.c sha256.c -o slot-proof-fixture
ccache gcc-16 "${flags[@]}" clear-view-fixture.c -o clear-view-fixture
./clear-view-fixture > clear-view-fixture.log
./slot-proof-fixture > fixture.log
grep -Fx 'LEON_SLOT_PROOF_FIXTURE_PASS cases=36' fixture.log
./slot-proof-device --invalid > badargs.log 2>&1 && exit 1 || test "$?" = 64
test ! -s badargs.log
./slot-proof-device --create-slot-proof aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 11111111-2222-3333-4444-555555555555 > nondevice.log 2>&1 && exit 1 || test "$?" = 1
grep -Fx 'LEON_SLOT_PROOF_REFUSED stage=stock-root-and-native-namespace token_stage=none published=0' nondevice.log
readelf -h -l -d slot-proof-device > elf.txt
gcc-16 --version > compiler.txt
BUILD
'''
    (inputs/'build.sh').write_text(worker)
    with (out/'build.log').open('w') as log:
        result=subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(inputs/'build.sh'),str(root),str(inputs),a.label],stdout=log,stderr=subprocess.STDOUT)
    if result.returncode:raise SystemExit('build failed: '+str(out/'build.log'))
    stage=root/('work/slot-proof-'+a.label)
    for name in ['slot-proof-device','slot-proof-fixture','clear-view-fixture','clear-view-fixture.log','fixture.log','badargs.log','nondevice.log','elf.txt','compiler.txt']:
        shutil.copyfile(stage/name,out/name);(out/name).chmod(0o755 if name.startswith('slot-proof-') or name=='clear-view-fixture' else 0o644)
    assert 'INTERP' not in (out/'elf.txt').read_text() and 'AArch64' in (out/'elf.txt').read_text()
    cases=[x[5:] for x in (out/'fixture.log').read_text().splitlines() if x.startswith('PASS ')]
    receipt={'schema':1,'status':'static_helper_built_and_synthetic_transaction_passed','production_ready':False,
        'device_connections':0,'physical_block_writes':0,'physical_mounts':0,'boot_metadata_writes':0,'armed':False,'rebooted':False,'boot_committed':False,
        'sources':[ref(x) for x in sources],'source_snapshot':str(snapshot.relative_to(R)),
        'outputs':[ref(out/n) for n in ['slot-proof-device','slot-proof-fixture','clear-view-fixture','clear-view-fixture.log','fixture.log','nondevice.log','elf.txt','compiler.txt']],
        'fixture_cases':cases,'fixture_case_count':len(cases),'clear_view_cases':[x[5:] for x in (out/'clear-view-fixture.log').read_text().splitlines() if x.startswith('PASS ')],'fresh_metadata_expected_sha_source':'Required explicit host-reviewed postflash digest argument; never a baked-in metadata digest.',
        'compile_flags':'native GCC16.2 static PIE, cortex-a53+crypto+crc, time64/off64, stack protector, FORTIFY3',
        'only_new_root_writes':['/etc/leon/.trial-slot-proof.<random> transient staging','/etc/leon/trial-slot-proof atomic no-overwrite publication'],
        'shared_lock':'/tmp/leon-device-identity.lock','limitations':['Synthetic transaction runs in user/mount/network namespaces on new regular directories only; no real p11 mount or hardware preflight was exercised.',
            'Private ext4 mounting can update filesystem journal/metadata; no other payload file is written.',
            'Any existing token or leftover staging token requires explicit review; this helper never overwrites it.',
            'After publication/fsync failure the token remains and the command fails, with published=1; no silent retry or boot acceptance.',
            'Advisory lock does not exclude unrelated firmware writers or mounts; caller must provide exclusive maintenance.'],'builder_sha256':sha(Path(__file__))}
    (out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n');print(str(out/'manifest.json'))
if __name__=='__main__':main()

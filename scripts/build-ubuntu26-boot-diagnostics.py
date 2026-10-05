#!/usr/bin/env python3
"""Build the fixed stock-side diagnostics provisioner. No device execution."""
import argparse,hashlib,json,re,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/boot-diagnostics'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
    if not __debug__:raise RuntimeError('Python -O forbidden')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);p.add_argument('--reuse-format-manifest',type=Path);a=p.parse_args()
    assert re.fullmatch('[a-z0-9-]+',a.label)
    out=R/'build/ubuntu26-boot-diagnostics'/a.label;out.mkdir(parents=True,exist_ok=False)
    baseline=R/'build/ubuntu26-slot-proof/v7/manifest.json'
    assert sha(baseline)=='2a3db1ff59671dcd39089ec6fe7af67e45b8304047113ff756e9476d7e51c567'
    old=json.loads(baseline.read_text());expected={Path(row['path']).name:row['sha256'] for row in old['sources']}
    snap=out/'source';snap.mkdir(mode=0o755)
    inputs=Path(tempfile.mkdtemp(prefix='leon-boot-diagnostics-'));inputs.chmod(0o755)
    sources=[]
    for name in ['device.c','slot-proof.c','slot-proof.h','slot-device-policy.h','p11-clear-view.h','sha256-compat.h','sha256.c']:
        source=baseline.parent/'source-snapshot'/name;assert sha(source)==expected[name];sources.append(ref(source))
        destination='slot-device.c' if name=='device.c' else name
        shutil.copyfile(source,snap/destination);shutil.copyfile(source,inputs/destination)
    for name in ['boot-diagnostics.h','provision.c','fixture.c','reader.c','parse.py','test-format.py']:
        source=S/name;sources.append(ref(source));shutil.copyfile(source,snap/name);shutil.copyfile(source,inputs/name)
    payload=R/'configs/ubuntu26/asus-resolver-ordering/10-leon-ordering.conf'
    assert sha(payload)=='2a51b2b2ad2dc3393dcf6557824683548d1d0118d9416e7d4f0470ba5f63a7d4'
    header='#define RESOLVER_PAYLOAD_SHA '+json.dumps(sha(payload))+'\nstatic const char resolver_payload[]='+json.dumps(payload.read_text())+';\n'
    for d in [snap,inputs]:(d/'resolver-payload.h').write_text(header)
    format_names=['boot-diagnostics-read','fixture','records.bin','fixture.log','reader.log','reader-reject.log','reader-dump.log','reader-empty.log','reader-notempty.log']
    prior=None
    if a.reuse_format_manifest:
        prior=json.loads(a.reuse_format_manifest.read_text())
        assert prior['status']=='static_provisioner_and_bounded_format_tests_passed'
        old_sources={Path(x['path']).name:x for x in prior['sources']}
        for name in ['boot-diagnostics.h','fixture.c','reader.c','parse.py','test-format.py']:
            assert sha(S/name)==old_sources[name]['sha256']
        old_outputs={Path(x['path']).name:x for x in prior['outputs']}
        for name in format_names+['format-tests.json']:
            source=R/old_outputs[name]['path'];assert sha(source)==old_outputs[name]['sha256']
            shutil.copyfile(source,inputs/name)
        assert json.loads((inputs/'format-tests.json').read_text())==prior['format_tests']
    root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
    worker=r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"; reuse="$4"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/boot-diagnostics-$label"
cp "$inputs"/* "$root/work/boot-diagnostics-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" "$reuse" <<'BUILD'
set -euo pipefail
cd "/work/boot-diagnostics-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" provision.c slot-proof.c sha256.c -o provision-boot-diagnostics
if [ "$2" != 1 ]; then
ccache gcc-16 "${flags[@]}" fixture.c -o fixture
ccache gcc-16 "${flags[@]}" reader.c -o boot-diagnostics-read
./fixture records.bin > fixture.log
./boot-diagnostics-read --check records.bin 0 11111111-2222-3333-4444-555555555555 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa stage=paths > reader.log
./boot-diagnostics-read --check records.bin 1 11111111-2222-3333-4444-555555555555 - stage=paths > reader-reject.log && exit 1 || test "$?" = 125
test ! -s reader-reject.log
./boot-diagnostics-read --dump records.bin 0 11111111-2222-3333-4444-555555555555 - > reader-dump.log
grep -Fx 'stage=paths' reader-dump.log
head -c 16384 /dev/zero > empty.bin
chmod 0600 empty.bin
./boot-diagnostics-read --empty empty.bin 0 > reader-empty.log
./boot-diagnostics-read --empty empty.bin 1 >> reader-empty.log
./boot-diagnostics-read --empty records.bin 0 > reader-notempty.log && exit 1 || test "$?" = 125
test ! -s reader-notempty.log
fi
./provision-boot-diagnostics --invalid >badargs.stdout 2>badargs.stderr && exit 1 || test "$?" = 64
test ! -s badargs.stdout && test ! -s badargs.stderr
./provision-boot-diagnostics --initialize-diagnostics aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 11111111-2222-3333-4444-555555555555 >nondevice.stdout 2>nondevice.stderr && exit 1 || test "$?" = 1
test ! -s nondevice.stdout
grep -Fx 'LEON_DIAGNOSTICS_REFUSED stage=stock-root-and-native-namespace diagnostic_created=0 resolver_created=0 retained_for_review=true' nondevice.stderr
readelf -h -l -d provision-boot-diagnostics > elf.txt
gcc-16 --version > compiler.txt
chmod 0644 records.bin
BUILD
'''
    (inputs/'build.sh').write_text(worker)
    with (out/'build.log').open('w') as log:
        subprocess.run(['mmdebstrap','--unshare-helper','bash',str(inputs/'build.sh'),str(root),str(inputs),a.label,'1' if prior else '0'],stdout=log,stderr=subprocess.STDOUT,check=True)
    stage=root/f'work/boot-diagnostics-{a.label}'
    names=['provision-boot-diagnostics','boot-diagnostics-read','fixture','records.bin','fixture.log','reader.log','reader-reject.log','reader-dump.log','reader-empty.log','reader-notempty.log','badargs.stdout','badargs.stderr','nondevice.stdout','nondevice.stderr','elf.txt','compiler.txt']
    for name in names:shutil.copyfile(stage/name,out/name);(out/name).chmod(0o755 if name in ['provision-boot-diagnostics','boot-diagnostics-read','fixture'] else 0o644)
    assert 'INTERP' not in (out/'elf.txt').read_text() and 'AArch64' in (out/'elf.txt').read_text()
    if prior:shutil.copyfile(inputs/'format-tests.json',out/'format-tests.json')
    else:
        with (out/'format-tests.json').open('w') as log:
            subprocess.run(['python3',str(snap/'test-format.py'),str(out/'records.bin')],stdout=log,check=True)
    report={'schema':1,'status':'static_provisioner_and_bounded_format_tests_passed','physical_provisioning_performed':False,
        'sources':sources,'frozen_guard_manifest':ref(baseline),'resolver_payload':ref(payload),'builder':ref(Path(__file__)),
        'outputs':[ref(out/n) for n in names+['format-tests.json']],
        'common_header':ref(S/'boot-diagnostics.h'),'provisioner':ref(out/'provision-boot-diagnostics'),
        'parser':ref(S/'parse.py'),'format_tests':json.loads((out/'format-tests.json').read_text()),
        'format_evidence_reused_from':ref(a.reuse_format_manifest.resolve()) if prior else None,
        'mount_identity':'Fresh raw ext4 UUID on enrolled179:11 FD, in addition to fixed CID/GPT/extent gates; mount source is /proc/self/fd/N. No unchecked path or by-uuid fallback.',
        'usage':'provision-boot-diagnostics --initialize-diagnostics <fresh reviewed metadata SHA256> <current stock2 boot UUID>',
        'new_root_payload_writes':['/etc/leon/boot-diagnostics (16384 zero bytes; root0600 nlink1 initialized FIEMAP)',
            '/etc/systemd/system/leon-asus-resolver.path.d/10-leon-ordering.conf (exact reviewed bytes; root0644; parent root0755)'],
        'forbidden_operations_performed':{'device_access':False,'gpt_writes':False,'boot_metadata_writes':False,'firmware_writes':False,'guardian_arm':False,'reboot':False,'boot_commit':False},
        'idempotence':'Only existing exact all-zero allocated diagnostic file and exact approved resolver bytes are accepted. Valid prior diagnostic records, partial sizes, foreign content or metadata are refused. No truncation/reset/removal.',
        'limits':['No physical ext4 allocation/write test or hardware power-cut was performed. The host work filesystem is btrfs; ioctl/map validation is tested with synthetic extent records and real target acceptance remains separate.',
            'The provisioner reuses all v7 stock2/CID/layout/metadata/full-stock/all-process p11 guards; p11 must already be clean before this tool. No automatic fsck/replay.',
            'Mounting ext4 and fsync update filesystem metadata normally. Only the two listed payload files are written.',
            'Per-producer latest record replaces its previous slot. CRC rejects torn bytes; it does not preserve the prior valid record or prove durability under arbitrary hardware failure.',
            'The resolver override is a local diagnostic overlay, not a dpkg transaction; a supplemental package exists separately.']}
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(out/'manifest.json')
if __name__=='__main__':main()

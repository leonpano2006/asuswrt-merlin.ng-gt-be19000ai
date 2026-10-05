#!/usr/bin/env python3
"""Compile separate fixed-eMMC and RAM-loop p11 helpers; execute neither."""
import argparse,hashlib,json,re,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);a=p.parse_args();assert re.fullmatch('[a-zA-Z0-9_-]+',a.label)
 out=R/'build/ubuntu26-blkpg-helper'/a.label;out.mkdir(parents=True,exist_ok=False)
 manifest=R/'build/ubuntu26-gpt-candidate/v1/manifest.json';plan=json.loads(manifest.read_text())
 values={Path(x['path']).name:x for x in plan['outputs']}
 def blob(name):
  record=values[name];f=R/record['path'];assert sha(f)==record['sha256'];return f.read_bytes()
 header=['/* Exact reviewed candidate GPT bytes; generated, do not edit. */',
  '#define EXPECTED_CID "00000000000000000000000000000001"',
  '#define DISK_BYTES UINT64_C(%d)'%(plan['original_disk_sectors']*512),
  '#define BACKUP_OFFSET UINT64_C(%d)'%(plan['backup_file_first_lba']*512),
  '#define P11_START UINT64_C(%d)'%plan['new_partition']['start_sector'],
  '#define P11_SECTORS UINT64_C(%d)'%(plan['new_partition']['bytes']//512),
  'static const struct {uint64_t start,length;} parts[]={']
 for row in plan['existing_entries_preserved_byte_for_byte']:header.append('{UINT64_C(%d),UINT64_C(%d)},'%(row['start'],row['end']-row['start']+1))
 header+=['{P11_START,P11_SECTORS},','};']
 for stem in ['primary','backup']:
  data=blob(stem+'.bin');header.append('static const unsigned char expected_'+stem+'[]={')
  for off in range(0,len(data),32):header.append(','.join('0x%02x'%x for x in data[off:off+32])+',')
  header.append('};')
 (out/'gpt-policy.h').write_text('\n'.join(header)+'\n');shutil.copyfile(R/'scripts/ubuntu26-gpt/add-p11.c',out/'add-p11.c')
 tmp=Path(tempfile.mkdtemp(prefix='leon-blkpg-build-'));tmp.chmod(0o755)
 for name in ['gpt-policy.h','add-p11.c']:shutil.copyfile(out/name,tmp/name)
 root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 script=r'''set -euo pipefail
root="$1";input="$2";label="$3"
mount --make-rprivate /
for name in null zero full random urandom tty; do
 test ! -L "$root/dev/$name"
 touch "$root/dev/$name"
 mount --bind "/dev/$name" "$root/dev/$name"
 test -c "$root/dev/$name"
done
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/blkpg-$label"
cp "$input"/*.c "$input"/*.h "$root/work/blkpg-$label/"
unshare --net chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/blkpg-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -static-pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" add-p11.c -o add-p11-device
ccache gcc-16 "${flags[@]}" -DLEON_BLKPG_LOOP_FIXTURE add-p11.c -o add-p11-loop-fixture
readelf -h -l -d add-p11-device > device-elf.txt
readelf -h -l -d add-p11-loop-fixture > fixture-elf.txt
gcc-16 --version > compiler.txt
BUILD
'''
 (tmp/'build.sh').write_text(script)
 with (out/'build.log').open('w') as log:run=subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(tmp/'build.sh'),str(root),str(tmp),a.label],stdout=log,stderr=subprocess.STDOUT)
 result={'schema_version':1,'status':'build_failed','returncode':run.returncode,'candidate_gpt':ref(manifest),'source':ref(out/'add-p11.c'),'policy_header':ref(out/'gpt-policy.h'),'device_binary_executed':False,'fixture_binary_executed':False,'network_used':False,'device_opened':False,'gpt_written':False,'kernel_partition_table_changed':False,'hardware_accepted':False}
 if run.returncode==0:
  for name in ['add-p11-device','add-p11-loop-fixture','device-elf.txt','fixture-elf.txt','compiler.txt']:
   shutil.copyfile(root/('work/blkpg-'+a.label)/name,out/name)
  for name in ['add-p11-device','add-p11-loop-fixture']:(out/name).chmod(0o755)
  for name in ['device-elf.txt','fixture-elf.txt']:
   text=(out/name).read_text();assert 'AArch64' in text and 'INTERP' not in text and '(NEEDED)' not in text
  result.update(status='built_static_native_variants_not_executed',compiler=(out/'compiler.txt').read_text().splitlines()[0],variants={name:ref(out/name) for name in ['add-p11-device','add-p11-loop-fixture']})
 result['builder']=ref(Path(__file__).resolve());(out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(run.returncode)
if __name__=='__main__':main()

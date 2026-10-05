#!/usr/bin/env python3
"""Compose an offline-only immutable guardian identity test around frozen PID1."""
import argparse, hashlib, json, re, shutil, subprocess, tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--health-manifest',type=Path,required=True);a=p.parse_args()
 assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
 health=json.loads(a.health_manifest.read_text());assert health['status']=='built_readonly_fixture_tests_passed'
 client=a.health_manifest.parent/'trial-health';assert sha(client)==health['outputs']['trial-health']
 base=R/'build/ubuntu26-root-init/guardian-emergency-v1';meta=json.loads((base/'manifest.json').read_text());assert meta['policy']['scope']=='offline-qemu-fixture' and meta['emergency_fault_sink']
 for name,digest in meta['outputs'].items():assert sha(base/name)==digest
 out=R/'build/ubuntu26-root-init'/a.label;shutil.copytree(base,out)
 inputs=Path(tempfile.mkdtemp(prefix='guardian-health-build-'));inputs.chmod(0o755)
 src=R/'scripts/asus-integration/root-guardian-mock.c';shutil.copyfile(src,inputs/src.name)
 for source in [R/'scripts/asus-integration/trial-guard/trial-handoff.h',a.health_manifest.parent/'source-snapshot/control.h']:
  shutil.copyfile(source,inputs/source.name)
 env=json.loads((R/'build/asus-native-build/v2/result.json').read_text());assert env['status']=='prepared'
 script=inputs/'build.sh';script.write_text('''set -euo pipefail
root="$1"; inputs="$2"; label="$3"
mount --make-rprivate /
mkdir -m 0755 "$root/work/guardian-health-$label"
cp "$inputs"/*.[ch] "$root/work/guardian-health-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/guardian-health-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
ccache gcc-16 -std=gnu11 -O2 -g -Wall -Wextra -Werror -DLEON_GUARD_HEALTH_FIXTURE=1 -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -static-pie -Wl,-z,relro,-z,now root-guardian-mock.c -o root-guardian-mock
BUILD
''')
 with (out/'health-build.log').open('w') as f:subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(script),env['root'],str(inputs),a.label],check=True,stdout=f,stderr=subprocess.STDOUT)
 shutil.copyfile(Path(env['root'])/f'work/guardian-health-{a.label}/root-guardian-mock',out/'root-guardian-mock')
 (out/'root-guardian-mock').chmod(0o755)
 shutil.copyfile(client,out/'trial-health');(out/'trial-health').chmod(0o755)
 meta['outputs']['root-guardian-mock']=sha(out/'root-guardian-mock');meta['outputs']['trial-health']=sha(out/'trial-health')
 meta['mock_guardian_source_sha256']=sha(src)
 meta['health_identity_fixture']={'source':str(src.relative_to(R)),'source_sha256':sha(src),'mock_hardware_armed_response':True,'health_manifest':str(a.health_manifest),'health_manifest_sha256':sha(a.health_manifest),'client_sha256':sha(client),'control_header_sha256':sha(inputs/'control.h'),'base_manifest_sha256':sha(base/'manifest.json'),'builder_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n');print(json.dumps({'out':str(out),'guardian_sha256':sha(out/'root-guardian-mock')}))
if __name__=='__main__':main()

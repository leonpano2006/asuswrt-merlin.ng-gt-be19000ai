#!/usr/bin/env python3
"""One new rescue fixture: fix entry inventory and add private timeout only."""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import stat

R = Path(__file__).resolve().parents[1]
O = R / 'build/asus-uplink-rescue/qemu-source-v3'
M = R / 'build/asus-uplink-rescue/qemu-source-v2/manifest.json'
M_SHA = '3f6093636bc49378b52ae12158736bd63256c4bc8f8a4358bd76ae7dc978786d'
PARSER = R / 'scripts/prepare-asus-openssh-control-qemu.py'
PARSER_SHA = '80d589580482008cdbd6b634bef929d668851977506eb5b001f4ca4a537906e7'
TIMEOUT_PROOF = R / 'build/asus-uplink-rescue/controller-timeout-v1/completed-manifest-v1.json'
TIMEOUT_PROOF_SHA = 'f9be09c628a350c73f855ac4ca679fa9424b3ad7c9d1f405df12175d4ed09354'
LAB = 'usr/libexec/leon-lab/uplink-rescue/'
REPLACE = [
    ('usr/libexec/leon-lab/full-boot-proof', '94b6c6fe8e15bad117ef28e89e65a6f376de8d1aa7607872aa41d7e47bec51d6',
     'scripts/asus-integration/uplink-rescue/fixture-proof-v3.sh', 'afbc5c3a4cd9045d55f8ca53b12d94b091cd7e1d190155455bd28504cb9a3e39'),
    (LAB+'controller.sh', 'a65f19252c33a7f9e9118ffeab85c6b15ba7c0527e383918c1f0689942fa9bc1',
     'scripts/asus-integration/uplink-rescue/controller-transient-v3.sh', '4878f47d6218281fc31e8b30af7a430f6c85b9d3d0e011bf3f08990d57c83f24'),
    (LAB+'controller-init.sh', '0f8720400187d9862f02a4fa26a9c574ebcb1d464e5613607ebd9f4f9bb0c0cf',
     'scripts/asus-integration/uplink-rescue/fixture-controller-v2.sh', 'ca1c51c3de23ebb070e489cc263352610eef08b7f0974c20edd07174f1726c3c'),
]
ADD = [
    (LAB+'tools/bin/timeout', 'build/asus-uplink-rescue/controller-timeout-v1/bin/timeout', 'eee267c8317aff3902f573c1e5f0052a723b2a3521cb2903377caea04ec8c7df'),
    (LAB+'timeout-run.sh', 'scripts/asus-integration/uplink-rescue/timeout-private-run.sh', 'f887d0cdd35e3b87429e6553ee86cc83e9018315f3eac644813859d56e8ae27c'),
]


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ref(p):
    return {'path':str(p.relative_to(R)), 'sha256':sha(p)}


def main():
    require(__debug__ and not O.exists(), 'fresh immutable preparation required')
    require(sha(M) == M_SHA and sha(PARSER) == PARSER_SHA and sha(TIMEOUT_PROOF) == TIMEOUT_PROOF_SHA,
            'frozen prior receipt/parser/timeout proof changed')
    old = json.loads(M.read_text()); base = R / old['initramfs']['path']
    require(sha(base) == old['initramfs']['sha256'], 'prior initramfs changed')
    for _, _, src, digest in REPLACE:
        require(sha(R/src) == digest, 'reviewed replacement changed')
    for _, src, digest in ADD:
        require(sha(R/src) == digest, 'authenticated addition changed')
    spec = importlib.util.spec_from_file_location('frozen_newc_parser', PARSER)
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    rows = helper.parse(gzip.decompress(base.read_bytes()))
    before = copy.deepcopy(rows); indexed = {row[0]:row for row in rows}
    require(len(indexed) == len(rows) and rows[-1][0] == 'TRAILER!!!', 'unique archive members and final trailer required')
    for name, original_sha, src, _ in REPLACE:
        require(name in indexed and stat.S_ISREG(indexed[name][1][1])
                and indexed[name][1][1] & 0o7777 == 0o755
                and hashlib.sha256(indexed[name][2]).hexdigest() == original_sha, 'original member changed: '+name)
        indexed[name][2] = (R/src).read_bytes()
    inode = max(row[1][0] for row in rows) + 1
    for name, src, _ in ADD:
        require(name not in indexed and str(Path(name).parent) in indexed, 'new leaf collision or missing parent')
        data = (R/src).read_bytes()
        row = [name, [inode, stat.S_IFREG|0o755, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name.encode())+1, 0], data]
        inode += 1; rows.insert(-1, row); indexed[name] = row
    changed = {row[0] for row in before if indexed[row[0]] != row}
    require(changed == {row[0] for row in REPLACE}, 'unexpected prior member change')
    encoded = bytearray()
    for name, fields, data in rows:
        rawname = name.encode()+b'\0'; fields[6] = len(data); fields[11] = len(rawname)
        encoded += b'070701'+''.join(f'{v:08x}' for v in fields).encode()+rawname
        encoded += b'\0'*(-len(encoded)%4); encoded += data; encoded += b'\0'*(-len(encoded)%4)
    decoded = helper.parse(bytes(encoded))
    require(decoded == rows, 'encoded member readback mismatch')
    O.mkdir(parents=True)
    cpio = O / 'initramfs.cpio.gz'; cpio.write_bytes(gzip.compress(encoded, compresslevel=1, mtime=0))
    result = dict(old)
    result.update(base=ref(base), prior_preparation=ref(M), builder=ref(Path(__file__)),
                  sources=[ref(R/row[2]) for row in REPLACE]+[ref(R/row[1]) for row in ADD]+[ref(TIMEOUT_PROOF)],
                  initramfs=ref(cpio), delta='3 reviewed file contents replaced, 2 private timeout leaves added; all other members and metadata preserved',
                  replaced_members=sorted(changed), added_members=[row[0] for row in ADD],
                  unchanged_prior_members=len(before)-3, production_helper_inputs_unchanged=True,
                  root_authorization='Reviewed entry allowlist and new authenticated bounded timeout only',
                  prior_run_preserved='build/qemu/uplink-rescue-focused-v2/result.json')
    (O/'manifest.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(ref(O/'manifest.json')))


if __name__ == '__main__':
    main()

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
O = R / 'build/asus-uplink-rescue/qemu-source-v4'
M = R / 'build/asus-uplink-rescue/qemu-source-v3/manifest.json'
M_SHA = '1f72593968ef74e3044a404770724b2de49aece2c561954358566b39b42897a1'
PARSER = R / 'scripts/prepare-asus-openssh-control-qemu.py'
PARSER_SHA = '80d589580482008cdbd6b634bef929d668851977506eb5b001f4ca4a537906e7'
TIMEOUT_PROOF = R / 'build/asus-uplink-rescue/controller-timeout-v1/completed-manifest-v1.json'
TIMEOUT_PROOF_SHA = 'f9be09c628a350c73f855ac4ca679fa9424b3ad7c9d1f405df12175d4ed09354'
LAB = 'usr/libexec/leon-lab/uplink-rescue/'
REPLACE = [
    ('usr/libexec/leon-lab/full-boot-proof', 'afbc5c3a4cd9045d55f8ca53b12d94b091cd7e1d190155455bd28504cb9a3e39',
     'scripts/asus-integration/uplink-rescue/fixture-proof-v4.sh', 'a2cde26d84f2f81410124272705193e0879b4c37f41100188d0884c750383b69'),
    (LAB+'controller-init.sh', 'ca1c51c3de23ebb070e489cc263352610eef08b7f0974c20edd07174f1726c3c',
     'scripts/asus-integration/uplink-rescue/fixture-controller-v3.sh', '135b4c888c17c8d3a0d1a79eca01f236f061c82d658b8a7f709415bee9b2effa'),
]
ADD = []


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
                  sources=[ref(R/row[2]) for row in REPLACE]+old['sources'][1:2]+old['sources'][3:],
                  initramfs=ref(cpio), delta='2 fixture files replaced: absent-only mount target and synthetic controller rp_filter; all other members/metadata preserved',
                  replaced_members=sorted(changed), added_members=[row[0] for row in ADD],
                  unchanged_prior_members=len(before)-2, production_helper_inputs_unchanged=True,
                  root_authorization='Reviewed entry allowlist and new authenticated bounded timeout only',
                  prior_run_preserved='build/qemu/uplink-rescue-focused-v3/result.json')
    (O/'manifest.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(ref(O/'manifest.json')))


if __name__ == '__main__':
    main()

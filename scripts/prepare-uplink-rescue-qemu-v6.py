#!/usr/bin/env python3
"""One new rescue fixture: bounded controller waits and immediate failure markers."""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import stat

R = Path(__file__).resolve().parents[1]
O = R / 'build/asus-uplink-rescue/qemu-source-v6'
M = R / 'build/asus-uplink-rescue/qemu-source-v5/manifest.json'
M_SHA = 'e3fb44f85d2b15a397edc3d1fd7fad8aa141a85c212944256e51bbfcf3dfd7fe'
PARSER = R / 'scripts/prepare-asus-openssh-control-qemu.py'
PARSER_SHA = '80d589580482008cdbd6b634bef929d668851977506eb5b001f4ca4a537906e7'
TIMEOUT_PROOF = R / 'build/asus-uplink-rescue/controller-timeout-v1/completed-manifest-v1.json'
TIMEOUT_PROOF_SHA = 'f9be09c628a350c73f855ac4ca679fa9424b3ad7c9d1f405df12175d4ed09354'
LAB = 'usr/libexec/leon-lab/uplink-rescue/'
REPLACE = [('usr/libexec/leon-lab/full-boot-proof', '3d99c5c5acf19b5ae9876e0a49725d6a6d199e8a99b1fce563eea9a224315a88', 'scripts/asus-integration/uplink-rescue/fixture-proof-v6.sh', '480e8234c451b419a04fad6902fbf92966d13b3db513e3ef729e4e77798c6039'), ('usr/libexec/leon-lab/uplink-rescue/controller-init.sh', 'aeb12b75a997a01f7ae11c02016794f259c3e267238a0353f98bfe63017e030a', 'scripts/asus-integration/uplink-rescue/fixture-controller-v5.sh', 'd2abf8718bb427435f2b9c0687531545e9f035f0a8318af96e78d8d4c633cbd3')]
ADD = []
REPLAY_PROOF = R / 'build/asus-uplink-rescue/controller-readback-replay-v1/result.json'
REPLAY_PROOF_SHA = '1ee5e44c764626ba13e08788685bd2683ba8de0a7e6de793936706547f9fce16'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ref(p):
    return {'path':str(p.relative_to(R)), 'sha256':sha(p)}


def main():
    require(__debug__ and not O.exists(), 'fresh immutable preparation required')
    require(REPLAY_PROOF_SHA is not None and sha(REPLAY_PROOF) == REPLAY_PROOF_SHA, 'completed saved-dump replay required')
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
                  sources=[ref(R/REPLACE[0][2]),old['sources'][1],ref(R/REPLACE[1][2])]+old['sources'][3:],
                  initramfs=ref(cpio), delta='Controller fixture waits bounded at400*0.1s and failure marker/logs immediately exposed; production helper/controller/toolchain and other members/metadata unchanged',
                  replaced_members=sorted(changed), added_members=[row[0] for row in ADD],
                  unchanged_prior_members=len(before)-2, production_helper_inputs_unchanged=True,
                  root_authorization='V5 main wait10s expired while child still ROUTE_INTENT; fixture deadline/diagnostic change only, no production changes',
                  prior_run_preserved='build/qemu/uplink-rescue-focused-v5/result.json')
    (O/'manifest.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(ref(O/'manifest.json')))


if __name__ == '__main__':
    main()

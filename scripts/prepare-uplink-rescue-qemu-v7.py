#!/usr/bin/env python3
"""One helper-only Kernel10 fixture successor; every other cpio member preserved."""
import copy,gzip,hashlib,importlib.util,json,stat
from pathlib import Path
R=Path(__file__).resolve().parents[1]
O=R/'build/asus-uplink-rescue/qemu-source-v7'
M=R/'build/asus-uplink-rescue/qemu-source-v6/manifest.json'
M_SHA='86d9b449a7cac040af9180457735250041d4d20529af60bb37cc571a6d39f7d1'
N=R/'build/asus-uplink-rescue/native-v4/manifest.json'
N_SHA='6d1d6db6ccf2bbaca771338b7fdbe1080726b0b8ccfb010fbf9d092f4dfdd581'
NEW_SHA='55f6953743d6e0420d4d04d2ad95505fcf0ba340da9c84ce91ee375be622a133'
PARSER=R/'scripts/prepare-asus-openssh-control-qemu.py'
PARSER_SHA='80d589580482008cdbd6b634bef929d668851977506eb5b001f4ca4a537906e7'
NAME='usr/libexec/leon-asus/rescue-link'
OLD_SHA='e69cc01d4cd82fa356a7db2c4b4b9bfa8218759e7d7126241e5842d4848c2ee2'
def require(ok,why):
    if not ok:raise RuntimeError(why)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return dict(path=str(p.relative_to(R)),sha256=sha(p))
def main():
    require(__debug__ and not O.exists(),'fresh immutable output required')
    require(N_SHA is not None and NEW_SHA is not None,'completed native successor pins required before preparation')
    require(sha(N)==N_SHA and sha(M)==M_SHA and sha(PARSER)==PARSER_SHA,'frozen input changed')
    old=json.loads(M.read_text());native=json.loads(N.read_text())
    require(native['status']=='built_not_executed' and native['returncode']==0 and native['source_compile_invocations']==1 and not native['target_binary_executed'] and not native['device_accessed'],'one actual native compile required')
    require(native['ownership_flags_allowed']==[0,16] and native['live_route_flags_allowed']==[0] and native['binary']['sha256']==NEW_SHA,'reviewed kernel status identity required')
    binary=R/native['binary']['path'];require(sha(binary)==NEW_SHA,'successor ELF changed')
    base=R/old['initramfs']['path'];require(sha(base)==old['initramfs']['sha256'],'base archive changed')
    spec=importlib.util.spec_from_file_location('frozen_newc',PARSER);parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
    rows=parser.parse(gzip.decompress(base.read_bytes()));before=copy.deepcopy(rows);ix={r[0]:r for r in rows}
    require(len(ix)==len(rows) and rows[-1][0]=='TRAILER!!!','unique names and final trailer required')
    row=ix[NAME];require(stat.S_ISREG(row[1][1]) and row[1][1]&0o7777==0o755 and hashlib.sha256(row[2]).hexdigest()==OLD_SHA,'frozen original helper member required')
    row[2]=binary.read_bytes();changed={r[0] for r in before if ix[r[0]]!=r};require(changed=={NAME},'helper only member replacement required')
    out=bytearray()
    for name,fields,data in rows:
        raw=name.encode()+b'\0';fields[6]=len(data);fields[11]=len(raw)
        out+=b'070701'+''.join(f'{v:08x}' for v in fields).encode()+raw;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
    require(parser.parse(bytes(out))==rows,'complete encoded metadata/member readback required')
    O.mkdir(parents=True);cpio=O/'initramfs.cpio.gz';cpio.write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
    report=dict(old);report.update(base=ref(base),prior_preparation=ref(M),native=ref(N),builder=ref(Path(__file__)),sources=old['sources']+[ref(binary),native['sources']['new']],initramfs=ref(cpio),production_helper_inputs_unchanged=False,delta='Only helper ELF: strict owned kernel LINKDOWN16 recognition, live0 readiness, known-ACK cleanup, bounded route status evidence',root_authorization='Kernel4.19 carrier-loss source bug; new helper compile once, fixture/source peers required before run',prior_run_preserved='build/qemu/uplink-rescue-focused-v6/result.json',replaced_members=[NAME],added_members=[],unchanged_prior_members=len(before)-1)
    (O/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(ref(O/'manifest.json')))
if __name__=='__main__':main()

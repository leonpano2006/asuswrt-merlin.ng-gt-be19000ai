#!/usr/bin/env python3
"""Synthetic, no-network archive tests; no secrets, devices or rootfs execution."""
import argparse,copy,hashlib,importlib.util,io,json,os,tarfile,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('provision',R/'scripts/prepare-ubuntu26-provisioning.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
TARGET=b'[Unit]\nRequires=leon-trial-runtime-ready.service leon-asus.target\n'
PKG={'name':'leon-bcm-trial-activation','version':'0.fixture','architecture':'all'}

def record(name,data=b'',kind='file',mode=None,uid=0,link=''):
    m=tarfile.TarInfo(name);m.uid=m.gid=uid;m.mode=(0o755 if kind=='dir' else 0o644) if mode is None else mode
    m.type={'file':tarfile.REGTYPE,'dir':tarfile.DIRTYPE,'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE,'fifo':tarfile.FIFOTYPE,'char':tarfile.CHRTYPE}[kind];m.linkname=link;m.size=len(data) if kind=='file' else 0
    return m,data
base=[record(name,kind='dir') for name in ['.','etc','etc/leon','mnt','mnt/leon-vendor-root','etc/systemd','etc/systemd/system','usr','usr/lib','usr/lib/systemd','usr/lib/systemd/system','var','var/lib','var/lib/dpkg']]
base.extend([record('etc/leon/root-generation',p.GENERATION.encode()),record(p.TARGET,TARGET),record('etc/passwd',b'root:x:0:0:root:/root:/bin/bash\n'),record('etc/shadow',b'root:!:1:0:99999:7:::\n',mode=0o640),record('var/lib/dpkg/status',b'Package: leon-bcm-trial-activation\nStatus: install ok installed\nArchitecture: all\nVersion: 0.fixture\n\n')])

def archive(path,rows):
    with tarfile.open(path,'w') as a:
        for m,data in rows:a.addfile(m,io.BytesIO(data) if m.isfile() else None)
def changed(name,**args):return [record(name,**args) if m.name==name else (copy.copy(m),data) for m,data in base]
def refused(rows):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as a:
        for m,data in rows:a.addfile(m,io.BytesIO(data) if m.isfile() else None)
    stream.seek(0)
    try:
        with tarfile.open(fileobj=stream) as a:p.inspect(a,TARGET,expected_package=PKG)
    except ValueError:return True
    raise AssertionError('unsafe fixture accepted')
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--label',default='fixture-v1');args=parser.parse_args();assert args.label and all(c.isalnum() or c in '-_' for c in args.label)
    out=R/'build/ubuntu26-provisioning'/args.label;out.mkdir(parents=True,exist_ok=False);cases=[]
    with tempfile.TemporaryDirectory(prefix='leon-provision-fixture-') as d:
        d=Path(d);source=d/'source.tar';target=d/'candidate.tar';archive(source,base);original=p.sha(source)
        positive=p.prepare_tar(source,target,TARGET,PKG);assert p.sha(source)==original
        assert positive['device_identity_absent'] and positive['slot_token_absent'];cases.append('positive activation preserves every regular file')
        output_hash=p.sha(target)
        try:p.prepare_tar(source,target,TARGET,PKG)
        except FileExistsError:pass
        else:raise AssertionError('existing output overwritten')
        assert p.sha(target)==output_hash;cases.append('existing output refused without overwrite')
        for name in sorted(p.FORBIDDEN):refused(base+[record(name,b'fixture-not-a-secret')]);cases.append('reject '+name)
        for name,rows in [
            ('wrong-generation',changed('etc/leon/root-generation',data=b'old-generation\n')),
            ('marker-permission',changed('etc/leon/root-generation',data=p.GENERATION.encode(),mode=0o666)),
            ('marker-owner',changed('etc/leon/root-generation',data=p.GENERATION.encode(),uid=1000)),
            ('old-target',changed(p.TARGET,data=b'old-target')),
            ('old-package',changed('var/lib/dpkg/status',data=b'Package: leon-bcm-trial-activation\nStatus: install ok installed\nArchitecture: all\nVersion: 0.old\n\n')),
            ('preexisting-account',changed('etc/passwd',data=b'MastermixStudios:x:1000:1000::/home/MastermixStudios:/bin/bash\n')),
            ('preexisting-account-hash',changed('etc/shadow',data=b'MastermixStudios:!:1:0:99:7:::\n')),
            ('non-directory-parent',base+[record('danger',kind='symlink',link='/tmp'),record('danger/file',b'escape')]),
            ('duplicate',base+[record('etc/passwd',b'duplicate')]),
            ('absolute',base+[record('/outside',b'x')]),
            ('parent-traversal',base+[record('../outside',b'x')]),
            ('fifo',base+[record('etc/fifo',kind='fifo')]),
            ('device-outside-dev',base+[record('etc/device',kind='char')]),
            ('hardlink-outside',base+[record('etc/link',kind='hardlink',link='../../outside')]),
            ('active-asus',base+[record('etc/systemd/system/leon-asus.target',kind='symlink',link='/usr/lib/systemd/system/leon-asus.target')]),
            ('active-trial',base+[record(p.LINK,kind='symlink',link='/'+p.TARGET)]),
        ]:refused(rows);cases.append('reject '+name)
        for name in ['etc/leon/root-generation','mnt/leon-vendor-root',p.TARGET,'var/lib/dpkg/status']:
            refused([(m,data) for m,data in base if m.name!=name]);cases.append('reject missing '+name)
        symlink=d/'symlink.tar';symlink.symlink_to(source)
        try:p.prepare_tar(symlink,d/'never.tar',TARGET,PKG)
        except ValueError:pass
        else:raise AssertionError('symlink input accepted')
        assert not (d/'never.tar').exists();cases.append('reject symlink input')
        os.link(source,d/'hardlink.tar')
        try:p.prepare_tar(source,d/'never.tar',TARGET,PKG)
        except ValueError:pass
        else:raise AssertionError('multiply linked input accepted')
        cases.append('reject multiply linked input')
        (out/'synthetic-candidate.tar').write_bytes(target.read_bytes())
    policy=json.loads((R/'configs/ubuntu26/root-init-device-policy.json').read_text());p.dump(out/'device-local-contract.json',p.contract(policy))
    report={'status':'passed_synthetic_archive_fixtures','cases':cases,'count':len(cases),'real_rootfs_prepared':False,'ext4_created':False,'network_used':False,'block_devices_opened':False,'key_generation_executed':False,'account_database_changed':False,'slot_token_generated':False,'source':p.ref(R/'scripts/prepare-ubuntu26-provisioning.py'),'test_source':p.ref(Path(__file__).resolve()),'contract':p.ref(out/'device-local-contract.json'),'production_ready':False}
    p.dump(out/'manifest.json',report);p.dump(R/'reports/ubuntu26/provisioning-foundation.json',report);print(json.dumps({'status':report['status'],'cases':len(cases)},indent=2))
if __name__=='__main__':main()

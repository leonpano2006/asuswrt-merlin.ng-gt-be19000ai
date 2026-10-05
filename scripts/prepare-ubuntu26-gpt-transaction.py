#!/usr/bin/env python3
"""Offline GPT transaction/fault fixtures only: no device path or deploy mode.

Every disk opened for writing is a newly-created regular sparse file under the
new output directory. This is not a physical power-loss or eMMC atomicity test.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from unittest import mock

R=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('gpt_candidate',R/'scripts/prepare-ubuntu26-gpt-candidate.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
SECTOR=512


def digest(data):return hashlib.sha256(data).hexdigest()
def ref(path):return {'path':str(path.relative_to(R)),'sha256':g.sha(path)}
def dump(path,data):path.write_text(json.dumps(data,indent=2)+'\n')


class Cut(Exception):pass


class Fixture:
    def __init__(self,path,plan):
        self.path,self.plan=path,plan
        self.fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        s=os.fstat(self.fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid()
        os.ftruncate(self.fd,plan['disk_bytes'])
        for key in ('primary','backup'):
            row=plan[key];self.seed(row['offset'],row['old'])
        self.sentinels=[]
        for row in plan['old_entries']:
            for sector in (row['start'],row['end']):
                value=hashlib.sha256(('fixture-p'+str(row['number'])+'-'+str(sector)).encode()).digest()*16
                self.seed(sector*SECTOR,value);self.sentinels.append((sector*SECTOR,value))
        os.fsync(self.fd)
        self.writes=[]
    def seed(self,offset,data):
        assert os.pwrite(self.fd,data,offset)==len(data)
    def read(self,offset,size):
        data=os.pread(self.fd,size,offset);assert len(data)==size;return data
    def close(self):os.close(self.fd)
    def region(self,name):
        row=self.plan[name];return self.read(row['offset'],len(row['old']))
    def write(self,operation,desired,cut=None):
        # Only one exact GPT entry-array or header extent is permitted. Neither
        # PMBR nor any sector within any partition is a writable extent.
        assert any(operation is x for x in self.plan['operations'])
        assert len(desired)==operation['size']
        offset,size=operation['offset'],operation['size']
        assert offset>=SECTOR and all(offset+size<=p['start']*SECTOR or offset>(p['end']+1)*SECTOR-1 for p in self.plan['old_entries'])
        count=len(desired) if cut is None else cut
        assert 0<=count<=len(desired)
        if count:assert os.pwrite(self.fd,desired[:count],offset)==count
        self.writes.append({'operation':operation['name'],'offset':offset,'bytes':count,'fsynced':False})
        if cut is not None:raise Cut()
        os.fsync(self.fd);self.writes[-1]['fsynced']=True
        assert self.read(offset,size)==desired
    def payload_untouched(self):
        assert self.read(0,SECTOR)==self.plan['primary']['old'][:SECTOR]
        assert all(self.read(offset,len(data))==data for offset,data in self.sentinels)


def durable_backup(fixture,directory):
    directory.mkdir(mode=0o700)
    receipt={'fixture_only':True,'disk_bytes':fixture.plan['disk_bytes'],'snapshots':[]}
    for key in ('primary','backup'):
        data=fixture.region(key);assert data==fixture.plan[key]['old']
        name=key+'.bin';fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            assert os.write(fd,data)==len(data);os.fsync(fd)
        finally:os.close(fd)
        assert (directory/name).read_bytes()==data
        receipt['snapshots'].append({'name':name,'bytes':len(data),'sha256':digest(data)})
    raw=(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(directory/'receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:assert os.write(fd,raw)==len(raw);os.fsync(fd)
    finally:os.close(fd)
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    # The parent directory must also durably contain the backup-directory entry.
    dfd=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    return receipt


def status(fixture):
    state={}
    for key in ('primary','backup'):
        row=fixture.plan[key];raw=fixture.region(key)
        try:
            h=g.header(raw,row['header_offset']);g.entries(raw,h,row['offset']//SECTOR)
            valid=True
        except (AssertionError,struct.error):valid=False
        state[key]={'crc_valid':valid,'kind':'old' if raw==row['old'] else 'candidate' if raw==row['new'] else 'partial'}
    return state


def recognized(fixture):
    # No opportunistic repair of foreign/tampered GPT data. A simulated torn
    # prefix may only leave original or candidate bytes at reviewed positions.
    for key in ('primary','backup'):
        row=fixture.plan[key];current=fixture.region(key)
        assert all(c==a or c==b for c,a,b in zip(current,row['old'],row['new'])), 'foreign GPT byte'


def recover_original(fixture):
    recognized(fixture);s=status(fixture)
    assert s['primary']['crc_valid'] or s['backup']['crc_valid'], 'no valid GPT copy; refuse automatic recovery'
    if s['primary']['crc_valid'] and s['primary']['kind']=='old':order=['backup']
    elif s['backup']['crc_valid'] and s['backup']['kind']=='old':order=['primary']
    elif s['backup']['crc_valid']:order=['primary','backup']
    else:order=['backup','primary']
    for key in order:
        if fixture.region(key)==fixture.plan[key]['old']:continue
        other='primary' if key=='backup' else 'backup'
        assert status(fixture)[other]['crc_valid']
        for op in fixture.plan['operations']:
            if op['copy']==key:fixture.write(op,op['old'])
        assert status(fixture)[key]=={'crc_valid':True,'kind':'old'}
    assert all(x=={'crc_valid':True,'kind':'old'} for x in status(fixture).values())
    fixture.payload_untouched()
    return order


def transact(fixture,backup_dir,fault=None):
    assert all(x=={'crc_valid':True,'kind':'old'} for x in status(fixture).values())
    receipt=durable_backup(fixture,backup_dir)
    assert len(receipt['snapshots'])==2
    for index,op in enumerate(fixture.plan['operations']):
        cut=fault['prefix'] if fault and fault['index']==index and fault['kind']=='prefix' else None
        fixture.write(op,op['new'],cut)
        if fault and fault['index']==index and fault['kind']=='after_fsync':raise Cut()
        if index==1:assert status(fixture)['backup']=={'crc_valid':True,'kind':'candidate'}
    assert all(x=={'crc_valid':True,'kind':'candidate'} for x in status(fixture).values())
    fixture.payload_untouched()


def load_plan():
    mp=R/'build/ubuntu26-gpt-candidate/v1/manifest.json';m=json.loads(mp.read_text())
    original={Path(x['path']).name:(R/x['path'],x['sha256']) for x in m['inputs']}
    changed={Path(x['path']).name:(R/x['path'],x['sha256']) for x in m['outputs']}
    plan={'disk_bytes':m['original_disk_sectors']*SECTOR,'old_entries':m['existing_entries_preserved_byte_for_byte'],'manifest':ref(mp),'operations':[]}
    for key in ('primary','backup'):
        oldpath,oldsha=original['emmc-'+key+'-gpt.bin'];newpath,newsha=changed[key+'.bin']
        for path,want in [(oldpath,oldsha),(newpath,newsha)]:
            assert stat.S_ISREG(path.lstat().st_mode) and g.sha(path)==want
        old,new=oldpath.read_bytes(),newpath.read_bytes();assert len(old)==len(new)
        offset=0 if key=='primary' else m['backup_file_first_lba']*SECTOR
        ho=SECTOR if key=='primary' else len(old)-SECTOR
        oh,nh=g.header(old,ho),g.header(new,ho)
        oe,eo=g.entries(old,oh,offset//SECTOR);ne,_=g.entries(new,nh,offset//SECTOR)
        assert oe[:1280]==ne[:1280] and oe[1408:]==ne[1408:] and not any(oe[1280:1408])
        assert all(hashlib.sha256(ne[i*128:(i+1)*128]).hexdigest()==p['sha256'] for i,p in enumerate(plan['old_entries']))
        allowed=set(range(eo+1280,eo+1408))|set(range(ho+16,ho+20))|set(range(ho+88,ho+92))
        assert all(i in allowed for i,(a,b) in enumerate(zip(old,new)) if a!=b)
        plan[key]={'offset':offset,'header_offset':ho,'old':old,'new':new,'array_offset':eo,'array_size':len(oe)}
    assert plan['primary']['old'][:SECTOR]==plan['primary']['new'][:SECTOR]
    for key in ('backup','primary'):
        row=plan[key]
        for name,off,size in [('entries',row['array_offset'],row['array_size']),('header',row['header_offset'],SECTOR)]:
            plan['operations'].append({'name':key+'_'+name,'copy':key,'offset':row['offset']+off,'size':size,'old':row['old'][off:off+size],'new':row['new'][off:off+size]})
    return plan,m


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);a=p.parse_args()
    assert re.fullmatch('[a-zA-Z0-9_-]+',a.label)
    plan,candidate=load_plan();out=R/'build/ubuntu26-gpt-transaction'/a.label;out.mkdir(parents=True,exist_ok=False)
    tests=[]
    faults=[]
    for i,op in enumerate(plan['operations']):
        # Adjacent unchanged bytes produce the same persisted-prefix state.
        # Enumerate every DISTINCT old/new byte state, rather than sampling just
        # sector boundaries or assuming a whole GPT sector is atomic.
        cuts={0,len(op['new'])}
        cuts.update(n+1 for n,(x,y) in enumerate(zip(op['old'],op['new'])) if x!=y)
        faults.extend({'index':i,'kind':'prefix','prefix':n} for n in sorted(cuts))
        faults.append({'index':i,'kind':'after_fsync'})
    for number,fault in enumerate([None,*faults]):
        label='success' if fault is None else f'fault-{number:03d}'
        f=Fixture(out/(label+'.img'),plan)
        try:
            try:transact(f,out/(label+'-backup'),fault)
            except Cut:assert fault is not None
            else:assert fault is None
            s=status(f);assert any(x['crc_valid'] for x in s.values());recognized(f);f.payload_untouched()
            if fault is None:
                parsed=json.loads(subprocess.check_output(['sfdisk','--json',str(f.path)],text=True))
                assert len(parsed['partitiontable']['partitions'])==11
                assert parsed['partitiontable']['partitions'][-1]['start']==candidate['new_partition']['start_sector']
            written_before=len(f.writes);order=recover_original(f)
            if fault is None:
                parsed=json.loads(subprocess.check_output(['sfdisk','--json',str(f.path)],text=True))
                assert len(parsed['partitiontable']['partitions'])==10
            tests.append({'case':label,'fault':fault,'state_at_cut':s,'recovery_order':order,
                          'writes_before_recovery':written_before,'writes':f.writes,
                          'original_copies_restored':True,'pmbr_and_partition_sentinels_preserved':True})
        finally:f.close();f.path.unlink()
    # Reject a foreign byte even if the untouched GPT copy would still be valid.
    f=Fixture(out/'foreign.img',plan)
    try:
        position=plan['backup']['offset']+plan['backup']['header_offset']+24
        old=f.read(position,1);f.seed(position,bytes([old[0]^0x80]))
        try:recover_original(f)
        except AssertionError:foreign_refused=True
        else:raise AssertionError('foreign change accepted')
        assert not f.writes
        # The transaction writer cannot be repurposed to PMBR or p11 payload.
        for offset in [0,candidate['new_partition']['start_sector']*SECTOR]:
            try:f.write({'offset':offset,'size':512,'name':'foreign'},bytes(512))
            except AssertionError:pass
            else:raise AssertionError('unreviewed write extent accepted')
    finally:f.close();f.path.unlink()
    # Fail closed before metadata writes if durable host backup cannot finish.
    f=Fixture(out/'backup-failure.img',plan)
    try:
        with mock.patch('os.fsync',side_effect=OSError('injected backup fsync failure')):
            try:transact(f,out/'backup-failure-backup')
            except OSError:backup_failure_refused=True
            else:raise AssertionError('backup fsync failure accepted')
        assert not f.writes
        assert all(x=={'crc_valid':True,'kind':'old'} for x in status(f).values())
    finally:f.close();f.path.unlink()
    # A recognized old/new byte mixture is still not sufficient if neither
    # copy has a valid CRC. Recovery never guesses a table from partial data.
    f=Fixture(out/'both-invalid.img',plan)
    try:
        for key in ('primary','backup'):
            op=next(x for x in plan['operations'] if x['name']==key+'_entries')
            i=next(i for i,(a,b) in enumerate(zip(op['old'],op['new'])) if a!=b)
            f.seed(op['offset']+i,op['new'][i:i+1])
        recognized(f);assert not any(x['crc_valid'] for x in status(f).values())
        try:recover_original(f)
        except AssertionError as error:
            assert 'no valid GPT copy' in str(error);both_invalid_refused=True
        else:raise AssertionError('two invalid copies accepted')
        assert not f.writes
    finally:f.close();f.path.unlink()
    kernel=R/'build/pcan-usb-fd/work/kernel/linux-4.19'
    kernel_review={
        'status':'source_review_only_no_ioctl_or_device_access',
        'sources':[ref(kernel/x) for x in ('block/ioctl.c','block/partition-generic.c','include/uapi/linux/blkpg.h','.config')],
        'BLKPG_ADD_PARTITION':{
            'requires':['CAP_SYS_ADMIN','whole-disk descriptor','positive partition number','start aligned to logical block size','no overlap with any existing partition'],
            'does_not_require_all_other_partitions_unmounted':True,
            'userspace_must_check':['positive signed-64 start and length','both values divisible by 512','addition does not overflow','end does not exceed independently checked BLKGETSIZE64','exact p11 number and expected disk identity'],
            'argument_abi':'Native struct blkpg_ioctl_arg with native pointer to struct blkpg_partition; start and length are signed 64-bit byte quantities, not GPT little-endian serialized data.',
            'p11':{'number':11,'start_bytes':26849280*512,'length_bytes':25165824*512,'expected_major':179,'expected_minor':11},
            'CONFIG_MMC_BLOCK_MINORS':32,
            'partition_info':None,
            'immediate_sysfs_checks':['start','size','major:minor'],
            'PARTNAME_and_PARTUUID_after_BLKPG':False,
            'note':'add_partition receives info=NULL. GPT names and GUIDs become kernel partition metadata only after a later full GPT scan.'},
        'BLKRRPART':{'unsuitable_for_busy_root':True,'reason':'rescan_partitions calls drop_partitions, which returns EBUSY when bd_part_count or bd_super is nonzero.'},
        'native_helper_implemented':False,'target_ioctl_acceptance':False}
    assert 'CONFIG_MMC_BLOCK_MINORS=32' in (kernel/'.config').read_text()
    dump(out/'kernel-partition-review.json',kernel_review)
    ops=[{k:v for k,v in op.items() if k not in ('old','new')}|{'old_sha256':digest(op['old']),'new_sha256':digest(op['new'])} for op in plan['operations']]
    procedure={'status':'reviewable_physical_procedure_not_executable','expected_cid':None,
        'cid_gate':'Obtain and independently review a trusted fresh eMMC CID; exactmatch again immediately before transaction. No currentCID is invented.',
        'preconditions':['Trusted SSH identity and exactGT-BE19000AI model; samefreshbootID throughout acquisition.',
          'Booted originalstockslot2, exactoriginal p5/p6 SHA256, both bootmetadata CRCs valid, stockslot2 committed/valid; no firmware update or bootselection mutation in flight.',
          'Whole eMMC logicalsector512 and exact61226496sectors, reviewedCID and diskGUID; primary+backup GPT CRCs valid and rawbytes exactoriginalinputSHA; p1–10 start/end/names/attributes/GUIDs unchanged and p11–128 empty.',
          'Preserve4mandatory native filesystems data/defaults/jffs/aiboard with exactknownUUID/name/extent and healthyexistingmounts; damagedstockmandatorylayout is a stopcondition.',
          'Revalidate exactstockfallback ELF/ROM hashes and major179 SDHCI path against stock audit; normalMMC event path is excluded from USB major8, no invented hotplug suspension.',
          'Durable fresh GPTbackups plus receipt stored onhost before firstGPTwrite; a copy solely on the affected eMMC is insufficient.'],
        'write_order':ops,'per_step':'Write only the declared metadata extent; handle shortwrites; fsync whole-disk fd; reread exact bytes. After backupheader step validatebackup CRC before touchingprimary.',
        'prohibited':['No PMBRwrite','No partitionpayload write or filesystemformat','No alteration of p1–10 serializedentries','No stock bootmetadata/slotselection changes','No blind sgdisk recovery or whole-table reread onbusyroot'],
        'recovery':'Only recover a knowninterruptedtransaction state with authenticated oldbackup and at leastone validknownGPTcopy. Restoretheothercopy first and fsync/validate it before replacing the retainedvalidcopy. Refuseforeignbytes or no-valid-copy for manualreview.',
        'kernel_partition_visibility':'After both candidate GPT copies verify, prefer BLKPG_ADD_PARTITION for p11 using native ABI and the exact byte start/length in kernel-partition-review.json. Check signed range, alignment, capacity and identity in userspace. EBUSY/EEXIST requires inspection of existing p11 boundaries; never delete or recreate busy p1–10. BLKPG creates no GPT PARTNAME/PARTUUID; verify sysfs start, size and major:minor. Native helper implementation and target ioctl acceptance remain separate gates.',
        'stock_recovery_limit':'Exactstock audit excludes normalUSBautomount forMMC; missingmandatorypartitions can still trigger destructivepartitioncfg reconstruction ofp8+. No labelquarantine claim.'}
    dump(out/'physical-procedure.json',procedure)
    report={'schema_version':1,'status':'passed_regular_sparse_file_fault_and_recovery_tests','candidate_manifest':plan['manifest'],
        'operations':ops,'success_and_fault_cases':len(tests),'fault_cases':len(faults),'cases':tests,
        'foreign_byte_refused_before_write':foreign_refused,'unreviewed_extent_refused':True,
        'backup_fsync_failure_refused_before_write':backup_failure_refused,'two_invalid_copies_refused_before_write':both_invalid_refused,
        'kernel_partition_review':ref(out/'kernel-partition-review.json'),
        'every_distinct_persisted_byte_prefix_state_covered':True,'at_least_one_valid_copy_at_every_cut':True,
        'backups_fsynced_before_transaction_writes':True,'pmbr_and_partition_payload_transaction_writes':False,
        'independent_sfdisk_candidate_and_restored_checked':True,'physical_procedure':ref(out/'physical-procedure.json'),
        'stock_fallback_evidence':ref(R/'reports/ubuntu26/asus-stock-emmc-fallback.json'),
        'device_opened':False,'device_written':False,'network_used':False,'deployment_allowed':False,
        'limits':['Regularfile fsync tests do not prove eMMCcontroller powerlossatomicity or cacheflush honesty.',
                  'Distinct byteprefix persistence is a conservative testedfaultmodel, not all arbitrarysectorcorruption patterns.',
                  'Writer has no device/physical mode or arbitrary disk path input. BLKPG semantics were source-reviewed; native helper implementation and target ioctl acceptance remain pending.',
                  'FreshCID, bootedstock2, liveGPT and4mandatoryfilesystemhealth gates remain unsatisfied until a separatelyauthorizedread-onlycapture.'],
        'source':ref(Path(__file__).resolve())}
    (out/'builder.py').write_bytes(Path(__file__).read_bytes())
    report['source_snapshot']=ref(out/'builder.py')
    dump(out/'manifest.json',report)
    summary={k:v for k,v in report.items() if k!='cases'};summary['manifest']=ref(out/'manifest.json')
    dump(R/'reports/ubuntu26/gpt-transaction-offline.json',summary)
    print(json.dumps({'status':report['status'],'cases':len(tests),'manifest':str((out/'manifest.json').relative_to(R)),'device_opened':False},indent=2))


if __name__=='__main__':main()

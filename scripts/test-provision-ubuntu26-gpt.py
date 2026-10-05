#!/usr/bin/env python3
"""No-network GPT orchestration tests; all remote block contents are bytearrays."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock
import uuid
import zlib

R=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('gpt_host',R/'scripts/provision-ubuntu26-gpt.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)


def synthetic(plan):
    payload=b'COMMITTED=2\0VALID=1,2\0SEQ=5,4\0'
    meta=bytearray(262144);struct.pack_into('<III',meta,0,len(payload)+4,len(payload)+4,zlib.crc32(payload));meta[12:12+len(payload)]=payload
    raw={key:m.record_blob(row['old']) for key,row in [('primary',plan['primary']),('backup',plan['backup'])]}
    raw.update({key:m.record_blob(bytes(meta)) for key in ('metadata1','metadata2')})
    text={'boot_id':'11111111-2222-3333-4444-555555555555','uid':'0','cid':m.CID,
          'sectors':'61226496','logical_sector':'512','disk_dev':'179:0','disk_node':'61b0:b3:0',
          'mmc_sysfs':'../devices/platform/periph/ff810000.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0',
          'mmc_device':'../../../mmc0:0001','asus_mmc_absent':'absent','cmdline':'rootwait root=/dev/mmcblk0p6',
          'dd_help':'conv=notrunc|noerror|sync|fsync','mountinfo':'20 1 179:6 / / ro - squashfs /dev/root ro'}
    for n,(fsuuid,path) in m.FS.items():
        sb=bytearray(1024);sb[56:58]=b'\x53\xef';sb[104:120]=uuid.UUID(fsuuid).bytes
        raw['superblock'+str(n)]=m.record_blob(bytes(sb));text['errors'+str(n)]='0'
        text['mountinfo']+=f'\n{20+n} 20 179:{n} / {path} rw,relatime - ext4 /dev/alias rw,errors=remount-ro'
    return {'schema':1,'plan_sha256':m.PLAN_SHA,'captured_unix':1791130336,'full_slot_hashes_read':True,
            'transport':{'host':'192.168.100.15','port':22,'username':'MastermixStudios','source':'192.168.100.36',
                         'fingerprint':'SHA256:fixture','known_hosts_sha256':'a'*64},'text':text,'raw':raw,
            'partitions':{str(x['number']):{'start':str(x['start']),'size':str(x['end']-x['start']+1),'dev':'179:'+str(x['number'])} for x in plan['old_entries']},
            'hashes':{m.BB:m.BB_SHA,**m.STOCK,**{m.DEVICE+'p'+str(n):v for n,v in m.SLOTS.items()}}}


class Fake:
    def __init__(self,snapshot,plan,fail=None):
        self.current=copy.deepcopy(snapshot);self.plan=plan;self.fail=fail
        self.writes=[];self.begun=False;self.finished=False;self.captures=0
    def capture(self,plan,full=True,prior=None):
        self.captures+=1
        if self.fail=='capture_after_write' and self.writes:raise m.Refusal('offline_disconnected')
        result=copy.deepcopy(self.current);result['full_slot_hashes_read']=full
        if self.fail=='boot_after_backup' and self.captures>=2:result['text']['boot_id']='22222222-2222-3333-4444-555555555555'
        return result
    def begin(self,token):
        if self.fail=='lock_exists':raise m.Refusal('foreign_lock_exists')
        self.begun=True;return '/tmp/leon-gpt-'+token
    def stage_files(self,operations,desired):
        self.staged=[x['name'] for x in operations]
        if self.fail=='stage_hash':raise m.Refusal('staged_hash_mismatch')
    def write_extent(self,op,desired,boot_id):
        self.writes.append(op['name'])
        raw=bytearray(m.blob(self.current,op['copy']));offset=op['offset']-self.plan[op['copy']]['offset']
        data=op[desired]
        if self.fail==('torn',len(self.writes)):
            # Copy half of the changed positions, not an unchanged 16KB prefix.
            changes=[i for i,(a,b) in enumerate(zip(raw[offset:offset+len(data)],data)) if a!=b]
            cut=changes[len(changes)//2]+1 if changes else len(data)//2
            raw[offset:offset+cut]=data[:cut];self.current['raw'][op['copy']]=m.record_blob(bytes(raw))
            raise m.UnknownOutcome('mock_unknown_write')
        raw[offset:offset+len(data)]=data;self.current['raw'][op['copy']]=m.record_blob(bytes(raw))
        if self.fail=='foreign_after_write':
            raw[60]^=0x80;self.current['raw'][op['copy']]=m.record_blob(bytes(raw))
        if self.fail==('unknown_after_fsync',len(self.writes)):raise m.UnknownOutcome('mock_lost_exit_status')
    def finish(self,operations):self.finished=True


def main():
    p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
    m.require(__import__('re').fullmatch('[a-zA-Z0-9_-]+',a.label),'label')
    out=R/'build/ubuntu26-gpt-host'/a.label;out.mkdir(parents=True,exist_ok=False)
    plan,tx=m.load_plan();base=synthetic(plan);tests=[]
    m.validate(base,plan,tx,'old')
    def run(name,fn):
        fn();tests.append({'case':name,'passed':True})
    def reject(snapshot,code=None):
        try:m.validate(snapshot,plan,tx,'old')
        except m.Refusal as e:
            if code:assert str(e)==code,(str(e),code)
        else:raise AssertionError('accepted bad capture')
    def change(path,value):
        x=copy.deepcopy(base);dest=x
        for key in path[:-1]:dest=dest[key]
        dest[path[-1]]=value;return x
    with mock.patch.object(socket,'socket',side_effect=AssertionError('NETWORK FORBIDDEN')):
        for name,path,value in [
            ('cid',['text','cid'],'f'*32),('capacity',['text','sectors'],'1'),
            ('logical4096',['text','logical_sector'],'4096'),('notroot',['text','uid'],'1'),
            ('wrongdev',['text','disk_dev'],'8:0'),('regularnode',['text','disk_node'],'81b0:b3:0'),
            ('scsi',['text','mmc_sysfs'],'/host0/target0'),('asus_mmc',['text','asus_mmc_absent'],'exists'),
            ('kernel9_root_p4',['text','cmdline'],'root=/dev/mmcblk0p4'),
            ('duplicate_rootarg',['text','cmdline'],'root=/dev/mmcblk0p6 root=/dev/mmcblk0p4'),
            ('no_fsync',['text','dd_help'],'conv=notrunc'),('p7_extent',['partitions','7','size'],'1'),
            ('slot5_hash',['hashes',m.DEVICE+'p5'],'0'*64),('slot6_hash',['hashes',m.DEVICE+'p6'],'0'*64),
            ('stockrc_hash',['hashes','/sbin/rc'],'0'*64),('bb_hash',['hashes',m.BB],'0'*64),
            ('ext4_errorcount',['text','errors7'],'1'),('wrong_boot',['text','boot_id'],'not-uuid'),
            ('p11_exists',['partitions','11'],{'start':'26849280','size':'25165824','dev':'179:11'})]:
            run('reject_'+name,lambda path=path,value=value:reject(change(path,value)))
        for n in m.FS:
            def bad_uuid(n=n):
                x=copy.deepcopy(base);sb=bytearray(m.blob(x,'superblock'+str(n)));sb[104]^=1
                x['raw']['superblock'+str(n)]=m.record_blob(bytes(sb));reject(x,'mandatory_ext4_uuid_or_magic')
            run('reject_uuid_p'+str(n),bad_uuid)
        for name,fromtext,totext in [('mount_missing','/data','/wrong'),('mount_readonly','/data rw','/data ro'),
                                     ('root_wrong_major','179:6 / /','179:4 / /')]:
            run('reject_'+name,lambda f=fromtext,t=totext:reject(change(['text','mountinfo'],base['text']['mountinfo'].replace(f,t))))
        def bad_meta():
            x=copy.deepcopy(base);data=bytearray(m.blob(x,'metadata1'));data[20]^=1
            x['raw']['metadata1']=x['raw']['metadata2']=m.record_blob(bytes(data));reject(x,'metadata_crc')
        run('reject_metadata_crc',bad_meta)
        for name,word in [('mismatch',32),('overflow',65536),('short',7)]:
            def bad_header(name=name,word=word):
                x=copy.deepcopy(base);data=bytearray(m.blob(x,'metadata1'));struct.pack_into('<I',data,0,word)
                if name!='mismatch':struct.pack_into('<I',data,4,word)
                x['raw']['metadata1']=x['raw']['metadata2']=m.record_blob(bytes(data));reject(x,'metadata_length_header')
            run('reject_metadata_header_'+name,bad_header)
        def real_metadata():
            data=(R/'evidence/ubuntu26/boot-metadata/20261004-v4/metadata1.bin').read_bytes()
            assert m.metadata(data)=={'COMMITTED':'2','VALID':'1,2','SEQ':'5,4'}
        run('parse_existing_readonly_v4_metadata',real_metadata)
        def foreign():
            x=copy.deepcopy(base);data=bytearray(m.blob(x,'backup'));data[-1]^=1
            x['raw']['backup']=m.record_blob(bytes(data));reject(x,'foreign_gpt_bytes')
        run('reject_foreign_gpt',foreign)
        def success():
            d=out/'success';d.mkdir(mode=0o700);remote=Fake(base,plan)
            result=m.perform(remote,plan,tx,base,d)
            assert result['status']=='complete_gpt_only_no_kernel_partition_added'
            assert remote.writes==['backup_entries','backup_header','primary_entries','primary_header']
            assert remote.finished
            for name in ('primary','backup','metadata1','metadata2'):
                assert (d/'pre-write-backup'/(name+'.bin')).read_bytes()==m.blob(base,name)
            for path in (d/'pre-write-backup').iterdir():assert path.stat().st_mode&0o777==0o600
        run('success_fixed_four_extents_durable_backup',success)
        def fsync_failure():
            d=out/'fsyncfail';d.mkdir(mode=0o700);remote=Fake(base,plan)
            with mock.patch.object(m.os,'fsync',side_effect=OSError('fixture fsync failed')):
                try:m.perform(remote,plan,tx,base,d)
                except OSError:pass
                else:raise AssertionError('fsync accepted')
            assert not remote.begun and not remote.writes
        run('host_fsync_failure_zero_remote_mutations',fsync_failure)
        for fault in ('stage_hash','lock_exists','boot_after_backup','foreign_after_write','capture_after_write',
                      *[('torn',n) for n in range(1,5)],*[('unknown_after_fsync',n) for n in range(1,5)]):
            def failed(fault=fault):
                d=out/('fail-'+str(len(tests)));d.mkdir(mode=0o700);remote=Fake(base,plan,fault)
                try:m.perform(remote,plan,tx,base,d)
                except m.Refusal:pass
                else:raise AssertionError('failure ignored')
                result=json.loads((d/'result.json').read_text())
                assert result['status']=='stopped_requires_readonly_review' and not remote.finished
                if isinstance(fault,tuple):assert len(remote.writes)==fault[1]
                elif fault in ('stage_hash','lock_exists','boot_after_backup'):assert not remote.writes
                else:assert len(remote.writes)==1
            run('stop_without_retry_'+str(fault),failed)
        for cutindex in range(4):
            def recovery(cutindex=cutindex):
                state=Fake(base,plan)
                for op in plan['operations'][:cutindex+1]:state.write_extent(op,'new',base['text']['boot_id'])
                # A reboot after a power cut is permitted only when the new full
                # reviewed capture still proves stock p6, metadata and identity.
                state.current['text']['boot_id']='22222222-2222-3333-4444-555555555555'
                d=out/('recovery-'+str(cutindex));d.mkdir(mode=0o700)
                reviewed=copy.deepcopy(state.current);state.writes=[]
                result=m.perform(state,plan,tx,reviewed,d,recover=True,original=base)
                assert result['status']=='complete_gpt_only_no_kernel_partition_added'
                assert all(m.blob(state.current,k)==plan[k]['old'] for k in ('primary','backup'))
                assert state.writes[0]==('primary_entries' if cutindex>=2 else 'backup_entries')
            run('explicit_recovery_valid_copy_first_after_step'+str(cutindex+1),recovery)
        def sameboot():
            fresh=change(['text','boot_id'],'22222222-2222-3333-4444-555555555555')
            remote=Fake(fresh,plan);d=out/'sameboot';d.mkdir(mode=0o700)
            try:m.perform(remote,plan,tx,base,d)
            except m.Refusal as e:assert str(e)=='fresh_capture_identity_changed'
            else:raise AssertionError()
            assert not remote.begun and not remote.writes
        run('reviewed_same_boot_required',sameboot)
        def trustchanged():
            fresh=change(['transport','fingerprint'],'SHA256:different');remote=Fake(fresh,plan)
            d=out/'trust';d.mkdir(mode=0o700)
            try:m.perform(remote,plan,tx,base,d)
            except m.Refusal:pass
            else:raise AssertionError()
            assert not remote.begun
        run('fingerprint_changed_zero_mutations',trustchanged)
        def reviewedfile():
            f=out/'reviewed.json';m.durable_file(f,m.canonical(base))
            assert m.read_reviewed(f,m.sha(f.read_bytes()))==base
            for target,digest in [(f,'0'*64),(out/'symlink.json',m.sha(f.read_bytes()))]:
                if target!=f:target.symlink_to(f)
                try:m.read_reviewed(target,digest)
                except (m.Refusal,OSError):pass
                else:raise AssertionError()
        run('reviewed_file_hash_and_no_follow',reviewedfile)
        def ddsyntax():
            m.dd_status(b'32+0 records in\n32+0 records out\n',32)
            m.dd_status(b'32+0 records in\n32+0 records out\n16384 bytes (16.0kB) copied, 0.012345 seconds, 1.3MB/s\n',32)
            for x in [b'31+0 records in\n31+0 records out\n',b'32+0 records in\n32+0 records out\nI/O error\n']:
                try:m.dd_status(x,32)
                except m.Refusal:pass
                else:raise AssertionError()
        run('dd_exact_records_optional_speedline_and_errors',ddsyntax)
        def shortread():
            obj=object.__new__(m.SSH)
            obj.command=lambda *a,**kw:(b'x'*511,b'1+0 records in\n1+0 records out\n')
            try:obj.raw_read(m.DEVICE,0,1)
            except m.Refusal as e:assert str(e)=='remote_short_read'
            else:raise AssertionError()
        run('dd_shortread_refused_despite_exit0',shortread)
        def prewrite_source():
            obj=object.__new__(m.SSH);obj.stage='/tmp/leon-gpt-'+'0'*32;seen=[]
            obj.text=lambda command:base['text']['boot_id'] if 'boot_id' in command else '600:0:0:1:16384'
            obj.file_metadata=lambda path:{'mode':'-rw-------','links':1,'uid':0,'gid':0,'size':16384}
            obj.command=lambda command,**kw:(seen.append(command) or (b'0'*64+b'  '+(obj.stage+'/backup_entries.bin').encode()+b'\n',b''))
            try:obj.write_extent(plan['operations'][0],'new',base['text']['boot_id'])
            except m.Refusal as e:assert str(e)=='staged_file_changed'
            else:raise AssertionError()
            assert all(' of=' not in x for x in seen)
        run('staged_source_changed_prevents_dd_write',prewrite_source)
        def extent_guard():
            obj=object.__new__(m.SSH)
            for offset,size in [(0,512),(512*512,512),(26849280*512,16384),(512,1024)]:
                op=dict(plan['operations'][0],offset=offset,size=size)
                try:obj.write_extent(op,'new',base['text']['boot_id'])
                except m.Refusal as e:assert str(e)=='unapproved_write_extent'
                else:raise AssertionError()
        run('pmbr_partition_payload_and_wrong_size_refused',extent_guard)
        def staging():
            obj=object.__new__(m.SSH);obj.stage='/tmp/leon-gpt-'+'0'*32;commands=[]
            op=plan['operations'][0];path=obj.stage+'/'+op['name']+'.bin'
            def command(cmd,**kw):
                commands.append((cmd,kw))
                return ((m.sha(op['new'])+'  '+path+'\n').encode(),b'') if 'sha256sum' in cmd else (b'',b'')
            obj.command=command;obj.file_metadata=lambda path:{'mode':'-rw-------','links':1,'uid':0,'gid':0,'size':16384}
            obj.stage_files([op],'new')
            assert commands[0][0]=='umask 077; set -C; /bin/busybox cat > '+path
            assert commands[0][1]['stdin']==op['new']
            assert all(m.DEVICE not in cmd for cmd,_ in commands)
        run('staging_regular_noclobber_pipe_never_targets_block',staging)
        def bounded_transport():
            class Channel:
                def __init__(self,data=b'OK'):self.data=data;self.sent=b'';self.closed=False;self.eof=False
                def settimeout(self,n):pass
                def exec_command(self,c):self.cmd=c
                def sendall(self,d):self.sent+=d
                def shutdown_write(self):self.eof=True
                def recv_ready(self):return bool(self.data)
                def recv_stderr_ready(self):return False
                def recv(self,n):data=self.data[:n];self.data=self.data[n:];return data
                def exit_status_ready(self):return True
                def recv_exit_status(self):return 0
                def close(self):self.closed=True
            obj=object.__new__(m.SSH);obj.close=lambda:None
            channel=Channel();obj.transport=SimpleNamespace(open_session=lambda **kw:channel,is_active=lambda:True)
            assert obj.command('fixed',stdin=b'bytes',limit=2)==(b'OK',b'')
            assert channel.sent==b'bytes' and channel.eof and channel.closed
            channel=Channel(b'toolong')
            try:obj.command('fixed',limit=2)
            except m.Refusal as e:assert str(e)=='ssh_output_limit'
            else:raise AssertionError()
            assert channel.closed
            obj.capture_deadline=0
            try:obj.command('must-not-run')
            except m.Refusal as e:assert str(e)=='capture_total_deadline'
            else:raise AssertionError()
        run('mock_channel_stdin_eof_output_bound_and_capture_deadline',bounded_transport)
        def exact_stock_dd():
            bb=R/'build/stock-rootfs/bin/busybox'
            assert m.sha(bb.read_bytes())==m.BB_SHA
            fixture=tx.Fixture(out/'stock-dd-sparse.img',plan);logs=[]
            try:
                for op in plan['operations']:
                    source=out/(op['name']+'.bin');source.write_bytes(op['new'])
                    argv=['qemu-arm','-strace','-L',str(R/'build/stock-rootfs'),str(bb),'dd',
                        'if='+str(source),'of='+str(fixture.path),'bs=512',
                        'seek='+str(op['offset']//512),'count='+str(op['size']//512),'conv=notrunc,fsync']
                    result=subprocess.run(argv,capture_output=True,timeout=10)
                    logs.append({'name':op['name'],'status':result.returncode,
                                 'trace':result.stderr.decode(errors='replace')})
                    assert result.returncode==0 and not result.stdout
                    assert __import__('re').search(r'fsync\([0-9]+\) = 0',logs[-1]['trace'])
                    assert fixture.read(op['offset'],op['size'])==op['new']
                    fixture.payload_untouched()
                assert all(x=={'crc_valid':True,'kind':'candidate'} for x in tx.status(fixture).values())
                (out/'stock-dd-qemu-user.json').write_bytes(m.canonical({'stock_busybox_sha256':m.BB_SHA,
                    'regular_sparse_file_only':True,'block_device_opened':False,'operations':logs}))
            finally:fixture.close();fixture.path.unlink()
        run('exact_stock_armel_dd_large_offsets_fsync_regular_sparse_fixture',exact_stock_dd)
        def ls_metadata():
            actual='-rw-------    1 0        0              170 Jan  1  2024 /tmp/etc/shadow'
            assert m.safe_staged(m.parse_ls(actual,'/tmp/etc/shadow'),170)
            block='brw-------    1 0        0         179,  11 Oct  4 15:13 /dev/mmcblk0p11'
            assert m.block_node(m.parse_ls(block,'/dev/mmcblk0p11'))=='6000:b3:b'
            for line in [actual+'\n'+actual,actual.replace(' 0        0 ',' root     root '),actual+' -> /etc/shadow']:
                try:m.parse_ls(line,'/tmp/etc/shadow')
                except m.Refusal:pass
                else:raise AssertionError()
            assert m.root_uid('Name:\tcat\nUid:\t0\t0\t0\t0\n')=='0'
            try:m.root_uid('Uid:\t1000\t0\t0\t0\n')
            except m.Refusal:pass
            else:raise AssertionError()
            fixture=out/'ls-regular';fixture.write_bytes(b'fixture');fixture.chmod(0o600)
            argv=['qemu-arm','-L',str(R/'build/stock-rootfs'),str(R/'build/stock-rootfs/bin/busybox')]
            listing=subprocess.check_output(argv+['ls','-ldn',str(fixture)],text=True).strip()
            parsed=m.parse_ls(listing,str(fixture))
            assert parsed['mode']=='-rw-------' and parsed['links']==1 and parsed['size']==7 and parsed['uid']==os.getuid()
            applets=subprocess.check_output(argv+['--list'],text=True).splitlines()
            assert 'stat' not in applets and 'id' not in applets
            assert set(['ls','cat','dd','env','sh','sha256sum','readlink','mkdir','rm','rmdir','tr','test','awk','gzip','df','chmod'])<=set(applets)
            (out/'stock-busybox-applets.txt').write_text('\n'.join(applets)+'\n')
        run('exact_stock_ls_numeric_parser_and_no_stat_no_id_contract',ls_metadata)
    report={'schema':1,'status':'offline_mock_protocol_passed_not_hardware_accepted',
            'tests':tests,'test_count':len(tests),'network_connections':0,'block_devices_opened':0,
            'physical_gpt_writes':0,'sources':[{'path':str(p.relative_to(R)),'sha256':m.sha(p.read_bytes())}
                for p in [Path(m.__file__),Path(__file__).resolve()]],'plan_sha256':m.PLAN_SHA,
            'limits':['Mock SSH/block contents; no real Dropbear transport compatibility or physical fsync acceptance. Regular staging uses noclobber ash cat because the extracted stock image lacks SFTP.',
                'Retained remote lock after unknown outcome requires separate human/parent review and verified writer quiescence before explicit recovery.',
                'Recovery intentionally refuses any kernel p11, including after reboot when GPT scanning discovered p11; such a state needs a separate unmounted-consumer recovery review.',
                'Advisory lock only serializes this tool, not ASUS firmware writers; exclusive maintenance is an external prerequisite.',
                'No power-loss atomicity guarantee. Existing sparse-file fixture covers persisted-prefix cuts, not arbitrary hardware failures.']}
    (out/'result.json').write_bytes(m.canonical(report));print(json.dumps({'report':str(out/'result.json'),'tests':len(tests)}))


if __name__=='__main__':main()

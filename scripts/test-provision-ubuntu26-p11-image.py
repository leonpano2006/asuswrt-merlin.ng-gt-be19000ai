#!/usr/bin/env python3
"""Offline p11 transfer controls; bytearray mocks and new regular-file fixtures."""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from unittest import mock

R=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m
m=load('image_host',R/'scripts/provision-ubuntu26-p11-image.py')
t=load('gpt_test_fixture',R/'scripts/test-provision-ubuntu26-gpt.py')


def synthetic(plan):
    s=t.synthetic(plan);s['partitions']['11']=m.P11_ROW.copy()
    for k in ('primary','backup'):s['raw'][k]=m.g.record_blob(plan[k]['new'])
    s['text']['mountinfo']+='\n31 20 0:22 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw,size=2097152k'
    s['p11']={'node':'6000:b3:b','all_namespace_mounts':'','holders':'','active_swap':'',
        'meminfo':'MemTotal:       4042252 kB\nMemAvailable:   3187952 kB',
        'tmp_df':'Filesystem 1024-blocks Used Available Capacity Mounted on\ntmpfs 2097152 1024 2096128 1% /tmp/mnt'}
    return s


class Fake:
    def __init__(self,state,fail=None):self.state=copy.deepcopy(state);self.fail=fail;self.writes=0;self.uploads=[];self.captures=0
    def capture(self,plan,full=True,prior=None):
        self.captures+=1;s=copy.deepcopy(self.state);s['full_slot_hashes_read']=full
        if self.fail=='boot_changed' and self.captures>1:s['text']['boot_id']='22222222-2222-3333-4444-555555555555'
        if self.fail=='mounted_after_upload' and self.uploads:s['p11']['all_namespace_mounts']='999:/mountpoint'
        return s
    def begin_image(self,token):
        if self.fail=='lock':raise m.g.Refusal('lock_exists')
        return '/tmp/leon-p11-'+token
    def upload(self,name,stream,size,digest,mode=0o600):
        self.uploads.append(name)
        if self.fail=='upload':raise m.g.Refusal('upload_failed')
    def verify_gzip(self,image):
        if self.fail=='gzip_test':raise m.g.Refusal('gzip_bad')
    def write_image(self):
        self.writes+=1
        if self.fail=='write_unknown':raise m.g.UnknownOutcome('partial')
        return 'a'*64
    def readback_hash(self):return '0'*64 if self.fail=='wrong_readback' else m.IMAGE_SHA
    def fsck_readonly(self):
        if self.fail=='fsck_nonzero':raise m.g.Refusal('fsck_nonzero')
        return {'mode':'-fn','exit':0}


def main():
    p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
    m.g.require(__import__('re').fullmatch('[A-Za-z0-9_-]+',a.label),'label')
    out=R/'build/ubuntu26-p11-image-host'/a.label;out.mkdir(parents=True,exist_ok=False)
    plan,tx=m.g.load_plan();state=synthetic(plan);image=json.loads(m.IMAGE_MANIFEST.read_text());tests=[]
    def run(name,fn):fn();tests.append({'case':name,'passed':True})
    with mock.patch.object(socket,'socket',side_effect=AssertionError('NETWORK FORBIDDEN')):
        m.validate(state,plan,tx,image)
        for name,path,value in [
            ('extent',['partitions','11','start'],'26849281'),('size',['partitions','11','size'],'1'),
            ('node',['p11','node'],'6000:b3:a'),('namespace_mount',['p11','all_namespace_mounts'],'pid1:mounted'),
            ('holders',['p11','holders'],'dm-0'),('swap',['p11','active_swap'],'active'),
            ('lowram',['p11','meminfo'],'MemAvailable: 1024 kB'),
            ('lowtmp',['p11','tmp_df'],'Filesystem 1024-blocks Used Available Capacity Mounted on\ntmpfs 2097152 2097100 52 100% /tmp/mnt'),
            ('rootp4',['text','cmdline'],'root=/dev/mmcblk0p4'),('wrongcid',['text','cid'],'0'*32)]:
            def reject(path=path,value=value):
                s=copy.deepcopy(state);d=s
                for key in path[:-1]:d=d[key]
                d[path[-1]]=value
                try:m.validate(s,plan,tx,image)
                except m.g.Refusal:pass
                else:raise AssertionError('unsafe state accepted')
            run('reject_'+name,reject)
        def old_gpt():
            s=copy.deepcopy(state)
            for k in ('primary','backup'):s['raw'][k]=m.g.record_blob(plan[k]['old'])
            try:m.validate(s,plan,tx,image)
            except m.g.Refusal:pass
            else:raise AssertionError()
        run('only_exact_candidate_gpt',old_gpt)
        def tmp_contract():
            assert m.tmp_available(state['p11']['tmp_df'])==2096128*1024
            s=copy.deepcopy(state);s['text']['mountinfo']=s['text']['mountinfo'].replace('/tmp rw,','/tmp rw,noexec,')
            try:m.validate(s,plan,tx,image)
            except m.g.Refusal:pass
            else:raise AssertionError()
        run('tmp_mnt_alias_accepted_noexec_refused',tmp_contract)
        def success():
            remote=Fake(state);d=out/'success';d.mkdir(mode=0o700)
            result=m.perform(remote,plan,tx,image,io.BytesIO(b'mock'),[],state,d)
            assert result['status']=='verified_p11_image_only_needs_device_identity_and_boot_token'
            assert remote.writes==1 and not result['activated'] and not result['keys_accounts_tokens_provisioned']
            assert result['lock_may_remain']
        run('complete_requires_full_readback_and_readonly_fsck_never_activates',success)
        for failure in ('lock','upload','gzip_test','boot_changed','mounted_after_upload','write_unknown','wrong_readback','fsck_nonzero'):
            def fail(failure=failure):
                remote=Fake(state,failure);d=out/('fail-'+failure);d.mkdir(mode=0o700)
                try:m.perform(remote,plan,tx,image,io.BytesIO(b'mock'),[],state,d)
                except m.g.Refusal:pass
                else:raise AssertionError()
                result=json.loads((d/'result.json').read_text())
                assert not result['activated'] and result['lock_may_remain']
                assert remote.writes==(1 if failure in ('write_unknown','wrong_readback','fsck_nonzero') else 0)
            run('stop_without_retry_'+failure,fail)
        def source_inputs():
            actual,stream,payload=m.inputs()
            try:
                assert actual==image and len(payload)==9
                assert sum(x['name']=='e2fsck' for x in payload)==1
                assert all(x['name']!='fsck' for x in payload)
            finally:stream.close()
        run('exact_compressed_manifest_hash_and_9_file_fsck_closure',source_inputs)
        def fixed_pipeline():
            obj=object.__new__(m.Remote);obj.image_stage='/tmp/leon-p11-'+'a'*32;seen=[]
            obj.command=lambda cmd,**kw:(seen.append(cmd) or (b'',b'dd diagnostics'))
            obj.text=lambda cmd:'0\n0'
            assert obj.write_image()==m.g.sha(b'dd diagnostics')
            assert len(seen)==1 and 'dd of=/dev/mmcblk0p11 bs=1048576 conv=notrunc,fsync' in seen[0]
            assert 'count=' not in seen[0] and 'gzip.exit' in seen[0] and 'dd.exit' in seen[0]
            assert ' of=/dev/mmcblk0 ' not in seen[0]
        run('fixed_p11_pipeline_both_statuses_no_shortread_count',fixed_pipeline)
        def stock_gzip_dd():
            data=(b'bounded offline regular-file fixture\n'*40000)
            archive=out/'small.gz';archive.write_bytes(gzip.compress(data,mtime=0))
            target=out/'small.img';target.touch(mode=0o600)
            prefix=['qemu-arm','-L',str(R/'build/stock-rootfs'),str(R/'build/stock-rootfs/bin/busybox')]
            subprocess.run(prefix+['gzip','-t',str(archive)],check=True,timeout=10,capture_output=True)
            gz=subprocess.Popen(prefix+['gzip','-dc',str(archive)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            dd=subprocess.run(prefix+['dd','of='+str(target),'bs=1048576','conv=notrunc,fsync'],stdin=gz.stdout,capture_output=True,timeout=10)
            gz.stdout.close();gz_err=gz.stderr.read();gz_status=gz.wait(timeout=10)
            assert dd.returncode==gz_status==0 and not gz_err and target.read_bytes()==data
            truncated=out/'truncated.gz';truncated.write_bytes(archive.read_bytes()[:-8])
            result=subprocess.run(prefix+['gzip','-t',str(truncated)],capture_output=True,timeout=10)
            assert result.returncode!=0
            (out/'stock-gzip-dd.json').write_bytes(m.g.canonical({'fixture_bytes':len(data),'readback_sha256':m.g.sha(data),
                'gzip_status':gz_status,'dd_status':dd.returncode,'truncated_gzip_test_status':result.returncode,
                'dd_stderr':dd.stderr.decode(),'regular_file_only':True}))
        run('exact_stock_gzip_to_dd_regular_file_and_corrupt_gzip_refusal',stock_gzip_dd)
        def fsck_readonly():
            target=out/'fsck.img'
            with target.open('xb') as f:f.truncate(32*1024*1024)
            subprocess.run(['mke2fs','-q','-t','ext4','-F',str(target)],check=True,capture_output=True,timeout=30)
            before=hashlib.file_digest(target.open('rb'),'sha256').hexdigest()
            stage=m.FSCK_MANIFEST.parent/'stage/usr/libexec/leon-boot'
            result=subprocess.run(['qemu-aarch64',str(stage/'lib/ld-linux-aarch64.so.1'),'--inhibit-cache',
                '--library-path',str(stage/'lib'),str(stage/'e2fsck'),'-fn',str(target)],
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C','E2FSCK_CONFIG':str(stage/'e2fsck.conf')},capture_output=True,timeout=30)
            after=hashlib.file_digest(target.open('rb'),'sha256').hexdigest()
            assert result.returncode==0 and before==after
            (out/'native-fsck-readonly.json').write_bytes(m.g.canonical({'status':result.returncode,'sha256_before':before,
                'sha256_after':after,'regular_file_only':True,'stdout':result.stdout.decode(),'stderr':result.stderr.decode()}))
        run('exact_native_fsck_closure_fn_preserves_regular_ext4_bytes',fsck_readonly)
    report={'schema':1,'status':'offline_only_not_physical_execution_accepted','tests':tests,'test_count':len(tests),
        'network_connections':0,'block_devices_opened':0,'device_writes':0,'activation':False,
        'source_sha256':m.g.sha(Path(m.__file__).read_bytes()),'test_source_sha256':m.g.sha(Path(__file__).read_bytes()),
        'shared_gpt_source_sha256':m.GPT_SOURCE_SHA,'image_manifest_sha256':m.IMAGE_MANIFEST_SHA,
        'fsck_manifest_sha256':m.FSCK_MANIFEST_SHA,'limits':['Actual SSH transport, physical eMMC write speed/durability, and live namespace races not tested.',
        'Root-only advisory lock does not exclude unrelated ASUS writers; caller must provide exclusive maintenance.',
        'Success is image bytes/fsck only, not device-local identity, boot token, pivot, guardian or ASUS service acceptance.',
        'Staging and lock remain for review even on success; no automatic restart/retry/activation/cleanup.']}
    (out/'result.json').write_bytes(m.g.canonical(report));print(json.dumps({'report':str(out/'result.json'),'tests':len(tests)}))


if __name__=='__main__':main()

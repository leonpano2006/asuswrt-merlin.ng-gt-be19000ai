#!/usr/bin/env python3
"""Fixed p11 image transfer/write preparation; default read-only, never activates.

Development tool: offline tests do not authorize or prove physical deployment.
The only writable block device is /dev/mmcblk0p11 at the reviewed exact extent.
No mount, GPT update, boot-metadata update, reboot, account/key provisioning or
systemd activation is performed. A failed/unknown write remains explicitly partial.
"""
from __future__ import annotations
import argparse
import copy
import getpass
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading
import time

R=Path(__file__).resolve().parents[1]
GPT_SOURCE_SHA='71b14c1964f34bb7d7edb2a1a49e7bb566b43d35475ea291df0c4053ee0931bd'
spec=importlib.util.spec_from_file_location('p11_gpt',R/'scripts/provision-ubuntu26-gpt.py')
g=importlib.util.module_from_spec(spec);sys.modules[spec.name]=g;spec.loader.exec_module(g)
IMAGE_MANIFEST=R/'build/ubuntu26-root-transfer/runtime07-archive-v1/manifest.json'
IMAGE_MANIFEST_SHA='d1f8e3e395e399b3f2b63e436d6492cac70620d8e03ef0a1153bdaad4b03e7e3'
FSCK_MANIFEST=R/'build/ubuntu26-boot-fsck/device-v1/manifest.json'
FSCK_MANIFEST_SHA='8af51e610ccf5d2baec0a78e5ad288a191506647ca60fc1eb8e30415513feb92'
IMAGE_SHA='aed3ad1dc3e381506af4416228bcd99482fd0eebd4e3f55c2a8ec36969b8991a'
IMAGE_BYTES=12884901888
P11='/dev/mmcblk0p11'
P11_ROW={'start':'26849280','size':'25165824','dev':'179:11'}
RAM_RESERVE=256*1024*1024
TMP_RESERVE=128*1024*1024
LOCK='/tmp/leon-p11-image.lock'


def open_payload(path,want_sha,want_size=None):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        g.require(stat.S_ISREG(st.st_mode) and st.st_nlink==1,'unsafe_local_payload')
        if want_size is not None:g.require(st.st_size==want_size,'local_payload_size')
        f=os.fdopen(fd,'rb');fd=None
        g.require(hashlib.file_digest(f,'sha256').hexdigest()==want_sha,'local_payload_hash')
        f.seek(0);return f
    except BaseException:
        if 'f' in locals():f.close()
        raise
    finally:
        if fd is not None:os.close(fd)


def inputs():
    g.require(g.sha(Path(g.__file__).read_bytes())==GPT_SOURCE_SHA,'reviewed_gpt_source_changed')
    g.require(g.sha(IMAGE_MANIFEST.read_bytes())==IMAGE_MANIFEST_SHA,'image_manifest_changed')
    g.require(g.sha(FSCK_MANIFEST.read_bytes())==FSCK_MANIFEST_SHA,'fsck_manifest_changed')
    image=json.loads(IMAGE_MANIFEST.read_text());fsck=json.loads(FSCK_MANIFEST.read_text())
    g.require(image['status']=='compressed_transport_exact_roundtrip_verified' and image['exact_roundtrip'] is True
              and image['compressed_format']=='gzip' and image['uncompressed']['bytes']==IMAGE_BYTES
              and image['uncompressed']['sha256']==IMAGE_SHA,'image_manifest_contract')
    archive=image['archive'];stream=open_payload(R/archive['path'],archive['sha256'],archive['bytes'])
    payload=[]
    for name,meta in fsck['payload'].items():
        if name=='usr/libexec/leon-boot/fsck':continue # wrapper permits -p only; never invoke here
        short=name.removeprefix('usr/libexec/leon-boot/')
        g.require(short in {'e2fsck','e2fsck.conf','lib/ld-linux-aarch64.so.1','lib/libc.so.6','lib/libe2p.so.2',
                          'lib/libuuid.so.1','lib/libblkid.so.1','lib/libcom_err.so.2','lib/libext2fs.so.2'},'unexpected_fsck_member')
        path=FSCK_MANIFEST.parent/'stage'/name
        with open_payload(path,meta['sha256']) as f:data=f.read()
        payload.append({'name':short,'data':data,'sha256':meta['sha256'],'mode':0o700 if short in
                        ('e2fsck','lib/ld-linux-aarch64.so.1') else 0o600})
    g.require(len(payload)==9,'fsck_closure_incomplete')
    return image,stream,payload


def memory_available(text):
    matches=re.findall(r'^MemAvailable:\s+([0-9]+) kB$',text,re.M)
    g.require(len(matches)==1,'memavailable_missing');return int(matches[0])*1024


def tmp_available(text):
    lines=text.splitlines();g.require(len(lines)==2,'tmp_df_format')
    fields=lines[1].split()
    # ASUS mounts the same tmpfs again at /tmp/mnt; df may choose that alias.
    # The caller separately verifies the actual /tmp mountinfo filesystem.
    g.require(len(fields)==6 and fields[5].startswith('/') and all(x.isdigit() for x in fields[1:4]),'tmp_df_format')
    g.require(0<=int(fields[3])<=int(fields[1]),'tmp_df_values')
    return int(fields[3])*1024


def validate(snapshot,plan,tx,image,staged=False):
    p11=snapshot['p11']
    g.require(snapshot['partitions'].get('11')==P11_ROW,'p11_extent_missing_or_wrong')
    reduced=copy.deepcopy(snapshot);del reduced['partitions']['11']
    g.validate(reduced,plan,tx,'candidate')
    g.require(g.node_matches(p11['node'],11),'p11_node_identity')
    g.require(not p11['all_namespace_mounts'],'p11_mounted_in_a_process_namespace')
    g.require(not p11['holders'],'p11_has_block_holders')
    g.require(not p11['active_swap'],'p11_is_swap')
    mounts=g.parse_mounts(snapshot['text']['mountinfo'])
    g.require(not any(x['dev']=='179:11' for x in mounts),'p11_mounted')
    tmp=[x for x in mounts if x['path']=='/tmp']
    g.require(len(tmp)==1 and tmp[0]['type']=='tmpfs' and 'rw' in tmp[0]['flags'] and 'noexec' not in tmp[0]['flags'],
              'tmp_not_expected_executable_tmpfs')
    extra=0 if staged else image['archive']['bytes']+8*1024*1024
    g.require(memory_available(p11['meminfo'])>=extra+RAM_RESERVE,'insufficient_available_memory')
    g.require(tmp_available(p11['tmp_df'])>=extra+TMP_RESERVE,'insufficient_tmp_space')


class Remote(g.SSH):
    def capture(self,plan,full=True,prior=None):
        snapshot=super().capture(plan,full,prior)
        boot=snapshot['text']['boot_id']
        snapshot['p11']={
            'node':g.block_node(self.file_metadata(P11)),
            'holders':self.text('for x in /sys/class/block/mmcblk0p11/holders/*; do test ! -e "$x" || echo "$x"; done'),
            'meminfo':self.text(g.BB+' cat /proc/meminfo'),
            'tmp_df':self.text(g.BB+' df -Pk /tmp'),
            # Require all readable process mount namespaces, not only the SSH
            # process namespace. A race disappearing process fails closed.
            'all_namespace_mounts':self.text('for p in /proc/[0-9]*/mountinfo; do '+
                'if test -r "$p"; then '+g.BB+' awk \'$3=="179:11" {print FILENAME ":" $0}\' "$p" || exit 1; '+
                'elif test -d "${p%/mountinfo}"; then exit 1; fi; done'),
            'active_swap':''}
        swaptext=self.text(g.BB+' cat /proc/swaps')
        for row in swaptext.splitlines()[1:]:
            fields=row.split();g.require(len(fields)==5,'proc_swaps_syntax')
            meta=self.file_metadata(fields[0])
            if meta['mode'].startswith('b') and meta['major']==179 and meta['minor']==11:
                snapshot['p11']['active_swap']='active'
        g.require(self.text(g.BB+' cat /proc/sys/kernel/random/boot_id')==boot,'boot_changed_during_p11_capture')
        return snapshot

    def begin_image(self,token):
        g.require(re.fullmatch('[0-9a-f]{32}',token),'stage_token')
        self.image_stage='/tmp/leon-p11-'+token
        self.command('umask 077; '+g.BB+' mkdir '+LOCK+' && '+g.BB+' mkdir '+self.image_stage+' && '+
                     g.BB+' mkdir '+self.image_stage+'/lib')
        for path in (LOCK,self.image_stage,self.image_stage+'/lib'):
            meta=self.file_metadata(path)
            g.require(meta['mode']=='drwx------' and meta['uid']==meta['gid']==0,'unsafe_image_stage')
        return self.image_stage

    def upload(self,name,stream,size,digest,mode=0o600):
        g.require(name in {'root.ext4.gz','e2fsck','e2fsck.conf','lib/ld-linux-aarch64.so.1','lib/libc.so.6',
            'lib/libe2p.so.2','lib/libuuid.so.1','lib/libblkid.so.1','lib/libcom_err.so.2','lib/libext2fs.so.2'},'stage_member')
        path=self.image_stage+'/'+name
        command='umask 077; set -C; '+g.BB+' cat > '+path
        timer=threading.Timer(600,self.close);timer.daemon=True;timer.start();channel=None
        try:
            channel=self.transport.open_session(timeout=8);channel.settimeout(8)
            channel.exec_command(g.BB+' env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin LC_ALL=C '+g.BB+' sh -c '+g.shlex.quote(command))
            stream.seek(0);remaining=size;hasher=hashlib.sha256()
            while remaining:
                chunk=stream.read(min(65536,remaining));g.require(chunk,'local_payload_short_read')
                channel.sendall(chunk);hasher.update(chunk);remaining-=len(chunk)
            g.require(not stream.read(1) and hasher.hexdigest()==digest,'local_payload_changed_during_upload')
            channel.shutdown_write();out=bytearray();err=bytearray();deadline=time.monotonic()+30
            while True:
                g.require(time.monotonic()<deadline,'upload_completion_timeout')
                if channel.recv_ready():out.extend(channel.recv(2))
                if channel.recv_stderr_ready():err.extend(channel.recv_stderr(8193))
                g.require(not out and len(err)<=8192,'unexpected_upload_output')
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    g.require(channel.recv_exit_status()==0 and not err,'remote_upload_failed');break
                g.require(self.transport.is_active(),'upload_disconnected');time.sleep(.005)
        finally:
            if channel:channel.close()
            timer.cancel();timer.join()
        self.command(g.BB+' chmod '+oct(mode)[2:]+' '+path)
        meta=self.file_metadata(path)
        g.require(meta['mode']==stat.filemode(stat.S_IFREG|mode) and meta['uid']==meta['gid']==0 and
            meta['links']==1 and meta['size']==size,'staged_image_metadata')
        out,_=self.command(g.BB+' sha256sum '+path,timeout=120)
        g.require(g.digest_line(out,path)==digest,'staged_image_hash')

    def verify_gzip(self,image):
        self.command(g.BB+' gzip -t '+self.image_stage+'/root.ext4.gz',limit=1,timeout=180)

    def write_image(self):
        stage=self.image_stage
        # There is intentionally NO dd count: this BusyBox has no fullblock
        # flag, so count=12288 at bs=1MiB would count short pipe reads incorrectly.
        # The exact compressed SHA pins a verified 12GiB decompression output.
        command=('umask 077; set -C; ( '+g.BB+' gzip -dc '+stage+'/root.ext4.gz; s=$?; '+
            'printf "%s\\n" "$s" > '+stage+'/gzip.exit; exit "$s" ) | '+g.BB+
            ' dd of='+P11+' bs=1048576 conv=notrunc,fsync; s=$?; printf "%s\\n" "$s" > '+stage+
            '/dd.exit; test "$s" = 0 && test "$('+g.BB+' cat '+stage+'/gzip.exit)" = 0')
        try:
            out,err=self.command(command,limit=1,stderr=True,timeout=900)
            g.require(not out,'unexpected_write_stdout')
            # Child statuses, complete readback and fsck, not just the pipeline's
            # last exit, decide success. Keep only the diagnostics digest.
            g.require(self.text(g.BB+' cat '+stage+'/gzip.exit '+stage+'/dd.exit')=='0\n0','decompress_or_dd_failed')
            return g.sha(err)
        except Exception:raise g.UnknownOutcome('p11_write_partial_or_unknown') from None

    def readback_hash(self):
        out,_=self.command(g.BB+' sha256sum '+P11,timeout=900)
        return g.digest_line(out,P11)

    def fsck_readonly(self):
        s=self.image_stage
        command=(g.BB+' env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin LC_ALL=C E2FSCK_CONFIG='+s+'/e2fsck.conf '+
            s+'/lib/ld-linux-aarch64.so.1 --inhibit-cache --library-path '+s+'/lib '+s+'/e2fsck -fn '+P11)
        out,err=self.command(command,limit=65536,stderr=True,timeout=180)
        return {'stdout_sha256':g.sha(out),'stderr_sha256':g.sha(err),'exit':0,'mode':'-fn; no repairs'}


def same(before,after):
    g.require_same(before,after)
    g.require(all(g.blob(before,k)==g.blob(after,k) for k in ('primary','backup')),'gpt_changed_during_image_operation')


def perform(remote,plan,tx,image,stream,payload,reviewed,out):
    import io
    validate(reviewed,plan,tx,image)
    g.require(reviewed['full_slot_hashes_read'] is True,'reviewed_not_full')
    fresh=remote.capture(plan,full=True);validate(fresh,plan,tx,image);same(reviewed,fresh)
    g.save_capture(out,'fresh-prewrite.json',fresh)
    # Durable original GPT/boot-metadata backup here is evidence only: this tool
    # never has a method that writes either, including its failure paths.
    backup=g.durable_backup(out,fresh)
    receipt={'schema':1,'status':'prepared','image_manifest_sha256':IMAGE_MANIFEST_SHA,
             'fsck_manifest_sha256':FSCK_MANIFEST_SHA,'reviewed_capture_sha256':g.sha(g.canonical(reviewed)),
             'image_sha256':IMAGE_SHA,'image_bytes':IMAGE_BYTES,'device':P11,'backup':backup,
             'boot_id':fresh['text']['boot_id'],'block_write_attempted':False,'activated':False,
             'keys_accounts_tokens_provisioned':False}
    token=secrets.token_hex(16);receipt['remote_stage']='/tmp/leon-p11-'+token
    g.durable_file(out/'prepared.json',g.canonical(receipt));g.fsync_dir(out)
    try:
        receipt['lock_may_remain']=True
        g.require(remote.begin_image(token)==receipt['remote_stage'],'image_stage_changed')
        for item in payload:remote.upload(item['name'],io.BytesIO(item['data']),len(item['data']),item['sha256'],item['mode'])
        archive=image['archive'];remote.upload('root.ext4.gz',stream,archive['bytes'],archive['sha256'])
        remote.verify_gzip(image)
        before=remote.capture(plan,full=True);validate(before,plan,tx,image,staged=True);same(fresh,before)
        receipt['block_write_attempted']=True
        g.durable_file(out/'write-intent.json',g.canonical(receipt));g.fsync_dir(out)
        receipt['dd_diagnostics_sha256']=remote.write_image()
        after=remote.capture(plan,full=False,prior=fresh);validate(after,plan,tx,image,staged=True);same(fresh,after)
        receipt['readback_sha256']=remote.readback_hash()
        g.require(receipt['readback_sha256']==IMAGE_SHA,'p11_full_readback_hash_mismatch')
        # Check mounts again immediately before fsck, and prove bytes unchanged
        # after its explicitly read-only pass before reporting acceptance.
        precheck=remote.capture(plan,full=False,prior=fresh);validate(precheck,plan,tx,image,staged=True);same(fresh,precheck)
        receipt['fsck']=remote.fsck_readonly()
        g.require(remote.readback_hash()==IMAGE_SHA,'readonly_fsck_changed_image')
        final=remote.capture(plan,full=True);validate(final,plan,tx,image,staged=True);same(fresh,final)
        receipt['final_capture']=g.save_capture(out,'final-capture.json',final)
        receipt['status']='verified_p11_image_only_needs_device_identity_and_boot_token'
        # Preserve exact staged files and lock for caller review/provisioning;
        # no unexpected cleanup, image activation or future run is automatic.
    except BaseException as error:
        receipt['status']='partial_or_unknown_no_activation' if receipt['block_write_attempted'] else 'staging_failed_no_block_write'
        receipt['failure_code']=str(error) if isinstance(error,g.Refusal) else type(error).__name__
        try:receipt['readonly_after_failure']=g.save_capture(out,'failure-capture.json',remote.capture(plan,full=False,prior=fresh))
        except Exception:receipt['readonly_after_failure_unavailable']=True
        g.durable_file(out/'result.json',g.canonical(receipt));g.fsync_dir(out)
        raise g.Refusal('image_operation_stopped_review_result_no_activation') from None
    g.durable_file(out/'result.json',g.canonical(receipt));g.fsync_dir(out)
    return receipt


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host',default='192.168.100.15');p.add_argument('--port',type=int,default=22)
    p.add_argument('--username',default='MastermixStudios');p.add_argument('--source',default='192.168.100.36')
    p.add_argument('--known-hosts',type=Path,required=True)
    auth=p.add_mutually_exclusive_group();auth.add_argument('--key',type=Path);auth.add_argument('--agent',action='store_true')
    p.add_argument('--key-passphrase',action='store_true');p.add_argument('--output',type=Path,required=True)
    p.add_argument('--apply',action='store_true');p.add_argument('--reviewed-capture',type=Path);p.add_argument('--capture-sha256')
    p.add_argument('--image-manifest-sha256');p.add_argument('--plan-sha256');a=p.parse_args()
    remote=stream=None
    try:
        ipaddress.ip_address(a.host);ipaddress.ip_address(a.source)
        g.require(1<=a.port<=65535 and re.fullmatch('[A-Za-z0-9_.-]{1,64}',a.username),'ssh_parameters')
        g.require(not a.key_passphrase or a.key is not None,'passphrase_without_key')
        image,stream,payload=inputs();plan,tx=g.load_plan();reviewed=None
        if a.apply:
            g.require(a.image_manifest_sha256==IMAGE_MANIFEST_SHA and a.plan_sha256==g.PLAN_SHA and
                      a.reviewed_capture is not None,'reviewed_image_plan_and_capture_required')
            reviewed=g.read_reviewed(a.reviewed_capture,a.capture_sha256);validate(reviewed,plan,tx,image)
        else:g.require(not any([a.reviewed_capture,a.capture_sha256,a.image_manifest_sha256,a.plan_sha256]),'review_args_without_apply')
        out=g.new_dir(a.output)
        password=None if a.key or a.agent else getpass.getpass('Stock SSH password (memory only): ')
        passphrase=getpass.getpass('SSH key passphrase (memory only): ') if a.key_passphrase else None
        remote=Remote(a,password,passphrase)
        if a.apply:
            result=perform(remote,plan,tx,image,stream,payload,reviewed,out)
            print(json.dumps({'status':result['status'],'result':str(out/'result.json')}))
        else:
            capture=remote.capture(plan,full=True);ref=g.save_capture(out,'capture.json',capture)
            try:validate(capture,plan,tx,image);ready=True;reason=None
            except g.Refusal as error:ready=False;reason=str(error)
            print(json.dumps({'status':'read_only_p11_capture','capture':ref,'eligible_state':ready,'refusal':reason}))
    except (g.Refusal,OSError,ValueError,KeyError,AssertionError) as error:
        print(json.dumps({'status':'refused','code':str(error) if isinstance(error,g.Refusal) else type(error).__name__}),file=sys.stderr);return 1
    finally:
        if stream:stream.close()
        if remote:remote.close()
    return 0


if __name__=='__main__':raise SystemExit(main())

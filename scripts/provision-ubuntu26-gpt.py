#!/usr/bin/env python3
"""Reviewed, fixed BE19000AI GPT transaction; default is read-only capture.

This tool never reboots, flashes firmware, writes partition contents/PMBR/boot
metadata, rereads the partition table or runs BLKPG. Hardware execution has NOT
been accepted by the offline tests. An interrupted transaction needs a separately
reviewed capture and explicit --recover-original; there is no automatic repair.
"""
from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import importlib.util
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import stat
import struct
import sys
import threading
import time
import uuid
import zlib

R = Path(__file__).resolve().parents[1]
PLAN_SHA = '60d2b71c6ed8560c311b4b3bd458a09868a025439a22776e08b3beef533c6a12'
CID = '00000000000000000000000000000001'
BB = '/bin/busybox'
BB_SHA = '75f940bafb9fd9db28d4849530ecdfeabb42df4e3fa25808eac43e7d0eed6819'
DEVICE = '/dev/mmcblk0'
LOCK = '/tmp/leon-gpt-transaction.lock'
SLOTS = {5: 'ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256',
         6: '51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465'}
FS = {7: ('b2779970-ea82-4aec-96ed-816e1aac53a0', '/data'),
      8: ('b33c1d3a-f5a1-4beb-b0fe-edfdecba957d', '/tmp/mnt/defaults'),
      9: ('7575e860-48ee-493e-bb5b-a1ca270b8512', '/jffs'),
      10: ('d6754055-3be0-4b1d-8dc4-3c3bb8493fbe', '/ai')}
STOCK = {
    '/sbin/rc': '9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814',
    '/lib/libdisk.so': 'b53d0007e10ba79503f0e9fb8f856e1fe58243d0d6d547e86863627adb2179ee',
    '/usr/lib/libshared.so': '0b280a0c80b16e0ecf1f36281661c9c24fa483fb1adb3de0b2e266d7c9f011d8',
    '/rom/etc/hotplug2.rules': 'e2c195e573028c7f7e10de3e45f14f3b05da25685776b456960ba6968dd14176',
    '/rom/etc/mdev.conf': 'ea00a4a24594e7b00a413ec894a62e674b67040f7223f84ff5d7db0c563c7559',
    '/rom/etc/make_mmc_links.sh': 'bfd7261f993369964aee0d97ec6b54ea9044d01711d1eff96d10107bb409452d',
    '/rom/etc/init.d/mount-fs.sh': 'db4c12ff9738818eb578ab81136a5ccc4953b65edbc1cc836d27e012f27a3ee6',
    '/rom/etc/init.d/mount-data.inc': '053ed6d2fbc0c02de5cde82407f4143869728d7b7137d6e9fc7bed7ffdaf16e2',
    '/rom/etc/init.d/partitioncfg': '45b1c150215d0238fb61a0e5e68c47e4f3425f5a958edb2e5dd7bda158daa4d9'}


class Refusal(Exception): pass
class UnknownOutcome(Refusal): pass


def require(condition, code):
    if not condition: raise Refusal(code)


def sha(data): return hashlib.sha256(data).hexdigest()
def canonical(value): return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    sys.modules[name] = obj
    spec.loader.exec_module(obj)
    return obj


def load_plan():
    require(__debug__, 'python_optimized_mode_not_supported')
    p = R / 'build/ubuntu26-gpt-candidate/v1/manifest.json'
    require(sha(p.read_bytes()) == PLAN_SHA, 'fixed_plan_manifest_changed')
    tx = load_module('reviewed_gpt_transaction', R / 'scripts/prepare-ubuntu26-gpt-transaction.py')
    plan, _ = tx.load_plan()
    require([(x['offset']//512, x['size']) for x in plan['operations']] ==
            [(61226463,16384),(61226495,512),(2,16384),(1,512)], 'unexpected_write_extents')
    return plan, tx


def write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        require(n > 0, 'host_short_write')
        view = view[n:]


def durable_file(path, data):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1, 'unsafe_host_output')
        write_all(fd, data)
        os.fsync(fd)
    finally: os.close(fd)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)


def new_dir(path):
    # Parent must already exist; resolve it once, rejecting writable parents.
    parent = path.parent.resolve(strict=True)
    st = parent.stat()
    require(st.st_uid in (0, os.geteuid()) and not st.st_mode & 0o022, 'unsafe_host_output_parent')
    path = parent/path.name
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    fsync_dir(parent)
    return path


def read_reviewed(path, expected):
    require(re.fullmatch('[0-9a-f]{64}', expected or '') is not None, 'missing_reviewed_sha256')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid in (0,os.geteuid()) and
                not st.st_mode & 0o022 and st.st_size <= 2*1024*1024, 'unsafe_reviewed_capture')
        with os.fdopen(fd, 'rb', closefd=False) as f: data = f.read(2*1024*1024+1)
    finally: os.close(fd)
    require(sha(data) == expected, 'reviewed_capture_hash_mismatch')
    obj = json.loads(data)
    require(obj.get('schema') == 1 and obj.get('plan_sha256') == PLAN_SHA, 'capture_schema_or_plan')
    return obj


def blob(snapshot, key):
    row = snapshot['raw'][key]
    try: data = base64.b64decode(row['base64'], validate=True)
    except Exception: raise Refusal('invalid_capture_base64') from None
    require(len(data) == row['bytes'] and sha(data) == row['sha256'], 'capture_blob_hash_mismatch')
    return data


def record_blob(raw):
    return {'bytes':len(raw), 'sha256':sha(raw), 'base64':base64.b64encode(raw).decode()}


def metadata(data):
    require(len(data) == 262144, 'metadata_size')
    first,second=struct.unpack_from('<II',data)
    require(first==second and 8<=first<=65535,'metadata_length_header')
    length = first-4
    payload = data[12:12+length]
    require(length > 0 and zlib.crc32(payload) == struct.unpack_from('<I', data,8)[0], 'metadata_crc')
    fields = {}
    for key in ('COMMITTED','VALID','SEQ'):
        values = re.findall(rb'(?:^|\0)'+key.encode()+rb'=([0-9,]+)\0', payload)
        require(len(values) == 1, 'metadata_duplicate_or_missing_field')
        fields[key] = values[0].decode()
    require(fields['COMMITTED'] == '2' and fields['VALID'] == '1,2', 'stock_slot2_not_committed_valid')
    require(re.fullmatch(r'(0|[1-9][0-9]{0,2}),(0|[1-9][0-9]{0,2})',fields['SEQ']) is not None, 'metadata_sequence')
    return fields


def gpt_state(snapshot, plan, tx):
    class ReadOnly:
        def __init__(self): self.plan = plan
        def region(self, key): return blob(snapshot,key)
    view = ReadOnly()
    for key in ('primary','backup'):
        require(len(view.region(key)) == len(plan[key]['old']), 'gpt_short_read')
    try:
        tx.recognized(view)
        result = tx.status(view)
    except (AssertionError,struct.error): raise Refusal('foreign_gpt_bytes') from None
    require(any(x['crc_valid'] for x in result.values()), 'both_gpt_copies_invalid')
    return result


def parse_mounts(text):
    rows=[]
    for line in text.splitlines():
        left, sep, right = line.partition(' - ')
        a,b = left.split(),right.split()
        require(sep and len(a)>=6 and len(b)>=3, 'mountinfo_syntax')
        rows.append({'dev':a[2], 'root':a[3], 'path':a[4], 'flags':a[5].split(','),
                     'type':b[0], 'super_flags':b[2].split(',')})
    return rows


def validate(snapshot, plan, tx, kind=None):
    require(snapshot['schema'] == 1 and snapshot['plan_sha256'] == PLAN_SHA, 'capture_plan')
    text = snapshot['text']
    try: require(str(uuid.UUID(text['boot_id'])) == text['boot_id'], 'boot_id')
    except ValueError: raise Refusal('boot_id') from None
    require(text['uid'] == '0', 'remote_uid_not_root')
    require(text['cid'] == CID and text['sectors'] == '61226496' and text['logical_sector'] == '512'
            and text['disk_dev'] == '179:0', 'device_identity_geometry')
    require(node_matches(text['disk_node'],0), 'disk_node_identity')
    require('sdhci/mmc_host/' in text['mmc_sysfs'] and '/host' not in text['mmc_sysfs'] and
            text['mmc_device'] == '../../../mmc0:0001', 'mmc_not_expected_sdhci')
    require(text['asus_mmc_absent'] == 'absent', 'unexpected_asus_mmc')
    roots = [x for x in text['cmdline'].split() if x.startswith('root=')]
    require(roots == ['root=/dev/mmcblk0p6'], 'not_booted_stock_rootfs2')
    mounts = parse_mounts(text['mountinfo'])
    require(any(x['path']=='/' and x['root']=='/' and x['dev']=='179:6' and x['type']=='squashfs'
                and 'ro' in x['flags'] for x in mounts), 'stock_root_mount_identity')
    expected_parts = {str(x['number']): {'start':str(x['start']), 'size':str(x['end']-x['start']+1),
                        'dev':'179:'+str(x['number'])} for x in plan['old_entries']}
    require(snapshot['partitions'] == expected_parts, 'kernel_partitions_not_exact_p1_to_p10')
    require(snapshot['hashes'] == {BB:BB_SHA,**STOCK,**{DEVICE+'p'+str(n):v for n,v in SLOTS.items()}},
            'original_firmware_hash_mismatch')
    require(re.search(r'\bfsync\b',text['dd_help']) and re.search(r'\bnotrunc\b',text['dd_help']),
            'busybox_dd_fsync_not_available')
    p1,p2=blob(snapshot,'metadata1'),blob(snapshot,'metadata2')
    require(p1==p2, 'metadata_copies_differ')
    metadata(p1)
    for n,(want_uuid,mountpoint) in FS.items():
        sb=blob(snapshot,'superblock'+str(n))
        require(len(sb)==1024 and sb[56:58]==b'\x53\xef' and str(uuid.UUID(bytes=sb[104:120]))==want_uuid,
                'mandatory_ext4_uuid_or_magic')
        require(struct.unpack_from('<I',sb,404)[0]==0 and text['errors'+str(n)]=='0', 'mandatory_ext4_errors')
        matches=[x for x in mounts if x['dev']=='179:'+str(n) and x['path']==mountpoint and x['root']=='/']
        require(matches and all(x['type']=='ext4' and 'rw' in x['flags'] and 'rw' in x['super_flags'] for x in matches),
                'mandatory_ext4_mount_unhealthy')
        require(all('rw' in x['flags'] and 'rw' in x['super_flags'] for x in mounts if x['dev']=='179:'+str(n)),
                'mandatory_ext4_has_readonly_mount')
    states=gpt_state(snapshot,plan,tx)
    if kind: require(all(x=={'crc_valid':True,'kind':kind} for x in states.values()), 'gpt_not_expected_'+kind)
    return states


def node_matches(value, minor):
    try:
        mode,major,gotminor=(int(x,16) for x in value.split(':'))
        return stat.S_ISBLK(mode) and major==179 and gotminor==minor
    except ValueError: return False


def digest_line(raw,path):
    text=raw.decode('ascii').strip()
    require(re.fullmatch('[0-9a-f]{64}  '+re.escape(path),text) is not None, 'remote_hash_response')
    return text[:64]


def dd_status(err, sectors):
    prefix=f'{sectors}+0 records in\n{sectors}+0 records out\n'.encode()
    require(err.startswith(prefix),'dd_records_not_exact')
    tail=err[len(prefix):]
    # BusyBox optionally compiles a third speed line. No warning/error text is
    # ignored; the record counts, byte count, exit status and readback must agree.
    require(not tail or re.fullmatch(str(sectors*512).encode()+
            rb' bytes \([0-9.]+[kKMGTPE]?B\) copied, [0-9.]+ seconds, (?:[0-9.]+[kKMGTPE]?|inf)B/s\n',tail),
            'unexpected_dd_diagnostics')


def parse_ls(text,path):
    # Fixed, whitespace-free paths and C locale. Block/char devices have two
    # decimal number columns; timestamps vary and are deliberately not parsed.
    g=re.fullmatch(r'([bcdlps-][rwxstST-]{9})\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+'
        r'([0-9]+)(?:,\s*([0-9]+))?\s+\S+\s+\S+\s+\S+\s+'+re.escape(path),text)
    require(g is not None,'ls_numeric_metadata_syntax')
    mode,links,uid,gid,first,second=g.groups()
    require((mode[0] in 'bc')==(second is not None),'ls_device_columns')
    return {'mode':mode,'links':int(links),'uid':int(uid),'gid':int(gid),
            'size':int(first) if second is None else None,
            'major':int(first) if second is not None else None,'minor':int(second) if second is not None else None}


def root_uid(status):
    matches=re.findall(r'^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$',status,re.M)
    require(matches==[('0','0','0','0')],'remote_uid_not_root')
    return '0'


def block_node(meta):
    require(meta['mode'].startswith('b'),'not_block_node')
    return f'{stat.S_IFBLK:x}:{meta["major"]:x}:{meta["minor"]:x}'


def safe_staged(meta,size):
    return (meta['mode']=='-rw-------' and meta['links']==1 and meta['uid']==meta['gid']==0 and meta['size']==size)


class SSH:
    """One strictly authenticated session, bounded commands, no agent/key discovery."""
    def __init__(self,args,password,passphrase):
        obs=load_module('gpt_trusted_ssh',R/'scripts/observe-ubuntu26-trial.py')
        trusted=obs.SSHTransport(args,password,passphrase)
        pm=trusted.paramiko
        self.args=args
        self.client=pm.SSHClient()
        logger=logging.getLogger('leon_gpt.ssh');logger.handlers=[logging.NullHandler()];logger.propagate=False
        self.client.set_log_channel('leon_gpt.ssh')
        self.client.set_missing_host_key_policy(pm.RejectPolicy())
        for host in trusted.keys:
            for keytype,key in trusted.keys[host].items():self.client.get_host_keys().add(host,keytype,key)
        self.sock=socket.socket(socket.AF_INET6 if ':' in args.host else socket.AF_INET,socket.SOCK_STREAM)
        self.sock.settimeout(8)
        if args.source:self.sock.bind((args.source,0))
        timer=threading.Timer(12,self.close);timer.daemon=True;timer.start()
        try:
            self.sock.connect((args.host,args.port))
            self.client.connect(args.host,port=args.port,username=args.username,sock=self.sock,
                timeout=8,banner_timeout=8,auth_timeout=8,password=password,passphrase=passphrase,
                key_filename=str(args.key) if args.key else None,allow_agent=args.agent,look_for_keys=False,
                gss_auth=False,gss_kex=False)
            self.transport=self.client.get_transport()
            key=self.transport.get_remote_server_key()
            self.fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            self.trust_sha=trusted.known_hosts_sha256
        except Exception:
            self.close();raise Refusal('ssh_connect_or_auth_failed') from None
        finally:timer.cancel();timer.join()

    def close(self):
        self.client.close()
        try:self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.sock.close()

    def command(self,command,limit=65536,timeout=20,allowed=(0,),stderr=False,stdin=b''):
        require(isinstance(stdin,bytes) and len(stdin)<=16384,'stdin_staging_limit')
        deadline=min(time.monotonic()+timeout,getattr(self,'capture_deadline',float('inf')))
        remaining=deadline-time.monotonic();require(remaining>0,'capture_total_deadline')
        timer=threading.Timer(remaining,self.close);timer.daemon=True;timer.start()
        channel=None
        try:
            channel=self.transport.open_session(timeout=min(8,remaining));channel.settimeout(min(8,remaining))
            # Shell program is host-generated from fixed paths, never user text.
            channel.exec_command(BB+' env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin LC_ALL=C '+BB+' sh -c '+shlex.quote(command))
            if stdin:channel.sendall(stdin)
            channel.shutdown_write();out=bytearray();err=bytearray()
            while True:
                require(time.monotonic()<deadline, 'ssh_command_timeout')
                if channel.recv_ready():out.extend(channel.recv(min(65536,limit+1)))
                if channel.recv_stderr_ready():err.extend(channel.recv_stderr(8193))
                require(len(out)<=limit and len(err)<=8192,'ssh_output_limit')
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    code=channel.recv_exit_status();break
                require(self.transport.is_active(),'ssh_disconnected')
                time.sleep(.005)
            require(code in allowed,'remote_command_failed')
            require(stderr or not err,'unexpected_remote_stderr')
            return bytes(out),bytes(err)
        except Refusal:raise
        except Exception:raise Refusal('ssh_command_outcome_unknown') from None
        finally:
            if channel:channel.close()
            timer.cancel();timer.join()

    def text(self,command,**kwargs):
        out,_=self.command(command,**kwargs)
        try:return out.decode('ascii').strip()
        except UnicodeError:raise Refusal('non_ascii_remote_output') from None

    def file_metadata(self,path):
        require(re.fullmatch('/[a-zA-Z0-9_./-]+',path) is not None,'metadata_path')
        return parse_ls(self.text('test ! -L '+path+' && '+BB+' ls -ldn '+path),path)

    def raw_read(self,path,start,count):
        require(path==DEVICE or path in [DEVICE+'p'+str(n) for n in range(1,11)],'unexpected_read_device')
        require(type(start) is int and type(count) is int and start>=0 and 0<count<=512,'invalid_read_extent')
        data,err=self.command(f'{BB} dd if={path} bs=512 skip={start} count={count}',limit=count*512,stderr=True)
        require(len(data)==count*512,'remote_short_read')
        dd_status(err,count)
        return data

    def capture(self,plan,full=True,prior=None):
        previous=getattr(self,'capture_deadline',float('inf'))
        self.capture_deadline=min(previous,time.monotonic()+300)
        try:return self._capture(plan,full,prior)
        finally:self.capture_deadline=previous

    def _capture(self,plan,full=True,prior=None):
        start=time.monotonic();boot=self.text(BB+' cat /proc/sys/kernel/random/boot_id')
        texts={
            'boot_id':boot, 'uid':root_uid(self.text(BB+' cat /proc/self/status')),
            'cmdline':self.text(BB+' cat /proc/cmdline'),
            'mountinfo':self.text(BB+' cat /proc/self/mountinfo'),
            'cid':self.text(BB+' cat /sys/class/block/mmcblk0/device/cid'),
            'sectors':self.text(BB+' cat /sys/class/block/mmcblk0/size'),
            'logical_sector':self.text(BB+' cat /sys/class/block/mmcblk0/queue/logical_block_size'),
            'disk_dev':self.text(BB+' cat /sys/class/block/mmcblk0/dev'),
            'disk_node':block_node(self.file_metadata(DEVICE)),
            'mmc_sysfs':self.text(BB+' readlink /sys/class/block/mmcblk0'),
            'mmc_device':self.text(BB+' readlink /sys/class/block/mmcblk0/device'),
            'asus_mmc_absent':self.text('test ! -e /sbin/asus_mmc && test ! -L /sbin/asus_mmc && echo absent')}
        out,err=self.command(BB+' dd --help',allowed=(0,1),stderr=True)
        texts['dd_help']=(out+err).decode('ascii')
        parts={}
        listing=self.text('for p in /sys/class/block/mmcblk0/mmcblk0p*; do test -d "$p" || exit 1; '+
            'printf "%s " "${p##*mmcblk0p}"; '+BB+' cat "$p/start" "$p/size" "$p/dev" | '+BB+" tr '\\n' ' '; echo; done")
        for line in listing.splitlines():
            fields=line.split();require(len(fields)==4 and re.fullmatch('[1-9][0-9]*',fields[0]),'partition_sysfs_syntax')
            n,startsector,size,dev=fields;require(n not in parts,'duplicate_partition')
            parts[n]={'start':startsector,'size':size,'dev':dev}
        raw={key:record_blob(self.raw_read(DEVICE,row['offset']//512,len(row['old'])//512)) for key,row in
             [('primary',plan['primary']),('backup',plan['backup'])]}
        for n in (1,2):raw['metadata'+str(n)]=record_blob(self.raw_read(DEVICE+'p'+str(n),0,512))
        for n in FS:
            raw['superblock'+str(n)]=record_blob(self.raw_read(DEVICE+'p'+str(n),2,2))
            texts['errors'+str(n)]=self.text(BB+' cat /sys/fs/ext4/mmcblk0p'+str(n)+'/errors_count')
        hashes={}
        for path in [BB,*STOCK]:
            out,_=self.command(BB+' sha256sum '+path);hashes[path]=digest_line(out,path)
        for n in SLOTS:
            path=DEVICE+'p'+str(n)
            if full:
                out,_=self.command(BB+' sha256sum '+path,timeout=120)
                hashes[path]=digest_line(out,path)
            else:
                require(prior is not None,'missing_full_capture')
                hashes[path]=prior['hashes'][path]
        require(self.text(BB+' cat /proc/sys/kernel/random/boot_id')==boot,'boot_changed_during_capture')
        require(time.monotonic()-start<300,'capture_total_deadline')
        return {'schema':1,'plan_sha256':PLAN_SHA,'captured_unix':int(time.time()),'full_slot_hashes_read':full,
                'transport':{'host':self.args.host,'port':self.args.port,'username':self.args.username,
                             'source':self.args.source,'fingerprint':self.fingerprint,'known_hosts_sha256':self.trust_sha},
                'text':texts,'partitions':parts,'raw':raw,'hashes':hashes}

    def begin(self,token):
        require(re.fullmatch('[0-9a-f]{32}',token),'invalid_stage_token')
        stage='/tmp/leon-gpt-'+token
        self.command('umask 077; '+BB+' mkdir '+LOCK+' && '+BB+' mkdir '+stage)
        self.stage=stage
        for path in (LOCK,stage):
            meta=self.file_metadata(path)
            require(meta['mode']=='drwx------' and meta['uid']==meta['gid']==0,'remote_stage_metadata')
        return stage

    def stage_files(self,operations,desired):
        # Stock Dropbear has no SFTP server in the extracted image. Send only
        # into a new regular staging file under the already-created 0700 dir;
        # ash noclobber refuses an existing file. dd never reads this SSH pipe.
        for op in operations:
            path=self.stage+'/'+op['name']+'.bin';data=op[desired]
            self.command('umask 077; set -C; '+BB+' cat > '+path,stdin=data,limit=1)
            require(safe_staged(self.file_metadata(path),len(data)),'unsafe_staged_file')
            out,_=self.command(BB+' sha256sum '+path)
            require(digest_line(out,path)==sha(data),'staged_hash_mismatch')

    def write_extent(self,op,desired,boot_id):
        allowed={'backup_entries':(61226463*512,16384),'backup_header':(61226495*512,512),
                 'primary_entries':(2*512,16384),'primary_header':(512,512)}
        require(op.get('name') in allowed and (op.get('offset'),op.get('size'))==allowed[op['name']]
                and desired in ('old','new') and len(op[desired])==op['size'],'unapproved_write_extent')
        path=self.stage+'/'+op['name']+'.bin'
        data=op[desired]
        # Check source after staging too. No writes happen before every guard.
        require(self.text(BB+' cat /proc/sys/kernel/random/boot_id')==boot_id,'boot_changed_before_write')
        require(safe_staged(self.file_metadata(path),len(data)),'staged_file_changed')
        out,_=self.command(BB+' sha256sum '+path)
        require(digest_line(out,path)==sha(data),'staged_file_changed')
        try:
            out,err=self.command(f'{BB} dd if={path} of={DEVICE} bs=512 seek={op["offset"]//512} '
                f'count={op["size"]//512} conv=notrunc,fsync',limit=1,stderr=True,timeout=30)
            n=op['size']//512
            require(not out,'write_unexpected_stdout');dd_status(err,n)
            require(self.raw_read(DEVICE,op['offset']//512,n)==data,'write_readback_mismatch')
        except Exception:raise UnknownOutcome('write_outcome_unknown_stop_no_retry') from None

    def finish(self,operations):
        # Only remove exact files created by this invocation; never rm -r.
        files=' '.join(self.stage+'/'+x['name']+'.bin' for x in operations)
        self.command(BB+' rm '+files+' && '+BB+' rmdir '+self.stage+' '+LOCK)


def immutable_identity(snapshot, include_boot=True):
    # Mounted ext4 statistics/superblocks may naturally change; UUID, health,
    # extent and mount checks run again, without byte-equality of live ext4.
    return {'boot_id':snapshot['text']['boot_id'] if include_boot else None,'transport':snapshot['transport'],
            'metadata1':blob(snapshot,'metadata1'),'metadata2':blob(snapshot,'metadata2'),
            'hashes':snapshot['hashes'],'partitions':snapshot['partitions']}


def require_same(before,after,include_boot=True):
    require(immutable_identity(before,include_boot)==immutable_identity(after,include_boot),'fresh_capture_identity_changed')


def save_capture(directory,name,snapshot):
    data=canonical(snapshot);durable_file(directory/name,data);fsync_dir(directory)
    return {'path':str(directory/name),'sha256':sha(data),'bytes':len(data)}


def durable_backup(directory,snapshot):
    path=directory/'pre-write-backup';path.mkdir(mode=0o700)
    entries=[]
    for key in ('primary','backup','metadata1','metadata2'):
        data=blob(snapshot,key);durable_file(path/(key+'.bin'),data)
        entries.append({'name':key+'.bin','bytes':len(data),'sha256':sha(data)})
    durable_file(path/'receipt.json',canonical({'schema':1,'plan_sha256':PLAN_SHA,
        'capture_sha256':sha(canonical(snapshot)),'snapshots':entries,'boot_id':snapshot['text']['boot_id']}))
    fsync_dir(path);fsync_dir(directory);fsync_dir(directory.parent)
    return entries


def recovery_ops(snapshot,plan,tx):
    s=gpt_state(snapshot,plan,tx)
    if s['primary']=={'crc_valid':True,'kind':'old'}:order=['backup']
    elif s['backup']=={'crc_valid':True,'kind':'old'}:order=['primary']
    elif s['backup']['crc_valid']:order=['primary','backup']
    else:order=['backup','primary']
    return [op for key in order if blob(snapshot,key)!=plan[key]['old']
            for op in plan['operations'] if op['copy']==key]


def perform(remote,plan,tx,reviewed,directory,recover=False,original=None):
    # A prior snapshot's freshness is its SAME boot and exact critical values,
    # not wall-clock trust. It must have read both complete stock slot hashes.
    require(reviewed['full_slot_hashes_read'] is True,'reviewed_capture_not_full')
    validate(reviewed,plan,tx,None if recover else 'old')
    if recover:
        require(original is not None and original['full_slot_hashes_read'] is True,'missing_original_capture')
        validate(original,plan,tx,'old');require_same(original,reviewed,include_boot=False)
    current=remote.capture(plan,full=True)
    validate(current,plan,tx,None if recover else 'old');require_same(reviewed,current)
    require(all(blob(current,k)==blob(reviewed,k) for k in ('primary','backup')),'reviewed_gpt_state_changed')
    save_capture(directory,'fresh-prewrite.json',current)
    operations=recovery_ops(current,plan,tx) if recover else plan['operations']
    desired='old' if recover else 'new'
    receipt={'schema':1,'operation':'recover-original' if recover else 'append-p11-gpt',
             'plan_sha256':PLAN_SHA,'reviewed_capture_sha256':sha(canonical(reviewed)),
             'status':'prepared','completed_extents':[],'block_partition_ioctl':False,
             'physical_power_loss_guarantee':False}
    if original is not None:receipt['original_capture_sha256']=sha(canonical(original))
    receipt['backup']=durable_backup(directory,current)
    if not operations:
        receipt['status']='already_original_noop';durable_file(directory/'result.json',canonical(receipt));fsync_dir(directory)
        return receipt
    stage=None;lock_attempted=False
    try:
        token=secrets.token_hex(16);receipt['remote_stage']='/tmp/leon-gpt-'+token
        # Persist identifiers before even the mkdir/lock may have unknown status.
        durable_file(directory/'prepared.json',canonical(receipt));fsync_dir(directory)
        lock_attempted=True
        stage=remote.begin(token);require(stage==receipt['remote_stage'],'unexpected_stage_path')
        remote.stage_files(operations,desired)
        expected={k:bytearray(blob(current,k)) for k in ('primary','backup')}
        deadline=time.monotonic()+300
        for op in operations:
            require(time.monotonic()<deadline,'transaction_total_deadline')
            fresh=remote.capture(plan,full=False,prior=current)
            validate(fresh,plan,tx);require_same(current,fresh)
            require(all(blob(fresh,k)==bytes(expected[k]) for k in expected),'gpt_changed_between_extents')
            other='backup' if op['copy']=='primary' else 'primary'
            require(gpt_state(fresh,plan,tx)[other]['crc_valid'],'other_copy_invalid_before_write')
            remote.write_extent(op,desired,current['text']['boot_id'])
            relative=op['offset']-plan[op['copy']]['offset']
            expected[op['copy']][relative:relative+op['size']]=op[desired]
            after=remote.capture(plan,full=False,prior=current)
            validate(after,plan,tx);require_same(current,after)
            require(all(blob(after,k)==bytes(expected[k]) for k in expected),'gpt_readback_not_exact')
            state=gpt_state(after,plan,tx)
            if op['name'].endswith('_header'):require(state[op['copy']]['crc_valid'],'written_copy_crc_invalid')
            receipt['completed_extents'].append({'name':op['name'],'offset':op['offset'],'bytes':op['size'],
                                                'sha256':sha(op[desired]),'readback_crc_state':state})
            durable_file(directory/('step-'+str(len(receipt['completed_extents']))+'.json'),canonical(receipt));fsync_dir(directory)
        final=remote.capture(plan,full=True);validate(final,plan,tx,'old' if recover else 'candidate');require_same(current,final)
        receipt['final_capture']=save_capture(directory,'final-capture.json',final)
        remote.finish(operations)
        receipt['status']='complete_gpt_only_no_kernel_partition_added'
    except BaseException as error:
        # This includes failures AFTER a known completed write. Do not retry,
        # automatically recover, remove lock, or assume a disconnected dd stopped.
        receipt['status']='stopped_requires_readonly_review'
        receipt['failure_code']=str(error) if isinstance(error,Refusal) else type(error).__name__
        receipt['remote_lock_may_remain']=lock_attempted
        try:
            observed=remote.capture(plan,full=False,prior=current)
            receipt['readonly_after_failure']=save_capture(directory,'unknown-outcome-capture.json',observed)
        except Exception:receipt['readonly_after_failure_unavailable']=True
        durable_file(directory/'result.json',canonical(receipt));fsync_dir(directory)
        raise Refusal('transaction_stopped_review_result_no_automatic_recovery') from None
    durable_file(directory/'result.json',canonical(receipt));fsync_dir(directory)
    return receipt


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host',default='192.168.100.15');p.add_argument('--port',type=int,default=22)
    p.add_argument('--username',default='MastermixStudios');p.add_argument('--source',default='192.168.100.36')
    p.add_argument('--known-hosts',type=Path,required=True)
    auth=p.add_mutually_exclusive_group();auth.add_argument('--key',type=Path);auth.add_argument('--agent',action='store_true')
    p.add_argument('--key-passphrase',action='store_true')
    action=p.add_mutually_exclusive_group();action.add_argument('--apply',action='store_true');action.add_argument('--recover-original',action='store_true')
    p.add_argument('--reviewed-capture',type=Path);p.add_argument('--capture-sha256');p.add_argument('--plan-sha256')
    p.add_argument('--original-capture',type=Path);p.add_argument('--original-capture-sha256')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    remote=None
    try:
        ipaddress.ip_address(a.host);ipaddress.ip_address(a.source)
        require(1<=a.port<=65535 and re.fullmatch('[A-Za-z0-9_.-]{1,64}',a.username),'ssh_parameters')
        require(not a.key_passphrase or a.key is not None,'passphrase_without_key')
        plan,tx=load_plan();reviewed=original=None
        if a.apply or a.recover_original:
            require(a.plan_sha256==PLAN_SHA and a.reviewed_capture is not None,'explicit_reviewed_plan_and_capture_required')
            reviewed=read_reviewed(a.reviewed_capture,a.capture_sha256)
            validate(reviewed,plan,tx,None if a.recover_original else 'old')
            if a.recover_original:
                require(a.original_capture is not None,'explicit_original_capture_required')
                original=read_reviewed(a.original_capture,a.original_capture_sha256)
                validate(original,plan,tx,'old');require_same(original,reviewed,include_boot=False)
        else:
            require(not any([a.reviewed_capture,a.capture_sha256,a.plan_sha256,a.original_capture,a.original_capture_sha256]),
                    'write_review_arguments_without_action')
        directory=new_dir(a.output)
        password=None if a.key or a.agent else getpass.getpass('Stock SSH password (memory only): ')
        passphrase=getpass.getpass('SSH key passphrase (memory only): ') if a.key_passphrase else None
        remote=SSH(a,password,passphrase)
        if reviewed:
            result=perform(remote,plan,tx,reviewed,directory,a.recover_original,original)
            print(json.dumps({'status':result['status'],'result':str(directory/'result.json')}))
        else:
            capture=remote.capture(plan,full=True)
            ref=save_capture(directory,'capture.json',capture)
            try:validate(capture,plan,tx,'old');ready=True;reason=None
            except Refusal as error:ready=False;reason=str(error)
            print(json.dumps({'status':'read_only_capture','capture':ref,'eligible_original_state':ready,'refusal':reason}))
    except (Refusal,OSError,ValueError,KeyError,AssertionError) as error:
        print(json.dumps({'status':'refused','code':str(error) if isinstance(error,Refusal) else type(error).__name__}),file=sys.stderr)
        return 1
    finally:
        if remote:remote.close()
    return 0


if __name__=='__main__':raise SystemExit(main())

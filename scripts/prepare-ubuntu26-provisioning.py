#!/usr/bin/env python3
"""Prepare a NEW offline trial-root archive; never provision a live device.

The sole rootfs mutation is a trial-target activation symlink. Host keys,
passwords, account state, and the post-flash slot token are deliberately absent.
The resulting image is NOT boot-ready: the immutable guardian must reject it
until a separate device-local provisioning transaction completes.
"""
import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile

R=Path(__file__).resolve().parents[1]
GENERATION='be19000ai-ubuntu26-kernel10-systemd-v1\n'
TARGET='usr/lib/systemd/system/leon-ubuntu-trial.target'
LINK='etc/systemd/system/multi-user.target.wants/leon-ubuntu-trial.target'
ACCOUNT='MastermixStudios'
KEYS=('rsa','ecdsa','ed25519')
FORBIDDEN={'etc/leon/trial-slot-proof','var/lib/leon-asus-ssh/device-identity','var/lib/leon-asus-ssh/account'}
FORBIDDEN.update('etc/ssh/ssh_host_'+kind+'_key'+suffix for kind in KEYS for suffix in ('','.pub'))
FEATURES=['has_journal','ext_attr','resize_inode','dir_index','filetype','extent','flex_bg','sparse_super','large_file','huge_file','dir_nlink','extra_isize','metadata_csum']

def sha(path):
    with open(path,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def dump(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def ref(path):
    path=path.resolve();return {'path':str(path.relative_to(R)),'sha256':sha(path)}
def canon(name):
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts:raise ValueError('unsafe archive path')
    return str(p)
def regular(path):
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise ValueError('input must be a regular file with one link')

def inspect(archive,target_bytes,generation=GENERATION,expected_package=None):
    members={};records={}
    for m in archive:
        name=canon(m.name)
        if name in members:raise ValueError('duplicate archive path')
        if name in FORBIDDEN:raise ValueError('device identity or slot token already present')
        if not (m.isfile() or m.isdir() or m.issym() or m.islnk() or m.ischr() or m.isblk()):raise ValueError('unsupported archive member')
        members[name]=m
        if m.isfile():records[name]=hashlib.sha256(archive.extractfile(m).read()).hexdigest()
    for name,m in members.items():
        for parent in PurePosixPath(name).parents:
            if str(parent) in members and not members[str(parent)].isdir():raise ValueError('archive member under non-directory')
        if m.islnk():
            dest=canon(m.linkname)
            if dest not in members or not members[dest].isfile():raise ValueError('invalid hardlink target')
        if (m.ischr() or m.isblk()) and not name.startswith('dev/'):raise ValueError('device inode outside dev')
        if name.startswith('etc/systemd/system/') and m.issym() and ('asus' in name or 'leon-ubuntu-trial' in name):raise ValueError('ASUS unit already activated')
    for name,mode in [('.',0o755),('etc',0o755),('etc/leon',0o755),('etc/leon/root-generation',0o644),('mnt/leon-vendor-root',0o755),('etc/systemd/system',0o755)]:
        m=members.get(name)
        if m is None or m.uid or m.gid or m.mode!=mode or (not m.isfile() if name.endswith('root-generation') else not m.isdir()):raise ValueError('boot profile metadata mismatch: '+name)
    if archive.extractfile(members['etc/leon/root-generation']).read()!=generation.encode():raise ValueError('root generation mismatch')
    m=members.get(TARGET)
    if m is None or not m.isfile() or m.uid or m.gid or m.mode!=0o644 or archive.extractfile(m).read()!=target_bytes:raise ValueError('trial target does not match reviewed package')
    for name in ('etc/passwd','etc/shadow'):
        m=members.get(name)
        if m is None or not m.isfile():raise ValueError('account database missing')
        if any(line.startswith(ACCOUNT.encode()+b':') for line in archive.extractfile(m).read().splitlines()):raise ValueError('device account must not be copied from build host')
    if expected_package:
        m=members.get('var/lib/dpkg/status')
        if m is None or not m.isfile():raise ValueError('dpkg status missing')
        records_text=archive.extractfile(m).read().decode().split('\n\n')
        matches=[]
        for record in records_text:
            fields=dict(line.split(': ',1) for line in record.splitlines() if ': ' in line and not line.startswith(' '))
            if fields.get('Package')==expected_package['name']:matches.append(fields)
        if len(matches)!=1 or matches[0].get('Status')!='install ok installed' or matches[0].get('Version')!=expected_package['version'] or matches[0].get('Architecture')!=expected_package['architecture']:raise ValueError('activation package is not installed at reviewed version')
    return members,records

def reviewed_target(manifest):
    data=json.loads(manifest.read_text());package=data['package'];path=R/package['path'];regular(path)
    if sha(path)!=package['sha256']:raise ValueError('activation package digest mismatch')
    if package['name']!='leon-bcm-trial-activation':raise ValueError('wrong package')
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(path)]))) as arc:
        items=[m for m in arc if canon(m.name)==TARGET]
        if len(items)!=1 or not items[0].isfile():raise ValueError('target missing from package')
        return arc.extractfile(items[0]).read(),package

def prepare_tar(source,target,target_bytes,expected_package=None):
    regular(source)
    with tarfile.open(source) as old:
        members,before=inspect(old,target_bytes,expected_package=expected_package)
        with target.open('xb') as stream,tarfile.open(fileobj=stream,mode='w',format=tarfile.PAX_FORMAT) as new:
            for m in old.getmembers():new.addfile(copy.copy(m),old.extractfile(m) if m.isfile() else None)
            parent=str(PurePosixPath(LINK).parent)
            if parent not in members:
                m=tarfile.TarInfo(parent);m.type=tarfile.DIRTYPE;m.mode=0o755;m.uid=m.gid=0;m.mtime=1791072000;new.addfile(m)
            m=tarfile.TarInfo(LINK);m.type=tarfile.SYMTYPE;m.mode=0o777;m.uid=m.gid=0;m.mtime=1791072000;m.linkname='/'+TARGET;new.addfile(m)
    with tarfile.open(target) as new:
        after={canon(m.name):hashlib.sha256(new.extractfile(m).read()).hexdigest() for m in new if m.isfile()}
        if before!=after:raise ValueError('source file bytes changed')
        link=new.getmember(LINK)
        if not link.issym() or link.linkname!='/'+TARGET or link.uid or link.gid:raise ValueError('activation link mismatch')
    return {'source_regular_files_preserved':len(before),'only_payload_mutation':'new trial-target symlink plus parent directory if absent','activation_link':{'path':'/'+LINK,'target':'/'+TARGET},'device_identity_absent':True,'slot_token_absent':True}

def contract(policy):
    return {
      'schema_version':1,'status':'offline_candidate_requires_separate_device_local_provisioning',
      'root_generation':GENERATION,'root_partition':{k:policy[k] for k in ('device','major','minor','start_sector','sectors','uuid')},
      'ext4_profile':{'bytes':policy['sectors']*512,'block_size':4096,'inode_size':256,'features':FEATURES,'mount_flags':['rw','relatime'],'mount_options':['data=ordered','errors=remount-ro'],'nosuid':False,'reason':'Official sudo requires its package-owned setuid executable.'},
      'activation':{'link':'/'+LINK,'target':'/'+TARGET,'requires_guardian_already_armed':True,'no_global_ssh_service_or_socket_enablement':True},
      'device_identity':{
        'run_location':'On the router only, inside the mounted new ext4 root; never on the build host.',
        'stock_chroot_cannot_call_initialize_device_identity':True,
        'reason':'native-control validates that the caller shares the native PID1 mount namespace and /etc, so a stock-PID1 chroot intentionally fails.',
        'account_before_guardian':{'name':ACCOUNT,'uid':'allocate a free UID >=1000 and !=65534; record and verify it','shell':'/bin/bash','supplementary_group':'sudo','password':'Read the configured ASUS password HASH locally, validate the accepted crypt format, and update only this native account. Do not export, log, or carry the hash on the command line.','account_marker':{'path':'/var/lib/leon-asus-ssh/account','mode':'0600','owner':'0:0','exact_template':'LEON_SSH_ACCOUNT_V1 MastermixStudios <allocated-uid>\n'}},
        'key_creation':'Require all six final host-key paths and device marker absent; create a private staging tree on the new filesystem, run its native /usr/bin/ssh-keygen -A -f STAGING locally, validate each private/public pair, install via no-overwrite link+unlink, fsync every key and /etc/ssh before writing the marker.',
        'device_marker':{'path':'/var/lib/leon-asus-ssh/device-identity','mode':'0600','owner':'0:0','exact_contents':'LEON_SSH_DEVICE_V1_OK\n','write_last':True},
        'partial_failure':'Refuse further automated initialization when any key or account marker is partial. Preserve state for explicit repair; never silently regenerate or overwrite keys.',
        'host_export_allowlist':['public host-key lines','SHA256 public-key fingerprints','nonsecret account UID','success/failure status'],
        'host_export_forbidden':['private host keys','ASUS password','password hash','shadow contents'],
        'observer_trust':'Verify and add the NEW Ubuntu public key to a separate known_hosts through the already trusted stock SSH channel. No TOFU; observer requires the previous stock boot ID and fresh TCP connections.'},
      'slot_token':{
        'path':'/etc/leon/trial-slot-proof','owner':'0:0','mode':'0600','hardlinks':1,
        'exact_template':'LEON_TRIAL_SLOT_V1\ngeneration '+GENERATION.rstrip('\n')+'\nmetadata_sha256 <fresh-postflash-262144-byte-metadata-sha256>\nstock_kernel_sha256 ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256\nstock_rootfs_sha256 51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465\n',
        'required_capture':'After the last slot write and selection change, read both COMPLETE 262144-byte metadata partitions from the same unchanged stock boot; require exact equality, valid per-copy CRC, COMMITTED=2 and desired valid/sequence fields. Verify full original p5/p6 hashes and exact partition geometry again. Then atomically create this proof on the device and fsync file+directory.',
        'no_token_generated_offline':True,'invalidated_by_any_later_metadata_change':True,
        'fresh_boot_semantics':'The five-line V1 token binds final metadata, not a boot UUID. The host provisioning receipt separately records the stock boot UUID; the observer rejects that previous UUID and pins the first acknowledged new boot. Guardian independently validates actual kernel/slot/reset reason and metadata at each trial boot.'},
      'pending_implementation':['Device-local account/key/token transaction with trusted device identity checks.','Device-local root ownership, fresh postflash metadata and direct stock-hash readback.','Actual hardware trial and orderly manual acceptance; no automatic commit.'],
      'network_used':False,'block_device_writes':False,'production_boot_ready':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--candidate-manifest',type=Path,required=True);p.add_argument('--candidate-manifest-sha256',required=True);p.add_argument('--activation-manifest',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args()
    if not re.fullmatch('[a-zA-Z0-9_-]+',a.label) or not re.fullmatch('[0-9a-f]{64}',a.candidate_manifest_sha256):raise ValueError('invalid argument')
    regular(a.candidate_manifest)
    if sha(a.candidate_manifest)!=a.candidate_manifest_sha256:raise ValueError('candidate manifest digest mismatch')
    candidate=json.loads(a.candidate_manifest.read_text());root=candidate['rootfs'];source=R/root['path'];regular(source)
    if sha(source)!=root['sha256'] or source.stat().st_size!=root['bytes']:raise ValueError('rootfs identity mismatch')
    target_bytes,package=reviewed_target(a.activation_manifest)
    policy=json.loads((R/'configs/ubuntu26/root-init-device-policy.json').read_text())
    if policy['generation']!=GENERATION or not policy['guardian']['required']:raise ValueError('wrong boot policy')
    out=R/'build/ubuntu26-provisioning'/a.label;out.mkdir(parents=True,exist_ok=False)
    target=out/'trial-root-needs-device-identity.tar';result=prepare_tar(source,target,target_bytes,package)
    dump(out/'device-local-contract.json',contract(policy))
    result.update(schema_version=1,status='offline_activated_archive_not_boot_ready',base_manifest=ref(a.candidate_manifest),activation_manifest=ref(a.activation_manifest),activation_package=package,rootfs={'path':str(target.relative_to(R)),'sha256':sha(target),'bytes':target.stat().st_size},contract=ref(out/'device-local-contract.json'),source=ref(Path(__file__).resolve()),network_used=False,block_devices_opened=False,production_ready=False)
    dump(out/'manifest.json',result);print(json.dumps({'status':result['status'],'rootfs':result['rootfs']},indent=2))
if __name__=='__main__':main()

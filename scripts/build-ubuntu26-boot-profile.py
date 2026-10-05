#!/usr/bin/env python3
"""Build an inert package-owned production root generation; optionally test in an offline clone."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

R = Path(__file__).resolve().parents[1]
PROTECTED = ['etc/passwd', 'etc/shadow', 'etc/group', 'etc/fstab',
             'usr/lib/systemd/systemd', 'usr/sbin/sshd', 'usr/bin/dash']


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def dump(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n')


def ns():
    return {x: os.readlink('/proc/self/ns/' + x) for x in ['user', 'mnt', 'pid', 'net']}


def worker(plan_path):
    plan = json.loads(plan_path.read_text())
    assert os.getuid() == 0
    assert all(ns()[x] != plan['host_namespaces'][x] for x in ['user', 'mnt', 'pid'])
    work = Path('/tmp/leon-boot-profile-' + plan['nonce']); assert not work.exists()
    work.mkdir(mode=0o700); root = work/'root'; root.mkdir(mode=0o755)
    result = {'status': 'failed', 'namespaces': ns(), 'router_access': False}
    mounts = []
    with (work/'install.log').open('w') as log:
        def run(command, inside=False):
            argv = (['unshare', '--net', 'chroot', str(root)] if inside else []) + list(map(str, command))
            log.write('COMMAND ' + json.dumps(argv) + '\n'); log.flush()
            p = subprocess.run(argv, text=True, capture_output=True,
                env={**os.environ, 'LC_ALL': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive'})
            log.write(p.stdout+p.stderr); log.flush()
            assert p.returncode == 0, ('command_failed', p.returncode, argv)
            return p.stdout
        try:
            run(['mount', '--make-rprivate', '/'])
            run(['tar', '--extract', '--same-owner', '--numeric-owner', '--same-permissions',
                 '--acls', '--xattrs', '--xattrs-include=*', '--exclude=./dev/*', '--exclude=dev/*',
                 '-f', plan['base']['path'], '-C', root])
            for name, major, minor in [('null',1,3),('zero',1,5),('random',1,8),('urandom',1,9)]:
                target=root/'dev'/name; assert not target.is_symlink(); target.touch()
                run(['mount','--bind','/dev/'+name,target]); mounts.append(target)
                s=target.stat(); assert stat.S_ISCHR(s.st_mode) and (os.major(s.st_rdev),os.minor(s.st_rdev))==(major,minor)
            run(['mount','-t','proc','proc',root/'proc']); mounts.append(root/'proc')
            policy=root/'usr/sbin/policy-rc.d'; assert not policy.exists()
            policy.write_text('#!/bin/sh\nexit 101\n'); policy.chmod(0o755)
            expected=plan['config']; marker=root/expected['marker'].lstrip('/'); mountpoint=root/expected['vendor_root_mountpoint'].lstrip('/')
            assert not marker.exists() and not mountpoint.exists()
            before={p:sha(root/p) for p in PROTECTED}
            units_before={str(p.relative_to(root)):os.readlink(p) for p in (root/'etc/systemd/system').rglob('*') if p.is_symlink()}
            query=['dpkg-query','-W','-f=${binary:Package}\t${Version}\n']
            versions_before=run(query,True)
            src=Path(plan['package']['path']); assert sha(src)==plan['package']['sha256']
            deb=root/'tmp/boot-profile.deb'; shutil.copyfile(src,deb)
            sim=run(['apt-get','--simulate','--no-install-recommends','install','/tmp/boot-profile.deb'],True)
            for line in sim.splitlines():
                assert not line.startswith('Remv ')
                if line.startswith('Inst '): assert line.split()[1]==expected['package']
            # Apt must perform its local file acquisition; --no-download also
            # disables that path. The isolated network namespace is the actual
            # network boundary, and simulation permits only this exact package.
            run(['apt-get','--yes','-o','Dpkg::Use-Pty=0','--no-install-recommends','install','/tmp/boot-profile.deb'],True)
            run(['dpkg','--install','/tmp/boot-profile.deb'],True)
            assert not run(['dpkg','--audit'],True).strip(); run(['apt-get','check'],True)
            assert marker.read_text()==expected['generation']
            for p,mode in [(root/'etc/leon',0o755),(marker,0o644),(mountpoint,0o755)]:
                s=p.lstat(); assert not p.is_symlink() and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode
            assert not list(mountpoint.iterdir())
            for entry in plan['archive']:
                p=root/entry['path'].lstrip('/');s=p.lstat()
                assert s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==entry['mode']
                if entry['type']=='file':assert p.is_file() and sha(p)==entry['sha256']
                else:assert p.is_dir() and not p.is_symlink()
            owned=run(['dpkg-query','--search',expected['marker'],expected['vendor_root_mountpoint']],True)
            assert all(line.startswith(expected['package']+': ') for line in owned.splitlines())
            versions_after=run(query,True)
            a=dict(x.split('\t') for x in versions_after.splitlines()); b=dict(x.split('\t') for x in versions_before.splitlines())
            assert a.pop(expected['package'])==expected['version'] and a==b
            assert {p:sha(root/p) for p in PROTECTED}==before
            assert {str(p.relative_to(root)):os.readlink(p) for p in (root/'etc/systemd/system').rglob('*') if p.is_symlink()}==units_before
            result.update(apt_install_reinstall=True, marker_content_exact=True, package_ownership=owned.splitlines(),
                all_existing_versions_unchanged=True, native_files_unchanged=True, unit_enablement_unchanged=True,
                installed_package_count=len(b)+1, archive_entries_checked=len(plan['archive']),
                apt_simulation=sim)
            # A data-only marker must disappear on purge; no hidden activation or
            # retained generation is allowed in this disposable test clone.
            run(['dpkg','--purge',expected['package']],True)
            assert not marker.exists() and not mountpoint.exists()
            assert run(query,True)==versions_before
            assert not run(['dpkg','--audit'],True).strip();run(['apt-get','check'],True)
            result.update(status='passed', offline_purge_removes_identity=True, production_services_executed=False)
        except Exception as error:
            result['error']=repr(error)
        finally:
            for mount in reversed(mounts):
                subprocess.run(['umount',str(mount)],stdout=log,stderr=log)
    dump(work/'result.json',result)
    return 0 if result['status']=='passed' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,default=R/'configs/ubuntu26/boot-profile-device.json')
    p.add_argument('--label')
    p.add_argument('--test-base-manifest',type=Path)
    p.add_argument('--namespace-worker',type=Path)
    args=p.parse_args()
    if args.namespace_worker:return worker(args.namespace_worker)
    assert args.label and re.fullmatch(r'[A-Za-z0-9_-]+',args.label)
    cfg=json.loads(args.config.read_text())
    assert cfg['schema_version']==1 and cfg['automatic_activation'] is False and cfg['flash_accepted'] is False
    assert cfg['generation']==cfg['profile_id']+'\n' and re.fullmatch(r'[A-Za-z0-9_-]{1,80}\n',cfg['generation'])
    assert cfg['package']=='leon-bcm-boot-profile' and cfg['architecture']=='all'
    assert re.fullmatch(r'[0-9][A-Za-z0-9.+~:-]*',cfg['version'])
    assert cfg['marker']=='/etc/leon/root-generation' and cfg['vendor_root_mountpoint']=='/mnt/leon-vendor-root'
    assert '\n' not in cfg['depends']
    out=R/'build/ubuntu26-boot-profile'/args.label;out.mkdir(parents=True,exist_ok=False)
    stage=out/'stage';stage.mkdir(mode=0o755)
    marker=stage/cfg['marker'].lstrip('/');marker.parent.mkdir(parents=True)
    marker.write_text(cfg['generation']);(stage/cfg['vendor_root_mountpoint'].lstrip('/')).mkdir(parents=True)
    doc=stage/'usr/share/doc'/cfg['package'];doc.mkdir(parents=True)
    (doc/'profile.json').write_bytes(args.config.read_bytes())
    (doc/'README').write_text('''BE19000AI Ubuntu production boot profile, inert data only.

/etc/leon/root-generation is immutable package-owned boot identity, not a
user-editable conffile and not a circular rootfs tar hash. The separately
reviewed SquashFS root-init policy must match its exact bytes including newline.
/mnt/leon-vendor-root is an empty0755 mountpoint for the read-only original
SquashFS after pivot; this package never mounts or populates it.

No root-init, guardian, fstab, units, presets, triggers, maintainer scripts or
activation links are installed. /run remains early-root/native-systemd tmpfs;
/tmp remains the existing Ubuntu tmp.mount. Native integration alone owns the
four UUID-specific ASUS storage units. Ubuntu root stays read-write with normal
setuid semantics for official sudo; API tmpfs mount flags must not be confused
with root mount flags. This package does not authorize boot acceptance or flash.
''')
    control=stage/'DEBIAN';control.mkdir()
    (control/'control').write_text(f'''Package: {cfg['package']}
Version: {cfg['version']}
Architecture: all
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: {cfg['depends']}
Description: Inert BE19000AI Ubuntu boot identity and original-root mountpoint
 Package-owned generation bytes for the separately guarded early root pivot.
 No boot helper, mount action, service activation or firmware operation.
''')
    files=sorted(p for p in stage.rglob('*') if p.is_file() and control not in p.parents)
    (control/'md5sums').write_text(''.join(hashlib.md5(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(stage))+'\n' for p in files))
    epoch=cfg['source_date_epoch']
    for path in [stage,*stage.rglob('*')]:
        assert not path.is_symlink()
        path.chmod(0o755 if path.is_dir() else 0o644);os.utime(path,(epoch,epoch))
    env={**os.environ,'SOURCE_DATE_EPOCH':str(epoch)}
    deb=out/f"{cfg['package']}_{cfg['version']}_all.deb";second=out/'reproducibility.deb'
    for target in (deb,second):
        subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','-Zxz','--build',str(stage),str(target)],check=True,env=env,stdout=subprocess.DEVNULL)
    assert sha(deb)==sha(second);second.unlink()
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(deb)]))) as t:
        assert {x.name.removeprefix('./') for x in t if not x.isdir()}=={'control','md5sums'}
    entries=[]
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(deb)]))) as t:
        for x in t:
            assert x.uid==x.gid==0 and x.mode==(0o755 if x.isdir() else 0o644)
            assert x.isdir() or x.isfile()
            item={'path':'/'+x.name.removeprefix('./'),'mode':x.mode,'type':'directory' if x.isdir() else 'file'}
            if x.isfile():item['sha256']=hashlib.sha256(t.extractfile(x).read()).hexdigest()
            entries.append(item)
    package={'name':cfg['package'],'version':cfg['version'],'architecture':'all','path':str(deb.relative_to(R)),'sha256':sha(deb),'bytes':deb.stat().st_size}
    result={'schema_version':1,'status':'reproducible_inert_boot_profile_built','package':package,'profile_id':cfg['profile_id'],
        'generation':cfg['generation'],'config':{'path':str(args.config),'sha256':sha(args.config)},'archive':entries,
        'two_builds_identical':True,'no_maintainer_scripts_or_triggers_or_units':True,'automatic_activation':False,
        'root_init_ownership':False,'guardian_ownership':False,'production_ready':False,'flash_allowed':False,'builder_sha256':sha(__file__)}
    if args.test_base_manifest:
        base_manifest=json.loads(args.test_base_manifest.read_text());base=base_manifest['rootfs'];bp=R/base['path']
        assert sha(bp)==base['sha256'];base={'path':str(bp),'sha256':base['sha256']}
        with tarfile.open(bp) as t:
            members={x.name.removeprefix('./'):x for x in t}
            for item in entries:
                name=item['path'].lstrip('/')
                if name in members:assert item['type']=='directory' and members[name].isdir() and members[name].mode==0o755
        inputs=Path(tempfile.mkdtemp(prefix='leon-boot-profile-inputs-'));inputs.chmod(0o755)
        for source in [bp,deb,Path(__file__).resolve()]:
            target=inputs/source.name
            subprocess.run(['cp','--reflink=auto','--',str(source),str(target)],check=True)
            target.chmod(0o644);assert sha(source)==sha(target)
        nonce=secrets.token_hex(12);plan={'nonce':nonce,'base':{**base,'path':str(inputs/bp.name)},'config':cfg,'archive':entries,
            'package':{**package,'path':str(inputs/deb.name)},'host_namespaces':ns()}
        pp=inputs/'install-plan.json';dump(pp,plan);pp.chmod(0o644);dump(out/'install-plan.json',plan)
        started=time.monotonic()
        with (out/'namespace.log').open('w') as log:
            proc=subprocess.run(['mmdebstrap','--unshare-helper','python3',str(inputs/Path(__file__).name),'--namespace-worker',str(pp)],stdout=log,stderr=subprocess.STDOUT)
        work=Path('/tmp/leon-boot-profile-'+nonce)
        gathered=subprocess.run(['mmdebstrap','--unshare-helper','tar','-C',str(work),'-cf','-','result.json','install.log'],capture_output=True)
        if gathered.returncode==0:
            with tarfile.open(fileobj=io.BytesIO(gathered.stdout)) as archive:
                for member in archive:
                    assert member.isfile() and member.name in ['result.json','install.log'] and member.size<4*1024*1024
                    (out/member.name).write_bytes(archive.extractfile(member).read())
        if not (out/'result.json').exists():
            result['status']='offline_namespace_setup_failed'
            result['apt_test']={'status':'not_started','returncode':proc.returncode,'base_unchanged':sha(bp)==base['sha256'],'log':str((out/'namespace.log').relative_to(R))}
            dump(out/'manifest.json',result)
            raise RuntimeError('namespace failed; see namespace.log')
        proof=json.loads((out/'result.json').read_text());result['apt_test']={'status':proof['status'],'result':str((out/'result.json').relative_to(R)),'sha256':sha(out/'result.json'),'elapsed_seconds':round(time.monotonic()-started,2),'base':base,'base_manifest_sha256':sha(args.test_base_manifest),'base_unchanged':sha(bp)==base['sha256'],'rootfs_exported':False}
        result['status']='reproducible_and_offline_coinstallation_passed' if proc.returncode==0 else 'offline_coinstallation_failed'
        dump(out/'manifest.json',result)
        assert proc.returncode==0,proof
    dump(out/'manifest.json',result)
    print(json.dumps({'status':result['status'],'package':package,'manifest':str((out/'manifest.json').relative_to(R))},indent=2))
    return 0


if __name__=='__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Offline apt-install the inert ASUS runtime and integration into a new clone.

No hardware, vendor executable, service activation, host configuration, network,
or original rootfs mutation. Namespace entry remounts /dev to avoid regular-file
/dev/null contamination of packaging and apt tools.
"""
import argparse, hashlib, io, json, os, secrets, shutil, stat, subprocess, sys, tarfile, tempfile, time
from pathlib import Path, PurePosixPath

R = Path(__file__).resolve().parents[2]
FMT = '${binary:Package}\t${Version}\t${Architecture}\n'
PROTECTED = ['etc/passwd', 'etc/shadow', 'etc/group', 'usr/bin/dash',
             'usr/lib/aarch64-linux-gnu/libc.so.6', 'usr/lib/arm-linux-gnueabi/libc.so.6',
             'usr/lib/systemd/systemd', 'usr/sbin/sshd', 'usr/bin/gcc-16',
             'usr/lib/aarch64-linux-gnu/libstdc++.so.6', 'usr/lib/aarch64-linux-gnu/libgcc_s.so.1']
METADATA_UPGRADES = {
    'leon-asus-notify:arm64': ('0.1+leonb53.1', '0.2+leonb53.1'),
    'leon-asus-notify:armel': ('0.1+leonb53.1', '0.2+leonb53.1'),
    'leon-gcc15-runtime:armel': ('15.2.0-0leonb53.1', '15.2.0-0leonb53.2'),
    'leon-bcm-rootfs-config': ('0.2', '0.3'),
}

def sha(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def dump(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')

def ns():
    return {key: os.readlink('/proc/self/ns/' + key) for key in ['user', 'mnt', 'pid', 'net']}

def canonical(name):
    path = PurePosixPath(name)
    assert not path.is_absolute() and '..' not in path.parts
    return str(path).removeprefix('./')

def worker(plan_path):
    plan = json.loads(plan_path.read_text())
    work = Path(plan['namespace_work']); root = work / 'rootfs'
    assert os.getuid() == 0 and all(ns()[k] != plan['host_namespaces'][k] for k in ['user', 'mnt', 'pid'])
    assert work == Path('/tmp/asus-runtime-clone-' + plan['guard']) and not work.exists()
    work.mkdir(mode=0o700); root.mkdir(); mounts = []
    result = {'status': 'running', 'namespaces': ns()}
    log = (work / 'worker.log').open('w', buffering=1)
    def run(argv, inside=False):
        command = (['unshare', '--net', 'chroot', str(root)] if inside else []) + list(map(str, argv))
        log.write('COMMAND ' + json.dumps(command) + '\n')
        output = subprocess.run(command, text=True, capture_output=True,
                                env={**os.environ, 'LC_ALL':'C.UTF-8', 'DEBIAN_FRONTEND':'noninteractive'})
        log.write(output.stdout + output.stderr)
        if output.returncode:
            raise RuntimeError('command failed ' + str(output.returncode) + ': ' + json.dumps(command))
        return output.stdout
    try:
        run(['mount', '--make-rprivate', '/'])
        run(['tar', '--extract', '--numeric-owner', '--same-owner', '--same-permissions', '--acls', '--xattrs',
             '--xattrs-include=*', '--exclude=./dev/*', '--exclude=dev/*', '-f', plan['base'], '-C', root])
        for name, major, minor in [('null',1,3),('zero',1,5),('full',1,7),('random',1,8),('urandom',1,9),('tty',5,0)]:
            device = root / 'dev' / name; assert not device.is_symlink(); device.touch()
            run(['mount', '--bind', '/dev/' + name, device]); mounts.append(device)
            s = device.stat(); assert stat.S_ISCHR(s.st_mode) and (os.major(s.st_rdev), os.minor(s.st_rdev)) == (major,minor)
        run(['mount', '-t', 'proc', 'proc', root / 'proc']); mounts.append(root / 'proc')
        policy = root / 'usr/sbin/policy-rc.d'; assert not policy.exists()
        policy.write_text('#!/bin/sh\nexit 101\n'); policy.chmod(0o755)
        before = run(['dpkg-query', '-W', '-f=' + FMT], True)
        protected_before = {p: sha(root/p) for p in PROTECTED}
        sources = root / 'etc/apt/sources.list.d/ubuntu.sources'; source_sha = sha(sources)
        assert 'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' in sources.read_text()
        assert 'trusted=yes' not in sources.read_text()
        package_dir = root / 'tmp/asus-runtime-packages'; package_dir.mkdir()
        for item in plan['packages']:
            src = Path(item['path']); assert sha(src) == item['sha256']
            shutil.copyfile(src, package_dir/src.name)
        paths = ['/tmp/asus-runtime-packages/' + Path(x['path']).name for x in plan['packages']]
        simulation = run(['apt-get', '-s', '--no-install-recommends', 'install', *paths], True)
        result['apt_simulation'] = simulation
        allowed = {x['name'] for x in plan['packages']}
        for line in simulation.splitlines():
            assert not line.startswith('Remv ')
            if line.startswith('Inst '): assert line.split()[1].split(':')[0] in allowed, line
        run(['apt-get', '-y', '--no-install-recommends', 'install', *paths], True)
        assert not run(['dpkg', '--audit'], True).strip()
        run(['apt-get', 'check'], True)
        # Reinstall exact local archives to exercise dpkg ownership again. Only
        # the hash-pinned architecture-registration/ldconfig hooks are allowed;
        # new ASUS packages have no activation hooks.
        run(['dpkg', '--install', *paths], True)
        assert not run(['dpkg', '--audit'], True).strip(); run(['apt-get', 'check'], True)
        result['protected_native_files'] = {p: sha(root/p) for p in PROTECTED}
        assert result['protected_native_files'] == protected_before
        after = run(['dpkg-query', '-W', '-f=' + FMT], True)
        bm = {r.split('\t')[0]: r.split('\t')[1] for r in before.splitlines()}
        am = {r.split('\t')[0]: r.split('\t')[1] for r in after.splitlines()}
        upgrades = {}
        for key, old in bm.items():
            if am.get(key) == old: continue
            assert METADATA_UPGRADES.get(key) == (old, am.get(key)), (key, old, am.get(key))
            upgrades[key] = {'before':old, 'after':am[key]}
        for item in plan['packages']:
            assert am.get(item['name'], am.get(item['name']+':'+item['architecture'])) == item['version']
        result['new_packages'] = {k:v for k,v in am.items() if k not in bm}
        assert len(result['new_packages']) + len(upgrades) == len(plan['packages'])
        result['approved_metadata_only_upgrades'] = upgrades
        assert am['leon-asus-shell'] == '0.2+asus3006.102.9'
        assert am['leon-asus-notify:arm64'] == am['leon-asus-notify:armel']
        (root/'usr/share/leon-bcm-rootfs/package-manifest.tsv').write_text(after)
        dump(work/'package-manifest.json', {'before':bm, 'after':am})
        # dpkg deliberately preserves permissions of pre-existing directories.
        # Correct only the exact old0755/0775 packaging regression described by
        # the approved metadata revisions, inside this disposable clone.
        repairs=[]
        for entry in plan['directory_repairs']:
            directory_path=root/entry['path'].lstrip('/');s=directory_path.lstat()
            assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0
            assert stat.S_IMODE(s.st_mode) in (0o775,0o755),entry
            if stat.S_IMODE(s.st_mode)==0o775:
                directory_path.chmod(0o755);repairs.append(entry)
        result['explicit_legacy_directory_mode_migrations']=repairs
        checked = 0
        for entry in plan['archive_entries']:
            p = root / entry['path'].lstrip('/'); s = p.lstat()
            assert s.st_uid == s.st_gid == 0, entry
            assert stat.S_IMODE(s.st_mode) == entry['mode'], entry
            if entry['type'] == 'file': assert p.is_file() and sha(p) == entry['sha256'], entry
            elif entry['type'] == 'symlink': assert p.is_symlink() and os.readlink(p) == entry['link'], entry
            else: assert p.is_dir(), entry
            checked += 1
        assert not (root/'etc/ld.so.preload').exists() and not (root/'run/asus/systemd-managed').exists()
        assert not any('asus' in p.name for p in (root/'etc/systemd/system').rglob('*') if p.is_symlink())
        assert sha(sources) == source_sha
        result.update(installed_entries_checked=checked, protected_native_files_unchanged=True,
                      existing_package_versions_unchanged_except_approved_metadata=True, signed_sources_unchanged=True,
                      no_global_preload=True, no_service_activation=True, apt_install_and_dpkg_reinstall=True)
        policy.unlink(); shutil.rmtree(package_dir); run(['apt-get', 'clean'], True)
        for mount in reversed(mounts): run(['umount', mount])
        mounts.clear()
        run(['tar','--create','--numeric-owner','--acls','--xattrs','--xattrs-include=*','--exclude=./dev',
             '--one-file-system','-f',work/'candidate-without-dev.tar','-C',root,'.'])
        result['status'] = 'built'
    except Exception as error:
        result.update(status='failed', error=repr(error))
    finally:
        for mount in reversed(mounts): subprocess.run(['umount',str(mount)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        log.close(); dump(work/'worker-result.json', result)
    return 0 if result['status'] == 'built' else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace-worker', type=Path)
    parser.add_argument('--projection', type=Path)
    parser.add_argument('--package-report', type=Path)
    parser.add_argument('--integration-manifest', type=Path)
    parser.add_argument('--extra-manifest', type=Path, action='append', default=[])
    parser.add_argument('--label')
    args = parser.parse_args()
    if args.namespace_worker: return worker(args.namespace_worker)
    assert os.getuid() != 0 and args.label and all(c.isalnum() or c in '-_' for c in args.label)
    projection = json.loads(args.projection.read_text()); base = R/projection['base']['path']
    assert sha(base) == projection['base']['sha256']
    packages = json.loads(args.package_report.read_text())['packages'] + [json.loads(args.integration_manifest.read_text())['package']]
    for extra in args.extra_manifest:
        data = json.loads(extra.read_text()); packages.extend(data['packages'] if 'packages' in data else [data['package']])
    for item in packages:
        for field, key in [('Package','name'),('Version','version'),('Architecture','architecture')]:
            value = subprocess.check_output(['dpkg-deb','--field',str(R/item['path']),field],text=True).strip()
            assert key not in item or item[key] == value, (key,item,value)
            item[key] = value
    work = R/'build/asus-runtime-projection'/args.label; assert not work.exists(); work.mkdir()
    target = R/'build/ubuntu26-rootfs'/('ubuntu26-bcm-' + args.label + '.tar'); assert not target.exists()
    with tarfile.open(base) as archive:
        base_entries = {}; base_hashes = {}
        for member in archive:
            name = canonical(member.name); base_entries[name] = member
            if member.isfile():base_hashes[name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    owned = {}; owned_by = {}; directories = {}; metadata_overlaps = []; functional_overlaps = []; shared_multiarch = []; directory_repairs={}
    for item in packages:
        path = R/item['path']; assert sha(path) == item['sha256']
        multiarch = subprocess.check_output(['dpkg-deb','--field',str(path),'Multi-Arch'],text=True).strip()
        controls = subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(path)])
        with tarfile.open(fileobj=io.BytesIO(controls)) as archive:
            controls_allowed = {'control','md5sums','conffiles'}
            if item['name'] == 'leon-bcm-rootfs-config' and item['version'] == '0.3':
                assert item['sha256'] == 'e033908b8cd78a7b0e5789f26e2216437001aef8a3d16b90346b40f507162c26'
                controls_allowed.add('postinst') # Exact unchanged architecture-check/registration script.
            if item['name'] == 'leon-gcc15-runtime' and item['version'] == '15.2.0-0leonb53.2':
                assert item['sha256'] == '95e8f87cb419232ecaa8da6da87be09f04ace003ca79e32895f6cb07e19597fc'
                controls_allowed.update(['shlibs','triggers']) # Existing libc-bin ldconfig activation only.
            if item['name']=='sudo' and item['version']=='1.9.17p2-1ubuntu3.1':
                assert item['sha256']=='7f14a53b18b28abe8ea529aa68e17d4dabe0dc2572561b3872f9da79a1e7a459'
                controls_allowed.update(['preinst','postinst','prerm','postrm','shlibs','triggers'])
            assert {canonical(x.name) for x in archive if not x.isdir()} <= controls_allowed
        raw = subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(path)])
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for member in archive:
                name = canonical(member.name)
                if name == '.': continue
                assert member.uid == member.gid == 0
                entry = {'path':'/'+name, 'mode':member.mode}
                if member.isdir():
                    assert member.mode == 0o755
                    assert name not in base_entries or base_entries[name].isdir(), name
                    if name in base_entries and base_entries[name].mode==0o775:
                        key=item['name']+(':'+item['architecture'] if item['architecture']!='all' else '')
                        approved=METADATA_UPGRADES.get(key,METADATA_UPGRADES.get(item['name']))
                        if approved and approved[1]==item['version']:
                            assert base_entries[name].uid==base_entries[name].gid==0
                            directory_repairs[name]={'path':'/'+name,'before':'0775','after':'0755','owner_package':key}
                    entry['type']='directory'; directories[name]=entry; continue
                resolver_hashes = {
                    '0.1+asus3006.102.9':'f10629f58deaf98279e201e081a4c9f2f6049de42874e0a2916d069fe7f49f80',
                    '0.2+asus3006.102.9':'45f15865a2113671c1553d10eab30205e3b8983e33caf48c5857582f33c67ba8',
                }
                functional_resolver = (item['name']=='leon-asus-resolver'
                                       and resolver_hashes.get(item['version'])==item['sha256']
                                       and name=='etc/resolv.conf')
                if name in base_entries:
                    key = item['name'] + (':'+item['architecture'] if item['architecture']!='all' else '')
                    approved = METADATA_UPGRADES.get(key, METADATA_UPGRADES.get(item['name']))
                    if functional_resolver:
                        assert base_entries[name].isfile() and base_hashes[name]=='ebdf560272a77357195c39e98340b77e18c8a8ce2025ee950e9e0c7b01467ab8'
                        assert member.issym() and member.linkname=='/run/asus/native-resolv.conf'
                        functional_overlaps.append({'path':'/'+name,'package':key,'old_sha256':base_hashes[name],
                                                    'new_symlink':member.linkname,'reason':'Replace copied nonfunctional127.0.0.53 stub with native exporter-owned resolver; explicitly authorized functional change.'})
                    else:
                        assert approved and approved[1] == item['version'], 'package/base collision: '+name
                        metadata_overlaps.append({'path':'/'+name,'package':key,'version':item['version']})
                if member.isfile():
                    if item['name']=='sudo' and name=='usr/bin/sudo.ws':assert member.mode==0o4755
                    else:assert not member.mode & 0o7022
                    entry.update(type='file', sha256=hashlib.sha256(archive.extractfile(member).read()).hexdigest())
                    if item['name']=='sudo-common' and name=='etc/sudoers':
                        assert item['sha256']=='ba909e8e796115f442d0915ed3baa1b752e8809ec4d8e723d2bbd0d177750d2c'
                        assert member.mode==0o644
                        entry.update(archive_mode=0o644,mode=0o440) # Exact official sudo postinst hardening.
                    if name in base_entries: assert base_entries[name].isfile() and base_hashes[name]==entry['sha256'], name
                else:
                    assert member.issym(); entry.update(type='symlink', link=member.linkname)
                    if name in base_entries and not functional_resolver: assert base_entries[name].issym() and base_entries[name].linkname==member.linkname, name
                    if item['name']=='sudo' and name in ['usr/bin/sudoedit','usr/share/man/man8/sudoedit.8.gz']:
                        entry['archive_link']=entry['link']
                        entry['link']='/etc/alternatives/'+('sudoedit' if name=='usr/bin/sudoedit' else 'sudoedit.8.gz')
                if name in owned:
                    prior = owned_by[name]
                    assert multiarch == prior['multiarch'] == 'same'
                    assert item['name']==prior['name'] and item['version']==prior['version'] and item['architecture']!=prior['architecture']
                    assert entry == owned[name], 'nonidentical Multi-Arch shared payload: '+name
                    shared_multiarch.append({'path':'/'+name,'package':item['name'],'architectures':[prior['architecture'],item['architecture']]})
                else:
                    owned[name]=entry; owned_by[name]={**item,'multiarch':multiarch}
    inputs = Path(tempfile.mkdtemp(prefix='asus-runtime-inputs-')); inputs.chmod(0o755)
    for source in [base, Path(__file__).resolve(), *[R/x['path'] for x in packages]]:
        subprocess.run(['cp','--reflink=auto','--',str(source),str(inputs/source.name)],check=True)
        (inputs/source.name).chmod(0o644); assert sha(source) == sha(inputs/source.name)
    guard = secrets.token_hex(20)
    plan = {'guard':guard, 'namespace_work':'/tmp/asus-runtime-clone-'+guard,
            'base':str(inputs/base.name), 'host_namespaces':ns(),
            'packages':[{**x, 'path':str(inputs/Path(x['path']).name)} for x in packages],
            'archive_entries':[*directories.values(), *owned.values()], 'directory_repairs':list(directory_repairs.values())}
    pp = inputs/'plan.json'; dump(pp,plan); dump(work/'plan.json',plan)
    command = ['mmdebstrap','--unshare-helper',sys.executable,str(inputs/Path(__file__).name),'--namespace-worker',str(pp)]
    start = time.monotonic()
    with (work/'namespace.log').open('w') as log:
        rc = subprocess.run(command,stdout=log,stderr=subprocess.STDOUT).returncode
    gathered = subprocess.run(['mmdebstrap','--unshare-helper','tar','-C',plan['namespace_work'],'-cf','-',
                               'worker-result.json','worker.log','package-manifest.json'],capture_output=True)
    if gathered.stdout:
        with tarfile.open(fileobj=io.BytesIO(gathered.stdout)) as archive:
            for member in archive:
                assert member.isfile() and member.name in ['worker-result.json','worker.log','package-manifest.json']
                (work/member.name).write_bytes(archive.extractfile(member).read())
    result = json.loads((work/'worker-result.json').read_text()) if (work/'worker-result.json').exists() else {'status':'failed'}
    if rc == 0 and result['status']=='built':
        with target.open('wb') as stream:
            subprocess.run(['mmdebstrap','--unshare-helper','cat',plan['namespace_work']+'/candidate-without-dev.tar'],stdout=stream,check=True)
        with tarfile.open(base) as src, tarfile.open(target,'a') as dst:
            for member in src:
                name = canonical(member.name)
                if name == 'dev' or name.startswith('dev/'): dst.addfile(member,src.extractfile(member) if member.isfile() else None)
        result.update(rootfs_tar=str(target.relative_to(R)),rootfs_sha256=sha(target),rootfs_bytes=target.stat().st_size,
                      rootfs={'path':str(target.relative_to(R)), 'sha256':sha(target), 'bytes':target.stat().st_size})
    result.update(schema_version=1,label=args.label,returncode=rc,elapsed_seconds=round(time.monotonic()-start,2),
                  base_rootfs=str(base.relative_to(R)),base_sha256=sha(base),base_unchanged=sha(base)==projection['base']['sha256'],
                  packages=packages,builder_sha256=sha(Path(__file__)),logs=str(work.relative_to(R)),
                  package_collision_audit={'unapproved_non_directory_collisions':[], 'owned_paths':len(owned),'approved_metadata_overlaps':metadata_overlaps,'approved_functional_overlaps':functional_overlaps,'identical_multiarch_shared_paths':shared_multiarch},
                  hardware_or_vendor_main_executed=False,production_ready=False)
    dump(work/'build.json',result)
    print(json.dumps({k:v for k,v in result.items() if k in ['status','error','rootfs_tar','rootfs_sha256','new_packages','installed_entries_checked']},indent=2))
    return rc

if __name__ == '__main__': raise SystemExit(main())

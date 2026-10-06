#!/usr/bin/env python3
"""Package rebuilt ARMEL libraries with Ubuntu ownership and coinstall rules."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

R=Path(__file__).resolve().parents[1];W=R/'build/ubuntu26-armel-runtime-gcc15'
ROOT=Path((W/'chroot-path.txt').read_text().strip());RESULTS=ROOT/'work/results'
OUT=W/'packages';STAGE=W/'package-stage'
GV='16.2.0-3ubuntu1+leonb53.1';CV='2.44-1ubuntu1+leonb53.1'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args):subprocess.run([str(x) for x in args],check=True)
def field(p,name):return subprocess.check_output(['dpkg-deb','-f',str(p),name],text=True).strip()
def update_control(p,updates):
    lines=p.read_text().splitlines();out=[];skip=False
    for line in lines:
        if line and not line.startswith((' ','\t')):
            key=line.split(':',1)[0];skip=key in updates
            if skip:
                if updates[key] is not None:out.append(key+': '+updates[key])
                updates.pop(key)
        if not skip:out.append(line)
    out += [key+': '+val for key,val in updates.items() if val is not None]
    p.write_text('\n'.join(out)+'\n')
def md5s(stage):
    lines=[]
    for p in sorted(stage.rglob('*')):
        if p.is_file() and not p.is_symlink() and 'DEBIAN' not in p.relative_to(stage).parts:
            lines.append(hashlib.md5(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(stage)))
    (stage/'DEBIAN/md5sums').write_text('\n'.join(lines)+'\n')
def build(stage,name,version,arch):
    md5s(stage)
    size=sum(p.stat().st_size for p in stage.rglob('*') if p.is_file() and not p.is_symlink() and 'DEBIAN' not in p.relative_to(stage).parts)
    update_control(stage/'DEBIAN/control',{'Installed-Size':str((size+1023)//1024)})
    out=OUT/f'{name}_{version}_{arch}.deb'
    run(['dpkg-deb','--root-owner-group','-Zxz','-z6','--build',stage,out]);return out
def inventory(stage):
    rows={}
    for p in sorted(stage.rglob('*')):
        rel=str(p.relative_to(stage))
        if rel.startswith('DEBIAN/'):continue
        if p.is_symlink():rows[rel]={'kind':'symlink','target':os.readlink(p)}
        elif p.is_file():rows[rel]={'kind':'file','sha256':sha(p)}
    return rows
def shared_check(a,b):
    a=inventory(a);b=inventory(b);shared=sorted(a.keys()&b.keys())
    divergent=[p for p in shared if a[p]!=b[p]]
    assert not divergent,divergent
    return len(shared)
def main():
    os.umask(0o022)
    assert not OUT.exists() and not STAGE.exists(),'Use a fresh staging location; never overwrite accepted packages'
    OUT.mkdir();STAGE.mkdir()
    records=[]
    for package in ['libc6','libc-gconv-modules-extra']:
        inp=RESULTS/'glibc15'/f'{package}_{CV}_armel.deb';s=STAGE/(package+'-armel')
        run(['dpkg-deb','-R',inp,s])
        changes={}
        if package=='libc6':
            # The distribution stage2 build profile skips optional daemon build
            # dependencies, but also suppresses these real runtime Depends.
            # Restore the ordinary library contract before candidate install.
            changes={'Depends':f'libgcc-s1, libc-gconv-modules-extra (= {CV})'}
            update_control(s/'DEBIAN/control',dict(changes))
        native=STAGE/(package+'-native-reference')
        run(['dpkg-deb','-R',R/'build/ubuntu26-glibc/results'/f'{package}_{CV}_arm64.deb',native])
        common=shared_check(s,native)
        out=build(s,package,CV,'armel')
        records.append({'name':package,'architecture':'armel','version':CV,'path':str(out.relative_to(R)),'sha256':sha(out),
                        'build_origin':'Ubuntu glibc dpkg-buildpackage cross build','input_package_sha256':sha(inp),
                        'control_runtime_dependency_repair':changes,'coinstalled_common_files_identical':common})
    package='leon-gcc15-runtime';version='15.2.0-0leonb53.2'
    s=STAGE/package;(s/'DEBIAN').mkdir(parents=True);libdir=s/'usr/lib/arm-linux-gnueabi';libdir.mkdir(parents=True)
    results=RESULTS/'gcc15-runtime'
    cpp=list(results.glob('libstdc++.so.6.0.*'));assert len(cpp)==1
    for src in [results/'libgcc_s.so.1',cpp[0]]:
        shutil.copy2(src,libdir/src.name);(libdir/src.name).chmod(0o644)
        run(['/usr/bin/llvm-strip-18','--strip-unneeded',libdir/src.name])
    (libdir/'libstdc++.so.6').symlink_to(cpp[0].name)
    doc=s/'usr/share/doc'/package;doc.mkdir(parents=True)
    src=ROOT/'work/gcc15-runtime-source/src'
    for n in ['COPYING3','COPYING.RUNTIME']:shutil.copy2(src/n,doc/n)
    (doc/'README').write_text('GCC 15.2 legacy runtime for BCM B53 foreign 32-bit userspace.\n'
      'Rebuilt from authenticated upstream GCC15.2 source, with A53 crypto/CRC and time64 for new code.\n'
      'Native Ubuntu GCC16 libraries retain their own package ownership. This is not a GCC16 ABI provider.\n')
    meta=doc/'build';meta.mkdir()
    (meta/'armel.json').write_text(json.dumps({'source_version':'15.2.0','target':'arm-linux-gnueabi',
      'float_abi':'softfp','source_authentication_sha256':sha(W/'gcc15-source-authentication.json'),
      'compiler_bootstrap_authentication_sha256':sha(W/'gcc15-bootstrap-authentication.json')},indent=2)+'\n')
    (s/'DEBIAN/control').write_text(f"""Package: {package}
Version: {version}
Architecture: armel
Multi-Arch: same
Section: libs
Priority: optional
Maintainer: Leon BCM Project <noreply@localhost>
Depends: libc6 (>= 2.44)
Provides: libgcc-s1 (= {version}), libstdc++6 (= {version})
Conflicts: libgcc-s1:armel, libstdc++6:armel
Replaces: libgcc-s1:armel, libstdc++6:armel
Description: GCC15.2 compatibility runtime for BCM B53 foreign ARM ABI
 Canonical multiarch libgcc and libstdc++ rebuilt from the real GCC15.2
 source for legacy ASUS compatibility. Does not provide GCC16 symbols.
""")
    (s/'DEBIAN/shlibs').write_text(f'libgcc_s 1 {package} (>= {version})\nlibstdc++ 6 {package} (>= {version})\n')
    (s/'DEBIAN/triggers').write_text('activate-noawait ldconfig\n')
    for path in [s,*s.rglob('*')]:
        if not path.is_symlink():path.chmod(0o755 if path.is_dir() else 0o644)
    out=build(s,package,version,'armel')
    records.append({'name':package,'architecture':'armel','version':version,'path':str(out.relative_to(R)),
      'sha256':sha(out),'build_origin':'Fresh GCC15.2 source compilation; no default cross compiler shared runtime copied',
      'virtual_provisions_limited_to_version':version,'canonical_paths':sorted(inventory(s)),
      'native_gcc16_package_ownership_changed':False})
    crypt_stages={'libcrypt1': [], 'libcrypt-dev': []}
    for arch in ['arm64','armel']:
        for package in crypt_stages:
            inp=RESULTS/('libcrypt15-'+arch)/f'{package}_4.5.1-1+leonb53.1_{arch}.deb'
            out=OUT/inp.name;shutil.copy2(inp,out)
            s=STAGE/(package+'-'+arch);run(['dpkg-deb','-R',out,s]);crypt_stages[package].append(s)
            records.append({'name':package,'architecture':arch,'version':field(out,'Version'),'path':str(out.relative_to(R)),
                            'sha256':sha(out),'build_origin':'Ubuntu libxcrypt dpkg-buildpackage; matched runtime and development packages'})
    for package, stages in crypt_stages.items():
        common=shared_check(*stages)
        for row in records:
            if row['name']==package:row['coinstalled_common_files_identical']=common
    report={'schema_version':1,'status':'packaged_not_installed_or_runtime_validated','packages':records,
            'library_prefix':'/usr/lib/arm-linux-gnueabi','merged_usr_loader_entry':'/usr/lib/ld-linux.so.3',
            'armhf_packages':[],'host_packages_modified':False,'router_access':False,
            'gcc_runtime_packaging':'Explicit leon-gcc15-runtime:armel provides only real GCC15.2 ABI in foreign canonical paths. Native GCC16 package names, versions and ownership stay unchanged.'}
    (W/'packages.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()

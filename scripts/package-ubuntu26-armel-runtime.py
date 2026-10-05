#!/usr/bin/env python3
"""Package rebuilt ARMEL libraries with Ubuntu ownership and coinstall rules."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

R=Path(__file__).resolve().parents[1];W=R/'build/ubuntu26-armel-runtime'
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
    policy=json.loads((R/'configs/ubuntu26/compiler-policy.json').read_text())
    if policy['armel']['accepted_runtime_major'] != 16:
        raise SystemExit('ARMEL GCC16 packaging is quarantined by compiler-policy.json; use package-ubuntu26-armel-runtime-gcc15.py')
    assert not (W/'QUARANTINE.json').exists(), 'GCC16 ARM32 batch quarantined; use GCC15 driver and package policy'
    assert not OUT.exists() and not STAGE.exists(),'Use a fresh staging location; never overwrite accepted packages'
    OUT.mkdir();STAGE.mkdir()
    records=[]
    for package in ['libc6','libc-gconv-modules-extra']:
        inp=RESULTS/'glibc'/f'{package}_{CV}_armel.deb';s=STAGE/(package+'-armel')
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
    for package,lib in [('gcc-16-base',None),('libgcc-s1','libgcc_s.so.1'),('libstdc++6','libstdc++')]:
        native_deb=R/'build/ubuntu26-gcc/packages'/f'{package}_{GV}_arm64.deb'
        s=STAGE/(package+'-armel');native=STAGE/(package+'-native-reference')
        run(['dpkg-deb','-R',native_deb,s]);run(['dpkg-deb','-R',native_deb,native])
        update_control(s/'DEBIAN/control',{'Architecture':'armel'})
        if lib:
            libdir=s/'usr/lib/aarch64-linux-gnu';assert libdir.exists();shutil.rmtree(libdir)
            libdir=s/'usr/lib/arm-linux-gnueabi';libdir.mkdir()
            if package=='libstdc++6':
                found=list((RESULTS/'gcc-runtime').glob('libstdc++.so.6.0.*'));assert len(found)==1;lib=found[0].name
                gdb=s/'usr/share/gdb/auto-load/usr/lib/aarch64-linux-gnu'
                if gdb.exists():
                    target=gdb.with_name('arm-linux-gnueabi');gdb.rename(target)
                    for item in target.iterdir():
                        item.write_text(item.read_text().replace('aarch64-linux-gnu','arm-linux-gnueabi'))
            source=RESULTS/'gcc-runtime'/lib;assert source.is_file();shutil.copy2(source,libdir/lib);(libdir/lib).chmod(0o644)
            run(['arm-linux-gnueabi-strip' if shutil.which('arm-linux-gnueabi-strip') else '/usr/bin/llvm-strip-18','--strip-unneeded',libdir/lib])
            if package=='libstdc++6':(libdir/'libstdc++.so.6').symlink_to(lib)
            depends=f'gcc-16-base (= {GV}), libc6 (>= 2.44)'
            if package=='libstdc++6':depends+=f', libgcc-s1 (>= {GV})'
            update_control(s/'DEBIAN/control',{'Depends':depends})
            # These symbols are audited from the new ARM binary; do not ship
            # AArch64 symbol tables or claim unsupported historic minimums.
            for name in ['symbols','shlibs']:
                (s/'DEBIAN'/name).unlink(missing_ok=True)
            soname,abi=('libgcc_s','1') if package=='libgcc-s1' else ('libstdc++','6')
            (s/'DEBIAN/shlibs').write_text(f'{soname} {abi} {package} (>= {GV})\n')
        common=shared_check(s,native)
        out=build(s,package,GV,'armel')
        records.append({'name':package,'architecture':'armel','version':GV,'path':str(out.relative_to(R)),'sha256':sha(out),
                        'build_origin':'Fresh GCC16 ARMEL runtime compilation; native package is common-doc/control template only',
                        'native_template_sha256':sha(native_deb),'coinstalled_common_files_identical':common})
    crypt_stages=[]
    for arch in ['arm64','armel']:
        inp=RESULTS/('libcrypt-'+arch)/f'libcrypt1_4.5.1-1+leonb53.1_{arch}.deb'
        out=OUT/inp.name;shutil.copy2(inp,out)
        s=STAGE/('libcrypt1-'+arch);run(['dpkg-deb','-R',out,s]);crypt_stages.append(s)
        records.append({'name':'libcrypt1','architecture':arch,'version':field(out,'Version'),'path':str(out.relative_to(R)),
                        'sha256':sha(out),'build_origin':'Ubuntu libxcrypt dpkg-buildpackage; obsolete glibc API explicitly retained'})
    common=shared_check(*crypt_stages)
    for row in records:
        if row['name']=='libcrypt1':row['coinstalled_common_files_identical']=common
    report={'schema_version':1,'status':'packaged_not_installed_or_runtime_validated','packages':records,
            'library_prefix':'/usr/lib/arm-linux-gnueabi','merged_usr_loader_entry':'/usr/lib/ld-linux.so.3',
            'armhf_packages':[],'host_packages_modified':False,'router_access':False,
            'gcc_runtime_packaging':'Library-only local packaging derived from same-version native Ubuntu package metadata/common docs; no ARM compiler package is claimed.'}
    (W/'packages.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Read BE98 toolchain artifacts and query compilers; never rebuild/install them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from datetime import datetime, timezone

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--be98-root', type=Path, required=True)
p.add_argument('--output', type=Path, default=Path('reports/ubuntu26/toolchain-audit.json'))
a = p.parse_args()
root = a.be98_root.resolve()

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def ref(name):
    q=root/name
    return {'path':str(q),'sha256':sha(q),'bytes':q.stat().st_size}

def run(argv,env=None,stdin=None):
    r=subprocess.run(argv,input=stdin,capture_output=True,text=True,env=env,timeout=30)
    return {'command':argv,'returncode':r.returncode,'stdout':r.stdout.strip(),'stderr':r.stderr.strip()}

m=root/'multiarch-loader-20260916'
report={
 'schema_version':1,'date':datetime.now(timezone.utc).date().isoformat(),
 'scope':'Local read-only BE98 source/artifact inspection and compiler/loader metadata queries. No device access, compiler rebuild, package install, runtime replacement, Git mutation or hardware acceptance.',
 'status':'audit_complete; distro-packaged toolchain rebuild and BE19000AI userspace acceptance pending',
 'source_root':str(root),
 'verified_upstream_release_targets':{
  'checked_on':'2026-10-04',
  'gcc':{'version':'16.2.0','release_date':'2026-08-07','source':'https://gcc.gnu.org/gcc-16/'},
  'glibc':{'version':'2.44','release_date':'2026-07-25','source':'https://sourceware.org/glibc/'},
  'binutils':{'version':'2.47','source':'https://gcc.gnu.org/ftp/binutils/releases/','announcement':'https://sourceware.org/pipermail/binutils/2026-July/150520.html'},
  'limitation':'Official release pages/index checked; downloaded release signatures and current stable-branch head must be verified/pinned again when building. Existing pinned glibc commit is not claimed to include all subsequent stable-branch fixes.'},
 'compilers':{},'reusable_glibc':{},'reference_artifacts':[],
 'cpu_policy':json.loads(Path('configs/b53-userspace-targets.json').read_text())['userspace_targets']}
for abi in ['aarch64','armel','armhf']:
    config=json.loads((m/'builds'/abi/'configuration.json').read_text())
    cc=shlex.split(config['cc']); env=dict(os.environ)
    for k in ['LD_LIBRARY_PATH','LD_PRELOAD','CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','LIBRARY_PATH','GCC_EXEC_PREFIX']:
        env.pop(k,None)
    if config.get('host_library_dir'):env['LD_LIBRARY_PATH']=config['host_library_dir']
    queries={f:run(cc+[f],env) for f in ['-dumpmachine','-dumpfullversion','-print-multiarch','-print-sysroot','-print-search-dirs','-print-file-name=libgcc_s.so.1','-print-file-name=crt1.o','-print-prog-name=ld']}
    specs=run(cc+['-dumpspecs'],env)
    queries['specs']={'returncode':specs['returncode'],'sha256':hashlib.sha256(specs['stdout'].encode()).hexdigest(),'link':specs['stdout'].split('*link:\n',1)[1].split('\n\n',1)[0] if specs['returncode']==0 else specs['stderr']}
    flags=report['cpu_policy']['arm64' if abi=='aarch64' else abi]['target_flags']
    macros=run(cc+flags+['-dM','-E','-x','c','-'],env,'')
    selected={line.split()[1]:' '.join(line.split()[2:]) for line in macros['stdout'].splitlines() if line.startswith('#define ') and any(t in line.split()[1] for t in ['__ARM_FEATURE_','__ARM_ARCH','__ARM_PCS','__ARM_NEON','__aarch64__','_TIME_BITS','_FILE_OFFSET_BITS'])}
    queries['b53_preprocessor']={'flags':flags,'returncode':macros['returncode'],'macros':selected,'stderr':macros['stderr']}
    if abi != 'aarch64':
        legacy=run(cc+flags+['-U_TIME_BITS','-U_FILE_OFFSET_BITS','-dM','-E','-x','c','-'],env,'')
        queries['legacy_time32_default_override']={'returncode':legacy['returncode'],'time_bits_macro_defined':'#define _TIME_BITS ' in legacy['stdout'],'file_offset_bits_macro_defined':'#define _FILE_OFFSET_BITS ' in legacy['stdout'],'stderr':legacy['stderr']}
    ld=queries['-print-prog-name=ld']['stdout']
    if ld: queries['ld_version']=run([ld,'--version'],env)
    report['compilers'][abi]={'configuration':config,'executable_sha256':sha(Path(cc[0])),'queries':queries}
    stage=m/'builds'/abi/'stage'
    triplet='aarch64-linux-gnu' if abi=='aarch64' else 'arm-linux-gnueabihf' if abi=='armhf' else 'arm-linux-gnueabi'
    loader='ld-linux-aarch64.so.1' if abi=='aarch64' else 'ld-linux-armhf.so.3' if abi=='armhf' else 'ld-linux.so.3'
    candidates=list(stage.rglob(loader)); load=next((x for x in candidates if x.is_file() and not x.is_symlink()),None)
    libc=stage/'lib'/triplet/'libc.so.6'
    g={'stage':str(stage),'triplet':triplet,'loader_abi_entry':'/lib/'+loader,'loader':ref(str(load.relative_to(root))) if load else None,'libc':ref(str(libc.relative_to(root))) if libc.is_file() else None,'configuration':ref(str((m/'builds'/abi/'configuration.json').relative_to(root))),'result':json.loads((m/'builds'/abi/'result.json').read_text()),'deb_package':False,'minimum_kernel':'4.19','default_arm32_time_t_bits':64 if abi=='aarch64' else 32}
    if load:
        cmd=[str(load),'--list-diagnostics']
        if abi!='aarch64': cmd=[shutil.which('qemu-arm') or 'qemu-arm','-cpu','max']+cmd
        diag=run(cmd)
        g['loader_diagnostics']={'command':cmd,'returncode':diag['returncode'],'path_fields':[s for s in diag['stdout'].splitlines() if s.startswith(('dl_dst_lib=','path.system_dirs','version.version='))],'stderr':diag['stderr']}
    report['reusable_glibc'][abi]=g
stagegcc=root/'gcc162-usb/stage/tmp/mnt/JFFS/gcc-16.2.0-usb'
report['gcc16_usb_packaging']={
 'source_archive':ref('gcc162-usb/gcc-16.2.0.tar.xz'),
 'base_version':(root/'gcc162-usb/gcc-16.2.0/gcc/BASE-VER').read_text().strip(),
 'datestamp':(root/'gcc162-usb/gcc-16.2.0/gcc/DATESTAMP').read_text().strip(),
 'release_phase':(root/'gcc162-usb/gcc-16.2.0/gcc/DEV-PHASE').read_text().strip(),
 'build_script':ref('gcc162-usb/build.sh'),'packaging_script':ref('gcc162-usb/package.py'),
 'installed_specs':ref(str((stagegcc/'lib/gcc/aarch64-unknown-linux-gnu/16.2.0/specs').relative_to(root))),
 'installed_specs_excerpt':(stagegcc/'lib/gcc/aarch64-unknown-linux-gnu/16.2.0/specs').read_text().split('*link:\n',1)[1].split('\n\n',1)[0],
 'not_ubuntu_ready':['prefix /tmp/mnt/JFFS/gcc-16.2.0-usb','target aarch64-unknown-linux-gnu; -print-multiarch is empty','sysroot /opt, native headers /include','package.py redirects interpreter to /opt/lib/ld-linux-aarch64.so.1 and embeds USB lib64 plus /opt/lib rpaths','no dpkg ownership, dependencies, triggers, or Ubuntu package split'],
 'reuse':'Source archive, B53 flags, test programs, and build lessons are reusable; do a fresh distro-layout build rather than copying the staged USB compiler.'}
for name in [
 'usrmerge-20260915/README.md','usrmerge-20260915/scripts/merge-rootfs.py',
 'runtime-dirs-20260915/README.md','armel-multiarch-20260915/README.md',
 'armel-multiarch-20260915/evidence/toolchain-verification.json',
 'multiarch-loader-20260916/README.md','multiarch-loader-20260916/configs/glibc-source.json',
 'multiarch-loader-20260916/patches/ubuntu-multiarch-glibc244.patch',
 'multiarch-loader-20260916/scripts/build-glibc.py',
 'multiarch-loader-20260916/evidence/ubuntu-reference.json',
 'multiarch-loader-20260916/evidence/qemu-final.json',
 'multiarch-loader-20260916/flash/evidence/live-summary.json',
 'multiarch-loader-20260916/packages/runtime-manifest.json',
 'libgcc-runtime-20260916/README.md','libgcc-runtime-20260916/packages/runtime-manifest.json']:
    report['reference_artifacts'].append(ref(name))
report['glibc_source']=json.loads((m/'configs/glibc-source.json').read_text())
report['binutils']={
 'prior_build_inputs':'BE98 older ARM32 cross toolchains use Ubuntu 2.42; newer GCC15 cross trees carry Ubuntu binutils 2.46-3ubuntu2. See actual ld query output for executable versions.',
 'target_release':'2.47','local_b53_247_build_found_in_audited_checkpoints':False,
 'plan':'Rebuild official binutils 2.47 with Ubuntu/Debian packaging, AArch64 host flags -O2 -mcpu=cortex-a53+crypto+crc, and separate aarch64-linux-gnu/arm-linux-gnueabi/arm-linux-gnueabihf targets as needed. Enable and package linker plugin/LTO support, shared dependency metadata, zstd support where packaging provides it. Do not infer speedup from flags; benchmark representative links separately.',
 'distinction':'B53 host CFLAGS tune the tools themselves; target ISA defaults and ABI are separate compiler settings. Never use -march=native on the GB10 build host for router binaries.'}
report['ubuntu_layout_contract']={
 'native_architecture':'arm64','optional_foreign_architecture':'armhf',
 'vendor_abi':'armel softfp (not Ubuntu native armel archive support)',
 'usrmerge':{'/bin':'usr/bin','/sbin':'usr/sbin','/lib':'usr/lib'},
 'library_directories':['/usr/lib/aarch64-linux-gnu','/usr/lib/arm-linux-gnueabi','/usr/lib/arm-linux-gnueabihf'],
 'loader_entries':['/lib/ld-linux-aarch64.so.1','/lib/ld-linux.so.3','/lib/ld-linux-armhf.so.3'],
 'private_vendor_plugins':'Retain only audited hardcoded paths as compatibility links or configure/rebuild consumers; BE98 pins cannot be blindly applied to different BE19000AI bytes.',
 'runtime_directories':'BE98 /run -> var/run was an ASUS compatibility shim, not a complete Ubuntu model. Essential Ubuntu needs persistent /etc and /var/lib/dpkg,/var/lib/apt with transient /run; do not inherit ASUS whole-/var tmpfs for package state.',
 'package_ownership':'Every base/toolchain/runtime/vendor file is owned by a .deb or explicitly documented local configuration; never merely copy a libc/toolchain over dpkg-owned files and leave package metadata stale.',
 'armel_repository':'Keep Ubuntu ports entries arch-filtered to supported arm64 and optional armhf. Supply local armel packages from a separately signed project repository; Ubuntu cross packages are SDK payloads, not native armel base packages.'}
report['required_rebuilds']=[
 {'component':'GCC16','required':True,'recipe':'Fresh native arm64 Debian/Ubuntu package build using target aarch64-linux-gnu, prefix /usr, --enable-multiarch, major-version directories and gcc-16/g++-16 entry points. Rebase supported Ubuntu packaging patches onto 16.2.0. Use the real Ubuntu sysroot/header layout and default /lib ABI loader; remove all /opt/USB rpaths. Build separate armel and armhf cross compiler packages if required; AArch64 GCC -m32 does not provide the ARM32 compilers.'},
 {'component':'glibc2.44','required':'Deb packaging required; existing validated source/patches/stages reusable as reference, not an installed-package substitute.','recipe':'Rebase current Ubuntu packaging onto pinned release/2.44 source, retaining known multiarch patches and --enable-kernel=4.19. Build coherent libc6/libc-bin/libc6-dev/locales or minimal needed subset and per-ABI libgcc/libstdc++ packages, preserving maintainer scripts/triggers/shlibs/symbols and Multi-Arch semantics. Test dpkg install/upgrade/remove rules in the offline rootfs.'},
 {'component':'binutils2.47','required':True,'recipe':'New signed-source build and .deb packaging; no completed B53 2.47 artifact was found in audited checkpoints.'}]
report['abi_pitfalls']=[
 'Ubuntu GCC15 ARM32 defaults define _TIME_BITS=64 and _FILE_OFFSET_BITS=64. Earlier BE98 checkpoints cleared them broadly to preserve legacy ABI. Current user policy supersedes that default: new/rebuilt components prefer time64, source bugs are repaired first, and -U is allowed only for a proven individual legacy boundary documented in configs/ubuntu26/layout-profile.json.',
 'armel softfp permits hardware FP/NEON while preserving the soft-float call ABI; do not change vendor calls to hard-float.',
 'Existing kernel9 time64 tests validate the new ARM32 syscall surface, not every syscall required by Ubuntu systemd or every vendor process.',
 'Latest glibc release and kernel minimum are distinct: keep 4.19 fallback assumptions even with backported time64; --enable-kernel=5.1 would assume unrelated newer APIs.',
 'Use one ABI-matched loader/runtime set atomically. Validate cache-disabled and cached resolution, dlopen/plugins, TLS/pthreads, DNS/NSS, crypto and C++ unwinding. Systemd/PID1/vendor service coexistence requires separate QEMU and physical acceptance.'
]
report['documentation']=['https://gcc.gnu.org/install/configure.html','https://www.debian.org/doc/debian-policy/ch-opersys.html','https://packages.ubuntu.com/source/resolute/glibc']
report['required_acceptance']=[
 'gcc-16 -dumpmachine=aarch64-linux-gnu and -print-multiarch=aarch64-linux-gnu; both ARM32 compilers report their own tuples.',
 'Compile/link C, C++, DSO, TLS/pthread, exception-unwind and LTO tests for every installed ABI; verify ELF interpreter, symbols, target ISA, actual dependencies and no /opt/USB absolute paths.',
 'dpkg-shlibdeps and apt dependency solver accept package metadata; matching Multi-Arch:same package versions coinstall without conflicting files; package upgrade maintains loader symlinks/cache.',
 'Existing ASUS binaries, private plugins, web UI, Wi-Fi/Runner/AiMesh and the separate AI-board link pass on the final BE19000AI candidate before deployment.'
]
a.output.parent.mkdir(parents=True,exist_ok=True)
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'report':str(a.output),'compilers':{k:{'version':v['queries']['-dumpfullversion']['stdout'],'tuple':v['queries']['-dumpmachine']['stdout'],'multiarch':v['queries']['-print-multiarch']['stdout'],'b53_flags_rc':v['queries']['b53_preprocessor']['returncode']} for k,v in report['compilers'].items()},'loader_diagnostics':{k:v['loader_diagnostics']['returncode'] for k,v in report['reusable_glibc'].items()}},indent=2))

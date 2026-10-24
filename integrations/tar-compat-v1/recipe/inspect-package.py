#!/usr/bin/env python3
"""Read and copy completed local build artifacts; never install or execute tar."""
import hashlib,json,shutil,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=Path('/tmp/be19000ai-tar-compat-build-v1/work');S=W/'tar-source'
O=R/'build-proof-v1';PK=R/'packages';ST=R/'package-stage'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size}
def run(args):return subprocess.check_output(args,text=True)
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 if O.exists() or PK.exists() or ST.exists():raise RuntimeError('immutable output exists')
 deb=W/'tar_1.35+dfsg-4ubuntu0.4+leonb53.1_arm64.deb'
 if not deb.is_file() or 'binary-only upload' not in (W/'package.log').read_text():raise RuntimeError('packaging not complete')
 O.mkdir();PK.mkdir();ST.mkdir()
 for p in sorted(W.iterdir()):
  if p.name.endswith(('.deb','.buildinfo','.changes')):shutil.copyfile(p,PK/p.name)
 for name in ['build-macro-arity-failure.log','build-resume-declaration.log','package.log','config-before-resume.sha256','config-reused.txt','versions.txt','declared-builddeps.txt','compiler.txt','dependency-plan.txt']:
  p=W/name
  if p.exists():shutil.copyfile(p,O/name)
 for name in ['config.log','config.h','config.status']:
  shutil.copyfile(S/name,O/name)
 subprocess.run(['dpkg-deb','-x',str(PK/deb.name),str(ST)],check=True)
 exe=ST/'usr/bin/tar'
 outputs={}
 for name,args in [('elf-header',['readelf','-Wh',str(exe)]),('elf-program',['readelf','-Wl',str(exe)]),('elf-dynamic',['readelf','-Wd',str(exe)]),('elf-symbols',['readelf','-Ws',str(exe)]),('elf-versions',['readelf','-WV',str(exe)]),('unstripped-symbols',['nm','-an',str(S/'src/tar')]),('libgnu-members',['ar','t',str(S/'gnu/libgnu.a')]),('package-control',['dpkg-deb','-f',str(PK/deb.name)])]:
  text=run(args);(O/(name+'.txt')).write_text(text);outputs[name]=text
 cfg=(S/'config.log').read_text();header=(S/'config.h').read_text()
 assert 'ac_cv_func_openat2=no' in cfg and "HAVE_OPENAT2='0'" in cfg
 assert '/* #undef HAVE_OPENAT2 */' in header
 assert 'libgnu_a-openat2.o' in outputs['libgnu-members']
 assert any(line.endswith(' openat2') and (' T ' in line or ' t ' in line) for line in outputs['unstripped-symbols'].splitlines())
 assert not any('UND' in line and 'openat2' in line for line in outputs['elf-symbols'].splitlines())
 assert 'AArch64' in outputs['elf-header']
 upstream=[]
 with tarfile.open(R/'source-inputs/tar_1.35+dfsg-4ubuntu0.4.debian.tar.xz') as tf:
  for m in tf:
   if m.isfile() and m.name.startswith('debian/patches/'):
    b=tf.extractfile(m).read();p=R/'source'/m.name
    if m.name.endswith('/series'):
     assert p.read_bytes()==b+b'leon-openat2-legacy-declaration.patch\n'
    else:assert p.read_bytes()==b
    upstream.append({'path':m.name,'official_sha256':hashlib.sha256(b).hexdigest(),'unchanged':not m.name.endswith('/series'),'series_append_only':m.name.endswith('/series')})
 report={'schema':1,'status':'built_not_deployed','package':ref(PK/deb.name),'tar_elf':ref(exe),'packages':[ref(p) for p in sorted(PK.glob('*.deb'))],'buildinfo':[ref(p) for p in sorted(PK.glob('*.buildinfo'))],'config':{'cached_function_no':True,'HAVE_OPENAT2_false':True,'replacement_archive_member':True,'final_openat2_defined_in_executable':True,'no_libc_openat2_import':True},'official_patch_members':upstream,'downstream_declaration_patch':ref(R/'source/debian/patches/leon-openat2-legacy-declaration.patch'),'rules':ref(R/'source/debian/rules'),'fallback_source':ref(R/'source/gnu/openat2.c'),'logs':[ref(p) for p in sorted(O.iterdir()) if p.is_file()],'attempt_history':['clone source visibility failure before compiler','declared dependencies installed; dpkg build-essential metapackage preflight stopped before source compiler','root configure refused; retained refusal','nonroot configure successful; first source compile failed on existing backport macro arity','one-character reviewed declaration correction; configured make succeeded','dpkg -nc packaging unexpectedly re-ran configure because empty debhelper stamp lacked package names; recorded, source unchanged'],'upstream_test_suite_run':False,'focused_fixture_pending':True,'kernel_or_glibc_rebuilt':False,'device_access':False}
 (O/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'manifest':ref(O/'manifest.json'),'package':report['package'],'tar_elf':report['tar_elf']}))
if __name__=='__main__':main()

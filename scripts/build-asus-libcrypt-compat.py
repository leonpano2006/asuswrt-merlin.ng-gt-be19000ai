#!/usr/bin/env python3
"""Rebuild a diagnostic armel libcrypt compatibility candidate, never deploy it.

Uses the pinned libxcrypt source and reference GCC15/glibc2.44 SDK. This is
not final Ubuntu package tooling or proof that ASUS services run correctly.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from elftools.elf.elffile import ELFFile

R = Path(__file__).resolve().parents[1]
B = Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100')
W = R / 'build/asus-libcrypt-compat'
OLD = R / 'build/kernel9-ui1-rootfs/lib/libcrypt.so.1'
SDK_HEADER = Path('/home/leonpano/br-sdk/focal-sdks/br-arm/output/host/arm-buildroot-linux-gnueabi/sysroot/usr/include/crypt.h')
ARCHIVE = B / 'systemd-lab-20260916/downloads/libxcrypt-4.4.38.tar.gz'
ARCHIVE_SHA = '9fb45586b2e83727934fbe046a4fef4804017577f1d048f91d56d0d830a5a98e'
OLD_SHA = '50efa54b898167e3bfbf2673c2f682a74ddc455e686328839d79915d0ca422c5'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def inspect_elf(path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        versions = {0: 'local', 1: 'global'}
        section = elf.get_section_by_name('.gnu.version_d')
        if section:
            for version, aux in section.iter_versions():
                versions[version['vd_ndx']] = next(aux).name
        section = elf.get_section_by_name('.gnu.version_r')
        if section:
            for _, aux in section.iter_versions():
                for item in aux:
                    versions[item['vna_other']] = item.name
        vs = elf.get_section_by_name('.gnu.version')
        exports, imports = {}, []
        symbols = elf.get_section_by_name('.dynsym')
        for i, symbol in enumerate(symbols.iter_symbols()):
            index = vs.get_symbol(i)['ndx'] if vs else 1
            if isinstance(index, str):
                index = {'VER_NDX_GLOBAL': 1, 'VER_NDX_LOCAL': 0}[index]
            version = versions[index & 0x7fff]
            name = symbol.name + '@' + version
            if symbol['st_shndx'] == 'SHN_UNDEF':
                if symbol.name:
                    imports.append(name)
                continue
            if symbol['st_info']['bind'] not in ('STB_GLOBAL', 'STB_WEAK', 'STB_GNU_UNIQUE', 'STB_LOOS'):
                continue
            if symbol['st_other']['visibility'] not in ('STV_DEFAULT', 'STV_PROTECTED'):
                continue
            kind = symbol['st_info']['type']
            if kind in ('STT_FUNC', 'STT_GNU_IFUNC', 'STT_LOOS'):
                kind = 'FUNCTION'
            exports[name] = {'type': kind, 'binding': symbol['st_info']['bind'],
                             'visibility': symbol['st_other']['visibility'],
                             'hidden_version': bool(index & 0x8000),
                             'object_size': symbol['st_size'] if kind in ('STT_OBJECT', 'STT_TLS') else None}
        tags = list(elf.get_section_by_name('.dynamic').iter_tags())
        return {'elf_class': elf.elfclass, 'machine': elf.header['e_machine'],
                'float_abi_flags': elf.header['e_flags'] & 0x600,
                'soname': [t.soname for t in tags if t.entry.d_tag == 'DT_SONAME'],
                'needed': [t.needed for t in tags if t.entry.d_tag == 'DT_NEEDED'],
                'rpath_runpath': [str(t) for t in tags if t.entry.d_tag in ('DT_RPATH', 'DT_RUNPATH')],
                'exports': exports, 'imports': sorted(imports)}


NATIVE_PROBE = r'''#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <crypt.h>
_Static_assert(sizeof(time_t)==8 && sizeof(off_t)==8,"time64/off64 required");
_Static_assert(sizeof(struct crypt_data)==32768,"unexpected libxcrypt structure");
static const char *des="abJnggxhB/yWI", *md5="$1$salt$qJH7.N4xYta3aEG/dfqo/0";
int main(void) {
 struct { unsigned long before; struct crypt_data data; unsigned long after; } box;
 memset(&box,0,sizeof(box)); box.before=0x19790611UL;box.after=0x10203040UL;
 char *p=crypt("password","ab");assert(p && !strcmp(p,des));
 p=crypt("password","$1$salt$");assert(p && !strcmp(p,md5));
 p=crypt_r("password","ab",&box.data);assert(p && !strcmp(p,des));
 p=crypt_r("password","$1$salt$",&box.data);assert(p && !strcmp(p,md5));
 assert(box.before==0x19790611UL && box.after==0x10203040UL);
 printf("LAB_ASUS_LIBCRYPT_NEW_HEADER_SIZE=%zu TIME_T=%zu OFF_T=%zu\n",sizeof(box.data),sizeof(time_t),sizeof(off_t));
 puts("LAB_ASUS_LIBCRYPT_DES_MD5_TIME64_PASS");return 0;
}
'''


LEGACY_PROBE = r'''#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include "vendor-crypt.h"
_Static_assert(sizeof(time_t)==8 && sizeof(off_t)==8,"time64/off64 required");
_Static_assert(sizeof(struct crypt_data)==131228,"unexpected SDK crypt_data");
_Static_assert(offsetof(struct crypt_data,initialized)==131224,"SDK initialized offset changed");
extern char *old_crypt(const char *,const char *);
extern char *old_crypt_r(const char *,const char *,struct crypt_data *);
extern char *old_fcrypt(const char *,const char *);
extern void old_setkey(const char *);
extern void old_encrypt(char *,int);
extern void old_setkey_r(const char *,struct crypt_data *);
extern void old_encrypt_r(char *,int,struct crypt_data *);
__asm__(".symver old_crypt,crypt@GLIBC_2.4");
__asm__(".symver old_crypt_r,crypt_r@GLIBC_2.4");
__asm__(".symver old_fcrypt,fcrypt@GLIBC_2.4");
__asm__(".symver old_setkey,setkey@GLIBC_2.4");
__asm__(".symver old_encrypt,encrypt@GLIBC_2.4");
__asm__(".symver old_setkey_r,setkey_r@GLIBC_2.4");
__asm__(".symver old_encrypt_r,encrypt_r@GLIBC_2.4");
static const char *des="abJnggxhB/yWI", *md5="$1$salt$qJH7.N4xYta3aEG/dfqo/0";
static void bits(char out[64],const unsigned char in[8]) {
 for(int i=0;i<64;i++)out[i]=(in[i/8]>>(7-i%8))&1;
}
int main(void) {
 struct { uint32_t before[4]; struct crypt_data data; uint32_t after[4]; } box;
 memset(&box,0,sizeof(box));for(int i=0;i<4;i++)box.before[i]=box.after[i]=0x19470611;
 char *p=old_crypt("password","ab");assert(p && !strcmp(p,des));
 p=old_crypt("password","$1$salt$");assert(p && !strcmp(p,md5));
 p=old_fcrypt("password","ab");assert(p && !strcmp(p,des));
 p=old_crypt_r("password","ab",&box.data);assert(p && !strcmp(p,des));
 assert((uintptr_t)p>=(uintptr_t)&box.data && (uintptr_t)p<(uintptr_t)(&box.data+1));
 p=old_crypt_r("password","$1$salt$",&box.data);assert(p && !strcmp(p,md5));
 assert((uintptr_t)p>=(uintptr_t)&box.data && (uintptr_t)p<(uintptr_t)(&box.data+1));
 /* Also exercise callers that set only the legacy initialized member,
    despite the exact SDK header requiring the full object zeroed. */
 memset(&box.data,0xa5,sizeof(box.data));box.data.initialized=0;
 const char *salts[]={"ab","cd","$1$salt$"};
 const char *answers[]={"abJnggxhB/yWI","cdlRbNJGImptk","$1$salt$qJH7.N4xYta3aEG/dfqo/0"};
 for(int round=0;round<6;round++)for(int s=0;s<3;s++) {
   p=old_crypt_r("password",salts[s],&box.data);assert(p && !strcmp(p,answers[s]));
   assert((uintptr_t)p>=(uintptr_t)&box.data && (uintptr_t)p<(uintptr_t)(&box.data+1));
   for(int i=0;i<4;i++)assert(box.before[i]==0x19470611 && box.after[i]==0x19470611);
 }
 const unsigned char *poison=(const unsigned char *)&box.data;
 for(size_t i=32768;i<offsetof(struct crypt_data,initialized);i++)assert(poison[i]==0xa5);
 assert(box.data.initialized==0);
 puts("LAB_ASUS_LIBCRYPT_POISON_INITIALIZED_ONLY_PASS");
 /* Standard DES known-answer test, plus decrypt roundtrip. Not just a
    roundtrip, so no-op/ENOSYS legacy stubs cannot accidentally pass. */
 const unsigned char key_bytes[8]={0x13,0x34,0x57,0x79,0x9b,0xbc,0xdf,0xf1};
 const unsigned char plain_bytes[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
 const unsigned char cipher_bytes[8]={0x85,0xe8,0x13,0x54,0x0f,0x0a,0xb4,0x05};
 char key[64],plain[64],expected[64],block[64];
 bits(key,key_bytes);bits(plain,plain_bytes);bits(expected,cipher_bytes);memcpy(block,plain,64);
 errno=0;old_setkey(key);assert(errno!=ENOSYS);old_encrypt(block,0);assert(errno!=ENOSYS && !memcmp(block,expected,64));
 old_encrypt(block,1);assert(!memcmp(block,plain,64));
 memset(&box.data,0,sizeof(box.data));memcpy(block,plain,64);
 errno=0;old_setkey_r(key,&box.data);assert(errno!=ENOSYS);old_encrypt_r(block,0,&box.data);
 assert(errno!=ENOSYS && !memcmp(block,expected,64));old_encrypt_r(block,1,&box.data);assert(!memcmp(block,plain,64));
 for(int i=0;i<4;i++)assert(box.before[i]==0x19470611 && box.after[i]==0x19470611);
 /* The compatible library requires only its 32KiB scratch size; the old
    caller's remaining storage is still zero and remains inside canaries. */
 const unsigned char *raw=(const unsigned char *)&box.data;
 for(size_t i=32768;i<sizeof(box.data);i++)assert(raw[i]==0);
 printf("LAB_ASUS_LIBCRYPT_LEGACY_HEADER_SIZE=%zu INITIALIZED_OFFSET=%zu TIME_T=%zu OFF_T=%zu\n",sizeof(box.data),offsetof(struct crypt_data,initialized),sizeof(time_t),sizeof(off_t));
 puts("LAB_ASUS_LIBCRYPT_GLIBC24_OBSOLETE_ABI_PASS");return 0;
}
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh-probes',action='store_true',help='Rebuild stronger probes against the hash-verified candidate without replacing the library')
    args=parser.parse_args()
    assert sha(ARCHIVE) == ARCHIVE_SHA
    assert sha(OLD) == OLD_SHA
    if args.refresh_probes:
        previous=json.loads((W/'build.json').read_text())
        assert sha(W/'libcrypt.so.1')==previous['candidate']['sha256']
        assert sha(SDK_HEADER)==previous['crypt_data']['sdk_header_sha256']
        saved=W/'build-initial-probes.json'
        if not saved.exists():shutil.copyfile(W/'build.json',saved)
    else:
        assert not W.exists(), 'Keep previous results immutable; select a fresh build revision before rebuilding'
        W.mkdir(parents=True)
    target_file = B / 'a53-runtimes-20260916/configs/build-targets.json'
    target = json.loads(target_file.read_text())['armel']
    env = dict(os.environ, LD_LIBRARY_PATH=target['host_library_dir'], CC=target['cc'],
               CFLAGS='-O2 -g -frecord-gcc-switches -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64',
               LDFLAGS='-Wl,--build-id=sha1', LC_ALL='C', SOURCE_DATE_EPOCH='1791072000')
    commands = json.loads((W/'commands.json').read_text()) if args.refresh_probes else []
    def run(command, cwd=W):
        commands.append({'cwd': str(cwd), 'argv': list(map(str,command))})
        with (W/'build.log').open('ab') as log:
            subprocess.run(list(map(str,command)),cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        write_json(W/'commands.json',commands)
    source_parent=W/'source'
    source=source_parent/'libxcrypt-4.4.38'
    obj=W/'obj'
    stage=W/'stage'
    candidate=W/'libcrypt.so.1'
    if not args.refresh_probes:
        source_parent.mkdir()
        with tarfile.open(ARCHIVE) as archive:
            archive.extractall(source_parent,filter='data')
        assert source.is_dir()
        source_entries={p.relative_to(source).as_posix():sha(p) for p in sorted(source.rglob('*')) if p.is_file()}
        write_json(W/'pristine-source-files.json',source_entries)
        run(['sh','autogen.sh'],source)
        obj.mkdir()
        run([source/'configure','--prefix=/usr','--libdir=/usr/lib/arm-linux-gnueabi',
             '--host=arm-linux-gnueabi','--build=aarch64-linux-gnu','--enable-obsolete-api=yes',
             '--disable-static','--disable-werror'],obj)
        run(['make','-j4'],obj)
        run(['make','DESTDIR='+str(stage),'install'],obj)
        run([target['tools']+'strip','--strip-unneeded','-o',candidate,stage/'usr/lib/arm-linux-gnueabi/libcrypt.so.1'])
    before,after=inspect_elf(OLD),inspect_elf(candidate)
    missing=sorted(set(before['exports'])-set(after['exports']))
    incompatible=[];changes={}
    for name,old in before['exports'].items():
        new=after['exports'].get(name)
        if not new:
            continue
        if old != new:
            changes[name]={'old':old,'new':new}
        if any(old[k]!=new[k] for k in ('type','object_size','visibility')):
            incompatible.append(name+': type/object size/visibility')
        if old['binding']!=new['binding'] and (old['binding'],new['binding'])!=('STB_WEAK','STB_GLOBAL'):
            incompatible.append(name+': binding')
        if old['hidden_version']!=new['hidden_version']:
            default=after['exports'].get(name.split('@')[0]+'@XCRYPT_2.0',{})
            if name not in ('crypt@GLIBC_2.4','crypt_r@GLIBC_2.4') or default.get('hidden_version',True) or default.get('type')!='FUNCTION':
                incompatible.append(name+': version default')
    private=[x for x in after['imports']+list(after['exports']) if x.endswith('@GLIBC_PRIVATE')]
    assert not missing and not incompatible and not private,(missing,incompatible,private)
    assert after['elf_class']==32 and after['machine']=='EM_ARM' and after['float_abi_flags']==0x200
    assert before['soname']==after['soname']==['libcrypt.so.1']
    assert not after['rpath_runpath']
    header=W/'vendor-crypt.h';shutil.copyfile(SDK_HEADER,header)
    probes=[]
    for name,text,include in [('crypt-probe',NATIVE_PROBE,stage/'usr/include'),('crypt-legacy-probe-v2',LEGACY_PROBE,W)]:
        src=W/(name+'.c');src.write_text(text)
        output=W/name
        run([target['cc'],'-O2','-g','-D_TIME_BITS=64','-D_FILE_OFFSET_BITS=64','-I'+str(include),
             src,'-L'+str(W),'-Wl,-rpath-link,'+str(W),'-Wl,-l:libcrypt.so.1','-o',output])
        info=inspect_elf(output)
        assert not info['rpath_runpath']
        expected_markers=(['LAB_ASUS_LIBCRYPT_DES_MD5_TIME64_PASS'] if name=='crypt-probe' else
                          ['LAB_ASUS_LIBCRYPT_POISON_INITIALIZED_ONLY_PASS','LAB_ASUS_LIBCRYPT_GLIBC24_OBSOLETE_ABI_PASS'])
        probes.append({'path':str(output.relative_to(R)),'sha256':sha(output),'source_sha256':sha(src),
                       'needed':info['needed'],'imports':info['imports'],
                       'expected_markers':expected_markers,'runtime_tested':False})
    gcc=subprocess.check_output([target['cc'],'--version'],env=env,text=True).splitlines()[0]
    config=(obj/'config.h').read_text()
    assert '#define ENABLE_OBSOLETE_API_ENOSYS 0' in config
    report={'schema_version':1,'status':'diagnostic compatibility candidate built; target QEMU runtime acceptance pending',
            'source':{'version':'4.4.38','url':'https://codeload.github.com/besser82/libxcrypt/tar.gz/refs/tags/v4.4.38',
                      'archive':str(ARCHIVE),'sha256':ARCHIVE_SHA,'provenance':'cached upstream tag archive, exact hash matches prior source manifest',
                      'pristine_file_inventory':str((W/'pristine-source-files.json').relative_to(R)),
                      'pristine_inventory_sha256':sha(W/'pristine-source-files.json'),'source_patches':[]},
            'compiler':{'version':gcc,'wrapper':target['cc'],'wrapper_sha256':sha(target['cc']),
                        'config_sha256':sha(target_file),'target_flags':target['flags'],'cflags':env['CFLAGS'],
                        'sdk_libc':'reference BE98 glibc2.44; not final Ubuntu libc6:armel',
                        'final_ubuntu_package_compiler':False},
            'vendor':{'path':str(OLD.relative_to(R)),'sha256':OLD_SHA,'elf':before},
            'candidate':{'path':str(candidate.relative_to(R)),'sha256':sha(candidate),'bytes':candidate.stat().st_size,'elf':after},
            'abi':{'old_versioned_exports':len(before['exports']),'missing_exports':missing,
                   'incompatible_export_metadata':incompatible,'allowed_metadata_changes':changes,
                   'glibc_private_references':private,'obsolete_api_enosys_stubs':False,
                   'rule':'All old callable/object exports, versions, visibility and object sizes preserved. Weak-to-global is compatible; crypt and crypt_r retain GLIBC_2.4 aliases with new XCRYPT_2.0 defaults.'},
            'crypt_data':{'sdk_header':str(SDK_HEADER),'sdk_header_sha256':sha(SDK_HEADER),
                          'old_armel_size':131228,'new_size':32768,'old_initialized_offset':131224,
                          'identical_layout':False,'compatibility':'Legacy SDK header explicitly declares internal scratch fields opaque and requires all-zero initialization. GLIBC_2.4 is a direct libxcrypt alias, not a layout translator. The versioned probe tests all-zero and also 0xA5-filled data with only the old initialized member zero, six rounds of three salts/algorithms, known answers, pointer containment and buffer guards. No claim that old internal fields are layout-compatible.',
                          'implementation_source':'lib/crypt.c:234-244 crypt_r calls do_crypt and does not read initialized; do_crypt clears internal scratch after each hash',
                          'unverified_boundary':'Consumers that directly inspect internal fields or mix saved crypt state across implementations require separate audit.'},
            'vendor_direct_crypt_imports':{p:[n for n in inspect_elf(R/'build/kernel9-ui1-rootfs'/p)['imports'] if n.split('@')[0] in ('crypt','crypt_r','fcrypt','encrypt','encrypt_r','setkey','setkey_r')] for p in ('sbin/rc','usr/sbin/httpd','usr/libexec/ledg-node/rc')},
            'probes':probes,'runtime_probe_markers':['LAB_ASUS_LIBCRYPT_DES_MD5_TIME64_PASS','LAB_ASUS_LIBCRYPT_POISON_INITIALIZED_ONLY_PASS','LAB_ASUS_LIBCRYPT_GLIBC24_OBSOLETE_ABI_PASS'],
            'probe_validation_passed':False,'loader_validation_passed':False,
            'runtime_accepted':False,
            'runtime_acceptance_scope':'Full ASUS/Ubuntu integration remains unaccepted; loader and standalone vector/ABI validation are independent narrower gates.',
            'vendor_services_executed':False,'baseline_tree_modified':False,
            'production_deb_built':False,'router_access':False,'hardware_or_flash_operations':False,
            'commands':str((W/'commands.json').relative_to(R)),'build_log_sha256':sha(W/'build.log'),
            'builder_sha256':sha(Path(__file__))}
    write_json(W/'build.json',report)
    write_json(R/'reports/ubuntu26/asus-libcrypt-compat.json',report)
    print(json.dumps({'candidate':report['candidate']['path'],'sha256':report['candidate']['sha256'],
                      'missing_exports':missing,'private_imports':private,'probes':probes},indent=2))


if __name__=='__main__':
    main()

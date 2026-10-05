#!/usr/bin/env python3
"""Install/test/export locally rebuilt GCC packages in their disposable chroot."""
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/ubuntu26-gcc'
CHECK = r'''set -euo pipefail
test -f /work/build-complete
cd /work
packages=()
for p in /work/*.deb; do
    case "$p" in *-dbg_*|*-dbgsym_*|*-doc_*|*-pic_*) continue;; esac
    packages+=("$p")
done
# APT must be allowed to copy local file: packages into its acquisition cache.
# --no-download incorrectly skips that local acquisition on this APT version.
apt-get -y install "${packages[@]}"
dpkg --audit > /work/acceptance-dpkg-audit.txt
test ! -s /work/acceptance-dpkg-audit.txt
mkdir -p /work/acceptance
cd /work/acceptance
test "$(gcc-16 -dumpmachine)" = aarch64-linux-gnu
test "$(gcc-16 -print-multiarch)" = aarch64-linux-gnu
test "$(gcc-16 -dumpfullversion)" = 16.2.0
test "$(g++-16 -print-multiarch)" = aarch64-linux-gnu
gcc-16 -v 2> compiler-configuration.txt
gcc-16 -print-search-dirs > compiler-search-dirs.txt
gcc-16 -dumpspecs > compiler-specs.txt
gcc-16 -Q --help=target > compiler-target-defaults.txt
gcc-16 -dM -E -x c /dev/null > compiler-default-macros.txt
grep -q '^#define __ARM_FEATURE_CRC32 1$' compiler-default-macros.txt
grep -q '^#define __ARM_FEATURE_AES 1$' compiler-default-macros.txt
grep -q '^#define __ARM_FEATURE_SHA2 1$' compiler-default-macros.txt
! grep -E '/opt/|/tmp/mnt/|/work/source' compiler-specs.txt compiler-search-dirs.txt
cat > time64.c <<'EOF'
#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
_Static_assert(sizeof(time_t) == 8, "time64 required");
_Static_assert(sizeof(off_t) == 8, "large files required");
int main(void) {
  struct timespec ts[2]={{4102444800LL,123456789},{4102444800LL,123456789}};
  struct stat st;
  int fd=open("future-file",O_CREAT|O_RDWR|O_TRUNC,0600);
  if(fd<0 || ftruncate(fd,1LL<<33) || futimens(fd,ts) || fstat(fd,&st)) return 1;
  if(st.st_mtim.tv_sec!=4102444800LL || st.st_size!=(1LL<<33)) return 2;
  close(fd); unlink("future-file");
  puts("TIME64_2100_LARGEFILE_PASS"); return 0;
}
EOF
gcc-16 -O2 time64.c -o time64
./time64
cat > tls.cpp <<'EOF'
#include <thread>
#include <stdexcept>
#include <cstdio>
thread_local int value=11;
extern "C" int tls_test(void) {
  int child=0;
  std::thread t([&]{value=23; try {throw std::runtime_error("test");}
    catch(const std::exception&) {child=value;} });
  t.join(); return child==23 && value==11;
}
EOF
cat > dltest.cpp <<'EOF'
#include <dlfcn.h>
#include <cstdio>
int main() { void *h=dlopen("./libtls.so",RTLD_NOW|RTLD_LOCAL); if(!h)return 1;
 auto f=(int(*)())dlsym(h,"tls_test"); if(!f||!f())return 2;
 dlclose(h); puts("CXX_DSO_TLS_THREAD_UNWIND_PASS"); }
EOF
g++-16 -O2 -fPIC -shared -pthread tls.cpp -o libtls.so
g++-16 -O2 -pthread dltest.cpp -ldl -o dltest
./dltest
printf 'int answer(void) {return 42;}\n' > lto-lib.c
printf 'extern int answer(void); int main(void) {return answer()!=42;}\n' > lto-main.c
gcc-16 -O2 -flto -c lto-lib.c -o lto-lib.o
gcc-16 -O2 -flto -c lto-main.c -o lto-main.o
gcc-16 -O2 -flto lto-main.o lto-lib.o -o lto-test
./lto-test
echo LTO_LINK_RUNTIME_PASS
for p in /usr/bin/aarch64-linux-gnu-gcc-16 /usr/libexec/gcc/aarch64-linux-gnu/16/cc1 ./time64 ./dltest ./lto-test; do
    readelf -l "$p" | grep 'Requesting program interpreter: /lib/ld-linux-aarch64.so.1'
    ! readelf -d "$p" | grep -E '\((RPATH|RUNPATH)\)'
done
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > installed-package-manifest.tsv
echo GCC16_UBUNTU_NATIVE_ACCEPTANCE_PASS
'''


def main():
    chroot = Path((WORK / 'chroot-path.txt').read_text().strip())
    entry = ('set -eu; mount --make-rprivate /; mount -t proc proc "$1/proc"; '
             'mount --rbind /dev "$1/dev"; exec chroot "$1" /bin/bash -s')
    command = ['mmdebstrap', '--unshare-helper', '/bin/sh', '-c', entry,
               'gcc-acceptance', str(chroot)]
    with (WORK / 'acceptance.log').open('w') as log:
        result = subprocess.run(command, input=CHECK, text=True, stdout=log,
                                stderr=subprocess.STDOUT)
    report = {
        'source_version': '16.2.0-3ubuntu1',
        'local_version': '16.2.0-3ubuntu1+leonb53.1',
        'build_distribution': 'Ubuntu 26.04 resolute',
        'architecture': 'arm64',
        'flags': '-O2 -mcpu=cortex-a53+crypto+crc',
        'returncode': result.returncode,
        'acceptance_log': str((WORK / 'acceptance.log').relative_to(ROOT)),
        'limitations': [
            'Native host namespace runtime checks; actual kernel9 QEMU runtime is separate.',
            'C/C++ compiler core only; ARM32 cross-compilers not built by this recipe.',
            'Full upstream bootstrap and DejaGNU suite not run for this candidate.',
            'Existing official Ubuntu ARM32 time64 default patch retained in source packaging; no ARM32 runtime acceptance claimed.',
            'No router or host package installation; no firmware deployment.'
        ],
        'packages': []
    }
    if result.returncode == 0:
        out = WORK / 'packages'
        out.mkdir(exist_ok=True)
        listing = subprocess.check_output(['mmdebstrap', '--unshare-helper',
            'chroot', str(chroot), '/bin/sh', '-c', 'cd /work; printf "%s\\n" *.deb'], text=True)
        for name in sorted(listing.splitlines()):
            assert Path(name).name == name and name.endswith('.deb')
            dest = out / name
            with dest.open('wb') as output:
                subprocess.run(['mmdebstrap', '--unshare-helper', 'cat',
                    str(chroot / 'work' / name)], stdout=output, check=True)
            fields = subprocess.check_output(['dpkg-deb', '-f', str(dest),
                                              'Package', 'Version', 'Architecture', 'Depends'], text=True)
            report['packages'].append({'path': str(dest.relative_to(ROOT)),
                'bytes': dest.stat().st_size, 'sha256': hashlib.sha256(dest.read_bytes()).hexdigest(),
                'metadata': fields})
        source_metadata = subprocess.check_output(['mmdebstrap', '--unshare-helper',
            'chroot', str(chroot), '/bin/sh', '-c',
            'cd /work; printf "%s\\n" *.buildinfo *.changes'], text=True)
        for name in source_metadata.splitlines():
            assert Path(name).name == name and '*' not in name
            with (out / name).open('wb') as output:
                subprocess.run(['mmdebstrap', '--unshare-helper', 'cat',
                    str(chroot / 'work' / name)], stdout=output, check=True)
        exported = WORK / 'acceptance-evidence.tar'
        with exported.open('wb') as output:
            subprocess.run(['mmdebstrap', '--unshare-helper', 'tar', '-C',
                str(chroot / 'work'), '-cf', '-', 'acceptance', 'ccache-stats.txt',
                'build-package-manifest.tsv', 'build-dpkg-audit.txt'], stdout=output, check=True)
        with tarfile.open(exported) as archive:
            archive.extractall(WORK, filter='data')
        indexed = {}
        for item in report['packages']:
            item['fields'] = dict(line.split(': ', 1) for line in item['metadata'].splitlines()
                                  if ': ' in line)
            indexed[item['fields']['Package']] = item
        needed = {'gcc-16', 'g++-16'}
        pending = list(needed)
        external = set()
        while pending:
            item = indexed[pending.pop()]
            for dependency in item['fields'].get('Depends', '').split(','):
                dependency = dependency.strip()
                if not dependency:
                    continue
                alternatives = [re.match(r'([a-zA-Z0-9+.-]+)', part.strip())[1]
                                for part in dependency.split('|')]
                local = next((name for name in alternatives if name in indexed), None)
                if local and local not in needed:
                    needed.add(local)
                    pending.append(local)
                elif not local:
                    external.add(dependency)
        install_set = {
            'version': report['local_version'], 'native_architecture': 'arm64',
            'selection': 'Dependency closure of native gcc-16 and g++-16 among this build output.',
            'package_names': sorted(needed),
            'package_paths': [indexed[name]['path'] for name in sorted(needed)],
            'bytes': sum(indexed[name]['bytes'] for name in needed),
            'external_dependencies': sorted(external),
            'installation': 'Install the listed local packages together with apt and their normal external dependencies. Preserve local file acquisition; do not use --no-download.',
            'test_scope': 'The full non-debug/non-documentation candidate selection was installed and tested. The minimal closure is derived from final binary dependency metadata.'
        }
        (ROOT / 'reports/ubuntu26/gcc16-install-set.json').write_text(
            json.dumps(install_set, indent=2) + '\n')
        report.update(
            status='candidate_built_and_native_namespace_acceptance_passed',
            tests=['apt local install/upgrade and dependency solver passed',
                   'dpkg --audit empty', 'gcc/g++ tuple and multiarch aarch64-linux-gnu',
                   'version16.2.0', 'default Cortex-A53 crypto/CRC macros present',
                   '2100-01-01 file timestamps and8GiB sparse file passed',
                   'C++ DSO dlopen/thread_local/std::thread/exception unwind passed',
                   'separate translation unit LTO link/run passed',
                   'standard /lib/ld-linux-aarch64.so.1 ELF interpreters',
                   'no RPATH/RUNPATH in compiler,cc1 or test executables',
                   'no /opt,USB or build sysroot paths in specs/search directories'],
            build_log='build/ubuntu26-gcc/package-build.log',
            ccache_stats='build/ubuntu26-gcc/ccache-stats.txt',
            source_report='reports/ubuntu26/gcc16-source.json',
            install_set='reports/ubuntu26/gcc16-install-set.json')
    path = ROOT / 'reports/ubuntu26/gcc16-build.json'
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()

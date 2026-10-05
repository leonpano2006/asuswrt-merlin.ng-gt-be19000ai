#!/bin/bash
# Run only inside the disposable Ubuntu build namespace after package creation.
set -euo pipefail
export LC_ALL=C.UTF-8 DEBIAN_FRONTEND=noninteractive
cd /work
mkdir -p tests
cd tests
version=2.47-6ubuntu1+leonb53.1
packages=(binutils binutils-common binutils-aarch64-linux-gnu binutils-arm-linux-gnueabi binutils-arm-linux-gnueabihf libbinutils libctf0 libctf-nobfd0 libsframe3 libgprofng0 binutils-dev libsframe-dev libgprofng-dev binutils-for-host)
debs=()
for package in "${packages[@]}"; do debs+=("/work/${package}_${version}_arm64.deb"); done
apt-get -y --no-install-recommends install "${debs[@]}"
dpkg --audit > audit.txt
test ! -s audit.txt
for program in as ld objcopy objdump readelf arm-linux-gnueabi-as arm-linux-gnueabihf-ld; do "$program" --version | head -1; done
/bin/sh /work/source/debian/tests/libc-link
/bin/sh /work/source/debian/tests/shlib-build
cat > a.c <<'C'
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
_Static_assert(sizeof(time_t)==8,"time64");
_Static_assert(sizeof(off_t)==8,"LFS64");
extern int answer(void);
int main(void) { printf("%d %zu %zu\n", answer(), sizeof(time_t), sizeof(off_t)); return answer()!=42; }
C
cat > b.c <<'C'
int answer(void) { return 42; }
C
gcc -O2 -mcpu=cortex-a53+crypto+crc -flto -g -c a.c -o a.o
gcc -O2 -mcpu=cortex-a53+crypto+crc -flto -g -c b.c -o b.o
gcc-ar rcs libb.a b.o
gcc -flto a.o libb.a -o lto-test
./lto-test
objcopy --compress-debug-sections=zstd lto-test lto-test.zstd
readelf -SW lto-test.zstd > compressed-sections.txt
objcopy --decompress-debug-sections lto-test.zstd lto-test.expanded
objcopy --dump-section .debug_info=debug-original.bin lto-test
objcopy --dump-section .debug_info=debug-expanded.bin lto-test.expanded
cmp debug-original.bin debug-expanded.bin
./lto-test.expanded
cat > bfd-test.c <<'C'
#define PACKAGE "leon-binutils-test"
#define PACKAGE_VERSION "0.1"
#include <bfd.h>
#include <stdio.h>
int main(int argc,char **argv) {
 if(argc!=2) return 2;
 bfd_init(); bfd *b=bfd_openr(argv[1],NULL);
 if(!b || !bfd_check_format(b,bfd_object)) return 3;
 printf("BFD target=%s arch=%s\n",bfd_get_target(b),bfd_printable_name(b));
 return !bfd_close(b);
}
C
gcc -O2 -mcpu=cortex-a53+crypto+crc bfd-test.c -o bfd-test -lbfd
./bfd-test lto-test
objdump -d lto-test > disassembly.txt
cat > unwind.cc <<'CXX'
#include <stdexcept>
int main(){try {throw std::runtime_error("B53");}catch(const std::exception&){return 0;} return 1;}
CXX
g++ -O2 -mcpu=cortex-a53+crypto+crc unwind.cc -o unwind
./unwind
cat > exit32.s <<'ASM'
.syntax unified
.arch armv8-a
.text
.global _start
_start:
 mov r0, #0
 mov r7, #1
 svc #0
ASM
for target in arm-linux-gnueabi arm-linux-gnueabihf; do
 "${target}-as" -mcpu=cortex-a53+crypto+crc exit32.s -o "${target}.o"
 "${target}-ld" -e _start "${target}.o" -o "$target.exit"
 "${target}-readelf" -hA "$target.exit" > "$target.elf.txt"
 "${target}-objdump" -d "$target.exit" > "$target.disassembly.txt"
done
ld --verbose > ld-verbose.txt
! grep -E 'SEARCH_DIR\([^)]*(/opt|/tmp/mnt)' ld-verbose.txt
readelf -l lto-test | grep '/lib/ld-linux-aarch64.so.1'
readelf -d /usr/bin/aarch64-linux-gnu-ld.bfd > linker-needed.txt
! grep -E 'RPATH|RUNPATH' linker-needed.txt
ldconfig -p | grep -E 'libbfd-2.47-system|libopcodes-2.47-system|libsframe.so.3'
printf '%s\n' BINUTILS_FUNCTIONAL_TESTS_PASS
# Remove and reinstall optional cross/dev packages: exercises package lifecycle
# without removing the native compiler's dependencies in this build fixture.
apt-get -y remove binutils-arm-linux-gnueabi binutils-arm-linux-gnueabihf binutils-dev libsframe-dev libgprofng-dev
test ! -e /usr/bin/arm-linux-gnueabi-as
test ! -e /usr/bin/arm-linux-gnueabihf-as
test ! -e /usr/include/bfd.h
apt-get -y --no-install-recommends install "${debs[@]}"
dpkg --audit > audit-after-cycle.txt
test ! -s audit-after-cycle.txt
printf '%s\n' BINUTILS_APT_LIFECYCLE_PASS

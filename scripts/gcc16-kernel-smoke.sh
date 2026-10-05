#!/bin/sh
# Run only in the disposable QEMU guest prepared by this repository.
set -eu
test -f /QEMU_LAB_GUEST
test ! -L /run/leon-gcc16-smoke
mkdir -p /run/leon-gcc16-smoke
chmod 700 /run/leon-gcc16-smoke
cd /run/leon-gcc16-smoke

test "$(gcc-16 -dumpmachine)" = aarch64-linux-gnu
test "$(gcc-16 -print-multiarch)" = aarch64-linux-gnu
test "$(gcc-16 -dumpfullversion)" = 16.2.0
test "$(g++-16 -print-multiarch)" = aarch64-linux-gnu
gcc-16 -Q --help=target > target-defaults.txt
gcc-16 -dM -E -x c /dev/null > target-macros.txt
grep -q 'cortex-a53+crypto+crc' target-defaults.txt
grep -q '^#define __ARM_FEATURE_CRC32 1$' target-macros.txt
grep -q '^#define __ARM_FEATURE_AES 1$' target-macros.txt
grep -q '^#define __ARM_FEATURE_SHA2 1$' target-macros.txt
gcc-16 -dumpspecs > compiler-specs.txt
gcc-16 -print-search-dirs > compiler-search-dirs.txt
if grep -E '/opt/|/tmp/mnt/|/work/source' compiler-specs.txt compiler-search-dirs.txt; then
    echo GCC16_UNEXPECTED_PRIVATE_SEARCH_PATH
    exit 1
fi
echo GCC16_UBUNTU_LAYOUT_CPU_PASS

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
    int fd=open("future-file",O_CREAT|O_EXCL|O_RDWR,0600);
    if(fd<0) {perror("open"); return 1;}
    if(ftruncate(fd,1LL<<33) || futimens(fd,ts) || fstat(fd,&st)) {
        perror("time64 file operations"); close(fd); unlink("future-file"); return 2;
    }
    close(fd); unlink("future-file");
    if(st.st_mtim.tv_sec!=4102444800LL || st.st_mtim.tv_nsec!=123456789 ||
       st.st_size!=(1LL<<33)) return 3;
    printf("time_t=%zu off_t=%zu\n",sizeof(time_t),sizeof(off_t));
    puts("GCC16_TIME64_2100_LARGEFILE_PASS"); return 0;
}
EOF
gcc-16 -O2 time64.c -o time64
./time64

cat > tls.cpp <<'EOF'
#include <thread>
#include <stdexcept>
thread_local int value=11;
extern "C" int tls_test(void) {
    int child=0;
    std::thread t([&] {
        value=23;
        try {throw std::runtime_error("unwind-test");}
        catch(const std::exception&) {child=value;}
    });
    t.join();
    return child==23 && value==11;
}
EOF
cat > dltest.cpp <<'EOF'
#include <dlfcn.h>
#include <cstdio>
int main() {
    void *h=dlopen("./libtls.so",RTLD_NOW|RTLD_LOCAL);
    if(!h) {std::puts(dlerror()); return 1;}
    auto f=(int(*)())dlsym(h,"tls_test");
    if(!f || !f()) return 2;
    if(dlclose(h)) return 3;
    std::puts("GCC16_CXX_DSO_TLS_THREAD_UNWIND_PASS");
}
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
echo GCC16_LTO_LINK_RUNTIME_PASS

cc1_path=$(gcc-16 -print-prog-name=cc1)
for program in /usr/bin/aarch64-linux-gnu-gcc-16 "$cc1_path" ./time64 ./dltest ./lto-test; do
    readelf -l "$program" > elf-program.txt
    grep -q 'Requesting program interpreter: /lib/ld-linux-aarch64.so.1' elf-program.txt
    readelf -d "$program" > elf-dynamic.txt
    if grep -E '\((RPATH|RUNPATH)\)' elf-dynamic.txt; then
        echo GCC16_UNEXPECTED_RPATH
        exit 1
    fi
done
readelf -d ./libtls.so > elf-dynamic.txt
if grep -E '\((RPATH|RUNPATH)\)' elf-dynamic.txt; then
    echo GCC16_UNEXPECTED_DSO_RPATH
    exit 1
fi
echo GCC16_STANDARD_LOADER_NO_RPATH_PASS
echo QEMU_GCC16_KERNEL_SMOKE_PASS

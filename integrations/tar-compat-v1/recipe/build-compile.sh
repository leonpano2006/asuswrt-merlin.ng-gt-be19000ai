#!/bin/bash
set -euo pipefail
root=/tmp/be19000ai-tar-compat-build-v1
mount --make-rprivate /
for name in null zero full random urandom tty; do test ! -L "$root/dev/$name"; mount --bind "/dev/$name" "$root/dev/$name"; done
mount -t proc proc "$root/proc"
chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/tar-source
cp /work/build.log /work/build-preflight-missing-meta.log
dpkg-checkbuilddeps -I > /work/declared-builddeps.txt 2>&1
dpkg-query -W -f='${binary:Package}\t${Version}\n' gcc-16 g++-16 make libc6-dev dpkg-dev >> /work/declared-builddeps.txt
make --version | head -1 >> /work/declared-builddeps.txt
gcc-16 --version | head -1 >> /work/declared-builddeps.txt
g++-16 --version | head -1 >> /work/declared-builddeps.txt
export CC='ccache gcc-16' CXX='ccache g++-16' CCACHE_DIR=/work/ccache DEB_BUILD_OPTIONS='nocheck parallel=6'
printf '%s\n' LEON_TAR_REAL_BUILD_STARTED
dpkg-buildpackage -d -b -us -uc > /work/build.log 2>&1
printf '%s\n' LEON_TAR_REAL_BUILD_COMPLETE
BUILD

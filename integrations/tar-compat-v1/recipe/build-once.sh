#!/bin/bash
set -euo pipefail
base=/tmp/be19000ai-asus-native-build-v2
root=/tmp/be19000ai-tar-compat-build-v1
inputs=/home/leonpano/Documents/ChatGPT/asuswrt/tar-compat-v1
mount --make-rprivate /
test ! -e "$root"
mkdir -m0755 "$root"
for name in bin boot dev etc home lib media mnt opt proc root run sbin srv sys tmp usr var; do
    cp -a --reflink=auto "$base/$name" "$root/$name"
done
mkdir -m0755 "$root/work"
cp -a "$inputs/source" "$root/work/tar-source"
chmod 1777 "$root/tmp"
for name in null zero full random urandom tty; do
    test ! -L "$root/dev/$name"
    mount --bind "/dev/$name" "$root/dev/$name"
done
mount -t proc proc "$root/proc"
printf '#!/bin/sh\nexit 101\n' > "$root/usr/sbin/policy-rc.d"
chmod 0755 "$root/usr/sbin/policy-rc.d"
chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cd /work
apt-get -s --no-install-recommends install debhelper dh-exec gettext autoconf automake autopoint bison libacl1-dev libselinux1-dev > dependency-plan.txt
apt-get -y --no-install-recommends install debhelper dh-exec gettext autoconf automake autopoint bison libacl1-dev libselinux1-dev > dependency-install.txt 2>&1
dpkg-query -W -f='${binary:Package}\t${Version}\n' gcc-16 libc6 debhelper dh-exec gettext autoconf automake autopoint bison libacl1-dev libselinux1-dev ccache > versions.txt
gcc-16 --version > compiler.txt
export CC='ccache gcc-16' CXX='ccache g++-16' CCACHE_DIR=/work/ccache DEB_BUILD_OPTIONS='nocheck parallel=6'
cd /work/tar-source
printf '%s\n' LEON_TAR_SINGLE_BUILD_STARTED
dpkg-buildpackage -b -us -uc > /work/build.log 2>&1
printf '%s\n' LEON_TAR_SINGLE_BUILD_COMPLETE
BUILD

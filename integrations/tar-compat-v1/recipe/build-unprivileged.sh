#!/bin/bash
set -euo pipefail
root=/tmp/be19000ai-tar-compat-build-v1
mount --make-rprivate /
for name in null zero full random urandom tty; do test ! -L "$root/dev/$name"; mount --bind "/dev/$name" "$root/dev/$name"; done
mount -t proc proc "$root/proc"
chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
test ! -e /work/tar-source/src/tar
cp /work/build.log /work/build-configure-root-refusal.log
cp /work/tar-source/config.log /work/config-root-refusal.log
if ! getent passwd 1000 >/dev/null; then printf 'leonbuild:x:1000:1000:Disposable build:/work:/bin/bash\n' >> /etc/passwd; fi
if ! getent group 1000 >/dev/null; then printf 'leonbuild:x:1000:\n' >> /etc/group; fi
chown -R 1000:1000 /work
setpriv --reuid=1000 --regid=1000 --clear-groups /bin/bash -s <<'UNPRIV'
set -euo pipefail
cd /work/tar-source
export CC='ccache gcc-16' CXX='ccache g++-16' CCACHE_DIR=/work/ccache DEB_BUILD_OPTIONS='nocheck parallel=6'
printf '%s\n' LEON_TAR_NONROOT_BUILD_STARTED
dpkg-buildpackage -d -b -us -uc > /work/build.log 2>&1
printf '%s\n' LEON_TAR_NONROOT_BUILD_COMPLETE
UNPRIV
BUILD

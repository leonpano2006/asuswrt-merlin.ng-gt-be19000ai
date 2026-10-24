#!/bin/bash
set -euo pipefail
root=/tmp/be19000ai-tar-compat-build-v1
mount --make-rprivate /
for name in null zero full random urandom tty; do test ! -L "$root/dev/$name"; mount --bind "/dev/$name" "$root/dev/$name"; done
mount -t proc proc "$root/proc"
test ! -e "$root/work/build-macro-arity-failure.log"
cp "$root/work/build.log" "$root/work/build-macro-arity-failure.log"
cp -a /tmp/leon-tar-declaration-fix-v1/. "$root/work/tar-source/"
chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
chown -R 1000:1000 /work/tar-source
setpriv --reuid=1000 --regid=1000 --clear-groups /bin/bash -s <<'UNPRIV'
set -euo pipefail
cd /work/tar-source
export CC='ccache gcc-16' CXX='ccache g++-16' CCACHE_DIR=/work/ccache DEB_BUILD_OPTIONS='nocheck parallel=6'
sha256sum config.log config.status config.h > /work/config-before-resume.sha256
make -j6 > /work/build-resume-declaration.log 2>&1
# The configured upstream build has now completed. Full upstream tests are
# intentionally skipped (nocheck); finite extraction/security checks follow.
touch debian/debhelper-build-stamp
dpkg-buildpackage -nc -d -b -us -uc > /work/package.log 2>&1
sha256sum -c /work/config-before-resume.sha256 > /work/config-reused.txt
printf '%s\n' LEON_TAR_PACKAGE_COMPLETE
UNPRIV
BUILD

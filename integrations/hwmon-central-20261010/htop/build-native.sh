#!/bin/bash
set -euo pipefail
export LC_ALL=C PATH=/usr/local/bin:/usr/bin:/bin
stage=$PWD
test "$(id -un)" = MastermixStudios
test "$(git -C /home/MastermixStudios/htop rev-parse HEAD)" = d76b23eeb68515bd9e088a14c98e5c7d658f892f
test -z "$(git -C /home/MastermixStudios/htop status --porcelain)"
test ! -e "$stage/build"
# Reuse all unaffected objects from the accepted first build.
cp -a /var/tmp/leon-htop-bcm-20261010-v1/build "$stage/build"
for name in LinuxMachine.c LibSensors.c LibSensors.h; do
    test ! -L "$stage/build/linux/$name"
    install -m644 "$stage/$name" "$stage/build/linux/$name"
done
rm -f "$stage/build/linux/BcmTelemetry.h"
cd "$stage/build"
nice -n 10 make -j2 htop > "$stage/compile.log" 2>&1
./htop --version
mkdir -p "$stage/pkg/DEBIAN" "$stage/pkg/usr/bin" "$stage/pkg/usr/share/doc/htop-bcm"
cat > "$stage/pkg/DEBIAN/control" <<'EOF'
Package: htop-bcm
Version: 3.6.0~git20261010.d76b23e+leon2
Architecture: arm64
Maintainer: Local BE19000AI build <root@localhost>
Section: utils
Priority: optional
Depends: libc6 (>= 2.38), libcap2 (>= 1:2.10), libncursesw6 (>= 6), libtinfo6 (>= 6), libunwind8, libsensors5 (>= 1:3.6.2), libnl-3-200, libnl-genl-3-200, leon-bcm4916-hwmon
Description: htop with BCM CPU monitoring through libsensors
 Uses standard CPUFreq and proc data first, then libsensors CPU clock data.
 CPU temperatures also use the shared libsensors backend. No private BCM
 interface or privileged polling service is used by this version.
EOF
install -m755 htop "$stage/pkg/usr/bin/htop-bcm"
install -m644 COPYING "$stage/pkg/usr/share/doc/htop-bcm/copyright"
install -m644 "$stage/htop-libsensors-cpu.patch" "$stage/review.txt" "$stage/pkg/usr/share/doc/htop-bcm/"
cat > "$stage/pkg/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ] && [ -f /usr/lib/systemd/system/leon-bcm-telemetry.service ]; then
    systemctl disable --now leon-bcm-telemetry.service
fi
EOF
cat > "$stage/pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
EOF
chmod 755 "$stage/pkg/DEBIAN/preinst" "$stage/pkg/DEBIAN/postinst"
dpkg-deb --root-owner-group -Zgzip -b "$stage/pkg" "$stage/htop-bcm_3.6.0~git20261010.d76b23e+leon2_arm64.deb"
test -z "$(git -C /home/MastermixStudios/htop status --porcelain)"
sha256sum "$stage/htop-bcm_3.6.0~git20261010.d76b23e+leon2_arm64.deb" ./htop
touch "$stage/BUILD_OK"

#!/bin/sh
# Build fresh inside the disposable Ubuntu QEMU guest, never on a router.
set -eu
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" != systemd
test "$(gcc-16 -dumpfullversion)" = 16.2.0
test "$(getconf GNU_LIBC_VERSION)" = 'glibc 2.44'
D=/usr/libexec/leon-lab/asus-bridge
cd "$D"
set -- -std=gnu11 -O2 -g -Wall -Wextra -Werror -mcpu=cortex-a53+crypto+crc \
 -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
 -frecord-gcc-switches -Wl,--build-id=sha1 -Wl,-z,relro,-z,now \
 '-DLEON_RC_DIR="/run/asus-broker-qemu"' -Isrc
gcc-16 "$@" -shared -fPIC src/notify-compat.c src/rc-client.c -ldl \
 -Wl,-soname,libleon-rc-notify.so -o libleon-rc-notify.so
gcc-16 "$@" src/rc-broker.c src/rc-client.c -ldl -o broker-production-not-executed
gcc-16 "$@" -DLEON_RC_OFFLINE_TEST src/rc-broker.c src/rc-client.c -ldl -o broker
gcc-16 "$@" src/rcctl.c src/rc-client.c -ldl -o rcctl
gcc-16 "$@" -DLEON_RC_OFFLINE_TEST mock-backend.c src/rc-client.c src/rc-manager.c \
 -L. -Wl,--no-as-needed -l:libleon-rc-notify.so -Wl,-rpath,'$ORIGIN' -ldl -o mock-backend
# This executable only verifies posix_spawn's child mask/exit status. It is
# not a shell and exists exclusively inside the QEMU fixture.
mkdir -p /usr/libexec/asus
gcc-16 "$@" signal-shell-fixture.c -o /usr/libexec/asus/ash
gcc-16 --version | head -1
getconf GNU_LIBC_VERSION
for f in libleon-rc-notify.so broker-production-not-executed broker rcctl mock-backend; do
 sha256sum "$f"
done
echo LAB_ASUS_BRIDGE_TARGET_BUILD_PASS

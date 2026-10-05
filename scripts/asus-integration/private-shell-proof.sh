#!/bin/sh
set -eu
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
stage=prepare
trap 'rc=$?; echo LAB_ASUS_SHELL_EXIT_code=$rc stage=$stage' EXIT
BB=/usr/libexec/asus/busybox
ASH=/usr/libexec/asus/ash
WORK=/run/leon-shell
mkdir -m 0700 "$WORK"
readlink /bin/sh > "$WORK/sh-link.before"
sha256sum /usr/bin/dash /etc/passwd /etc/shadow /etc/group > "$WORK/global.before"
dpkg-query -W -f='${binary:Package} ${Version}\n' > "$WORK/packages.before"
stage=apt-install
apt-get -y install /root/leon-asus-shell.deb
test "$(dpkg-query -W -f='${db:Status-Status}' leon-asus-shell)" = installed
test "$(stat -c %a "$BB")" = 755
test "$(stat -c %u "$BB")" = 0
test "$(stat -c %a "$ASH")" = 755
"$BB" --list > "$WORK/applets"
cmp "$WORK/applets" /usr/share/doc/leon-asus-shell/applets.txt
test "$(wc -l < "$WORK/applets")" = 162
echo LAB_ASUS_SHELL_APPLETS_PASS
stage=ash-semantics
"$ASH" -c '
 set -eu
 test "$#" = 2
 test "$1" = "a b" && test "$2" = "literal * $"
 [[ "$1" == "a b" ]]
 value=prefix-middle-suffix
 test "${value#prefix-}" = middle-suffix
 test "${value%-suffix}" = prefix-middle
 test "$((7 * 9))" = 63
 test "$(printf "x\ny\n" | /usr/libexec/asus/busybox tail -n 1)" = y
 (exit 17) && exit 99 || test "$?" = 17
 trap "printf trap-ok > /run/leon-shell/trap" EXIT
 (sleep 0.1; printf child-ok > /run/leon-shell/wait) & child=$!
 wait "$child"
' shell-label 'a b' 'literal * $'
test "$(cat "$WORK/trap")" = trap-ok
test "$(cat "$WORK/wait")" = child-ok
echo LAB_ASUS_SHELL_SEMANTICS_PASS
stage=signal-and-large-file
gcc-16 -std=gnu11 -O2 -Wall -Wextra -Werror -mcpu=cortex-a53+crc+crypto -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -I/usr/libexec/leon-lab/shell-src /usr/libexec/leon-lab/shell-src/private-shell-probe.c /usr/libexec/leon-lab/shell-src/rc-manager.c /usr/libexec/leon-lab/shell-src/rc-client.c -ldl -o /usr/libexec/leon-lab/private-shell-probe
/usr/libexec/leon-lab/private-shell-probe
"$BB" ls -ln "$WORK/large-file" > "$WORK/ls-large"
cat "$WORK/ls-large"
test "$(awk '{print $5}' "$WORK/ls-large")" = 5368709120
grep -q 2040 "$WORK/ls-large"
test "$(TZ=UTC "$BB" date -d '2040-01-01 00:00:00' +%s)" = 2208988800
echo LAB_ASUS_SHELL_TIME64_OFF64_PASS
stage=file-and-archive
cd "$WORK"
printf 'c\na\nb\na\n' > source
"$BB" sort source | "$BB" uniq > sorted
printf 'a\nb\nc\n' > expected
"$BB" cmp sorted expected
"$BB" sed 's/b/B/' sorted | "$BB" grep -qx B
"$BB" awk '{n++} END {exit n != 4}' source
"$BB" tar -czf sample.tar.gz source sorted
"$BB" mkdir unpack
"$BB" tar -xzf sample.tar.gz -C unpack
"$BB" cmp source unpack/source
"$BB" cmp sorted unpack/sorted
"$BB" sha256sum source | "$BB" sha256sum -c -
echo LAB_ASUS_SHELL_FILE_APPLETS_PASS
stage=apt-remove-reinstall
apt-get --no-download -y remove leon-asus-shell
test ! -e "$BB"
test ! -e "$ASH"
apt-get -y install /root/leon-asus-shell.deb
"$ASH" -c 'test "$((20 + 22))" = 42'
readlink /bin/sh > "$WORK/sh-link.after"
cmp "$WORK/sh-link.before" "$WORK/sh-link.after"
sha256sum -c "$WORK/global.before"
dpkg-query -W -f='${binary:Package} ${Version}\n' | grep -v '^leon-asus-shell ' > "$WORK/packages.after"
cmp "$WORK/packages.before" "$WORK/packages.after"
dpkg --audit > "$WORK/dpkg-audit"
test ! -s "$WORK/dpkg-audit"
echo LAB_ASUS_SHELL_APT_CYCLE_PASS
echo LAB_ASUS_SHELL_KERNEL10_COMPLETE

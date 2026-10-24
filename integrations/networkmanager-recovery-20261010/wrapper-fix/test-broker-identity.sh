#!/bin/bash
set -euo pipefail
wrapper=/home/leonpano/Documents/ChatGPT/asuswrt/networkmanager-recovery-20261010/wrapper-fix/asus
source <(sed -n '/^broker_fd_secure() {/,/^broker=$(/{ /^broker=$(/!p; }' "$wrapper")
fixture=$(mktemp -d /tmp/asus-wrapper-fd.XXXXXX)
fixture_pid=
cleanup() {
 if [[ -n $fixture_pid ]]; then kill "$fixture_pid" 2>/dev/null || :; wait "$fixture_pid" 2>/dev/null || :; fi
 rm -rf -- "$fixture"
}
trap cleanup EXIT
expect_match() { broker_fds_match "$livefd" "$diskfd"; printf 'PASS %s\n' "$1"; }
expect_reject() {
 if broker_fds_match "$livefd" "$diskfd"; then printf 'FAIL %s\n' "$1" >&2; exit 1; fi
 printf 'PASS %s\n' "$1"
}
cp /usr/bin/sleep "$fixture/broker"
chmod 0755 "$fixture/broker"
"$fixture/broker" 30 & fixture_pid=$!
for ((i=0; i<50; i++)); do
 [[ /proc/$fixture_pid/exe -ef $fixture/broker ]] && break
 sleep 0.02
done
[[ /proc/$fixture_pid/exe -ef $fixture/broker ]]
exec {livefd}< /proc/$fixture_pid/exe
exec {diskfd}< "$fixture/broker"
expect_match same_inode
exec {diskfd}<&-
cp "$fixture/broker" "$fixture/replacement"
mv "$fixture/replacement" "$fixture/broker"
exec {diskfd}< "$fixture/broker"
[[ ! /proc/self/fd/$livefd -ef /proc/self/fd/$diskfd ]]
[[ $(readlink /proc/$fixture_pid/exe) == *' (deleted)' ]]
expect_match identical_replacement_deleted_live_executable
[[ /proc/$fixture_pid/exe -ef /proc/self/fd/$livefd ]]
printf 'PASS pinned_live_identity_survives_replacement\n'
chmod 0775 "$fixture/broker"
expect_reject group_writable_disk
chmod 0757 "$fixture/broker"
expect_reject world_writable_disk
chmod 0755 "$fixture/broker"
chmod 0775 /proc/self/fd/$livefd
expect_reject group_writable_live
chmod 0755 /proc/self/fd/$livefd
exec {diskfd}<&-
cp /usr/bin/true "$fixture/changed"
chmod 0755 "$fixture/changed"
exec {diskfd}< "$fixture/changed"
expect_reject different_executable_bytes
exec {diskfd}<&-
exec {diskfd}< "$fixture"
expect_reject non_regular_file
exec {diskfd}<&-
exec {diskfd}< /usr/bin/sleep
expect_reject non_root_owned_executable
exec {diskfd}<&-
exec {diskfd}< "$fixture/broker"
mkdir "$fixture/bin"
printf '#!/bin/bash\nexit 1\n' > "$fixture/bin/sha256sum"
chmod 0755 "$fixture/bin/sha256sum"
PATH="$fixture/bin:$PATH" expect_reject failed_hash_command

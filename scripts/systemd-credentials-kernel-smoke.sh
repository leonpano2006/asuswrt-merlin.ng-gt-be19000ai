#!/bin/sh
# Bounded credentials regression for the disposable full-system QEMU guest.
set -eu
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
test "$(id -u)" = 0
if test "${1-}" != --lab-run; then
    exec timeout --signal=TERM --kill-after=2s 60s /bin/sh "$0" --lab-run
fi

# Use real base-passwd accounts: systemd needs NSS user records, including
# primary GID/home/shell, even when a numeric User= value is supplied.
main_uid=$(id -u daemon)
other_uid=$(id -u bin)
test "$main_uid" != 0
test "$other_uid" != 0
test "$main_uid" != "$other_uid"
test "$(id -gn daemon)" = daemon
test "$(id -gn bin)" = bin

base=/run/leon-credentials-smoke
main=lab-credentials-main.service
other=lab-credentials-other.service
failed=lab-credentials-failed.service
test ! -e "$base"
test ! -L "$base"
for unit in "$main" "$other" "$failed"; do
    test ! -e "/run/systemd/system/$unit"
    test ! -L "/run/systemd/system/$unit"
    test ! -e "/run/credentials/$unit"
done
mkdir -m 755 "$base"
mkdir -m 700 "$base/input"
mkdir -p /run/systemd/system

cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    systemctl stop "$main" "$other" "$failed" >/dev/null 2>&1 || :
    systemctl reset-failed "$main" "$other" "$failed" >/dev/null 2>&1 || :
    rm -f "/run/systemd/system/$main" "/run/systemd/system/$other" "/run/systemd/system/$failed"
    systemctl daemon-reload >/dev/null 2>&1 || :
    if test "$result" -ne 0; then
        echo LAB_CREDENTIALS_SMOKE_FAIL
        test ! -f "$base/probe.log" || cat "$base/probe.log"
        # Leave this test's small /run evidence directory on failure.
    else
        rm -rf "$base"
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 124' HUP INT TERM

# Temporary random workspace names must disappear, while a pre-existing empty
# parent directory is allowed. Capture only this implementation's staging tree.
snapshot_workspaces() {
    for entry in /run/systemd/temporary-credentials/* \
                 /run/systemd/temporary-credentials/.[!.]* \
                 /run/systemd/temporary-credentials/..?*; do
        if test -e "$entry" || test -L "$entry"; then
            printf 'entry %s\n' "$entry"
        fi
    done
    awk '$5 ~ /^\/run\/systemd\/temporary-credentials(\/|$)/ {print "mount " $5}' /proc/1/mountinfo
}
snapshot_workspaces | LC_ALL=C sort > "$base/workspaces-before"
no_workspace_leak() {
    snapshot_workspaces | LC_ALL=C sort > "$base/workspaces-after"
    cmp "$base/workspaces-before" "$base/workspaces-after"
}
no_unit_leak() {
    cred="/run/credentials/$1"
    test ! -e "$cred"
    test ! -L "$cred"
    awk -v path="$cred" '$5 == path || index($5,path "/") == 1 {bad=1} END {exit bad}' /proc/1/mountinfo
    awk -v path="$cred" '$5 == path || index($5,path "/") == 1 {bad=1} END {exit bad}' /proc/self/mountinfo
}

cat > "$base/probe.sh" <<'EOF'
#!/bin/sh
set -eu
test "$(id -u)" = "$(id -u daemon)"
test "$(id -g)" = "$(id -g daemon)"
test "$(id -u)" != 0
base=/run/leon-credentials-smoke
cred=${CREDENTIALS_DIRECTORY:?credential directory missing}
test "$cred" = /run/credentials/lab-credentials-main.service
expected=$(cat "$base/expected")
test "$(cat "$cred/loaded")" = "$expected"
test "$(cat "$cred/inline")" = inline-dummy
set -- "$cred"/*
test "$#" = 2
for entry in "$cred"/* "$cred"/.[!.]* "$cred"/..?*; do
    if test -e "$entry" || test -L "$entry"; then
        case "$entry" in "$cred/loaded"|"$cred/inline") :;; *) exit 11;; esac
    fi
done
if cat "$base/input/loaded" >/dev/null 2>&1; then exit 12; fi
if cat /run/credentials/lab-credentials-other.service/foreign >/dev/null 2>&1; then exit 13; fi
test "$(stat -f -c %T "$cred")" = ramfs
awk -v path="$cred" '
    $5 == path {
        count++;
        n=split($6,opts,","); for(i=1;i<=n;i++) found[opts[i]]=1;
        for(i=7;i<=NF;i++) if($i=="-") {if($(i+1)!="ramfs") bad=1; break;}
    }
    END {exit !(count==1 && !bad && found["ro"] && found["nodev"] && found["nosuid"] && found["noexec"])}
' /proc/self/mountinfo
if (printf 'changed' > "$cred/loaded") 2>/dev/null; then exit 14; fi
if (printf 'extra' > "$cred/new") 2>/dev/null; then exit 15; fi
if chmod u+w "$cred/loaded" 2>/dev/null; then exit 16; fi
test "$(cat "$cred/loaded")" = "$expected"
printf 'LAB_CREDENTIALS_PROBE_PASS %s\n' "$expected"
EOF
chmod 755 "$base/probe.sh"
printf 'load-dummy-0\n' > "$base/input/loaded"
chmod 600 "$base/input/loaded"
printf 'load-dummy-0\n' > "$base/expected"
chmod 644 "$base/expected"

cat > "/run/systemd/system/$other" <<EOF
[Unit]
Description=Disposable credential isolation control
[Service]
Type=oneshot
RemainAfterExit=yes
User=bin
Group=bin
SetCredential=foreign:other-user-dummy
ExecStart=/usr/bin/true
ExecStop=/usr/bin/true
TimeoutStartSec=8s
TimeoutStopSec=8s
EOF
cat > "/run/systemd/system/$main" <<EOF
[Unit]
Description=Disposable credential legacy mount regression
StartLimitIntervalSec=0
[Service]
Type=oneshot
RemainAfterExit=yes
User=daemon
Group=daemon
LoadCredential=loaded:$base/input/loaded
SetCredential=inline:inline-dummy
ExecStartPre=/bin/sh $base/probe.sh
ExecStart=/bin/sh $base/probe.sh
ExecStop=/usr/bin/true
StandardOutput=append:$base/probe.log
StandardError=append:$base/probe.log
TimeoutStartSec=8s
TimeoutStopSec=8s
EOF
cat > "/run/systemd/system/$failed" <<EOF
[Unit]
Description=Disposable credential failed exec cleanup regression
[Service]
Type=oneshot
User=daemon
Group=daemon
LoadCredential=loaded:$base/input/loaded
SetCredential=inline:inline-dummy
ExecStart=$base/intentionally-missing-executable
TimeoutStartSec=8s
TimeoutStopSec=8s
EOF
systemctl daemon-reload
systemctl start "$other"
test "$(cat "/run/credentials/$other/foreign")" = other-user-dummy
test "$main_uid" != "$other_uid"
no_workspace_leak

round=1
while test "$round" -le 6; do
    printf 'load-dummy-%s\n' "$round" > "$base/input/loaded"
    printf 'load-dummy-%s\n' "$round" > "$base/expected"
    systemctl start "$main"
    test "$(systemctl show -p ActiveState --value "$main")" = active
    test "$(systemctl show -p Result --value "$main")" = success
    test "$(grep -c "^LAB_CREDENTIALS_PROBE_PASS load-dummy-$round\$" "$base/probe.log")" = 2
    # Root's DAC override must not bypass the protected superblock either.
    if (printf 'root-write' > "/run/credentials/$main/loaded") 2>/dev/null; then exit 21; fi
    if chmod 600 "/run/credentials/$main/loaded" 2>/dev/null; then exit 22; fi
    no_workspace_leak
    systemctl stop "$main"
    no_unit_leak "$main"
    no_workspace_leak
    printf 'LAB_CREDENTIALS_ROUND_%s_PASS\n' "$round"
    round=$((round + 1))
done
echo LAB_CREDENTIALS_RAMFS_FLAGS_ACCESS_WRITE_REJECT_PASS

if systemctl start "$failed" > "$base/failed-start.log" 2>&1; then exit 31; fi
test "$(systemctl show -p Result --value "$failed")" = exit-code
test "$(systemctl show -p ExecMainStatus --value "$failed")" = 203
no_unit_leak "$failed"
no_workspace_leak
systemctl stop "$failed"
systemctl reset-failed "$failed"
echo LAB_CREDENTIALS_FAILED_EXEC_CLEANUP_PASS

systemctl stop "$other"
no_unit_leak "$other"
no_workspace_leak
rm -f "/run/systemd/system/$main" "/run/systemd/system/$other" "/run/systemd/system/$failed"
systemctl daemon-reload
for unit in "$main" "$other" "$failed"; do
    no_unit_leak "$unit"
    test "$(systemctl show -p LoadState --value "$unit")" = not-found
done
no_workspace_leak
echo LAB_CREDENTIALS_STOP_REMOVE_CLEANUP_PASS
echo LAB_SYSTEMD_CREDENTIALS_KERNEL_SMOKE_PASS

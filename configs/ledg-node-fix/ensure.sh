#!/bin/sh
# GT-BE19000AI / Merlin 3006.102.9 only. Never change the actual AiMesh role.
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
base=/jffs/ledg-node-fix
lock=/tmp/ledg-node-fix.lock
stock_sha=9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814
fixed_sha=630bf99efe7d014b55dda7e337bf43d80cd5d1f93514c30115b170a96d6e9567

log() { logger -t ledg-node-fix "$*"; }
digest() { sha256sum "$1" | cut -d ' ' -f 1; }
valid_pid() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "$(cat /proc/"$1"/comm 2>/dev/null)" = ledg ]
}
start_stock() {
    (trap '' HUP; exec /sbin/ledg) </dev/null >>/tmp/ledg-node-fix.log 2>&1 &
    log 'Trial failed; restored stock ledg'
}

[ "$(nvram get productid)" = GT-BE19000AI ] || exit 0
[ "$(nvram get re_mode)" = 1 ] || exit 0
[ "$(digest /sbin/rc)" = "$stock_sha" ] || {
    log 'Firmware version changed; leaving stock ledg in control'; exit 0;
}
[ "$(digest "$base/rc")" = "$fixed_sha" ] || {
    log 'Patched executable checksum mismatch; leaving stock ledg in control'; exit 1;
}

attempt=0
until mkdir "$lock" 2>/dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 15 ] || { log 'Another LED update holds the lock'; exit 1; }
    sleep 1
done
trap 'rmdir "$lock" 2>/dev/null' EXIT
trap 'exit 1' HUP INT TERM

pid=$(pidof ledg)
if [ -n "$pid" ]; then
    valid_pid "$pid" || { log 'Unexpected ledg process set; no action'; exit 1; }
    executable=$(readlink /proc/"$pid"/exe)
    [ "$executable" = "$base/rc" ] && exit 0
    case "$executable" in
        /sbin/rc|/tmp/codex-ledg-node-trial/rc) ;;
        *) log 'Unknown ledg executable; no action'; exit 1 ;;
    esac
    kill -TERM "$pid" || exit 1
    attempt=0
    while kill -0 "$pid" 2>/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 6 ] || { log 'Stock ledg did not exit; no duplicate started'; exit 1; }
        sleep 1
    done
fi

# Do not issue service restart_ledg here: that would recursively trigger this hook.
(trap '' HUP; exec "$base/ledg") </dev/null >>/tmp/ledg-node-fix.log 2>&1 &
sleep 1
pid=$(pidof ledg)
if valid_pid "$pid" && [ "$(readlink /proc/"$pid"/exe)" = "$base/rc" ]; then
    log "Patched node LED controller active (pid $pid)"
    exit 0
fi
if [ -z "$pid" ]; then start_stock; fi
exit 1

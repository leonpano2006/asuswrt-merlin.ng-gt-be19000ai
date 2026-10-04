#!/bin/sh
# Exact-file web overlay. Keep the real AiMesh role and authentication unchanged.
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
base=/jffs/node-web-fix
[ ! -e "$base/disabled" ] || exit 0
[ "$(nvram get productid)" = GT-BE19000AI ] || exit 0
[ "$(nvram get re_mode)" = 1 ] || exit 0
hash() { sha256sum "$1" | cut -d ' ' -f 1; }
# Check the entire set before mounting anything, including firmware upgrades.
while read -r stock patched path; do
    [ "$(hash "$base/files/$path")" = "$patched" ] || {
        logger -t node-web-fix "Overlay checksum failed: $path"; exit 1;
    }
    current=$(hash "/www/$path")
    if [ "$current" != "$stock" ] && [ "$current" != "$patched" ]; then
        logger -t node-web-fix "Firmware or web file changed; overlay skipped: $path"
        exit 0
    fi
done < "$base/files.tsv"
applied=""
undo_partial() {
    for target in $applied; do umount "$target"; done
}
trap undo_partial EXIT
trap 'exit 1' HUP INT TERM
while read -r stock patched path; do
    [ "$(hash "/www/$path")" = "$patched" ] && continue
    mount -o bind "$base/files/$path" "/www/$path" || exit 1
    applied="/www/$path $applied"
done < "$base/files.tsv"
trap - EXIT HUP INT TERM
logger -t node-web-fix 'Authenticated node web UI overlay active'

[ ! -x /jffs/node-history/history.sh ] || /jffs/node-history/history.sh start
[ ! -x /jffs/ccr-status/collect.sh ] || /jffs/ccr-status/collect.sh start

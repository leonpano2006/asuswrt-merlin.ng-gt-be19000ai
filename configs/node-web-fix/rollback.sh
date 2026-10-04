#!/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
base=/jffs/node-web-fix
# Keep RGB hooks and all unrelated Merlin scripts enabled.
touch "$base/disabled" || exit 1
[ ! -x /jffs/node-history/history.sh ] || /jffs/node-history/history.sh stop
[ ! -x /jffs/ccr-status/collect.sh ] || /jffs/ccr-status/collect.sh stop
while read -r stock patched path; do
    current=$(sha256sum "/www/$path" | cut -d ' ' -f 1)
    if [ "$current" = "$patched" ]; then
        umount "/www/$path" || exit 1
    elif [ "$current" != "$stock" ]; then
        logger -t node-web-fix "Unrecognized file left untouched: $path"
    fi
done < "$base/files.tsv"
logger -t node-web-fix 'Web overlay disabled; stock pages restored'

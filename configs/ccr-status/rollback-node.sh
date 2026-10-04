#!/bin/sh
set -eu
base=/jffs/node-web-fix
backup=$base/before-ccr-status-20261004
test -f "$backup/files/pages/dashboard.html"
/jffs/ccr-status/collect.sh stop
touch /jffs/ccr-status/disabled
umount /www/pages/dashboard.html
cp "$backup/files/pages/dashboard.html" "$base/files/pages/dashboard.html"
cp "$backup/manifest.json" "$backup/files.tsv" "$backup/apply.sh" "$backup/rollback.sh" "$base/"
"$base/apply.sh"

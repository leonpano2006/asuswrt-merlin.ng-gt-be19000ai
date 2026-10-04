#!/bin/sh
# Local, bounded RAM history. No radio setters, NVRAM writes or network listener.
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 077
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
run=/tmp/node-history
db=/tmp/.diag/node_stats.db
supported() {
 [ "$(nvram get productid)" = GT-BE19000AI ] && [ "$(nvram get re_mode)" = 1 ] &&
 [ "$(sha256sum /sbin/rc | cut -d ' ' -f 1)" = 9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814 ] &&
 [ ! -e "$base/disabled" ] && [ ! -e /jffs/node-web-fix/disabled ]
}
live_pid() {
 [ -f "$run/pid" ] || return 1
 pid=$(cat "$run/pid")
 case "$pid" in ''|*[!0-9]*) return 1;; esac
 kill -0 "$pid" 2>/dev/null && tr '\000' ' ' < "/proc/$pid/cmdline" | grep -q 'node-history/history.sh run'
}
case "$1" in
 stop) if live_pid; then kill "$pid"; fi; exit 0;;
 start) supported || exit 0; live_pid && exit 0
        "$base/history.sh" run </dev/null >/dev/null 2>&1 & exit 0;;
 run) supported || exit 0; mkdir -p "$run" /tmp/.diag
      if ! mkdir "$run/lock" 2>/dev/null; then
       sleep 1; live_pid && exit 0; rmdir "$run/lock" 2>/dev/null || exit 1
       mkdir "$run/lock" || exit 1
      fi
      echo $$ > "$run/pid"
      trap 'rm -f "$run/pid"; rmdir "$run/lock" 2>/dev/null' EXIT
      trap 'exit 0' HUP INT TERM
      rm -f "$run/previous"; : > "$run/previous"
      sqlite3 -bail "$db" < "$base/schema.sql" >/dev/null || exit 1
      chmod 600 "$db"
      ;;
 *) exit 2;;
esac
while [ ! -e "$base/disabled" ] && [ ! -e /jffs/node-web-fix/disabled ] && [ "$(nvram get re_mode)" = 1 ]; do
 {
  read -r uptime rest < /proc/uptime
  echo "CLOCK $(date +%s) $uptime"
  for net in /sys/class/net/eth[0-9]* /sys/class/net/eth.ai /sys/class/net/bond[0-9]* /sys/class/net/wl[012].*; do
   [ -d "$net" ] || continue
   name=${net##*/}
   echo "IF $name $(cat "$net/ifindex") $(cat "$net/statistics/rx_bytes") $(cat "$net/statistics/tx_bytes")"
  done
  for unit in 0 1 2; do
   raw=$(wl -i "wl$unit" radio 2>/dev/null)
   case "$raw" in 0x0000) on=1;; 0x000[1-3]) on=0;; *) on=NULL;; esac
   : > "$run/auth"
   ok=1
   # The front-haul SSIDs start at .2; .1 is the reserved AiMesh backhaul BSS.
   for net in /sys/class/net/wl"$unit".*; do
    [ -d "$net" ] || continue; name=${net##*/}; sub=${name#*.}
    [ "$sub" -ge 2 ] 2>/dev/null || continue
    wl -i "$name" autho_sta_list >> "$run/auth" 2>/dev/null || ok=0
   done
   if [ "$ok" = 1 ]; then
    count=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]$/) seen[toupper($i)]=1} END{for(k in seen)c++;print c+0}' "$run/auth")
   else count=NULL; fi
   rm -f "$run/auth"
   # chanim is an on-channel passive driver read; it does not start a scan.
   metrics=$(wl -i "wl$unit" chanim_stats 2>/dev/null | awk '
    /^chspec/ {for(i=1;i<=NF;i++)p[$i]=i;next}
    p["busy"] && NF>=p["busy"] && $1 ~ /^[0-9]/ {print $1,$p["busy"],$p["obss"],$p["nopkt"],$p["knoise"];found=1;exit}
    END{if(!found)print "unknown NULL NULL NULL NULL"}')
   echo "RADIO $unit $on $count $metrics"
  done
 } > "$run/sample"
 : > "$run/next"
 if awk -v previous="$run/previous" -v next_previous="$run/next" -f "$base/collect.awk" "$run/sample" > "$run/sample.sql" 2>"$run/error" &&
 sqlite3 -bail -cmd '.timeout 1500' "$db" < "$run/sample.sql" >/dev/null 2>>"$run/error"; then
  mv "$run/next" "$run/previous"
 else logger -t node-history 'History sample failed; see /tmp/node-history/error'; fi
 sleep 60 & wait $!
done

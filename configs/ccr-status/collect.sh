#!/bin/sh
# Direct, read-only CCR2216 telemetry. Private credentials never enter /www or SQL.
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 077
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
run=/tmp/ccr-status
db=/tmp/.diag/ccr_status.db
supported() {
 [ "$(nvram get productid)" = GT-BE19000AI ] && [ "$(nvram get re_mode)" = 1 ] &&
 [ "$(sha256sum /sbin/rc | cut -d ' ' -f 1)" = 9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814 ] &&
 [ -r "$base/curl.conf" ] && [ ! -e "$base/disabled" ] && [ ! -e /jffs/node-web-fix/disabled ]
}
live_pid() {
 [ -f "$run/pid" ] || return 1
 pid=$(cat "$run/pid")
 case "$pid" in ''|*[!0-9]*) return 1;; esac
 kill -0 "$pid" 2>/dev/null && tr '\000' ' ' < "/proc/$pid/cmdline" | grep -q 'ccr-status/collect.sh run'
}
init_db() {
 mkdir -p "$run" /tmp/.diag || return 1
 sqlite3 -bail "$db" < "$base/schema.sql" >/dev/null || return 1
 chmod 600 "$db"
 [ -s "$run/previous.json" ] || echo '{}' > "$run/previous.json"
}
get() {
 # No redirects: a changed endpoint must not receive the credential.
 curl -q --config "$base/curl.conf" --silent --fail --connect-timeout 2 --max-time 4 --max-filesize 65536 \
  --noproxy '*' --proto '=http' "http://192.168.100.1/rest/$2" > "$run/$1.json" 2>/dev/null &&
 jq -e "$3" "$run/$1.json" >/dev/null 2>&1 && return 0
 echo '{}' > "$run/$1.json"
 printf '%s\n' "$1" >> "$run/errors"
 return 1
}
uptime_seconds() {
 awk '{s=$0;t=0;while(match(s,/[0-9]+[wdhms]/)){v=substr(s,RSTART,RLENGTH);s=substr(s,RSTART+RLENGTH);u=substr(v,length(v),1);n=v+0;t+=n*(u=="w"?604800:u=="d"?86400:u=="h"?3600:u=="m"?60:1)};print t}'
}
sample() {
 : > "$run/errors"
 now=$(date +%s); read -r mono rest < /proc/uptime
 if ! get resource 'system/resource?.proplist=board-name,version,uptime,cpu-load,cpu-count,total-memory,free-memory' 'type=="object" and (."board-name" | startswith("CCR2216"))'; then
  jq -c --argjson now "$now" '. + {schema:1,ip:"192.168.100.1",status:"unavailable",attempt:$now,errors:["resource"],seen:(.seen // 0)}' "$run/previous.json" > "$run/result.json"
 else
  get identity 'system/identity' 'type=="object" and (.name|type)=="string"' || :
  get health 'system/health' 'type=="array"' || :
  get ethernet 'interface/ethernet?.proplist=.id,name,default-name,running,disabled' 'type=="array" and length>0' || :
  get interfaces 'interface?.proplist=name,rx-byte,tx-byte,rx-error,tx-error,rx-drop,tx-drop' 'type=="array"' || :
  get neighbors 'ip/neighbor?.proplist=interface,identity,address,mac-address,platform,board,discovered-by' 'type=="array"' || :
  get routes 'ip/route?.proplist=dst-address,immediate-gw,active' 'type=="array"' || :
  get leases 'ip/dhcp-server/lease?.proplist=address,mac-address,host-name,status,active-address,active-mac-address' 'type=="array"' || :
  get arp 'ip/arp?.proplist=address,mac-address,interface,status,complete' 'type=="array"' || :
  get fdb 'interface/bridge/host?.proplist=mac-address,on-interface,bridge,local' 'type=="array"' || :
  : > "$run/monitors.json"
  # RouterOS monitor uses POST for a read-only, one-shot status operation.
  # Fixed path, no setters or arbitrary commands, no redirected credentials.
  for id in $(jq -r 'if type=="array" then .[]|select(.running=="true")|.[".id"] else empty end' "$run/ethernet.json"); do
   body=$(jq -nc --arg id "$id" '{".id":$id,once:"",".proplist":"name,status,rate"}')
   if curl -q --config "$base/curl.conf" --silent --fail --connect-timeout 2 --max-time 3 --max-filesize 65536 \
      --noproxy '*' --proto '=http' -H 'Content-Type: application/json' -X POST --data "$body" \
      'http://192.168.100.1/rest/interface/ethernet/monitor' > "$run/monitor.json" 2>/dev/null &&
      jq -e 'type=="array"' "$run/monitor.json" >/dev/null 2>&1; then
    cat "$run/monitor.json" >> "$run/monitors.json"; echo >> "$run/monitors.json"
   else echo monitor >> "$run/errors"; fi
  done
  upt=$(jq -r '.uptime' "$run/resource.json" | uptime_seconds)
  errors=$(jq -Rsc 'split("\n") | map(select(length>0)) | unique' "$run/errors")
  jq -nc --argjson now "$now" --argjson mono "$mono" --argjson uptime "$upt" --argjson errors "$errors" \
   --slurpfile resource "$run/resource.json" --slurpfile identity "$run/identity.json" \
   --slurpfile health "$run/health.json" --slurpfile ethernet "$run/ethernet.json" \
   --slurpfile interfaces "$run/interfaces.json" --slurpfile neighbors "$run/neighbors.json" \
   --slurpfile routes "$run/routes.json" --slurpfile monitors "$run/monitors.json" \
   --slurpfile previous "$run/previous.json" -f "$base/normalize.jq" > "$run/result.json" || return 1
  jq -c --slurpfile leases "$run/leases.json" --slurpfile arp "$run/arp.json" \
   --slurpfile fdb "$run/fdb.json" --slurpfile neighbors "$run/neighbors.json" \
   --slurpfile previous "$run/previous.json" -f "$base/network.jq" "$run/result.json" > "$run/network.json" || return 1
  mv "$run/network.json" "$run/result.json"
 fi
 [ "$(wc -c < "$run/result.json")" -le 131072 ] || return 1
 encoded=$(jq -rc '@base64' "$run/result.json") || return 1
 case "$encoded" in ''|*[!A-Za-z0-9+/=]*) return 1;; esac
 printf "INSERT OR REPLACE INTO DATA_INFO(data_id,data_time,payload) VALUES(1,%s,'%s');\n" "$now" "$encoded" |
  sqlite3 -bail -cmd '.timeout 1500' "$db" >/dev/null || return 1
 # Advance only after publication; failed samples must not poison deltas.
 [ "$(jq -r .status "$run/result.json")" = unavailable ] || cp "$run/result.json" "$run/previous.json"
}
case "$1" in
 stop) if live_pid; then kill "$pid"; fi; exit 0;;
 once) supported && init_db && sample; exit $?;;
 start) supported || exit 0; live_pid && exit 0
        "$base/collect.sh" run </dev/null >/dev/null 2>&1 & exit 0;;
 run) supported || exit 0; mkdir -p "$run"
      if ! mkdir "$run/lock" 2>/dev/null; then
       sleep 1; live_pid && exit 0; rmdir "$run/lock" 2>/dev/null || exit 1
       mkdir "$run/lock" || exit 1
      fi
      echo $$ > "$run/pid"
      trap 'rm -f "$run/pid"; rmdir "$run/lock" 2>/dev/null' EXIT
      trap 'exit 0' HUP INT TERM
      init_db || exit 1;;
 *) exit 2;;
esac
while supported; do
 sample || logger -t ccr-status 'Status sample failed; previous snapshot will expire'
 sleep 30 & wait $!
done

#!/bin/sh
# Runs inside the existing .51 netpanel collector. Reuses its local credentials.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
run=/tmp/netpanel-ccr
[ -r /etc/netpanel.cred ] || exit 1
. /etc/netpanel.cred
[ -n "$NPUSER" ] && [ -n "$NPPASS" ] || exit 1
credential=$(printf '%s:%s' "$NPUSER" "$NPPASS" | jq -Rrs '"user = " + @json') || exit 1
mkdir -p "$run"
[ -s "$run/previous.json" ] || echo '{}' > "$run/previous.json"
get() {
 # No redirects: a changed endpoint must not receive the credential.
 printf '%s\n' "$credential" | curl -q --config - --silent --fail --connect-timeout 2 --max-time 4 \
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
  get neighbors 'ip/neighbor?.proplist=interface,identity' 'type=="array"' || :
  get routes 'ip/route?.proplist=dst-address,immediate-gw,active' 'type=="array"' || :
  # Reuse the just-collected netpanel link rates, not another monitor request.
  if ! jq -ec --argjson now "$now" '[.switches[] | select(.ip=="192.168.100.1" and .off==false and .seen >= ($now-90)) | .ports[] | select(.up) | {name:.n,rate:.rate,status:.st}] | select(length>0)' /tmp/netpanel.json > "$run/monitors.json"; then
   echo '[]' > "$run/monitors.json"; echo monitor >> "$run/errors"
  fi
  upt=$(jq -r '.uptime' "$run/resource.json" | uptime_seconds)
  errors=$(jq -Rsc 'split("\n") | map(select(length>0)) | unique' "$run/errors")
  jq -nc --argjson now "$now" --argjson mono "$mono" --argjson uptime "$upt" --argjson errors "$errors" \
   --slurpfile resource "$run/resource.json" --slurpfile identity "$run/identity.json" \
   --slurpfile health "$run/health.json" --slurpfile ethernet "$run/ethernet.json" \
   --slurpfile interfaces "$run/interfaces.json" --slurpfile neighbors "$run/neighbors.json" \
   --slurpfile routes "$run/routes.json" --slurpfile monitors "$run/monitors.json" \
   --slurpfile previous "$run/previous.json" -f "$base/normalize.jq" > "$run/result.json" || return 1
  cp "$run/result.json" "$run/previous.json"
 fi
 [ "$(wc -c < "$run/result.json")" -le 65536 ] || return 1
 # Atomic RAM-only publication. The CGI has no credentials and executes no API calls.
 cp "$run/result.json" /tmp/netpanel-ccr.json.new && mv /tmp/netpanel-ccr.json.new /tmp/netpanel-ccr.json
}
sample

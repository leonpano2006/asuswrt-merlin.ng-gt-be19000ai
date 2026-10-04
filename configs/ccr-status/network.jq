# Evidence-based inventory: a DHCP reservation is never proof of presence.
def arr: if type=="array" then . else [] end;
def yes: .==true or .=="true";
def text: if type=="string" then .[0:96] else "" end;
def mac: (. // "" | ascii_upcase) | select(test("^[0-9A-F]{2}(:[0-9A-F]{2}){5}$") and .!="00:00:00:00:00:00" and .!="FF:FF:FF:FF:FF:FF");
def lanip: (. // "") | select(test("^192\\.168\\.100\\.[0-9]{1,3}$"));
def idx: map({key:(."mac-address"|mac),value:.}) | from_entries;
. as $s | $previous[0] as $prev |
($leases[0]|arr) as $l | ($arp[0]|arr|map(select((.address|[lanip]|length)>0))) as $a |
($fdb[0]|arr|map(select((.local|yes|not) and .bridge=="lan"))) as $f |
($neighbors[0]|arr) as $n |
($l|idx) as $lm | ($a|group_by(."mac-address")|map({key:(.[0]."mac-address"|mac),value:.})|from_entries) as $am |
($f|group_by(."mac-address")|map({key:(.[0]."mac-address"|mac),value:.})|from_entries) as $fm |
($n|idx) as $nm |
([$l[],$a[],$f[]]|map(."mac-address"|mac)|unique) as $keys |
($keys|map(. as $m | $lm[$m] as $lease | ($am[$m]//[]) as $ar | ($fm[$m]//[]) as $fr |
 ([$ar[]|select(.status=="reachable")|.address|lanip] + (if $lease.status=="bound" then [$lease."active-address"|lanip] else [] end)|unique) as $ips |
 ($fr|map(."on-interface"|text)|unique) as $via |
 ([$ar[].address|lanip]|unique|. - $ips) as $cached |
 {mac:$m,cached_ips:$cached,name:(($nm[$m].identity // $lease."host-name" // "")|text),ips:$ips,
  reserved_ip:(if $lease.status!="bound" then ($lease.address // "") else "" end),
  via:$via,arp:($ar|map(.status//"unknown")|unique),lease:($lease.status//""),
  evidence:([if $ar|any(.status=="reachable") then "arp-reachable" else empty end,
    if $fr|length>0 then "fdb" else empty end,if $lease then "dhcp" else empty end,
    if $ar|length>0 then "arp" else empty end]),
  state:(if ($ar|any(.status=="reachable")) or ($fr|length>0) then "seen" else "unknown" end)
 })) as $devices |
($n|map(. as $p |
 {name:(.identity|text),model:((.board//.platform)|text),mac:(."mac-address"|mac),
  ip:(([.address|lanip][0]) // ([$devices[]|select(.mac==($p."mac-address"|ascii_upcase))|(.ips+.cached_ips)[]][0]) // ""),
  via:(.interface//""|split(",")|.[0]|text),
  protocols:(."discovered-by"//""|split(",")|map(text)),
  kind:(if (."discovered-by"//""|split(",")|index("lldp"))!=null then "lldp" else "discovered" end)
 } ) | unique_by([.mac,.via])) as $peers |
($s.monotonic - ($prev.monotonic//$s.monotonic)) as $elapsed |
($prev.network.schema==1 and $elapsed>0 and $elapsed<=120 and $s.uptime_s>=($prev.uptime_s//1e20)) as $continuous |
($prev.ports//[]|map({key:.name,value:.})|from_entries) as $oldports |
(if $s.uptime_s < ($prev.uptime_s//0) then [] else ($prev.network.observed_up//[]) end) as $watched |
([$s.ports[]|select(.up and (.disabled|not))|.name]+$watched|unique|.[0:32]) as $observed |
([if $s.errors|length>0 then {kind:"collection",target:($s.errors|join(", ")),level:"warning"} else empty end,
  if ($s.errors|index("routes"))==null and ($s.wan|length)==0 then {kind:"wan-route",target:"CCR2216",level:"warning"} else empty end,
  ($s.health[]|select((.name|endswith("-state")) and (.value|tostring|ascii_downcase)!="ok")|
   {kind:"health",target:.name,detail:(.value|text),level:"warning"})]) as $baseissues |
([$s.ports[]|. as $p|select((.up|not) and (.disabled|not) and ($observed|index($p.name))!=null)|
 {kind:"link-down",target:.name,level:"warning"}]) as $linkissues |
([if $continuous then $s.ports[]|. as $p|$oldports[.name] as $o|
  ["rx_errors","tx_errors","rx_drops","tx_drops"][] as $k|
  select($p[$k]!=null and $o[$k]!=null and $p[$k]>$o[$k])|
  {kind:"counter",target:$p.name,detail:$k,value:($p[$k]-$o[$k]),level:"warning"} else empty end]) as $counterissues |
([if $continuous and ($s.errors|index("ethernet"))==null and (($prev.errors//[])|index("ethernet"))==null then
  $s.ports[]|. as $p|$oldports[.name] as $o|select($o!=null and $p.up!=$o.up)|
  {at:$s.seen,kind:(if $p.up then "link-up" else "link-down" end),target:$p.name}
 else empty end,
 if $prev.network.schema==1 and $s.uptime_s<($prev.uptime_s//0) then {at:$s.seen,kind:"reboot",target:"CCR2216"} else empty end,
 if $prev.network.schema==1 and $elapsed>120 then {at:$s.seen,kind:"gap",target:"CCR2216"} else empty end,
 if $prev.network.schema!=1 then {at:$s.seen,kind:"started",target:"CCR2216"} else empty end]) as $events |
$s + {network:{schema:1,scope:"192.168.100.0/24",sources:{dhcp:($l|length),arp:($a|length),fdb:($f|length),neighbors:($n|length)},
 total:($devices|length),seen_total:($devices|map(select(.state=="seen"))|length),truncated:(($devices|length)>160 or ($peers|length)>32),
 devices:($devices|sort_by(.state!="seen",.name=="",.name,.mac)|.[0:160]),peers:($peers|.[0:32]),
 observed_up:$observed,issues:($baseissues+$linkissues+$counterissues|.[0:48]),
 events:($events+($prev.network.events//[])|map(select(.at>=$s.seen-86400))|.[0:30])}}

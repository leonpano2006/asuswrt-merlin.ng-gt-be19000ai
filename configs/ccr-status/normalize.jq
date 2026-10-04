def num: if . == null or . == "" then null else (tonumber? // null) end;
def yes: . == true or . == "true";
def array: if type == "array" then . else [] end;
def rate($current;$old;$dt):
  if $dt != null and $current != null and $old != null and
     $current >= $old and $current < 9007199254740991 and $old >= 0
  then (($current - $old) * 8 / $dt / 1000000) else null end;
$resource[0] as $r | $previous[0] as $prev |
($interfaces[0] | array | map({key:.name,value:.}) | from_entries) as $im |
($monitors | map(select(type == "array")) | add // [] | map({key:.name,value:.}) | from_entries) as $mm |
($prev.ports // [] | map({key:.name,value:.}) | from_entries) as $pm |
($routes[0] | array | map(select(."dst-address" == "0.0.0.0/0" and (.active | yes))) |
 map(."immediate-gw" // "" | split("%") | .[1] // empty) | unique) as $wan |
($mono - ($prev.monotonic // $mono)) as $elapsed |
(if $elapsed > 0 and $elapsed <= 120 and $uptime >= ($prev.uptime_s // 1e20)
 then $elapsed else null end) as $dt |
{
 schema:1, source:"direct", ip:"192.168.100.1", seen:$now, attempt:$now, monotonic:$mono,
 status:(if $errors | length > 0 then "partial" else "ok" end), errors:$errors,
 model:$r."board-name", name:($identity[0].name // "CCR2216"), version:($r.version // ""),
 uptime_s:$uptime, cpu:($r."cpu-load" | num), cores:($r."cpu-count" | num),
 memory_total:($r."total-memory" | num), memory_free:($r."free-memory" | num),
 health:($health[0] | array | map({name,unit:.type,value})), wan:$wan,
 ports:($ethernet[0] | array | map(. as $p | $im[$p.name] as $i | $pm[$p.name] as $old |
   ($i."rx-byte" | num) as $rx | ($i."tx-byte" | num) as $tx |
   {name:$p.name, physical:($p."default-name" // $p.name),
    up:($p.running | yes), disabled:($p.disabled | yes),
    speed:($mm[$p.name].rate // ""), wan:($wan | index($p.name) != null),
    peers:($neighbors[0] | array | map(select((.interface // "" | split(",") | .[0]) == $p.name) | .identity // empty) | unique),
    rx_bytes:$rx, tx_bytes:$tx, rx_mbps:rate($rx;$old.rx_bytes;$dt), tx_mbps:rate($tx;$old.tx_bytes;$dt),
    rx_errors:($i."rx-error" | num), tx_errors:($i."tx-error" | num),
    rx_drops:($i."rx-drop" | num), tx_drops:($i."tx-drop" | num)
   }))
}

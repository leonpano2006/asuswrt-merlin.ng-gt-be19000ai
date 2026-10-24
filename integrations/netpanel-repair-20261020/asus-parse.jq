def rows($tag): map(select(.[0]==$tag));
def val($tag): (rows($tag)[0][1] // "");
def num: tonumber? // null;
def iface($model;$key):
 if $model=="GT-BE19000AI" then (if $key=="W0" then "eth0" else "eth"+($key|ltrimstr("L")) end)
 elif $model=="GT-BE98" and $key=="W0" then "eth0"
 else "" end;
split("\n") | map(select(length>0)|split("|")) as $r
| ($r|val("MODEL")) as $model
| ($r|val("ATE")|split(";")|map(select(contains("="))|split("="))|map({(.[0]):.[1]})|add // {}) as $ate
| select($model!="" and ($ate|length)>0)
| ($r|rows("MODE")[0]) as $mode
| ($r|val("UPLINK")) as $uplink
| ($r|val("WANIF")) as $wanif
| ($r|rows("LINK")|map({(.[1]):{carrier:.[2],mbps:(.[3]|num),master:.[4]}})|add // {}) as $links
| {t:"10Mbps",M:"100Mbps",G:"1Gbps",Q:"2.5Gbps",F:"5Gbps",T:"10Gbps"} as $speeds
| ($r|rows("STA")|map({radio:.[1],interface:.[2],mac:(.[3]|ascii_upcase)})|unique_by([.radio,.mac])) as $stations
| ($r|rows("RADIO")|map(. as $radio | {r:.[1],band:({"1":"5GHz","2":"2.4GHz","4":"6GHz"}[.[2]] // "未知"),ch:.[3],cl:([$stations[]|select(.radio==$radio[1])]|length)})) as $radios
| ($r|rows("ACCEL")|map(.[1])) as $acc
| {dev:$model,model:$model,ip:$ip,uptime:($r|val("UPTIME")|num),
   mode_label:(if $mode[2]=="1" then "AiMesh 節點" elif $mode[1]=="3" then "AP" elif $mode[1]=="1" then "路由器" else "模式 "+($mode[1]//"未知") end),
   uplink_interface:$uplink,uplink_source:"gateway-fdb",port_source:(if ($r|val("PORT_SOURCE"))!="" then ($r|val("PORT_SOURCE")) else "ATE Get_WanLanStatus" end),
   accel:{on:(if ($acc|map(contains("HW Acceleration"))|any) then ($acc|map(contains("<Enabled>"))|any) else null end),flows:($acc|map(select(startswith("Active<"))|ltrimstr("Active<")|rtrimstr(">")|num)|.[0] // null)},
   wifi:{radios:$radios,stations:$stations,total:([$stations[].mac]|unique|length),count_kind:"unique_station_mac"},
   ports:(["W0","L1","L2","L3","L4","L5","L6"]|map(. as $key | ($ate[$key]//"") as $code | iface($model;$key) as $if |
     {n:(if $key=="W0" then "WAN 0" else "LAN "+($key|ltrimstr("L")) end),label:(if $key=="W0" then "WAN / LAN" else "LAN "+($key|ltrimstr("L")) end),raw:$key,interface:$if,
      up:($speeds|has($code)),dis:false,rate:($speeds[$code]//""),
      st:(if $code=="X" then "no-link" elif ($speeds|has($code)) then "link-ok" else "unknown" end),
      wan:($mode[1]=="1" and $if!="" and $if==$wanif),
      ul:(($speeds|has($code)) and $if!="" and ($if==$uplink or (($links[$if].master//"")!="" and $links[$if].master==$uplink))),
      lag:(if (($links[$if].master//"")|startswith("bond")) then $links[$if].master else "" end)})),
   internal:(if $ate|has("AI") then [{label:"AI 板內部連線",interface:"eth.ai",up:($speeds|has($ate.AI)),rate:($speeds[$ate.AI]//""),st:(if $ate.AI=="X" then "no-link" elif ($speeds|has($ate.AI)) then "link-ok" else "unknown" end)}] else [] end)}

# Input contains only driver counters and validated interface names, never SSIDs.
function number(s) { return s ~ /^[0-9]+([.][0-9]+)?$/ }
function pct(s) { return number(s) && s+0<=100 ? s+0 : "-1" }
function metric(s) { return s ~ /^-?[0-9]+$/ && s+0>=-140 && s+0<=0 ? s+0 : "-999" }
BEGIN {
 while ((getline row < previous)>0) {
  split(row,a," "); oldindex[a[1]]=a[2]; oldtime[a[1]]=a[3]; oldrx[a[1]]=a[4]; oldtx[a[1]]=a[5];
 }
 close(previous);
 print "PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF; PRAGMA max_page_count=8192; BEGIN IMMEDIATE;";
}
$1=="CLOCK" { ts=$2; up=$3; valid=number(ts) && ts>1700000000 && number(up); }
$1=="IF" && valid && $2 ~ /^(eth[0-9]+|eth[.]ai|bond[0-9]+|wl[0-9]+[.][0-9]+)$/ {
 name=$2; idx=$3; rx=$4; tx=$5;
 if(!number(idx)||!number(rx)||!number(tx)) next;
 dt=up-oldtime[name]; r="-1";t="-1";
 if(oldindex[name]==idx && dt>=30 && dt<=180 && rx>=oldrx[name] && tx>=oldtx[name]) {
  r=sprintf("%.6f",(rx-oldrx[name])*8/dt/1000000);t=sprintf("%.6f",(tx-oldtx[name])*8/dt/1000000);
 }
 printf "INSERT INTO DATA_INFO(kind,iface,uptime,rx_bytes,tx_bytes,rx_mbps,tx_mbps,data_time) VALUES('interface','%s',%.2f,%.0f,%.0f,%s,%s,%.0f);\n",name,up,rx,tx,r,t,ts;
 printf "%s %s %.2f %.0f %.0f\n",name,idx,up,rx,tx > next_previous;
}
$1=="RADIO" && valid && $2 ~ /^[012]$/ {
 band=$2;on=($3=="0"||$3=="1")?$3:"-1";
 links=number($4)?$4:"-1"; spec=$5;
 if(spec !~ /^[0-9A-Za-z\/+.-]+$/) spec="";
 b=pct($6);o=pct($7);n=pct($8);noise=metric($9);
 if(on!="1") { b="-1";o="-1";n="-1";noise="-999";spec="";links=on=="0"?0:"-1"; }
 printf "INSERT INTO DATA_INFO(kind,iface,band,uptime,links,chspec,busy,obss,nopkt,noise,radio_on,data_time) VALUES('radio','wl%s',%s,%.2f,%s,'%s',%s,%s,%s,%s,%s,%.0f);\n",band,band,up,links,spec,b,o,n,noise,on,ts;
}
END {
 if(valid) printf "DELETE FROM DATA_INFO WHERE data_time<%.0f OR data_time>%.0f;\n",ts-86400,ts+120;
 print "DELETE FROM DATA_INFO WHERE data_id < (SELECT MAX(data_id)-90000 FROM DATA_INFO); COMMIT;";
 close(next_previous);
}

#!/bin/sh
# SOURCE-ONLY v3 candidate. Private fullip/timeout closure, no BusyBox stat. Not executed.
# .51 only. No permanent network configuration, sysctl, firewall or key edits.
set -eu
set -o pipefail || { echo 'BusyBox shell pipefail support required' >&2; exit 125; }
umask 077
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
TOOLS=/tmp/leon-uplink-rescue-tools
IP=$TOOLS/ip-run.sh
TIMEOUT=$TOOLS/timeout-run.sh
BB=/bin/busybox
DIR=/tmp/leon-uplink-rescue-controller
SELF=169.254.190.51
PEER=169.254.190.15
DEV=br-lan
TAG=br-lan:lr
MAC=02:00:00:f0:00:02
PHASE=
INDEX=
BOOT=
LOCK_HELD=0
ACTION=${1-}
[ "$#" -eq 1 ] && { [ "$ACTION" = --setup ] || [ "$ACTION" = --cleanup-owned ]; } || exit 125

die() { echo "LEON_RESCUE_CONTROLLER error=$1 retained_state=$DIR" >&2; exit 125; }
release_lock() {
    if [ "$LOCK_HELD" -eq 1 ]; then
        "$BB" rmdir "$DIR/operation-lock" || return 1
        LOCK_HELD=0
    fi
}
take_lock() {
    "$BB" mkdir -m 700 "$DIR/operation-lock" || return 1
    LOCK_HELD=1
}
trap 'release_lock || :' EXIT
trap 'exit 125' HUP INT TERM
capture() {
    # Trusted finite ip dump, bounded wall time AND stored output. pipefail
    # prevents a failing producer/timeout from masquerading as a valid dump.
    file=$1
    shift
    "$TIMEOUT" -s TERM -k 1 3 "$@" | "$BB" head -c 65537 > "$DIR/$file" || return 1
    n=$("$BB" wc -c < "$DIR/$file") || return 1
    [ "$n" -le 65536 ] || return 1
}
numeric_meta() {
    # Fixed paths contain no whitespace. Upstream BusyBox1.37 supports numeric
    # ls; exact -ldni output remains a fixture/preflight check. Captured .51
    # has no stat. Never parse a symlink target or user/group name.
    p=$1 want=$2 links=$3 size=$4
    [ ! -L "$p" ] || return 1
    "$BB" ls -ldni "$p" | "$BB" awk -v p="$p" -v mode="$want" -v links="$links" -v size="$size" '
      NR==1 {ok=(NF==10 && $1~/^[0-9]+$/ && $2==mode && $3~/^[0-9]+$/ && $3>0 && $4==0 && $5==0 && $6~/^[0-9]+$/ && $10==p);
        if(links!="any" && $3!=links)ok=0;if(size!="any" && $6!=size)ok=0}
      END {exit(NR!=1 || !ok)}'
}
file0600() { [ -f "$1" ] && numeric_meta "$1" -rw------- 1 any; }
check_dir() { [ -d "$DIR" ] && numeric_meta "$DIR" drwx------ any any; }
check_tools() {
    numeric_meta "$TOOLS" drwx------ any any || return 1
    numeric_meta "$TOOLS/bin" drwxr-xr-x any any || return 1
    numeric_meta "$TOOLS/lib" drwxr-xr-x any any || return 1
    numeric_meta "$TOOLS/bin/ip-full" -rwxr-xr-x 1 476963 || return 1
    numeric_meta "$TOOLS/bin/timeout" -rwxr-xr-x 1 33264 || return 1
    numeric_meta "$TOOLS/timeout-run.sh" -rwxr-xr-x 1 303 || return 1
    numeric_meta "$TOOLS/lib/libbpf.so.1" -rw-r--r-- 1 315447 || return 1
    numeric_meta "$TOOLS/lib/libelf.so.1" -rw-r--r-- 1 77827 || return 1
    numeric_meta "$TOOLS/lib/libmnl.so.0" -rw-r--r-- 1 12290 || return 1
    numeric_meta "$TOOLS/lib/libz.so.1" -rw-r--r-- 1 69635 || return 1
    numeric_meta "$TOOLS/lib/libgcc_s.so.1" -rw-r--r-- 1 45058 || return 1
    numeric_meta "$TOOLS/lib/libc.so" -rwxr-xr-x 1 508607 || return 1
    numeric_meta "$TOOLS/ip-run.sh" -rwxr-xr-x 1 299 || return 1
    (cd "$TOOLS" && "$BB" sha256sum -c <<'LEON_FIXED_TOOLS'
686d9f7baa305a00ddfaa06f674707661f66a8578361e80bb0787eaf9dbe71fa  bin/ip-full
eee267c8317aff3902f573c1e5f0052a723b2a3521cb2903377caea04ec8c7df  bin/timeout
f887d0cdd35e3b87429e6553ee86cc83e9018315f3eac644813859d56e8ae27c  timeout-run.sh
ee5b4a218658fe371973dc8ae337f0d365b9696fce6d48a2b9367bdb091cbdda  lib/libbpf.so.1
42e670b9fff79ade089515e7e78044b16938e28c006a0539ed9e585034161ede  lib/libelf.so.1
66ec7ee8f828ea334420a450b3fe87f2bbca24439633a55985bb30d09330912d  lib/libmnl.so.0
d1d09644134064824a8b09c3560ef513768f31cd3d19188d05a392162dd15d31  lib/libz.so.1
212ec73048315d4d174b8c8ee3c98f32a29c59fec69677b1dc88802b4021ea2b  lib/libgcc_s.so.1
fbc1ac4517f9218e97eeaeed31ccc37ec70c02992cb953e82cc911f08a710e30  lib/libc.so
53b21a39f5de6393725ca63a38378b4e772faa1f8ef378087ef470a36be337e1  ip-run.sh
LEON_FIXED_TOOLS
    ) >/dev/null || return 1
}
identity() {
    check_tools || return 1
    [ "$("$BB" id -u)" = 0 ] || return 1
    [ "$("$BB" readlink /proc/self/ns/net)" = "$("$BB" readlink /proc/1/ns/net)" ] || return 1
    [ "$("$BB" cat /sys/class/net/br-lan/address)" = "$MAC" ] || return 1
    [ "$("$BB" cat /sys/class/net/br-lan/carrier)" = 1 ] || return 1
    [ "$("$BB" cat /sys/class/net/br-lan/operstate)" = up ] || return 1
    i=$("$BB" cat /sys/class/net/br-lan/ifindex) || return 1
    case $i in ''|*[!0-9]*) return 1;; esac
    [ "$i" -gt 0 ] || return 1
    [ -z "$INDEX" ] || [ "$i" = "$INDEX" ] || return 1
    INDEX=$i
    b=$("$BB" cat /proc/sys/kernel/random/boot_id) || return 1
    echo "$b" | "$BB" grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || return 1
    [ -z "$BOOT" ] || [ "$b" = "$BOOT" ] || return 1
    BOOT=$b
    for dev in all br-lan; do
        [ "$("$BB" cat /proc/sys/net/ipv4/conf/$dev/rp_filter)" = 0 ] || return 1
        [ "$("$BB" cat /proc/sys/net/ipv4/conf/$dev/arp_ignore)" = 1 ] || return 1
        [ "$("$BB" cat /proc/sys/net/ipv4/conf/$dev/arp_filter)" = 0 ] || return 1
        [ "$("$BB" cat /proc/sys/net/ipv4/conf/$dev/arp_announce)" = 0 ] || return 1
    done
}
snapshot() {
    identity || return 1
    capture addr "$IP" -N -o -4 addr show || return 1
    capture routes "$IP" -N -o -4 route show table all || return 1
    capture rules "$IP" -N -4 rule show || return 1
    # The normal br-lan address must be preserved. Rescue label is separate.
    "$BB" awk '{gsub(/\\/," ")} $2=="br-lan" && $3=="inet" && $4=="192.168.100.51/24" {scope=label=0;for(i=5;i<=NF;i++){if($i=="scope" && $(i+1)=="0")scope++;if($i=="br-lan")label++}if(scope==1&&label==1)n++} END{exit(n!=1)}' "$DIR/addr" || return 1
    "$BB" awk 'NF {if(NF!=5||$2!="from"||$3!="all"||$4!="lookup"){bad=1;next}
      if($1=="0:"&&$5=="255")a++;else if($1=="32766:"&&$5=="254")b++;else if($1=="32767:"&&$5=="253")c++;else bad=1}
      END{exit(bad||a!=1||b!=1||c!=1)}' "$DIR/rules" || return 1
    # No default replacement. The parent-captured normal default is retained.
    "$BB" awk '$1=="default" {n++;if($2!="via"||$3!="192.168.100.1"||$4!="dev"||$5!="br-lan")bad=1} END{exit(n!=1||bad)}' "$DIR/routes" || return 1
}
count_owned() {
    # Complete dump: reject any rescue local address/label on another device,
    # prefix, scope or label. Never infer absence from a truncated command.
    "$BB" awk -v self="$SELF" -v peer="$PEER" -v tag="$TAG" '
      {gsub(/\\/," ");hit=0;for(i=1;i<=NF;i++){split($i,ip,"/");if(ip[1]==self||ip[1]==peer||$i==tag)hit=1}}
      hit {n++;ok=($2=="br-lan"&&$3=="inet"&&$4==self"/32");scope=label=flag=valid=preferred=0;
        for(i=5;i<=NF;i++){
          if($i=="scope"&&$(i+1)=="253"){scope++;i++}
          else if($i=="noprefixroute")flag++;
          else if($i==tag)label++;
          else if($i=="valid_lft"&&$(i+1)=="forever"){valid++;i++}
          else if($i=="preferred_lft"&&$(i+1)=="forever"){preferred++;i++}
          else bad=1}
        if(!ok||scope!=1||label!=1||flag!=1||valid!=1||preferred!=1)bad=1}
      END{if(bad||n>1)exit 1;print n+0}' "$DIR/addr" > "$DIR/address-count" || return 1
    # Validate only our exact /32 peer route; unrelated routes are not changed.
    # ip-full -N prints protocol186, table255/254 and scope253/254 numerically.
    # The local route type itself remains the literal local in iproute2.
    "$BB" awk -v peer="$PEER" -v self="$SELF" '
      $1==peer || $1==peer"/32" || $2==peer || $2==peer"/32" {n++;dev=src=proto=metric=scope=0;
        if($1!=peer && $1!=peer"/32")bad=1;
        for(i=2;i<=NF;i++){if($i=="dev"&&$(i+1)=="br-lan"){dev++;i++}
          else if($i=="src"&&$(i+1)==self){src++;i++}
          else if($i=="proto"&&$(i+1)=="186"){proto++;i++}
          else if($i=="metric"&&$(i+1)=="42760"){metric++;i++}
          else if($i=="scope"&&$(i+1)=="253"){scope++;i++}
          else if($i=="table"&&$(i+1)=="254"){i++}
          else bad=1}
        if(dev!=1||src!=1||proto!=1||metric!=1||scope!=1)bad=1}
      $1==self || $1==self"/32" || $2==self || $2==self"/32" {localcount++;
        if($1!="local")bad=1;dev2=src2=table2=proto2=scope2=0;
        for(i=3;i<=NF;i++){if($i=="dev"&&$(i+1)=="br-lan"){dev2++;i++}
          else if($i=="src"&&$(i+1)==self){src2++;i++}
          else if($i=="table"&&$(i+1)=="255"){table2++;i++}
          else if($i=="proto"&&$(i+1)=="2"){proto2++;i++}
          else if($i=="scope"&&$(i+1)=="254"){scope2++;i++}
          else bad=1}
        if(dev2!=1||src2!=1||table2!=1||proto2!=1||scope2!=1)bad=1}
      END{if(bad||n>1||localcount>1)exit 1;print n+0,localcount+0}' "$DIR/routes" > "$DIR/route-count" || return 1
    A=$("$BB" cat "$DIR/address-count")
    IFS=" " read -r R LOCAL < "$DIR/route-count" || return 1
    [ "$LOCAL" -eq "$A" ] || return 1
}
write_state() {
    PHASE=$1
    # Private tmpfs state, atomic rename. Do not claim storage-level fsync.
    [ ! -e "$DIR/state.next" ] && [ ! -L "$DIR/state.next" ] || return 1
    (set -C; printf 'LEON_CONTROLLER_RESCUE_V1\nboot=%s\nindex=%s\nphase=%s\n' "$BOOT" "$INDEX" "$PHASE" > "$DIR/state.next") || return 1
    "$BB" mv "$DIR/state.next" "$DIR/state" || return 1
}
load_state() {
    file0600 "$DIR/state" || return 1
    [ "$("$BB" wc -l < "$DIR/state")" -eq 4 ] || return 1
    { IFS= read -r magic; IFS= read -r b; IFS= read -r i; IFS= read -r p; } < "$DIR/state" || return 1
    [ "$magic" = LEON_CONTROLLER_RESCUE_V1 ] || return 1
    case $b in boot=*) BOOT=${b#boot=};; *) return 1;; esac
    case $i in index=*) INDEX=${i#index=};; *) return 1;; esac
    case $p in phase=*) PHASE=${p#phase=};; *) return 1;; esac
    case $PHASE in ADDR|ACTIVE|ADDR_INTENT|ROUTE_INTENT|ROUTE_DELETE|ADDR_DELETE) ;; *) return 1;; esac
    identity || return 1
    printf 'LEON_CONTROLLER_RESCUE_V1\nboot=%s\nindex=%s\nphase=%s\n' "$BOOT" "$INDEX" "$PHASE" > "$DIR/state.compare"
    "$BB" cmp -s "$DIR/state" "$DIR/state.compare"
}
cleanup_owned() {
    check_dir && load_state && snapshot && count_owned || return 1
    case $PHASE in ADDR|ACTIVE) ;; *) echo 'Pending outcome retained; no automatic retry' >&2;return 1;; esac
    if [ "$R" -eq 1 ]; then
        [ "$PHASE" = ACTIVE ] || return 1
        check_tools || return 1
        write_state ROUTE_DELETE || return 1
        "$TIMEOUT" -s TERM -k 1 3 "$IP" route del "$PEER/32" dev "$DEV" proto 186 metric 42760 src "$SELF" || return 1
        snapshot && count_owned && [ "$R" -eq 0 ] || return 1
        write_state ADDR || return 1
    fi
    if [ "$A" -eq 1 ]; then
        check_tools || return 1
        write_state ADDR_DELETE || return 1
        "$TIMEOUT" -s TERM -k 1 3 "$IP" addr del "$SELF/32" dev "$DEV" label "$TAG" || return 1
        snapshot && count_owned && [ "$A" -eq 0 ] && [ "$R" -eq 0 ] || return 1
    fi
    # Exact known files only. Foreign files make rmdir fail; never rm -rf.
    "$BB" rm -f "$DIR/state" "$DIR/state.compare" "$DIR/addr" "$DIR/routes" "$DIR/rules" "$DIR/address-count" "$DIR/route-count" || return 1
    release_lock || return 1
    "$BB" rmdir "$DIR" || return 1
    echo 'LEON_RESCUE_CONTROLLER cleanup=complete normal_lan=preserved'
}

if [ "$ACTION" = --cleanup-owned ]; then
    check_dir && take_lock || die cleanup-lock
    cleanup_owned || die cleanup-refused
    exit 0
fi
[ ! -e "$DIR" ] && [ ! -L "$DIR" ] || die existing-state
"$BB" mkdir -m 700 "$DIR" || die private-directory
take_lock || die operation-lock
check_dir && snapshot && count_owned || die preflight
[ "$A" -eq 0 ] && [ "$R" -eq 0 ] || die preexisting-rescue-state
check_tools || die fixed-tools
write_state ADDR_INTENT || die address-intent
"$TIMEOUT" -s TERM -k 1 3 "$IP" addr add "$SELF/32" dev "$DEV" scope link label "$TAG" noprefixroute || die address-add-unknown
snapshot && count_owned && [ "$A" -eq 1 ] && [ "$R" -eq 0 ] || die address-readback
write_state ADDR || die address-receipt
check_tools || die fixed-tools
write_state ROUTE_INTENT || die route-intent
"$TIMEOUT" -s TERM -k 1 3 "$IP" route add "$PEER/32" dev "$DEV" scope link proto 186 metric 42760 src "$SELF" || die route-add-unknown
snapshot && count_owned && [ "$A" -eq 1 ] && [ "$R" -eq 1 ] || die route-readback
write_state ACTIVE || die active-receipt
echo 'LEON_RESCUE_CONTROLLER configured=169.254.190.51/32 peer=169.254.190.15/32 normal_lan=preserved'
echo 'No SSH success claim. Verify peer Ethernet MAC and existing native host key before login.'

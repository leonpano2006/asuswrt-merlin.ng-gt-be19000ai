#!/bin/sh
# SOURCE-ONLY: pending timeout literals intentionally make this non-executable.
# Resume only the captured prepared public-key transaction. Never take/remove
# its lock, create a new transaction, read private keys, or retry publication.
set -eu
set -o pipefail
umask 077
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BB=/bin/busybox
TOOLS=/tmp/leon-uplink-rescue-tools
TIMEOUT=$TOOLS/timeout-run.sh
SYNC=$TOOLS/known-host-fsync
KH=/root/.ssh/known_hosts
LOCK=/root/.ssh/.leon-native-2223-enroll
BACKUP=$LOCK/backup
CAND=$LOCK/candidate
RECEIPT=$LOCK/receipt
OLD_HASH=dd671dbe288806c45e79940c62d3fa58f7f2469b950a414901b380c9b70c64d0
NEW_HASH=38624da2217743620b0fd6f952dcd07bd657adce56e443c7e916121f0d282ae6
RECEIPT_HASH=19e2549b4ec3f5aacdcaeef9154496ae0d04db5e37adb10d9c1de699f75935ba
KEY=AAAAC3NzaC1lZDI1NTE5AAAAIHmlNoSkQZrtS2uhr5dG1+qzMXLyYghF6NJjVcfniuNY
TIMEOUT_SHA=eee267c8317aff3902f573c1e5f0052a723b2a3521cb2903377caea04ec8c7df
TIMEOUT_SIZE=33264
TIMEOUT_WRAPPER_SHA=f887d0cdd35e3b87429e6553ee86cc83e9018315f3eac644813859d56e8ae27c
TIMEOUT_WRAPPER_SIZE=303
# Closure pinning will be finalized only after readelf/source receipt review.
TIMEOUT_CLOSURE_READY=reviewed-private-musl-libgcc

[ "$#" -eq 1 ] && [ "$1" = --resume-captured-public-2223 ] || exit 125
die() { echo "LEON_PUBLIC_HOSTPIN_RESUME refused=$1 retained_transaction=$LOCK" >&2; exit 125; }
case "$TIMEOUT_SHA:$TIMEOUT_SIZE:$TIMEOUT_WRAPPER_SHA:$TIMEOUT_WRAPPER_SIZE:$TIMEOUT_CLOSURE_READY" in
    *PENDING*) die source-only-timeout-pins-pending;;
esac
trap 'die interrupted-no-retry' HUP INT TERM

meta() {
    [ ! -L "$1" ] || return 1
    "$BB" ls -ldni "$1" | "$BB" awk -v p="$1" '
      NR==1 {ok=(NF==10&&$1~/^[0-9]+$/&&$3~/^[0-9]+$/&&$3>0&&$4==0&&$5==0&&$6~/^[0-9]+$/&&$10==p);
        if(ok)print $1,$2,$3,$4,$5,$6,$10}
      END {exit(NR!=1||!ok)}'
}
directory() {
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    meta "$1" | "$BB" awk -v inode="$2" -v mode="$3" '
      NR==1 {ok=($2==mode&&$3>0&&(inode=="any"||$1==inode))} END{exit(NR!=1||!ok)}'
}
regular() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    meta "$1" | "$BB" awk -v inode="$2" -v mode="$3" -v size="$4" '
      NR==1 {ok=($2==mode&&$3==1&&$6==size&&(inode=="any"||$1==inode))} END{exit(NR!=1||!ok)}'
}
hash() {
    "$BB" sha256sum "$1" | "$BB" awk 'NR==1&&$1~/^[0-9a-f]+$/&&length($1)==64{h=$1} END{if(NR!=1||h=="")exit 1;print h}'
}
parents() {
    [ "$("$BB" id -u)" = 0 ] || return 1
    directory /root any drwxr-x--- && directory /root/.ssh any drwxr-xr-x || return 1
    directory "$LOCK" 139 drwx------ || return 1
}
same_mount() {
    # mv must use same-mount rename, never its cross-filesystem copy fallback.
    # Mountinfo is read only; all fixed transaction paths have no escapes.
    "$BB" awk -v parent=/root/.ssh -v lock="$LOCK" -v a="$KH" -v b="$CAND" '
      BEGIN {p[1]=parent;p[2]=lock;p[3]=a;p[4]=b}
      NF<10||$1!~/^[0-9]+$/||$3!~/^[0-9]+:[0-9]+$/ {bad=1;next}
      {m=$5;for(i=1;i<=4;i++)if(m=="/"||p[i]==m||index(p[i],m"/")==1) {
        if(length(m)>len[i]){len[i]=length(m);id[i]=$1;dev[i]=$3}}}
      END {for(i=1;i<=4;i++)if(!len[i]||id[i]!=id[1]||dev[i]!=dev[1])bad=1;exit(bad)}' /proc/self/mountinfo
}
tool_metadata() {
    directory "$TOOLS" 170477 drwx------ && directory "$TOOLS/bin" 170479 drwxr-xr-x && directory "$TOOLS/lib" 170480 drwxr-xr-x || return 1
    regular "$SYNC" any -rwxr-xr-x 2000 || return 1
    regular "$TIMEOUT" any -rwxr-xr-x "$TIMEOUT_WRAPPER_SIZE" || return 1
    regular "$TOOLS/bin/timeout" any -rwxr-xr-x "$TIMEOUT_SIZE" || return 1
    regular "$TOOLS/lib/libc.so" any -rwxr-xr-x 508607 || return 1
    regular "$TOOLS/lib/libgcc_s.so.1" any -rw-r--r-- 45058 || return 1
}
tool_hashes() {
    [ "$TIMEOUT_CLOSURE_READY" = reviewed-private-musl-libgcc ] || return 1
    [ "$(hash "$SYNC")" = 9c5cdb1d8e0536727b33ef246b0a5c70bf5feedf85fdf18d0100e0afdcb5e69f ] || return 1
    [ "$(hash "$TIMEOUT")" = "$TIMEOUT_WRAPPER_SHA" ] || return 1
    [ "$(hash "$TOOLS/bin/timeout")" = "$TIMEOUT_SHA" ] || return 1
    [ "$(hash "$TOOLS/lib/libc.so")" = fbc1ac4517f9218e97eeaeed31ccc37ec70c02992cb953e82cc911f08a710e30 ] || return 1
    [ "$(hash "$TOOLS/lib/libgcc_s.so.1")" = 212ec73048315d4d174b8c8ee3c98f32a29c59fec69677b1dc88802b4021ea2b ] || return 1
}
prepared_metadata() {
    parents && same_mount || return 1
    regular "$KH" 187 -rw------- 558 && regular "$BACKUP" 806 -rw------- 558 &&
        regular "$CAND" 807 -rw------- 670 && regular "$RECEIPT" 808 -rw------- 268
}
prepared_contents() {
    [ "$(hash "$KH")" = "$OLD_HASH" ] && [ "$(hash "$BACKUP")" = "$OLD_HASH" ] &&
        [ "$(hash "$CAND")" = "$NEW_HASH" ] && [ "$(hash "$RECEIPT")" = "$RECEIPT_HASH" ] || return 1
    expected_receipt_hash=$("$BB" sha256sum <<'LEON_EXACT_RECEIPT' | "$BB" awk 'NR==1{h=$1} END{if(NR!=1)exit 1;print h}'
LEON_PUBLIC_2223_PREPARED_V1
old_inode=187
old_mode=600
old_bytes=558
old_sha256=dd671dbe288806c45e79940c62d3fa58f7f2469b950a414901b380c9b70c64d0
candidate_inode=807
candidate_bytes=670
candidate_sha256=38624da2217743620b0fd6f952dcd07bd657adce56e443c7e916121f0d282ae6
LEON_EXACT_RECEIPT
    ) || return 1
    [ "$expected_receipt_hash" = "$RECEIPT_HASH" ] || return 1
    [ "$("$BB" head -c 558 "$CAND" | "$BB" sha256sum | "$BB" awk '{print $1}')" = "$OLD_HASH" ] || return 1
    [ "$( { "$BB" cat "$BACKUP"; printf '[leon-ubuntu26-be19000ai]:2223 ssh-ed25519 %s\n' "$KEY"; } | "$BB" sha256sum | "$BB" awk '{print $1}')" = "$NEW_HASH" ] || return 1
    "$BB" awk -v key="$KEY" '
      /^[[:space:]]*#/||NF==0 {next}
      {marked=($1~/^@/);hosts=marked?$2:$1;type=marked?$3:$2;pub=marked?$4:$3;
        n=split(hosts,a,",");for(i=1;i<=n;i++){
          if(a[i]=="leon-ubuntu26-be19000ai"){normal++;if(marked||type!="ssh-ed25519"||pub!=key)bad=1}
          if(a[i]=="[leon-ubuntu26-be19000ai]:2222"){old++;if(marked||type!="ssh-ed25519"||pub!=key)bad=1}
          if(a[i]=="[leon-ubuntu26-be19000ai]:2223")bad=1}}
      END {exit(bad||normal!=1||old!=1)}' "$BACKUP"
}
bounded_sync() {
    tool_metadata && tool_hashes || return 1
    "$TIMEOUT" -s TERM -k 1 10 "$SYNC" "$1" "$2"
}

# Validate every transaction/tool object before any content hash or new tool
# execution. All hashes/readback concern public files, never an identity key.
prepared_metadata && tool_metadata || die captured-metadata-mismatch
prepared_contents && tool_hashes || die captured-content-mismatch
bounded_sync file "$BACKUP" || die backup-fsync
bounded_sync file "$CAND" || die candidate-fsync
bounded_sync file "$RECEIPT" || die receipt-fsync
bounded_sync dir "$LOCK" || die prepared-directory-fsync
bounded_sync dir /root/.ssh || die prepared-parent-fsync

# Last full identity/content checks immediately precede same-mount rename.
# Root-only retained lock coordinates this transaction; unrelated privileged
# writers are not excluded by an advisory directory or shell TOCTOU checks.
prepared_metadata && prepared_contents || die changed-before-publication
regular "$KH" 187 -rw------- 558 && [ "$(hash "$KH")" = "$OLD_HASH" ] &&
    regular "$CAND" 807 -rw------- 670 && [ "$(hash "$CAND")" = "$NEW_HASH" ] || die changed-last-moment
"$BB" mv "$CAND" "$KH" || die rename-outcome-unknown
bounded_sync dir /root/.ssh || die published-parent-fsync
bounded_sync dir "$LOCK" || die published-source-directory-fsync
parents && regular "$KH" 807 -rw------- 670 && [ "$(hash "$KH")" = "$NEW_HASH" ] || die published-readback
regular "$BACKUP" 806 -rw------- 558 && [ "$(hash "$BACKUP")" = "$OLD_HASH" ] &&
    regular "$RECEIPT" 808 -rw------- 268 && [ "$(hash "$RECEIPT")" = "$RECEIPT_HASH" ] || die retained-evidence-changed
[ ! -e "$CAND" ] && [ ! -L "$CAND" ] || die candidate-still-present
printf '{"schema":1,"status":"captured_public_2223_transaction_resumed","known_hosts_inode":807,"known_hosts_sha256":"%s","backup_retained":true,"lock_retained":true,"receipt_retained":true,"private_key_read":false,"network_changed":false}\n' "$NEW_HASH"

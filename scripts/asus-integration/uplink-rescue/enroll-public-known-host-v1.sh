#!/bin/sh
# Candidate transaction, not yet executed. Public host trust only.
# Retain backup and prepared receipt even after success; never retake a lock.
set -eu
set -o pipefail
umask 077
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BB=/bin/busybox
KH=/root/.ssh/known_hosts
LOCK=/root/.ssh/.leon-native-2223-enroll
SYNC=/tmp/leon-uplink-rescue-tools/known-host-fsync
SYNC_SHA=9c5cdb1d8e0536727b33ef246b0a5c70bf5feedf85fdf18d0100e0afdcb5e69f
SYNC_SIZE=2000
KEY=AAAAC3NzaC1lZDI1NTE5AAAAIHmlNoSkQZrtS2uhr5dG1+qzMXLyYghF6NJjVcfniuNY
[ "$#" -eq 1 ] && [ "$1" = --enroll-fixed-public-2223 ] || exit 125
die() { echo "LEON_PUBLIC_HOSTPIN refused=$1 backup_retained=$LOCK" >&2; exit 125; }
hash() { "$BB" sha256sum "$1" | "$BB" awk 'NR==1&&$1~/^[0-9a-f]+$/&&length($1)==64{h=$1} END{if(NR!=1||h=="")exit 1;print h}'; }
meta() {
    [ ! -L "$1" ] || return 1
    "$BB" ls -ldni "$1" | "$BB" awk -v p="$1" '
      NR==1{ok=(NF==10&&$1~/^[0-9]+$/&&$3~/^[0-9]+$/&&$4==0&&$5==0&&$6~/^[0-9]+$/&&$10==p);
        if(ok)print $1,$2,$3,$4,$5,$6,$10}
      END{exit(NR!=1||!ok)}'
}
parents() {
    [ "$("$BB" id -u)" = 0 ] || return 1
    [ -d /root ] && [ -d /root/.ssh ] || return 1
    m=$(meta /root) || return 1
    [ "${m#* }" = "drwxr-x--- 1 0 0 0 /root" ] || return 1
    m=$(meta /root/.ssh) || return 1
    # Only permissions/owner/type are fixed: directory nlink/size may change
    # when this transaction creates its new child directory.
    echo "$m" | "$BB" awk '$2=="drwxr-xr-x"&&$3>0&&$4==0&&$5==0{ok=1}END{exit(!ok)}'
}
regular() {
    [ -f "$1" ] || return 1
    m=$(meta "$1") || return 1
    echo "$m" | "$BB" awk -v mode="$2" -v max="$3" '$2==mode&&$3==1&&$6>0&&$6<=max{ok=1}END{exit(!ok)}'
}
parents || die parent-preflight
meta /tmp/leon-uplink-rescue-tools | "$BB" awk '$2=="drwx------"&&$3>0{ok=1}END{exit(!ok)}' || die helper-parent
regular "$SYNC" -rwxr-xr-x "$SYNC_SIZE" && [ "$(hash "$SYNC")" = "$SYNC_SHA" ] || die fsync-helper
[ "$(meta "$SYNC" | "$BB" awk '{print $6}')" -eq "$SYNC_SIZE" ] || die fsync-helper-size
OLD_META=$(meta "$KH") || die known-host-metadata
set -- $OLD_META
OLD_INODE=$1 OLD_PERMS=$2 OLD_SIZE=$6
case $OLD_PERMS in -rw-------) MODE=600;; -rw-r--r--) MODE=644;; *) die known-host-mode;; esac
regular "$KH" "$OLD_PERMS" 1048576 || die known-host-type
OLD_HASH=$(hash "$KH") || die known-host-hash
[ "$("$BB" tail -c 1 "$KH" | "$BB" wc -l)" -eq 1 ] || die final-newline
[ ! -e "$LOCK" ] && [ ! -L "$LOCK" ] || die existing-lock
"$BB" mkdir -m 700 "$LOCK" || die lock
parents && [ "$(meta "$KH")" = "$OLD_META" ] && [ "$(hash "$KH")" = "$OLD_HASH" ] || die changed-after-lock
NEW_PRESENT=$("$BB" awk -v key="$KEY" '
  /^[[:space:]]*#/||NF==0{next}
  {marked=($1~/^@/);hosts=marked?$2:$1;type=marked?$3:$2;pub=marked?$4:$3;
   n=split(hosts,a,",");for(i=1;i<=n;i++){
    if(a[i]=="leon-ubuntu26-be19000ai"){normal++;if(marked||type!="ssh-ed25519"||pub!=key)bad=1}
    if(a[i]=="[leon-ubuntu26-be19000ai]:2222"){oldport++;if(marked||type!="ssh-ed25519"||pub!=key)bad=1}
    if(a[i]=="[leon-ubuntu26-be19000ai]:2223"){newport++;if(marked||type!="ssh-ed25519"||pub!=key)bad=1}}}
  END{if(bad||normal!=1||oldport!=1||newport>1)exit 1;print newport+0}' "$KH") || die conflicting-public-trust
if [ "$NEW_PRESENT" -eq 1 ]; then
    parents && [ "$(meta "$KH")" = "$OLD_META" ] && [ "$(hash "$KH")" = "$OLD_HASH" ] || die changed-idempotent
    "$BB" rmdir "$LOCK" || die empty-lock-release
    printf '{"schema":1,"status":"fixed_public_2223_already_present","changed":false,"known_hosts_sha256":"%s"}\n' "$OLD_HASH"
    exit 0
fi
BACKUP=$LOCK/backup
CAND=$LOCK/candidate
RECEIPT=$LOCK/receipt
(set -C; "$BB" cat "$KH" > "$BACKUP") || die backup-create
regular "$BACKUP" -rw------- 1048576 && [ "$(hash "$BACKUP")" = "$OLD_HASH" ] || die backup-readback
(set -C; { "$BB" cat "$BACKUP"; printf '[leon-ubuntu26-be19000ai]:2223 ssh-ed25519 %s\n' "$KEY"; } > "$CAND") || die candidate-create
regular "$CAND" -rw------- 1048800 || die candidate-type
[ "$("$BB" head -c "$OLD_SIZE" "$CAND" | "$BB" sha256sum | "$BB" awk '{print $1}')" = "$OLD_HASH" ] || die original-prefix
NEW_HASH=$(hash "$CAND") || die candidate-hash
"$BB" chmod "$MODE" "$CAND" || die preserve-mode
CAND_META=$(meta "$CAND") || die candidate-metadata
set -- $CAND_META
CAND_INODE=$1 NEW_SIZE=$6
[ "$2" = "$OLD_PERMS" ] && [ "$3" = 1 ] || die candidate-final-mode
(set -C; printf 'LEON_PUBLIC_2223_PREPARED_V1\nold_inode=%s\nold_mode=%s\nold_bytes=%s\nold_sha256=%s\ncandidate_inode=%s\ncandidate_bytes=%s\ncandidate_sha256=%s\n' "$OLD_INODE" "$MODE" "$OLD_SIZE" "$OLD_HASH" "$CAND_INODE" "$NEW_SIZE" "$NEW_HASH" > "$RECEIPT") || die prepared-receipt
"$BB" timeout -s TERM -k 1 10 "$SYNC" file "$BACKUP" || die backup-fsync
"$BB" timeout -s TERM -k 1 10 "$SYNC" file "$CAND" || die candidate-fsync
"$BB" timeout -s TERM -k 1 10 "$SYNC" file "$RECEIPT" || die receipt-fsync
"$BB" timeout -s TERM -k 1 10 "$SYNC" dir "$LOCK" || die prepared-directory-fsync
"$BB" timeout -s TERM -k 1 10 "$SYNC" dir /root/.ssh || die prepared-parent-fsync
# Last checks before same-filesystem atomic rename. This coordinates our own
# transaction; it makes no claim to exclude an unrelated privileged writer.
parents && [ "$(meta "$KH")" = "$OLD_META" ] && [ "$(hash "$KH")" = "$OLD_HASH" ] &&
    [ "$(meta "$CAND")" = "$CAND_META" ] && [ "$(hash "$CAND")" = "$NEW_HASH" ] || die publish-preflight
"$BB" mv "$CAND" "$KH" || die rename-unknown
"$BB" timeout -s TERM -k 1 10 "$SYNC" dir /root/.ssh || die published-directory-fsync
parents && regular "$KH" "$OLD_PERMS" 1048800 && [ "$(hash "$KH")" = "$NEW_HASH" ] || die published-readback
set -- $(meta "$KH")
[ "$1" = "$CAND_INODE" ] && [ "$6" = "$NEW_SIZE" ] || die published-inode
printf '{"schema":1,"status":"fixed_public_2223_enrolled","changed":true,"old_sha256":"%s","known_hosts_sha256":"%s","backup":"%s","private_key_read":false}\n' "$OLD_HASH" "$NEW_HASH" "$BACKUP"

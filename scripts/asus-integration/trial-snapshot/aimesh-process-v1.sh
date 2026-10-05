#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Read only fixed, bounded process metadata; never argv, environment or contents.
set +x
set -u -o pipefail
PATH=/usr/bin:/usr/sbin
LC_ALL=C
export PATH LC_ALL
umask 077
RC_EXE=/usr/libexec/asus/rc
BUSYBOX_EXE=/usr/libexec/asus/busybox
LLDPD_EXE=/usr/libexec/asus/vendor/usr/sbin/lldpd

# The service's outer timeout bounds this entire helper to 5s. Timed streams
# are capped at 8KiB. Buffered candidate data is emitted only after identity
# checks; neither a zero match count nor a missing END proves no hang.
capture() {
    CAPTURE_DATA=$(/usr/bin/timeout --signal=TERM --kill-after=1s 1s "$@" 2>&1 |
        /usr/bin/head -c 8192)
    CAPTURE_RC=$?
}

read_comm() {
    local pid=$1 raw= result
    COMM_DATA=
    # The pinned kernel exposes at most 15 comm bytes plus one newline. A Bash
    # builtin avoids one external process for every nonmatching proc entry.
    # -d '' preserves the newline; accept short EOF only with one final newline.
    IFS= read -r -d '' -n 16 raw 2>/dev/null < "/proc/$pid/comm"
    result=$?
    if [[ ( "$result" != 0 && "$result" != 1 ) || "$raw" != *$'\n' ]]; then
        return 1
    fi
    COMM_DATA=${raw%$'\n'}
    [[ -n "$COMM_DATA" && ${#COMM_DATA} -le 15 && "$COMM_DATA" != *$'\n'* ]]
}

identity() {
    local pid=$1 raw tail expected
    local -a fields=()
    ID_COMM= ID_EXE= ID_START= ID_PPID= ID_STATE= ID_REASON=
    if ! read_comm "$pid"; then ID_REASON=comm-read-or-format; return 1; fi
    case "$COMM_DATA" in
        amas_bhctrl|amas_status|amas_lanctrl|amas_misc|amas_wlcconnect) expected=$RC_EXE ;;
        lldpd) expected=$LLDPD_EXE ;;
        udhcpc) expected=$BUSYBOX_EXE ;;
        *) ID_REASON=comm-unmatched; return 1 ;;
    esac
    ID_COMM=$COMM_DATA
    capture /usr/bin/readlink "/proc/$pid/exe"
    if [[ "$CAPTURE_RC" != 0 ]]; then ID_REASON=exe-read; return 1; fi
    if [[ "$CAPTURE_DATA" != "$expected" ]]; then ID_REASON=exe-unmatched; return 1; fi
    ID_EXE=$CAPTURE_DATA
    capture /usr/bin/head -c 8192 "/proc/$pid/stat"
    if [[ "$CAPTURE_RC" != 0 ]]; then ID_REASON=stat-read; return 1; fi
    raw=$CAPTURE_DATA
    if [[ "$raw" != "$pid ("*") "* ]]; then ID_REASON=stat-format; return 1; fi
    # comm can contain ')' and spaces: starttime field22 follows the last ') '.
    tail=${raw##*) }
    read -r -a fields <<< "$tail"
    if [[ ${#fields[@]} -lt 20 || ! "${fields[19]}" =~ ^[0-9]+$ ||
        ! "${fields[1]}" =~ ^[0-9]+$ || ! "${fields[0]}" =~ ^[RSDZTWIPtXxK]$ ]]; then
        ID_REASON=stat-format
        return 1
    fi
    ID_START=${fields[19]} ID_PPID=${fields[1]} ID_STATE=${fields[0]}
}

emit_stream() {
    local label=$1 result=$2 data=$3
    printf 'TRIAL_AIMESH_PROCESS section=%s rc=%s bytes=%s begin\n' "$label" "$result" "${#data}"
    printf '%s\n' "$data"
    printf 'TRIAL_AIMESH_PROCESS section=%s end\n' "$label"
}

stat_metadata() {
    capture /usr/bin/stat --format='type=%F mode=%a uid=%u gid=%g bytes=%s inode=%i device=%D links=%h mtime=%Y' -- "$1"
    [[ "$CAPTURE_RC" == 0 ]] || ((file_stat_failed+=1))
    # No -L and no %N: stat final-component metadata, never contents or targets.
}

capture_process() {
    local pid=$1 pre_comm=$ID_COMM pre_exe=$ID_EXE pre_start=$ID_START
    local pre_ppid=$ID_PPID pre_state=$ID_STATE post_state
    local status_data status_rc status_line cgroup_data cgroup_rc wchan_data wchan_rc
    local syscall_data syscall_rc mount_data mount_rc post_mount_data post_mount_rc
    local root_pre= root_pre_rc= root_kind=unavailable root_post= root_post_rc=
    local file_view=0 socket_data= socket_rc= directory_data= directory_rc= script_data= script_rc=
    printf 'TRIAL_AIMESH_PROCESS pid=%s capture=begin\n' "$pid"
    capture /usr/bin/head -c 8192 "/proc/$pid/status"
    status_data= status_rc=$CAPTURE_RC
    while IFS= read -r status_line; do
        case "$status_line" in
            State:*|PPid:*|Uid:*|Gid:*) status_data+="$status_line"$'\n' ;;
        esac
    done <<< "$CAPTURE_DATA"
    capture /usr/bin/head -c 8192 "/proc/$pid/cgroup"
    cgroup_data=$CAPTURE_DATA cgroup_rc=$CAPTURE_RC
    capture /usr/bin/head -c 8192 "/proc/$pid/wchan"
    wchan_data=$CAPTURE_DATA wchan_rc=$CAPTURE_RC
    capture /usr/bin/head -c 8192 "/proc/$pid/syscall"
    syscall_data=$CAPTURE_DATA syscall_rc=$CAPTURE_RC
    capture /usr/bin/readlink "/proc/$pid/ns/mnt"
    mount_data=$CAPTURE_DATA mount_rc=$CAPTURE_RC
    capture /usr/bin/readlink "/proc/$pid/root"
    root_pre=$CAPTURE_DATA root_pre_rc=$CAPTURE_RC
    if [[ "$root_pre_rc" == 0 ]]; then
        case "$root_pre" in
            /) root_kind=known-outer-root ;;
            /run/lldpd|/var/run/lldpd) root_kind=known-lldpd-chroot ;;
            *) root_kind=unapproved ;;
        esac
    fi
    # One committed outer process view is enough. Preserve kernel magic-link
    # lookup through /proc/PID/root; readlink -e would resolve its '/' text in
    # the reader's namespace and lose the daemon's private mount view.
    if [[ "$root_kind" == known-outer-root && "$outer_file_view_committed" == 0 ]]; then
        file_view=1
        stat_metadata "/proc/$pid/root/var/run/lldpd.socket"
        socket_data=$CAPTURE_DATA socket_rc=$CAPTURE_RC
        stat_metadata "/proc/$pid/root/var/run/lldpd"
        directory_data=$CAPTURE_DATA directory_rc=$CAPTURE_RC
        stat_metadata "/proc/$pid/root/tmp/run_lldpd.sh"
        script_data=$CAPTURE_DATA script_rc=$CAPTURE_RC
    else
        ((process_root_file_view_skipped+=1))
    fi
    capture /usr/bin/readlink "/proc/$pid/ns/mnt"
    post_mount_data=$CAPTURE_DATA post_mount_rc=$CAPTURE_RC
    capture /usr/bin/readlink "/proc/$pid/root"
    root_post=$CAPTURE_DATA root_post_rc=$CAPTURE_RC
    if ! identity "$pid" || [[ "$ID_COMM" != "$pre_comm" || "$ID_EXE" != "$pre_exe" ||
        "$ID_START" != "$pre_start" || "$ID_PPID" != "$pre_ppid" ]] ||
        [[ "$mount_rc" != "$post_mount_rc" || "$mount_data" != "$post_mount_data" ]] ||
        [[ "$root_pre_rc" != "$root_post_rc" || "$root_pre" != "$root_post" ]]; then
        # No candidate stream or filesystem metadata is published on a race.
        status_data= cgroup_data= wchan_data= syscall_data= mount_data=
        socket_data= directory_data= script_data=
        printf 'TRIAL_AIMESH_PROCESS pid=%s capture=discarded reason=post-identity-or-namespace-raced\n' "$pid"
        ((discarded+=1))
        return
    fi
    post_state=$ID_STATE
    printf 'TRIAL_AIMESH_PROCESS pid=%s capture=committed comm=%s exe=%s pre_starttime=%s post_starttime=%s pre_ppid=%s post_ppid=%s pre_state=%s post_state=%s root_kind=%s root_readlink_rc=%s\n' \
        "$pid" "$pre_comm" "$pre_exe" "$pre_start" "$ID_START" "$pre_ppid" "$ID_PPID" \
        "$pre_state" "$post_state" "$root_kind" "$root_pre_rc"
    emit_stream status "$status_rc" "$status_data"
    emit_stream cgroup "$cgroup_rc" "$cgroup_data"
    emit_stream wchan "$wchan_rc" "$wchan_data"
    emit_stream syscall "$syscall_rc" "$syscall_data"
    emit_stream mount-namespace "$mount_rc" "$mount_data"
    if [[ "$file_view" == 1 ]]; then
        printf 'TRIAL_AIMESH_PROCESS file_view=stable-process-root canonical_root=/ host_view_equivalence_not_assumed=true\n'
        emit_stream process-root-var-run-lldpd-socket "$socket_rc" "$socket_data"
        emit_stream process-root-var-run-lldpd-directory "$directory_rc" "$directory_data"
        emit_stream process-root-tmp-run-lldpd-script-stat "$script_rc" "$script_data"
        outer_file_view_committed=1
    else
        printf 'TRIAL_AIMESH_PROCESS file_view=skipped reason=outer-view-unavailable-or-already-captured\n'
    fi
    ((committed+=1))
}

finish_scan() {
    local result=$1
    printf 'TRIAL_AIMESH_PROCESS_END schema=1 scan_status=%s scan_reason=%s exit_rc=%s proc_enumerated=%s proc_visited=%s proc_scanned=%s proc_ineligible=%s matched=%s committed=%s discarded=%s comm_read_or_format_rejected=%s comm_unmatched=%s exe_read_rejected=%s exe_unmatched=%s stat_read_rejected=%s stat_format_rejected=%s match_cap_reached=%s process_root_file_view_skipped=%s outer_file_view_committed=%s file_stat_failed=%s zero_matches_proves_no_hang=false\n' \
        "$scan_status" "$scan_reason" "$result" "$proc_enumerated" "$proc_visited" "$proc_scanned" "$proc_ineligible" \
        "$matched" "$committed" "$discarded" "$comm_read_or_format_rejected" "$comm_unmatched" \
        "$exe_read_rejected" "$exe_unmatched" "$stat_read_rejected" "$stat_format_rejected" "$match_cap_reached" \
        "$process_root_file_view_skipped" "$outer_file_view_committed" "$file_stat_failed"
}

proc_enumerated=0 proc_visited=0 proc_scanned=0 proc_ineligible=0
matched=0 committed=0 discarded=0 comm_read_or_format_rejected=0 comm_unmatched=0
exe_read_rejected=0 exe_unmatched=0 stat_read_rejected=0 stat_format_rejected=0
match_cap_reached=0 process_root_file_view_skipped=0 outer_file_view_committed=0 file_stat_failed=0
scan_status=incomplete scan_reason=unexpected-exit
trap 'scan_status=incomplete; scan_reason=term-or-outer-timeout; exit 143' TERM
trap 'scan_status=incomplete; scan_reason=interrupt; exit 130' INT
trap 'scan_status=incomplete; scan_reason=hangup; exit 129' HUP
trap 'finish_scan "$?"' EXIT
printf 'TRIAL_AIMESH_PROCESS_BEGIN schema=1 max_processes=16 per_stream_bytes=8192 global_deadline_seconds=5 end_marker_required=true complete_scope=bounded-traversal\n'
printf 'TRIAL_AIMESH_PROCESS file_view=service-private-namespace daemon_view_equivalence_not_assumed=true\n'
stat_metadata /run/lldpd.socket
emit_stream service-run-lldpd-socket "$CAPTURE_RC" "$CAPTURE_DATA"
stat_metadata /run/lldpd
emit_stream service-run-lldpd-directory "$CAPTURE_RC" "$CAPTURE_DATA"
stat_metadata /tmp/run_lldpd.sh
emit_stream service-tmp-run-lldpd-script-stat "$CAPTURE_RC" "$CAPTURE_DATA"
printf 'TRIAL_AIMESH_PROCESS private_etc_socket=skipped reason=no-source-bound-etc-socket-alias no_contents_read=true\n'
proc_entries=(/proc/[0-9]*)
proc_enumerated=${#proc_entries[@]}
for procdir in "${proc_entries[@]}"; do
    ((proc_visited+=1))
    if [[ ! -d "$procdir" || -L "$procdir" ]]; then ((proc_ineligible+=1)); continue; fi
    pid=${procdir##*/}
    if [[ ! "$pid" =~ ^[0-9]+$ ]]; then ((proc_ineligible+=1)); continue; fi
    ((proc_scanned+=1))
    if ! identity "$pid"; then
        case "$ID_REASON" in
            comm-read-or-format) ((comm_read_or_format_rejected+=1)) ;;
            comm-unmatched) ((comm_unmatched+=1)) ;;
            exe-read) ((exe_read_rejected+=1)) ;;
            exe-unmatched) ((exe_unmatched+=1)) ;;
            stat-read) ((stat_read_rejected+=1)) ;;
            stat-format) ((stat_format_rejected+=1)) ;;
        esac
        continue
    fi
    ((matched+=1))
    capture_process "$pid"
    if [[ "$matched" -ge 16 ]]; then match_cap_reached=1; break; fi
done
if [[ "$match_cap_reached" == 1 ]]; then
    scan_status=incomplete scan_reason=process-cap
else
    scan_status=complete scan_reason=bounded-traversal-finished
fi
exit 0

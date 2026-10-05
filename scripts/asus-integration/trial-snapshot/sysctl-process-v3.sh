#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Read only bounded proc metadata. Never read config, environment, argv or FD contents.
set +x
set -u -o pipefail
PATH=/usr/bin:/usr/sbin
LC_ALL=C
export PATH LC_ALL
umask 077
EXPECTED_EXE=/usr/lib/systemd/systemd-sysctl
# The pinned systemd-udevd alias is ../../bin/udevadm; proc exe names the ELF.
UDEV_EXE=/usr/bin/udevadm

# The ExecStartPost timeout bounds the complete scan to 20s. Each stream is
# separately timed and capped; output remains in shell variables until PID reuse
# and exec races have been excluded by a second executable/starttime check.
capture() {
    CAPTURE_DATA=$(/usr/bin/timeout --signal=TERM --kill-after=1s 1s "$@" 2>&1 |
        /usr/bin/head -c 8192)
    CAPTURE_RC=$?
}

identity() {
    local pid=$1 expected=$2 raw tail
    local -a fields=()
    ID_EXE= ID_START= ID_PPID=
    capture /usr/bin/readlink "/proc/$pid/exe"
    [[ "$CAPTURE_RC" == 0 && "$CAPTURE_DATA" == "$expected" ]] || return 1
    ID_EXE=$CAPTURE_DATA
    capture /usr/bin/cat "/proc/$pid/stat"
    [[ "$CAPTURE_RC" == 0 ]] || return 1
    raw=$CAPTURE_DATA
    [[ "$raw" == "$pid ("*") "* ]] || return 1
    # comm may contain ')' and spaces: remove through the last ') ' delimiter.
    # The remaining array begins at field3; starttime field22 is index19.
    tail=${raw##*) }
    read -r -a fields <<< "$tail"
    [[ ${#fields[@]} -ge 20 && "${fields[19]}" =~ ^[0-9]+$ && "${fields[1]}" =~ ^[0-9]+$ ]] || return 1
    ID_START=${fields[19]}
    ID_PPID=${fields[1]}
}

emit_stream() {
    local label=$1 result=$2 data=$3
    printf 'TRIAL_SYSCTL_PROCESS section=%s rc=%s bytes=%s begin\n' "$label" "$result" "${#data}"
    printf '%s\n' "$data"
    printf 'TRIAL_SYSCTL_PROCESS section=%s end\n' "$label"
}

zombie_identity() {
    local pid=$1 worker=$2 raw tail
    local -a fields=()
    Z_START= Z_PPID= Z_EXE_RC=
    capture /usr/bin/cat "/proc/$pid/stat"
    [[ "$CAPTURE_RC" == 0 ]] || return 1
    raw=$CAPTURE_DATA
    [[ "$raw" == "$pid ("*") "* ]] || return 1
    tail=${raw##*) }
    read -r -a fields <<< "$tail"
    [[ ${#fields[@]} -ge 20 && "${fields[0]}" == Z && "${fields[1]}" == "$worker" &&
        "${fields[1]}" =~ ^[0-9]+$ && "${fields[19]}" =~ ^[0-9]+$ ]] || return 1
    Z_START=${fields[19]} Z_PPID=${fields[1]}
    capture /usr/bin/readlink "/proc/$pid/exe"
    [[ "$CAPTURE_RC" != 0 ]] || return 1
    Z_EXE_RC=$CAPTURE_RC
}

chain_identity() {
    local manager=$1 worker=$2
    CHAIN_MANAGER_START= CHAIN_WORKER_START=
    identity "$manager" "$UDEV_EXE" && [[ "$ID_PPID" == 1 ]] || return 1
    CHAIN_MANAGER_START=$ID_START
    identity "$worker" "$UDEV_EXE" && [[ "$ID_PPID" == "$manager" ]] || return 1
    CHAIN_WORKER_START=$ID_START
}

capture_process() {
    local pid=$1 kind=$2 expected=$3 manager=${4:-} worker=${5:-} procdir=/proc/$1
    local pre_exe pre_start pre_ppid post_exe post_start post_ppid
    local pre_manager_start= pre_worker_start=
    local status_data status_rc syscall_data syscall_rc wchan_data wchan_rc
    local stack_data stack_rc mount_data mount_rc fd_count=0 fdpath fd index
    local -a fd_numbers=() fd_results=() fd_data=()
    printf 'TRIAL_SYSCTL_PROCESS pid=%s kind=%s capture=begin\n' "$pid" "$kind"
    if [[ "$kind" == suspected-preexec-not-proven-sysctl ]]; then
        if ! chain_identity "$manager" "$worker"; then
            printf 'TRIAL_SYSCTL_PROCESS pid=%s capture=discarded reason=pre-chain-unavailable\n' "$pid"
            ((raced+=1))
            return
        fi
        pre_manager_start=$CHAIN_MANAGER_START pre_worker_start=$CHAIN_WORKER_START
    fi
    if ! identity "$pid" "$expected" || { [[ -n "$worker" ]] && [[ "$ID_PPID" != "$worker" ]]; }; then
        printf 'TRIAL_SYSCTL_PROCESS pid=%s capture=discarded reason=pre-identity-unavailable\n' "$pid"
        ((raced+=1))
        return
    fi
    pre_exe=$ID_EXE pre_start=$ID_START pre_ppid=$ID_PPID
    capture /usr/bin/awk -F: '$1=="State" || $1=="PPid" || $1=="Uid" || $1=="Gid" ||
        $1=="NSpid" || $1=="Threads" || $1=="CapEff" || $1=="Seccomp" ||
        $1=="NoNewPrivs" {print}' "$procdir/status"
    status_data=$CAPTURE_DATA status_rc=$CAPTURE_RC
    capture /usr/bin/cat "$procdir/syscall"
    syscall_data=$CAPTURE_DATA syscall_rc=$CAPTURE_RC
    capture /usr/bin/cat "$procdir/wchan"
    wchan_data=$CAPTURE_DATA wchan_rc=$CAPTURE_RC
    capture /usr/bin/cat "$procdir/stack"
    stack_data=$CAPTURE_DATA stack_rc=$CAPTURE_RC
    capture /usr/bin/readlink /proc/1/ns/mnt "$procdir/ns/mnt"
    mount_data=$CAPTURE_DATA mount_rc=$CAPTURE_RC
    for fdpath in "$procdir"/fd/[0-9]*; do
        fd=${fdpath##*/}
        [[ "$fd" =~ ^[0-9]+$ ]] || continue
        capture /usr/bin/readlink "$fdpath"
        fd_numbers+=("$fd") fd_results+=("$CAPTURE_RC") fd_data+=("$CAPTURE_DATA")
        ((fd_count+=1))
        [[ "$fd_count" -lt 8 ]] || break
    done
    if ! identity "$pid" "$expected" || [[ "$ID_EXE" != "$pre_exe" || "$ID_START" != "$pre_start" || "$ID_PPID" != "$pre_ppid" ]]; then
        # None of this process's captured file content has been printed.
        status_data= syscall_data= wchan_data= stack_data= mount_data= fd_data=()
        printf 'TRIAL_SYSCTL_PROCESS pid=%s capture=discarded reason=post-identity-raced\n' "$pid"
        ((raced+=1))
        return
    fi
    post_exe=$ID_EXE post_start=$ID_START post_ppid=$ID_PPID
    if [[ -n "$worker" ]] && { ! chain_identity "$manager" "$worker" ||
        [[ "$CHAIN_MANAGER_START" != "$pre_manager_start" || "$CHAIN_WORKER_START" != "$pre_worker_start" ]]; }; then
        status_data= syscall_data= wchan_data= stack_data= mount_data= fd_data=()
        printf 'TRIAL_SYSCTL_PROCESS pid=%s capture=discarded reason=post-chain-raced\n' "$pid"
        ((raced+=1))
        return
    fi
    printf 'TRIAL_SYSCTL_PROCESS pid=%s kind=%s capture=committed pre_exe=%s post_exe=%s pre_starttime=%s post_starttime=%s pre_ppid=%s post_ppid=%s\n' \
        "$pid" "$kind" "$pre_exe" "$post_exe" "$pre_start" "$post_start" "$pre_ppid" "$post_ppid"
    if [[ -n "$worker" ]]; then
        printf 'TRIAL_SYSCTL_PROCESS manager=%s pre_starttime=%s post_starttime=%s worker=%s pre_starttime=%s post_starttime=%s\n' \
            "$manager" "$pre_manager_start" "$CHAIN_MANAGER_START" "$worker" "$pre_worker_start" "$CHAIN_WORKER_START"
    fi
    printf 'TRIAL_SYSCTL_PROCESS kernel_stack_limit=requires_CAP_SYS_ADMIN_not_granted expected_EACCES=true\n'
    emit_stream status "$status_rc" "$status_data"
    emit_stream syscall "$syscall_rc" "$syscall_data"
    emit_stream wchan "$wchan_rc" "$wchan_data"
    emit_stream stack "$stack_rc" "$stack_data"
    emit_stream mount-namespaces-pid1-then-process "$mount_rc" "$mount_data"
    for ((index=0; index<fd_count; index++)); do
        printf 'TRIAL_SYSCTL_PROCESS fd=%s rc=%s bytes=%s target=' "${fd_numbers[index]}" "${fd_results[index]}" "${#fd_data[index]}"
        printf '%q\n' "${fd_data[index]}"
    done
    ((committed+=1))
}

capture_zombie() {
    local pid=$1 manager=$2 worker=$3
    local pre_manager_start pre_worker_start pre_start pre_ppid pre_exe_rc
    local post_start post_ppid post_exe_rc
    local child_status child_status_rc worker_status worker_status_rc
    local worker_syscall worker_syscall_rc worker_wchan worker_wchan_rc
    printf 'TRIAL_SYSCTL_PROCESS pid=%s kind=exited-unreaped-callout-not-proven-sysctl capture=begin\n' "$pid"
    if ! chain_identity "$manager" "$worker"; then
        printf 'TRIAL_SYSCTL_PROCESS pid=%s capture=discarded reason=zombie-pre-chain-unavailable\n' "$pid"
        ((raced+=1))
        return
    fi
    pre_manager_start=$CHAIN_MANAGER_START pre_worker_start=$CHAIN_WORKER_START
    if ! zombie_identity "$pid" "$worker"; then
        printf 'TRIAL_SYSCTL_PROCESS pid=%s capture=discarded reason=zombie-pre-identity-unavailable\n' "$pid"
        ((raced+=1))
        return
    fi
    pre_start=$Z_START pre_ppid=$Z_PPID pre_exe_rc=$Z_EXE_RC
    capture /usr/bin/awk -F: '$1=="State" || $1=="PPid" || $1=="Uid" || $1=="Gid" ||
        $1=="NSpid" || $1=="Threads" || $1=="CapEff" || $1=="Seccomp" ||
        $1=="NoNewPrivs" {print}' "/proc/$pid/status"
    child_status=$CAPTURE_DATA child_status_rc=$CAPTURE_RC
    capture /usr/bin/awk -F: '$1=="State" || $1=="PPid" || $1=="Uid" || $1=="Gid" ||
        $1=="NSpid" || $1=="Threads" || $1=="CapEff" || $1=="Seccomp" ||
        $1=="NoNewPrivs" {print}' "/proc/$worker/status"
    worker_status=$CAPTURE_DATA worker_status_rc=$CAPTURE_RC
    capture /usr/bin/cat "/proc/$worker/syscall"
    worker_syscall=$CAPTURE_DATA worker_syscall_rc=$CAPTURE_RC
    capture /usr/bin/cat "/proc/$worker/wchan"
    worker_wchan=$CAPTURE_DATA worker_wchan_rc=$CAPTURE_RC
    if ! zombie_identity "$pid" "$worker" || [[ "$Z_START" != "$pre_start" || "$Z_PPID" != "$pre_ppid" ]]; then
        child_status= worker_status= worker_syscall= worker_wchan=
        printf 'TRIAL_SYSCTL_PROCESS pid=%s capture=discarded reason=zombie-post-identity-raced\n' "$pid"
        ((raced+=1))
        return
    fi
    post_start=$Z_START post_ppid=$Z_PPID post_exe_rc=$Z_EXE_RC
    if ! chain_identity "$manager" "$worker" ||
        [[ "$CHAIN_MANAGER_START" != "$pre_manager_start" || "$CHAIN_WORKER_START" != "$pre_worker_start" ]]; then
        child_status= worker_status= worker_syscall= worker_wchan=
        printf 'TRIAL_SYSCTL_PROCESS pid=%s capture=discarded reason=zombie-post-chain-raced\n' "$pid"
        ((raced+=1))
        return
    fi
    printf 'TRIAL_SYSCTL_PROCESS pid=%s kind=exited-unreaped-callout-not-proven-sysctl capture=committed pre_state=Z post_state=Z pre_starttime=%s post_starttime=%s pre_ppid=%s post_ppid=%s pre_exe_rc=%s post_exe_rc=%s\n' \
        "$pid" "$pre_start" "$post_start" "$pre_ppid" "$post_ppid" "$pre_exe_rc" "$post_exe_rc"
    printf 'TRIAL_SYSCTL_PROCESS manager=%s pre_starttime=%s post_starttime=%s worker=%s pre_starttime=%s post_starttime=%s worker_exe=%s\n' \
        "$manager" "$pre_manager_start" "$CHAIN_MANAGER_START" "$worker" "$pre_worker_start" "$CHAIN_WORKER_START" "$UDEV_EXE"
    emit_stream zombie-child-status "$child_status_rc" "$child_status"
    emit_stream zombie-parent-worker-status "$worker_status_rc" "$worker_status"
    emit_stream zombie-parent-worker-syscall "$worker_syscall_rc" "$worker_syscall"
    emit_stream zombie-parent-worker-wchan "$worker_wchan_rc" "$worker_wchan"
    ((committed+=1))
}

# Own metadata is fixed and bounded; never report arbitrary skipped exe targets.
capture_self_metadata() {
    capture /usr/bin/awk -F: '$1=="CapEff" || $1=="CapPrm" || $1=="CapBnd" ||
        $1=="NoNewPrivs" || $1=="Uid" || $1=="Gid" {print}' "/proc/$$/status"
    emit_stream self-capability-status "$CAPTURE_RC" "$CAPTURE_DATA"
    capture /usr/bin/readlink "/proc/$$/ns/mnt"
    emit_stream self-mount-namespace "$CAPTURE_RC" "$CAPTURE_DATA"
    capture /usr/bin/readlink /proc/1/ns/mnt
    emit_stream pid1-mount-namespace "$CAPTURE_RC" "$CAPTURE_DATA"
    capture /usr/bin/readlink "/proc/$$/ns/user"
    emit_stream self-user-namespace "$CAPTURE_RC" "$CAPTURE_DATA"
    capture /usr/bin/readlink /proc/1/ns/user
    emit_stream pid1-user-namespace "$CAPTURE_RC" "$CAPTURE_DATA"
}

finish_scan() {
    local exit_rc=$1
    [[ "$candidate_count" -lt 4 ]] || candidate_cap_reached=1
    printf 'TRIAL_SYSCTL_PROCESS_SCAN helper_revision=3 proc_enumerated=%s proc_visited=%s proc_scanned=%s proc_ineligible=%s initial_exe_errors=%s initial_nonmatching_exe=%s managers_found=%s managers_scanned=%s manager_identity_rejected=%s manager_role_rejected=%s workers_enumerated=%s workers_scanned=%s worker_identity_rejected=%s worker_parent_rejected=%s children_enumerated=%s children_scanned=%s children_read_or_format_rejected=%s child_candidate_rejected=%s traversal_cap_rejected=%s worker_cap_reached=%s child_cap_reached=%s candidate_cap_reached=%s\n' \
        "$proc_enumerated" "$proc_visited" "$proc_scanned" "$proc_ineligible" \
        "$initial_exe_errors" "$initial_nonmatching_exe" "$managers_found" "$managers_scanned" \
        "$manager_identity_rejected" "$manager_role_rejected" "$workers_enumerated" "$workers_scanned" \
        "$worker_identity_rejected" "$worker_parent_rejected" "$children_enumerated" "$children_scanned" \
        "$children_read_or_format_rejected" "$child_candidate_rejected" "$traversal_cap_rejected" \
        "$worker_cap_reached" "$child_cap_reached" "$candidate_cap_reached"
    printf 'TRIAL_SYSCTL_PROCESS_END schema=1 helper_revision=3 scan_status=%s scan_reason=%s exit_rc=%s candidates=%s exact_sysctl=%s suspected_preexec=%s exited_unreaped=%s committed=%s discarded=%s zero_matches_proves_no_hang=false\n' \
        "$scan_status" "$scan_reason" "$exit_rc" "$candidate_count" "$sysctl_matches" \
        "$preexec_candidates" "$zombie_candidates" "$committed" "$raced"
}

# Zombie candidates additionally require stable Z state with no executable link.
# Only exact known executables are otherwise candidates. Manager -> worker -> child parent
# relationships distinguish a possible pre-exec callout from an ordinary worker.
# udev's "Spawned" log does not establish that fexecve has completed.
candidate_count=0 sysctl_matches=0 preexec_candidates=0 zombie_candidates=0 committed=0 raced=0
proc_enumerated=0 proc_visited=0 proc_scanned=0 proc_ineligible=0
initial_exe_errors=0 initial_nonmatching_exe=0 managers_found=0 managers_scanned=0
manager_identity_rejected=0 manager_role_rejected=0 workers_enumerated=0 workers_scanned=0
worker_identity_rejected=0 worker_parent_rejected=0 children_enumerated=0 children_scanned=0
children_read_or_format_rejected=0 child_candidate_rejected=0 traversal_cap_rejected=0
worker_cap_reached=0 child_cap_reached=0 candidate_cap_reached=0
scan_status=incomplete scan_reason=unexpected-exit
manager_pids=()
# TERM may be the outer timeout or another interruption; the helper cannot prove which.
# SIGKILL cannot run a trap. Missing END therefore also means incomplete, never no hang.
trap 'scan_status=incomplete; scan_reason=term-or-outer-timeout; exit 143' TERM
trap 'scan_status=incomplete; scan_reason=interrupt; exit 130' INT
trap 'scan_status=incomplete; scan_reason=hangup; exit 129' HUP
trap 'finish_scan "$?"' EXIT
printf 'TRIAL_SYSCTL_PROCESS_BEGIN schema=1 helper_revision=3 max_candidates=4 per_stream_bytes=8192 end_marker_required=true complete_scope=bounded-traversal zero_matches_proves_no_hang=false\n'
capture_self_metadata
proc_entries=(/proc/[0-9]*)
proc_enumerated=${#proc_entries[@]}
for procdir in "${proc_entries[@]}"; do
    ((proc_visited+=1))
    if [[ ! -d "$procdir" || -L "$procdir" ]]; then
        ((proc_ineligible+=1))
        continue
    fi
    pid=${procdir##*/}
    if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
        ((proc_ineligible+=1))
        continue
    fi
    ((proc_scanned+=1))
    capture /usr/bin/readlink "$procdir/exe"
    if [[ "$CAPTURE_RC" != 0 ]]; then
        ((initial_exe_errors+=1))
        continue
    fi
    if [[ "$CAPTURE_DATA" == "$EXPECTED_EXE" ]]; then
        ((candidate_count+=1, sysctl_matches+=1))
        capture_process "$pid" exact-systemd-sysctl "$EXPECTED_EXE"
        [[ "$candidate_count" -lt 4 ]] || break
    elif [[ "$CAPTURE_DATA" == "$UDEV_EXE" ]]; then
        if ! identity "$pid" "$UDEV_EXE"; then
            ((manager_identity_rejected+=1))
        elif [[ "$ID_PPID" != 1 ]]; then
            # Ordinary workers share this exe; a role rejection is not an access error.
            ((manager_role_rejected+=1))
        else
            manager_pids+=("$pid")
            ((managers_found+=1))
        fi
    else
        ((initial_nonmatching_exe+=1))
    fi
done
for manager in "${manager_pids[@]}"; do
    [[ "$candidate_count" -lt 4 ]] || break
    ((managers_scanned+=1))
    if ! identity "$manager" "$UDEV_EXE"; then
        ((manager_identity_rejected+=1))
        continue
    elif [[ "$ID_PPID" != 1 ]]; then
        ((manager_role_rejected+=1))
        continue
    fi
    capture /usr/bin/cat "/proc/$manager/task/$manager/children"
    if [[ "$CAPTURE_RC" != 0 || "$CAPTURE_DATA" =~ [^0-9[:space:]] ]]; then
        ((children_read_or_format_rejected+=1))
        continue
    fi
    workers=()
    read -r -a workers <<< "$CAPTURE_DATA"
    ((workers_enumerated+=${#workers[@]}))
    workers_visited=0
    for worker in "${workers[@]}"; do
        [[ "$candidate_count" -lt 4 ]] || break
        if [[ "$workers_visited" -ge 32 ]]; then
            ((traversal_cap_rejected+=1, worker_cap_reached+=1))
            break
        fi
        [[ "$worker" =~ ^[0-9]+$ ]] || continue
        ((workers_visited+=1, workers_scanned+=1))
        if ! identity "$worker" "$UDEV_EXE"; then
            ((worker_identity_rejected+=1))
            continue
        elif [[ "$ID_PPID" != "$manager" ]]; then
            ((worker_parent_rejected+=1))
            continue
        fi
        capture /usr/bin/cat "/proc/$worker/task/$worker/children"
        if [[ "$CAPTURE_RC" != 0 || "$CAPTURE_DATA" =~ [^0-9[:space:]] ]]; then
            ((children_read_or_format_rejected+=1))
            continue
        fi
        children=()
        read -r -a children <<< "$CAPTURE_DATA"
        ((children_enumerated+=${#children[@]}))
        children_visited=0
        for child in "${children[@]}"; do
            [[ "$candidate_count" -lt 4 ]] || break
            if [[ "$children_visited" -ge 32 ]]; then
                ((traversal_cap_rejected+=1, child_cap_reached+=1))
                break
            fi
            [[ "$child" =~ ^[0-9]+$ ]] || continue
            ((children_visited+=1, children_scanned+=1))
            if identity "$child" "$UDEV_EXE" && [[ "$ID_PPID" == "$worker" ]]; then
                ((candidate_count+=1, preexec_candidates+=1))
                capture_process "$child" suspected-preexec-not-proven-sysctl "$UDEV_EXE" "$manager" "$worker"
            elif zombie_identity "$child" "$worker"; then
                ((candidate_count+=1, zombie_candidates+=1))
                capture_zombie "$child" "$manager" "$worker"
            else
                ((child_candidate_rejected+=1))
            fi
        done
    done
done
if [[ "$candidate_count" -ge 4 ]]; then
    candidate_cap_reached=1
    scan_status=incomplete scan_reason=candidate-cap
elif [[ "$traversal_cap_rejected" -gt 0 ]]; then
    scan_status=incomplete scan_reason=traversal-cap
else
    # Complete describes bounded traversal, not unrestricted proc visibility.
    # Rejection counters remain material, even when all traversal loops finished.
    scan_status=complete scan_reason=bounded-traversal-finished
fi
exit 0

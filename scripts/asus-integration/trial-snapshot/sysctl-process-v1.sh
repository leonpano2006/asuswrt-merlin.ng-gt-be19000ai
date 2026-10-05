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

# Only exact known executables are candidates. Manager -> worker -> child parent
# relationships distinguish a possible pre-exec callout from an ordinary worker.
# udev's "Spawned" log does not establish that fexecve has completed.
candidate_count=0 sysctl_matches=0 preexec_candidates=0 committed=0 raced=0
manager_pids=()
printf 'TRIAL_SYSCTL_PROCESS_BEGIN schema=1 max_candidates=4 per_stream_bytes=8192\n'
for procdir in /proc/[0-9]*; do
    [[ -d "$procdir" && ! -L "$procdir" ]] || continue
    pid=${procdir##*/}
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    capture /usr/bin/readlink "$procdir/exe"
    [[ "$CAPTURE_RC" == 0 ]] || continue
    if [[ "$CAPTURE_DATA" == "$EXPECTED_EXE" ]]; then
        ((candidate_count+=1, sysctl_matches+=1))
        capture_process "$pid" exact-systemd-sysctl "$EXPECTED_EXE"
        [[ "$candidate_count" -lt 4 ]] || break
    elif [[ "$CAPTURE_DATA" == "$UDEV_EXE" ]]; then
        if identity "$pid" "$UDEV_EXE" && [[ "$ID_PPID" == 1 ]]; then
            manager_pids+=("$pid")
        fi
    fi
done
for manager in "${manager_pids[@]}"; do
    [[ "$candidate_count" -lt 4 ]] || break
    identity "$manager" "$UDEV_EXE" && [[ "$ID_PPID" == 1 ]] || continue
    capture /usr/bin/cat "/proc/$manager/task/$manager/children"
    [[ "$CAPTURE_RC" == 0 && ! "$CAPTURE_DATA" =~ [^0-9[:space:]] ]] || continue
    workers=()
    read -r -a workers <<< "$CAPTURE_DATA"
    workers_visited=0
    for worker in "${workers[@]}"; do
        [[ "$candidate_count" -lt 4 && "$workers_visited" -lt 32 ]] || break
        [[ "$worker" =~ ^[0-9]+$ ]] || continue
        ((workers_visited+=1))
        identity "$worker" "$UDEV_EXE" && [[ "$ID_PPID" == "$manager" ]] || continue
        capture /usr/bin/cat "/proc/$worker/task/$worker/children"
        [[ "$CAPTURE_RC" == 0 && ! "$CAPTURE_DATA" =~ [^0-9[:space:]] ]] || continue
        children=()
        read -r -a children <<< "$CAPTURE_DATA"
        children_visited=0
        for child in "${children[@]}"; do
            [[ "$candidate_count" -lt 4 && "$children_visited" -lt 32 ]] || break
            [[ "$child" =~ ^[0-9]+$ ]] || continue
            ((children_visited+=1))
            identity "$child" "$UDEV_EXE" && [[ "$ID_PPID" == "$worker" ]] || continue
            ((candidate_count+=1, preexec_candidates+=1))
            capture_process "$child" suspected-preexec-not-proven-sysctl "$UDEV_EXE" "$manager" "$worker"
        done
    done
done
printf 'TRIAL_SYSCTL_PROCESS_END schema=1 candidates=%s exact_sysctl=%s suspected_preexec=%s committed=%s discarded=%s\n' \
    "$candidate_count" "$sysctl_matches" "$preexec_candidates" "$committed" "$raced"
exit 0

#!/usr/bin/env python3
"""One bounded no-NIC/no-drive unified Docker fixture; default is a read-only plan."""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/qemu/kernel11-device-bpf-docker-v2'
FIXTURE_MANIFEST = ('build/kernel-device-bpf/docker-cgroup-v2-fixture-v1/manifest.json', '5aec2f63f98a39a061800ee9aa5c9ecd833a090d525f5089a2d412eb2a9dfb2d')
PREPARER = ('scripts/prepare-qemu-docker-cgroup-v2-v1.py', '09672736a37e8ee12bd1eecd655f9356ed41e7c1650ac908febe538c99ebed1a')
BASE_RESULT = ('build/qemu/kernel10-docker/result.json', '82e0d2a3eba45c1adacaa2465c28060316336bdaf54b3c5b9d2cbfc4fcb2fdec')
KERNEL = ('build/kernel11-device-bpf/attempt1/Image', '7d0be9c9c719291e52cf8994221d3c6267185a27e9b5bd4079f40d9bf21a21ed')
MARKERS = ['LAB_DOCKER_CGROUP_V2_PASS pid1_rehomed_controllers_enabled',
           'LAB_DOCKER_CGROUP_V2_PASS actual_unified_cgroupfs_daemon',
           'LAB_DOCKER_CGROUP_V2_PASS normal_container_cpu_memory_pids',
           'DEVICE_OPEN_DENIED errno=1 major=7 minor=0',
           'LAB_DOCKER_CGROUP_V2_PASS device_read_open_eperm',
           'DEVICE_OPEN_ALLOWED errno=0 major=7 minor=0',
           'LAB_DOCKER_CGROUP_V2_PASS explicit_device_read_open_allowed',
           'QEMU_DOCKER_CGROUP_V2_COMPLETE']


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned(row):
    require(row[1] is not None, 'Actual completed fixture/preparer pin pending; cannot run')
    path = R / row[0]
    require(path.is_file() and not path.is_symlink() and sha(path) == row[1], 'Pinned input mismatch')
    return {'path': row[0], 'sha256': row[1], 'bytes': path.stat().st_size}


def plan():
    require(__debug__, 'Python optimization forbidden')
    refs = {name: pinned(row) for name, row in [('fixture', FIXTURE_MANIFEST),
            ('preparer', PREPARER), ('base_result', BASE_RESULT), ('kernel', KERNEL)]}
    fixture = json.loads((R / FIXTURE_MANIFEST[0]).read_text())
    require(fixture['status'] == 'offline_cgroup_v2_docker_fixture_prepared_not_run'
            and fixture['prepare_count'] == 1 and fixture['fixture_run_count'] == 0
            and fixture['builder'] == refs['preparer']
            and fixture['inputs']['kernel'] == refs['kernel'], 'Actual fixture closure mismatch')
    archive = fixture['archive']
    path = R / archive['path']
    require(path.is_file() and not path.is_symlink() and sha(path) == archive['sha256']
            and path.stat().st_size == archive['bytes'], 'Prepared archive changed')
    old = json.loads((R / BASE_RESULT[0]).read_text())['command']
    command = list(old)
    require(command.count('-kernel') == command.count('-initrd') == 1,
            'Known offline QEMU argument shape required')
    command[command.index('-kernel') + 1] = str((R / KERNEL[0]).resolve())
    command[command.index('-initrd') + 1] = str(path.resolve())
    inverse = list(command)
    inverse[inverse.index('-kernel') + 1] = old[old.index('-kernel') + 1]
    inverse[inverse.index('-initrd') + 1] = old[old.index('-initrd') + 1]
    require(inverse == old and '-nodefaults' in command and '-nic' in command
            and command[command.index('-nic') + 1] == 'none'
            and all(flag not in command for flag in ['-drive', '-blockdev', '-netdev', '-net', '-device']),
            'No-NIC/no-drive frozen QEMU envelope changed')
    require(command[command.index('-sandbox') + 1] ==
            'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny', 'QEMU sandbox changed')
    return {'schema': 1, 'status': 'offline_cgroup_v2_docker_fixture_run_plan_only',
            'runner': {'path': str(Path(__file__).relative_to(R)), 'sha256': sha(Path(__file__))},
            'inputs': refs, 'archive': archive, 'command': command,
            'output': str(OUT.relative_to(R)), 'timeout_seconds': 180, 'failure_drain_seconds': 3,
            'required_exact_once_markers': MARKERS, 'run_count': 0,
            'device_accessed': False, 'physical_network_accessed': False,
            'limits': fixture['limits']}


def execute(value, gate):
    expected = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(gate == expected, 'Exact reviewed QEMU plan hash required')
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive QEMU result already exists; no retry')
    OUT.mkdir(parents=True)
    log = OUT / 'serial.log'
    started = time.monotonic()
    reason, failure_time = 'qemu_exit', None
    with log.open('xb') as stream:
        process = subprocess.Popen(value['command'], stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while process.poll() is None:
                text = log.read_text(errors='replace')
                if 'Kernel panic' in text:
                    reason = 'panic'
                    break
                if 'LAB_DOCKER_CGROUP_V2_FAILED' in text:
                    failure_time = failure_time or time.monotonic()
                    if time.monotonic() - failure_time >= 3:
                        reason = 'guest_failure'
                        break
                if 'QEMU_DOCKER_CGROUP_V2_COMPLETE' in text:
                    reason = 'complete'
                    break
                if log.stat().st_size > 8_000_000:
                    reason = 'output_limit'
                    break
                if time.monotonic() - started >= 180:
                    reason = 'timeout'
                    break
                time.sleep(.2)
        finally:
            if process.poll() is None:
                try:
                    process.wait(timeout=3 if reason == 'complete' else .1)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    text = log.read_text(errors='replace')
    checks = {marker: text.splitlines().count(marker) == 1 for marker in MARKERS}
    kernel_faults = [marker for marker in ['Kernel panic', 'BUG:', 'Oops:', 'WARNING: CPU:', 'Unable to handle kernel', 'Bad page state'] if marker in text]
    ok = all(checks.values()) and not kernel_faults and 'LAB_DOCKER_CGROUP_V2_FAILED' not in text
    result = dict(value, status='offline_cgroup_v2_docker_fixture_passed' if ok else 'failed_evidence_preserved_no_retry',
                  run_count=1, returncode=process.returncode, stop_reason=reason,
                  elapsed_seconds=round(time.monotonic() - started, 3), checks=checks, kernel_fault_markers=kernel_faults,
                  serial_log={'path': str(log.relative_to(R)), 'sha256': sha(log), 'bytes': log.stat().st_size})
    with (OUT / 'result.json').open('x') as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write('\n')
    print(json.dumps({'status': result['status'], 'returncode': result['returncode'],
                      'result_sha256': sha(OUT / 'result.json')}))
    return 0 if ok else 1


def main():
    require(__debug__, 'Python optimization forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    value = plan()
    gate = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': value}, indent=2, sort_keys=True))
        return 0
    return execute(value, args.execute_plan_sha256)


if __name__ == '__main__':
    raise SystemExit(main())

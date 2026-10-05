#!/usr/bin/env python3
"""One reviewed three-case GNU timeout ELF fixture; no controller paths or network."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

R = Path(__file__).resolve().parents[3]
PLAN = R / 'build/asus-uplink-rescue/controller-timeout-v1/execution-proposal-v1.json'
OUT = R / 'build/asus-uplink-rescue/controller-timeout-v1/fixture-v1'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def main():
    require(__debug__, 'Python -O forbidden')
    require(not OUT.exists(), 'Fixture output already exists; no retry')
    raw_plan = PLAN.read_bytes()
    require(len(sys.argv) == 3 and sys.argv[1] == '--execute-plan-sha256'
            and sys.argv[2] == hashlib.sha256(raw_plan).hexdigest(), 'Exact reviewed plan SHA required')
    plan = json.loads(raw_plan)
    for row in plan['inputs']:
        p = Path(row['path'])
        require(p.is_file() and not p.is_symlink(), 'Regular pinned input required')
        raw = p.read_bytes()
        require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'], 'Changed fixture input')
    require(len(plan['cases']) == 3, 'Exactly three fixed cases required')
    OUT.mkdir(exist_ok=False)
    results = []
    overall = 'started_outcome_unknown'
    try:
        for case in plan['cases']:
            started = time.monotonic()
            child = subprocess.Popen(case['argv'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}, start_new_session=True)
            timed_out = False
            try:
                stdout, stderr = child.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = child.communicate(timeout=2)
            elapsed = time.monotonic() - started
            (OUT / (case['name'] + '.stdout')).write_bytes(stdout)
            (OUT / (case['name'] + '.stderr')).write_bytes(stderr)
            raw_status = child.returncode
            normalized = raw_status if raw_status >= 0 else 128 - raw_status
            passed = (not timed_out and normalized == case['expected_status']
                      and case['elapsed_min_seconds'] <= elapsed <= case['elapsed_max_seconds'])
            row = dict(case, raw_returncode=raw_status, normalized_status=normalized,
                       elapsed_seconds=elapsed, outer_timeout=timed_out, passed=passed)
            results.append(row)
            require(passed, 'First fixture failure retained; no retry: ' + case['name'])
        overall = 'one_three_case_timeout_fixture_passed'
    except Exception:
        overall = 'timeout_fixture_failed_retained_no_retry'
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps({'schema': 1, 'status': overall, 'cases': results,
            'fixture_invocations': 1, 'real_controller_or_keys_accessed': False,
            'network_used': False, 'production_wrapper_executed': False,
            'limitations': ['User-mode QEMU signal/ELF behavior only; actual Kernel10 wrapper behavior pending.']}, indent=2) + '\n')
    print(json.dumps({'status': overall, 'result': str((OUT / 'result.json').relative_to(R))}))


if __name__ == '__main__':
    main()

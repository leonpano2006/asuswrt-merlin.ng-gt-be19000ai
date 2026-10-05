#!/usr/bin/env python3
"""One isolated host-kernel model for frozen ARM ip/BusyBox readback parsers."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

R = Path(__file__).resolve().parents[3]
PLAN = R / 'build/asus-uplink-rescue/controller-readback-host-source-v1/plan.json'
OUT = R / 'build/asus-uplink-rescue/controller-readback-host-v1'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def main():
    require(__debug__, 'Python -O forbidden')
    raw = PLAN.read_bytes()
    require(len(sys.argv) == 3 and sys.argv[1] == '--execute-plan-sha256'
            and sys.argv[2] == hashlib.sha256(raw).hexdigest(), 'Exact source plan required')
    require(not OUT.exists(), 'Existing output; no retry')
    plan = json.loads(raw)
    for row in plan['inputs']:
        p = Path(row['path'])
        require(p.is_file() and not p.is_symlink(), 'Regular pinned input required')
        data = p.read_bytes()
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'Changed input')
    outer_net = os.readlink('/proc/self/ns/net')
    outer_user = os.readlink('/proc/self/ns/user')
    argv = [v.replace('__OUTPUT__', str(OUT)).replace('__OUTER_NETNS__', outer_net)
            .replace('__OUTER_USERNS__', outer_user) for v in plan['argv']]
    OUT.mkdir(exist_ok=False)
    started = time.monotonic()
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={'LC_ALL': 'C', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'},
                             start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = child.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = child.communicate(timeout=6)
    (OUT / 'stdout').write_bytes(stdout)
    (OUT / 'stderr').write_bytes(stderr)
    result = {'schema': 1, 'status': 'isolated_host_dump_case_recorded' if child.returncode == 0 and not timed_out else 'failed_retained_no_retry',
              'returncode': child.returncode, 'outer_timeout': timed_out,
              'elapsed_seconds': time.monotonic() - started, 'argv': argv,
              'source_plan_sha256': hashlib.sha256(raw).hexdigest(), 'fixture_invocations': 1,
              'host_kernel_model_only': True, 'kernel10_behavior_proven': False,
              'production_controller_executed': False, 'physical_network_or_keys_accessed': False,
              'limits': ['Snapshot identity seam deliberately omitted; exact parser bodies retained.',
                         'Success records dumps and parser outcome, and does not require parser acceptance.']}
    (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if child.returncode == 0 and not timed_out else 1


if __name__ == '__main__':
    raise SystemExit(main())

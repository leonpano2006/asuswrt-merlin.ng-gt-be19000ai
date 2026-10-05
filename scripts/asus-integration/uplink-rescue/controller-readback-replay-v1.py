#!/usr/bin/env python3
"""One saved-dump parser replay, with one exact route-type refusal mutation."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

R = Path(__file__).resolve().parents[3]
SOURCE = R / 'build/asus-uplink-rescue/controller-readback-replay-source-v1'
OUT = R / 'build/asus-uplink-rescue/controller-readback-replay-v1'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def main():
    require(__debug__, 'Python -O forbidden')
    raw_plan = (SOURCE / 'plan.json').read_bytes()
    require(len(sys.argv) == 3 and sys.argv[1] == '--execute-plan-sha256'
            and sys.argv[2] == hashlib.sha256(raw_plan).hexdigest(), 'Exact reviewed plan required')
    require(not OUT.exists(), 'Existing output; no retry')
    plan = json.loads(raw_plan)
    for row in plan['inputs']:
        p = Path(row['path'])
        require(p.is_file() and not p.is_symlink(), 'Regular pinned input required')
        raw = p.read_bytes()
        require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'], 'Changed input')
    address = Path(plan['address_dump']).read_bytes()
    routes = Path(plan['route_dump']).read_bytes()
    line = plan['local_route_line'].encode()
    require(routes.count(line) == 1 and line.startswith(b'2 '), 'Exact captured local route required')
    altered = routes.replace(line, b'3 ' + line[2:], 1)
    OUT.mkdir(exist_ok=False)
    results = []
    status = 'started_outcome_unknown'
    try:
        for name, route_data, expected_rc in [('positive', routes, 0), ('wrong_local_type_3', altered, 1)]:
            case = OUT / name
            case.mkdir(mode=0o700)
            (case / 'addr').write_bytes(address)
            (case / 'routes').write_bytes(route_data)
            argv = ['/bin/bash', str(SOURCE / 'worker.sh'), str(case)]
            child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={'LC_ALL': 'C', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'},
                                     start_new_session=True)
            timed_out = False
            try:
                stdout, stderr = child.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = child.communicate(timeout=4)
            (case / 'stdout').write_bytes(stdout)
            (case / 'stderr').write_bytes(stderr)
            observed = dict(line.split('=', 1) for line in stdout.decode().splitlines())
            passed = (not timed_out and child.returncode == expected_rc and not stderr
                      and observed.get('parser_rc') == str(expected_rc)
                      and (case / 'address-count').read_bytes() == b'1\n')
            if name == 'positive':
                passed = passed and observed == {'parser_rc': '0', 'A': '1', 'R': '0', 'LOCAL': '1'}
            else:
                passed = passed and (case / 'route-count').read_bytes() == b''
            results.append({'name': name, 'argv': argv, 'returncode': child.returncode,
                            'outer_timeout': timed_out, 'observed': observed, 'passed': passed})
            require(passed, 'First replay failure retained: ' + name)
        status = 'one_saved_dump_positive_and_strict_negative_replay_passed'
    except Exception:
        status = 'failed_retained_no_retry'
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps({'schema': 1, 'status': status,
            'cases': results, 'replay_invocations': 1, 'source_plan_sha256': hashlib.sha256(raw_plan).hexdigest(),
            'network_namespace_vm_or_device_actions': False,
            'production_controller_executed': False,
            'limits': ['Only captured host-model dumps are replayed; no full snapshot/rules/Kernel10/.51 acceptance claim.']}, indent=2) + '\n')
    print(json.dumps({'status': status, 'result': str((OUT / 'result.json').relative_to(R))}))


if __name__ == '__main__':
    main()

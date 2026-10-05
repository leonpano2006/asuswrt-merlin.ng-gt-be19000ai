#!/usr/bin/env python3
"""Rebuild ARM64 bridge sources and test only fixtures in a user namespace.

No ASUS executable, active unit, device, mount, real power command or PID1 signal
is used. Offline brokers compile out physical power actions. Production clients
have no legacy power/PID1 fallback. The fake
libshared call-shape fixture is NOT evidence for the real proprietary library.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORK = ROOT / 'build/asus-integration'
MAGIC = 0x4C524331


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait_for(fn, seconds=5):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if fn():
            return
        time.sleep(.02)
    raise AssertionError('bounded wait expired')


def assert_pid_absent(pid):
    # mmdebstrap may give us a PID namespace with an inherited host /proc view.
    # Signal zero checks only existence in our namespace and delivers no signal.
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    raise AssertionError('owned fixture PID was not reaped')


def inside(args):
    assert os.getuid() == 0
    runtime = Path(args.runtime)
    assert str(runtime).startswith('/tmp/asus-broker-offline-')
    runtime.mkdir(mode=0o700)  # Fail on collision; never adopt an existing tree.
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    broker = None
    results = []
    try:
        (runtime / 'systemd').mkdir()
        notify.bind(str(runtime / 'notify'))
        notify.settimeout(5)
        bindir = Path(args.fixture_dir)
        shutil.copy2(bindir / 'signal-shell-fixture', runtime / 'test-shell')
        env = dict(os.environ, NOTIFY_SOCKET=str(runtime / 'notify'),
                   LD_PRELOAD=str(bindir / 'libleon-rc-notify.so'))

        def exchange(op=1, value=0, payload=None):
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
                s.settimeout(3)
                s.connect(str(runtime / 'control'))
                s.send(payload if payload is not None else struct.pack('=IIii', MAGIC, op, value, 0))
                reply = s.recv(128)
                assert len(reply) == 16
                return struct.unpack('=IIii', reply)

        no_preload = dict(env)
        no_preload.pop('LD_PRELOAD')
        missing = subprocess.run([str(bindir / 'leon-rc-broker'), '--test-power',
                                  str(bindir / 'mock-backend')], env=no_preload,
                                 capture_output=True, timeout=5)
        assert missing.returncode == 10 and not (runtime / 'backend-pid').exists()
        results.append('missing_shim_refuses_backend')
        broker = subprocess.Popen([str(bindir / 'leon-rc-broker'), '--test-power',
                                   str(bindir / 'mock-backend')], env=env)
        wait_for(lambda: (runtime / 'backend-pid').exists())
        backend_pid = int((runtime / 'backend-pid').read_text())
        assert exchange()[3] == errno.EAGAIN
        assert exchange(3)[3] == errno.EPERM
        assert exchange(4)[3] == errno.EPERM
        assert exchange(99)[3] == errno.EINVAL
        assert exchange(5, 1)[3] == errno.EINVAL
        for payload in (b'x', b'x' * 17, struct.pack('=IIii', 0, 1, 0, 0),
                        struct.pack('=IIii', MAGIC, 1, 0, 1)):
            assert exchange(payload=payload)[3] == errno.EPROTO
        results.append('pre_ready_wrong_child_unknown_op_reserved_value_malformed_rejected')

        # Temporarily relax ONLY this disposable fixture endpoint so rejection
        # proves SO_PEERCRED validation rather than merely filesystem modes.
        runtime.chmod(0o755)
        (runtime / 'control').chmod(0o666)
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([])
                os.setresgid(65534, 65534, 65534)
                os.setresuid(65534, 65534, 65534)
                os._exit(0 if exchange()[3] == errno.EACCES else 1)
            except BaseException:
                os._exit(2)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        runtime.chmod(0o700)
        (runtime / 'control').chmod(0o600)
        results.append('nonroot_peer_rejected_even_with_accessible_socket')

        (runtime / 'ready-go').touch()
        assert b'READY=1' in notify.recv(512)
        wait_for(lambda: (runtime / 'ready').exists())
        assert exchange()[3] == 0
        assert (runtime / 'identity-subreaper').read_text().strip() == '1'
        assert (runtime / 'early-alarm-blocked').read_text().strip() == '1'
        assert (runtime / 'system-child-mask-reset').read_text().strip() == '1'
        results.append('early_sigalrm_blocked_child_spawn_mask_empty_parent_mask_preserved')
        results.append('direct_child_ready_role_not_inherited_subreaper_reaps')
        (runtime / 'systemd').rmdir()
        assert exchange()[3] == errno.ENOTCONN
        assert exchange(2, signal.SIGTERM)[3] == errno.ENOTCONN
        os.kill(backend_pid, signal.SIGUSR2)  # Owned fixture tests its lost role.
        wait_for(lambda: (runtime / 'marker-fail-closed').exists())
        assert not (runtime / 'power-request').exists()
        normal = subprocess.run([str(bindir / 'normal-missing-marker')],
                                env=no_preload, capture_output=True, text=True, timeout=5)
        assert normal.returncode == 0, normal.stderr
        assert 'NORMAL_LOGIC_MISSING_MARKER_FAIL_CLOSED_PASS' in normal.stdout
        refused = subprocess.run([str(bindir / 'normal-broker'), '--test-power',
                                  str(bindir / 'mock-backend')], env=no_preload,
                                 capture_output=True, timeout=5)
        assert refused.returncode == 2
        (runtime / 'systemd').mkdir()
        results.append('normal_logic_missing_marker_client_manager_shim_wrappers_fail_closed')
        results.append('running_broker_and_manager_reject_lost_marker_no_power')
        assert exchange(2, signal.SIGKILL)[3] == errno.EINVAL
        results.append('unlisted_signal_rejected')

        def signals():
            p = runtime / 'signals'
            return p.read_text().splitlines() if p.exists() else []

        for sig in (signal.SIGUSR1, signal.SIGUSR2, signal.SIGHUP, signal.SIGINT):
            before = len(signals())
            assert exchange(2, sig)[3] == 0
            wait_for(lambda: len(signals()) == before + 1)
            assert int(signals()[-1]) == sig
        results.append('allowed_signals_only_reach_owned_backend')
        for i in range(7):
            before = len(signals())
            p = subprocess.run([str(bindir / 'notify-caller'), str(i)], env=env,
                               capture_output=True, text=True, timeout=5)
            assert p.returncode == 0, p.stderr
            wait_for(lambda: len(signals()) == before + 1)
            assert int(signals()[-1]) == signal.SIGUSR1
        results.append('seven_notify_call_shapes_and_ordinary_self_signal')

        assert exchange(2, signal.SIGTERM)[3] == 0
        assert (runtime / 'power-request').read_text() == 'reboot\n'
        assert exchange(2, signal.SIGTERM)[3] == 0
        assert exchange(2, signal.SIGQUIT)[3] == errno.EBUSY
        assert not (runtime / 'drained').exists()
        broker.send_signal(signal.SIGTERM)  # Direct Popen child only.
        assert broker.wait(timeout=5) == 0
        assert int((runtime / 'drained').read_text()) == signal.SIGTERM
        assert not (runtime / 'control').exists()
        results.append('power_request_recorded_only_ordered_shutdown_no_real_power')
        assert_pid_absent(backend_pid)

        p = subprocess.run([str(bindir / 'notify-caller'), 'missing'], env=env,
                           capture_output=True, text=True, timeout=5)
        assert p.returncode == 0, p.stderr
        results.append('missing_broker_notify_fails_closed')

        for name in ('backend-pid', 'ready', 'identity-subreaper', 'drained'):
            (runtime / name).unlink()
        broker = subprocess.Popen([str(bindir / 'leon-rc-broker'), '--test-power',
                                   str(bindir / 'mock-backend')], env=env)
        wait_for(lambda: (runtime / 'ready').exists())
        backend_pid = int((runtime / 'backend-pid').read_text())
        os.kill(backend_pid, signal.SIGKILL)  # This second fixture's owned child.
        assert broker.wait(timeout=5) == 1
        assert not (runtime / 'control').exists()
        assert_pid_absent(backend_pid)
        results.append('backend_crash_fails_broker_no_restart_stale_socket_removed')
        print(json.dumps({'passed': True, 'cases': results}))
    finally:
        if broker is not None and broker.poll() is None:
            broker.terminate()
            try:
                broker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=5)
        notify.close()
        shutil.rmtree(runtime)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--inside', action='store_true')
    p.add_argument('--runtime')
    p.add_argument('--fixture-dir')
    args = p.parse_args()
    if args.inside:
        inside(args)
        return
    assert os.uname().machine == 'aarch64', 'This recipe builds a native arm64 foundation.'
    WORK.mkdir(parents=True, exist_ok=True)
    if (WORK / 'offline-test.json').exists():
        stamp = str(time.time_ns())
        for name in ('offline-test.json', 'offline-test.log'):
            shutil.copy2(WORK / name, WORK / (stamp + '-' + name))
    runtime = '/tmp/asus-broker-offline-' + uuid.uuid4().hex
    cc = shutil.which('gcc-16') or shutil.which('gcc')
    flags = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
             '-mcpu=cortex-a53+crypto+crc', '-D_TIME_BITS=64', '-D_FILE_OFFSET_BITS=64',
             '-frecord-gcc-switches', '-Wl,--build-id=sha1', '-I' + str(HERE / 'src')]
    commands = []

    def compile_one(out, sources, extra=(), offline=False, test_paths=False):
        out.parent.mkdir(exist_ok=True)
        defs = (['-DLEON_RC_DIR=' + json.dumps(runtime),
                 '-DLEON_RC_MANAGED_PATH=' + json.dumps(runtime + '/systemd'),
                 '-DLEON_RC_SHELL=' + json.dumps(runtime + '/test-shell')]
                if offline or test_paths else [])
        if offline:
            defs.append('-DLEON_RC_OFFLINE_TEST')
        cmd = [cc, *flags, *defs, *map(str, sources), *extra, '-o', str(out)]
        commands.append(cmd)
        subprocess.run(cmd, check=True)

    src = HERE / 'src'
    for kind in ('production-foundation', 'offline'):
        out = WORK / kind
        offline = kind == 'offline'
        compile_one(out / 'libleon-rc-notify.so', [src / 'notify-compat.c', src / 'rc-client.c'],
                    ['-shared', '-fPIC', '-Wl,-soname,libleon-rc-notify.so', '-ldl'], offline)
        compile_one(out / 'leon-rc-broker', [src / 'rc-broker.c', src / 'rc-client.c'], ['-ldl'], offline)
        compile_one(out / 'leon-rcctl', [src / 'rcctl.c', src / 'rc-client.c'], ['-ldl'], offline)
    out = WORK / 'offline'
    compile_one(out / 'signal-shell-fixture', [HERE / 'signal-shell-fixture.c'], offline=True)
    compile_one(out / 'mock-backend', [HERE / 'mock-backend.c', src / 'rc-client.c', src / 'rc-manager.c'],
                ['-L' + str(out), '-Wl,--no-as-needed', '-l:libleon-rc-notify.so', '-Wl,-rpath,$ORIGIN', '-ldl'], True)
    compile_one(out / 'libnotify-fixture.so', [HERE / 'notify-fixture.c'], ['-shared', '-fPIC'], True)
    compile_one(out / 'notify-caller', [HERE / 'notify-caller.c', src / 'rc-client.c'],
                ['-L' + str(out), '-l:libnotify-fixture.so', '-Wl,-rpath,$ORIGIN', '-ldl'], True)
    compile_one(out / 'normal-missing-marker', [HERE / 'missing-marker.c', src / 'rc-client.c',
                src / 'rc-manager.c', src / 'rc-legacy.c', src / 'notify-compat.c'],
                ['-rdynamic', '-ldl'], test_paths=True)
    compile_one(out / 'normal-broker', [src / 'rc-broker.c', src / 'rc-client.c'],
                ['-ldl'], test_paths=True)
    # Subordinate namespace UIDs cannot traverse the user's private home. Stage
    # only public fixture executables/source under a unique readable /tmp path.
    stage = Path(tempfile.mkdtemp(prefix='asus-broker-harness-'))
    stage.chmod(0o755)
    try:
        for f in out.iterdir():
            shutil.copy2(f, stage / f.name)
        shutil.copy2(__file__, stage / 'check-offline.py')
        cmd = ['mmdebstrap', '--unshare-helper', sys.executable, str(stage / 'check-offline.py'),
               '--inside', '--runtime', runtime, '--fixture-dir', str(stage)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    finally:
        shutil.rmtree(stage)
    (WORK / 'offline-test.log').write_text(result.stdout + result.stderr)
    artifacts = [{'path': str(f.relative_to(ROOT)), 'sha256': digest(f),
                  'elf_header': subprocess.check_output(['readelf', '-h', str(f)], text=True)}
                 for kind in ('production-foundation', 'offline')
                 for f in sorted((WORK / kind).iterdir()) if f.is_file()]
    report = {'status': 'passed' if result.returncode == 0 else 'failed',
              'scope': 'Native ARM64 source rebuild and isolated fixture tests only; not ASUS runtime acceptance.',
              'compiler': subprocess.check_output([cc, '--version'], text=True).splitlines()[0],
              'commands': commands, 'test_command': cmd, 'test_returncode': result.returncode,
              'test_stdout': result.stdout, 'test_stderr': result.stderr, 'artifacts': artifacts,
              'not_tested': ['Real ARMEL rc/libshared call paths', 'systemd PID1 lifecycle',
                             'Broadcom hardware startup', 'AI-board service actions',
                             'Real power requests', 'Foreign ABI shims', 'Candidate glibc2.44 rebuild']}
    (WORK / 'offline-test.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(WORK / 'offline-test.json'),
                      'test_stdout': result.stdout, 'test_stderr': result.stderr}))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()

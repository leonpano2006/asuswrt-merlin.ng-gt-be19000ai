#!/usr/bin/python3
"""BCM-only, single-use production switch recovery watchdog. Never run on the workstation.

Starts no action before --arm, platform gates and private-directory validation.
Only the parent installs/starts this via a root systemd service after review.
No credential, network client, env writer, block device or hardware-watchdog use.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

ASUS = Path('/usr/bin/asus')
RC = Path('/usr/libexec/asus/rc')
ASUS_SHA = '2312c2fd8a7602429f22f382e2c117edfb9f68e4502893961d473da7bf9d280b'
RC_SHA = 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2'
ROOT_UUID = 'e46de487-2d50-4bfb-9365-33ea9027d40e'
MISC_SHA = '229f0150cfd97aa65758d7e684921db35f4b0c7688e0d1404c9977e454e66b6b'
DEADLINE_SECONDS = 600
MAX_REQUEST = 4096
UUID = re.compile(r'^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
CLOCK = time.CLOCK_BOOTTIME


def now():
    return time.clock_gettime(CLOCK)


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def private_regular(st):
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
        raise RuntimeError('Expected a root-owned, single-link, mode0600 regular file')


class State:
    def __init__(self, path, nonce):
        expected = '/run/leon-ai-watch-' + nonce
        if str(path) != expected or path.is_symlink():
            raise RuntimeError('Unexpected state directory')
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(self.fd)
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
            raise RuntimeError('State directory must be root-owned mode0700')
        self.path = path

    def create(self, name, document):
        """Exclusive creation is also the shared, irreversible action latch."""
        blob = (json.dumps(document, sort_keys=True) + '\n').encode()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(blob)
                out.flush()
                os.fsync(out.fileno())
            os.fsync(self.fd)
        except BaseException:
            # Never remove an uncertain action latch and retry a pulse.
            raise

    def read(self, name):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'rb') as inp:
            private_regular(os.fstat(inp.fileno()))
            blob = inp.read(MAX_REQUEST + 1)
        if len(blob) > MAX_REQUEST:
            raise RuntimeError('Request too large')
        return json.loads(blob)

    def event(self, name, document):
        # Fixed one-time event names bound total storage; no unbounded log stream.
        try:
            self.create(name, document)
        except FileExistsError:
            pass


def levels():
    return {str(n): (Path('/sys/class/leds') / ('led_gpio_' + str(n)) / 'brightness').read_text().strip()
            for n in (16, 21, 6)}


def platform_gate(expected_boot):
    if os.geteuid() != 0 or boot_id() != expected_boot:
        raise RuntimeError('Wrong privilege or BCM boot identity')
    for path, digest in ((ASUS, ASUS_SHA), (RC, RC_SHA)):
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError('Unsafe command file ownership/mode')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Command hash mismatch')
    selected = None
    for folder in ('bin', 'sbin'):
        candidate = Path('/usr/share/asus/commands') / folder / 'service'
        if candidate.is_symlink():
            selected = candidate
            break
    if selected is None or selected.lstat().st_uid != 0 or selected.resolve() != RC:
        raise RuntimeError('Service route mismatch')
    if levels() != {'16': '0', '21': '0', '6': '0'}:
        raise RuntimeError('GPIO lines are not released')
    for n in (16, 21, 6):
        if '[none]' not in (Path('/sys/class/leds') / ('led_gpio_' + str(n)) / 'trigger').read_text():
            raise RuntimeError('GPIO trigger is active')
    return {'bcm_boot_id': expected_boot, 'service_map': str(selected),
            'wrapper_sha256': ASUS_SHA, 'rc_sha256': RC_SHA, 'levels': levels()}


def validate_request(document, nonce, initial_ai_boot):
    if not isinstance(document, dict) or document.get('nonce') != nonce:
        raise ValueError('Wrong request nonce/type')
    action = document.get('action')
    if action == 'reset':
        if document.get('reason') not in ('trial_complete', 'controller_recovery', 'user_abort'):
            raise ValueError('Unrecognized reset reason')
        return action
    if action == 'cancel_deployed':
        candidate_boot = document.get('candidate_boot_id', '')
        if not isinstance(candidate_boot, str) or not UUID.fullmatch(candidate_boot) or candidate_boot == initial_ai_boot:
            raise ValueError('Deployment cancellation requires a fresh candidate boot')
        required = {'candidate_kernel': '6.12.62-leonai7+', 'root_uuid': ROOT_UUID,
                    'both_env_crc_valid': True, 'saved_stock_next': True,
                    'native_health_pass': True, 'cohort_verified': True,
                    'module_bind_readonly': True, 'pinned_ssh_verified': True,
                    'misc_sha256': MISC_SHA}
        if any(document.get(k) != v for k, v in required.items()):
            raise ValueError('Cancellation lacks parent-verified deployed native health and saved fallback')
        return action
    if action in ('cancel', 'cancel_unarmed', 'cancel_before_reboot'):
        new_boot = document.get('stock_boot_id', '')
        if not isinstance(new_boot, str) or not UUID.fullmatch(new_boot):
            raise ValueError('Cancellation requires a stock boot identity')
        # Same initial boot is valid after a rejected/not-issued reboot or
        # an arm failure whose original environment was restored. A fresh boot
        # is a separate trial-acceptance fact, not a cancellation prerequisite.
        if action in ('cancel_unarmed', 'cancel_before_reboot'):
            if new_boot != initial_ai_boot or document.get('reboot_not_requested') is not True:
                raise ValueError('Pre-reboot cancellation requires the initial stock boot')
        if action == 'cancel_unarmed' and document.get('environment_never_armed') is not True:
            raise ValueError('Unarmed cancellation requires explicit proof')
        required = {'stock_kernel': '5.15.140', 'root_uuid': ROOT_UUID,
                    'environment_restored': True, 'both_env_crc_valid': True,
                    'temporary_keys_absent': True, 'misc_sha256': MISC_SHA,
                    'pinned_ssh_verified': True}
        if any(document.get(k) != v for k, v in required.items()):
            raise ValueError('Cancellation lacks parent-verified stock restoration')
        return action
    raise ValueError('Unrecognized action')


def pulse(state, nonce, expected_boot, reason):
    # Gate again immediately before the sole authorized action. Never reroute.
    gate = platform_gate(expected_boot)
    state.create('action-latch.json', {'nonce': nonce, 'action': 'reset', 'reason': reason,
                                      'boottime': now(), 'gate': gate})
    fd = os.open('reset-output.txt', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=state.fd)
    start = now()
    with os.fdopen(fd, 'wb', buffering=0) as output:
        child = subprocess.Popen([str(ASUS), 'service', 'start_ai_reboot'],
                                 stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                 close_fds=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        samples = []
        for _ in range(121):
            try:
                samples.append({'elapsed': round(now() - start, 3), **levels()})
            except OSError as exc:
                samples.append({'elapsed': round(now() - start, 3), 'read_error': type(exc).__name__})
            time.sleep(0.1)
        while child.poll() is None and now() - start < 45:
            time.sleep(0.25)
        rc = child.poll()
        # Never kill the reset helper mid-pulse; unit must use KillMode=process.
        # If it unexpectedly hangs, record the PID and require manual inspection.
        result = {'nonce': nonce, 'helper_pid': child.pid, 'helper_rc': rc,
                  'helper_timeout_left_running': rc is None,
                  'elapsed': round(now() - start, 3), 'samples': samples,
                  'bcm_boot_id_after': boot_id(), 'no_retry': True}
        state.create('reset-result.json', result)
        state.create('terminal.json', {'nonce': nonce, 'state': 'reset_finished' if rc is not None else 'helper_timeout',
                                       'boottime': now(), 'helper_rc': rc})
    return 0 if rc == 0 else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', action='store_true', required=True)
    parser.add_argument('--nonce', required=True)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--expected-bcm-boot-id', required=True)
    parser.add_argument('--initial-ai-boot-id', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{32}', args.nonce):
        raise SystemExit('Invalid nonce')
    if not UUID.fullmatch(args.expected_bcm_boot_id) or not UUID.fullmatch(args.initial_ai_boot_id):
        raise SystemExit('Invalid boot identity')
    os.umask(0o077)
    state = State(args.state_dir, args.nonce)
    state.create('owner-lock.json', {'pid': os.getpid(), 'nonce': args.nonce, 'bcm_boot_id': args.expected_bcm_boot_id})
    gate = platform_gate(args.expected_bcm_boot_id)
    start = now()
    state.create('ready.json', {'nonce': args.nonce, 'pid': os.getpid(), 'clock': 'CLOCK_BOOTTIME',
                                'started': start, 'deadline': start + DEADLINE_SECONDS,
                                'deadline_seconds': DEADLINE_SECONDS, 'gate': gate,
                                'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    while True:
        # Parent cancellation after proved stock restoration takes priority over
        # an early-reset request not yet claimed. At most one terminal decision.
        for name, expected_action in (('cancel-request.json', 'cancel'), ('reset-request.json', 'reset')):
            try:
                request = state.read(name)
                if request is None:
                    continue
                action = validate_request(request, args.nonce, args.initial_ai_boot_id)
                if expected_action == 'cancel':
                    if action not in ('cancel', 'cancel_unarmed', 'cancel_before_reboot', 'cancel_deployed'):
                        raise ValueError('Wrong cancellation action')
                    if action == 'cancel_unarmed' and state.read('arm-notice.json') is not None:
                        raise ValueError('Arm notice forbids unarmed cancellation')
                elif action != expected_action:
                    raise ValueError('Wrong request filename')
            except (OSError, ValueError, RuntimeError, TypeError) as exc:
                state.event(name + '.rejected.json', {'nonce': args.nonce, 'error': type(exc).__name__})
                continue  # Malformed files cannot disable the deadline.
            if action in ('cancel', 'cancel_unarmed', 'cancel_before_reboot', 'cancel_deployed'):
                state.create('action-latch.json', {'nonce': args.nonce, 'action': 'cancel', 'boottime': now(),
                                                  'parent_proof': request})
                state.create('terminal.json', {'nonce': args.nonce, 'state': 'cancelled_after_deployment_health' if action == 'cancel_deployed' else 'cancelled_after_stock_restore', 'cancel_action': action,
                                               'boottime': now()})
                return 0
            return pulse(state, args.nonce, args.expected_bcm_boot_id, request['reason'])
        if now() >= start + DEADLINE_SECONDS:
            return pulse(state, args.nonce, args.expected_bcm_boot_id, 'deadline')
        time.sleep(min(0.5, max(0.0, start + DEADLINE_SECONDS - now())))


if __name__ == '__main__':
    raise SystemExit(main())

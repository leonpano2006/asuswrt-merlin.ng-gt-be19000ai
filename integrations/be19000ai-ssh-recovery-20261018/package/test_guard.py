#!/usr/bin/python3
"""Focused fixture tests: no systemd, dpkg, network, or ASUS calls."""
import copy
import importlib.machinery
import importlib.util
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).parent / 'root/usr/libexec/leon-asus/openssh-upgrade-guard'
loader = importlib.machinery.SourceFileLoader('guard', str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
guard = importlib.util.module_from_spec(spec)
loader.exec_module(guard)
guard.log = lambda message: None


class Store:
    def __init__(self):
        self.state = None

    def read(self):
        return copy.deepcopy(self.state)

    def write(self, state):
        self.state = copy.deepcopy(state)

    def clear(self):
        self.state = None


class Host:
    def __init__(self):
        self.boot_id = 'boot-a'
        self.active_state = 'active'
        self.is_managed = True
        self.status = 'configured'
        self.version = '1:10.2p1-2ubuntu3.7'
        self.fingerprint = [1, 100, 5000, 200000]
        self.policy = '2'
        self.is_ready = True
        self.start_result = True
        self.wait_result = True
        self.requests = 0
        self.store = None

    def boot(self): return self.boot_id
    def service(self): return self.active_state
    def managed(self): return self.is_managed
    def package(self): return self.status, self.version
    def binary(self): return self.fingerprint[:]
    def enabled(self): return self.policy
    def ready(self): return self.is_ready

    def start(self):
        assert self.store.state['phase'] == 'requested', 'Request must be latched first'
        self.requests += 1
        return self.start_result

    def wait(self):
        if self.wait_result:
            self.active_state = 'active'
        return self.wait_result

    def replace(self, configured=True, same_version=False):
        self.active_state = 'inactive'
        self.fingerprint[1] += 1
        self.fingerprint[2] += 1
        if not same_version:
            self.version = '1:10.2p1-2ubuntu3.8'
        self.status = 'configured' if configured else 'pending'


class Tests(unittest.TestCase):
    def setUp(self):
        self.host, self.store = Host(), Store()
        self.host.store = self.store

    def hook(self, phase):
        guard.reconcile(phase, self.host, self.store)

    def test_successful_upgrade(self):
        self.hook('pre'); self.host.replace(); self.hook('post')
        self.assertEqual(self.host.requests, 1)
        self.assertIsNone(self.store.state)

    def test_split_unpack_configure_preserves_original_active_state(self):
        self.hook('pre'); original = copy.deepcopy(self.store.state)
        self.host.replace(configured=False); self.hook('post'); self.hook('pre')
        self.assertEqual(self.store.state, original)
        self.assertEqual(self.host.requests, 0)
        self.host.status = 'configured'; self.hook('post')
        self.assertEqual(self.host.requests, 1)

    def test_same_version_reinstall_detected_by_binary_identity(self):
        self.hook('pre'); self.host.replace(same_version=True); self.hook('post')
        self.assertEqual(self.host.requests, 1)

    def test_originally_inactive_never_starts(self):
        self.host.active_state = 'inactive'
        self.hook('pre'); self.host.replace(); self.hook('post')
        self.assertEqual(self.host.requests, 0)
        self.assertIsNone(self.store.state)

    def test_unmanaged_listener_never_snapshots(self):
        self.host.is_managed = False
        self.hook('pre'); self.host.replace(); self.hook('post')
        self.assertEqual(self.host.requests, 0)

    def test_asus_disabled_or_unsupported_policy_clears_snapshot(self):
        for policy in ('0', '1'):
            with self.subTest(policy=policy):
                self.setUp(); self.hook('pre'); self.host.replace()
                self.host.policy = policy; self.hook('post')
                self.assertEqual(self.host.requests, 0)
                self.assertIsNone(self.store.state)

    def test_unrelated_package_and_manual_stop_do_not_restore(self):
        self.hook('pre'); self.host.active_state = 'inactive'; self.hook('post')
        self.assertEqual(self.host.requests, 0)
        self.assertIsNone(self.store.state)

    def test_still_running_is_untouched(self):
        self.hook('pre'); self.host.fingerprint[1] += 1; self.hook('post')
        self.assertEqual(self.host.requests, 0)
        self.assertIsNone(self.store.state)

    def test_invalid_config_or_missing_socket_defers_without_request(self):
        self.hook('pre'); self.host.replace(); self.host.is_ready = False
        self.hook('post'); self.hook('post')
        self.assertEqual(self.host.requests, 0)
        self.assertEqual(self.store.state['phase'], 'pending')
        self.host.is_ready = True; self.hook('post')
        self.assertEqual(self.host.requests, 1)

    def test_interrupted_unpack_then_configure_can_recover(self):
        self.hook('pre'); self.host.replace(configured=False)
        # The unpack post hook never ran. A later dpkg configure preserves intent.
        self.hook('pre'); self.host.status = 'configured'; self.hook('post')
        self.assertEqual(self.host.requests, 1)

    def test_duplicate_post_after_uncertain_request_never_resends(self):
        self.hook('pre'); self.host.replace(); self.host.wait_result = False
        self.hook('post'); self.hook('post'); self.hook('pre'); self.hook('post')
        self.assertEqual(self.host.requests, 1)
        self.assertEqual(self.store.state['phase'], 'requested')

    def test_boot_change_and_package_removal_clear_pending(self):
        for change in ('boot', 'removed'):
            with self.subTest(change=change):
                self.setUp(); self.hook('pre'); self.host.replace()
                if change == 'boot': self.host.boot_id = 'boot-b'
                else: self.host.status = 'removed'
                self.hook('post')
                self.assertEqual(self.host.requests, 0)
                self.assertIsNone(self.store.state)

    def test_retained_hooks_survive_removal_and_unavailable_interpreter(self):
        config = (SOURCE.parents[3] / 'etc/dpkg/dpkg.cfg.d/90-leon-asus-openssh-upgrade-guard').read_text()
        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / 'helper'
            for payload in (None, '#!/bin/sh\nexit 1\n', '#!/missing-python-interpreter\n'):
                if payload is not None:
                    helper.write_text(payload); helper.chmod(0o755)
                for line in config.splitlines():
                    command = line.split('=', 1)[1].replace('/usr/libexec/leon-asus/openssh-upgrade-guard', shlex.quote(str(helper)))
                    result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, timeout=2)
                    self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)

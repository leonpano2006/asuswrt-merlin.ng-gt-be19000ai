#!/usr/bin/env python3
"""No-network protocol/transport mocks for observe-ubuntu26-trial.py."""
import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name("observe-ubuntu26-trial.py")
spec = importlib.util.spec_from_file_location("trial_observer", SOURCE)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
OLD = "11111111-1111-4111-8111-111111111111"
NEW = "22222222-2222-4222-8222-222222222222"
OTHER = "33333333-3333-4333-8333-333333333333"
NONCE = "b7" * 32
KEY = "SHA256:test-only-key"


def encoded(obj):
    return json.dumps(obj, separators=(",", ":")).encode() + b"\n"


def challenge(sequence=1, boot=NEW, **values):
    return {"schema": 1, "boot_id": boot, "challenge": NONCE, "sequence": sequence,
            "expires_in_ms": 20000, **values}


def accepted(sequence=1, boot=NEW, **values):
    return {"schema": 1, "accepted": True, "boot_id": boot, "sequence": sequence, **values}


def reply(obj, key=KEY, status=0, err=b""):
    return m.Reply(encoded(obj) if isinstance(obj, dict) else obj, err, status, key)


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value
    def sleep(self, seconds):
        assert seconds >= 0
        self.value += seconds


class MockExchange:
    def __init__(self, responses, clock):
        self.responses = list(responses)
        self.clock = clock
        self.calls = []
    def exchange(self, action, stdin, deadline, expected_fingerprint):
        self.calls.append((action, stdin, deadline, expected_fingerprint))
        item = self.responses.pop(0)
        elapsed = 0
        if isinstance(item, tuple): item, elapsed = item
        self.clock.sleep(elapsed)
        if isinstance(item, Exception): raise item
        return item


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.events = []
    def observer(self, responses):
        self.transport = MockExchange(responses, self.clock)
        return m.Observer(self.transport, OLD, lambda e, **kw: self.events.append({"event": e, **kw}),
                          self.clock, self.clock.sleep)
    def expect(self, code, fn):
        with self.assertRaises(m.ObserverError) as cm: fn()
        self.assertEqual(cm.exception.code, code)
        return cm.exception
    def test_canonical_ack_wire(self):
        c = m.parse_challenge(encoded(challenge()))
        expected = ('{"schema":1,"boot_id":"' + NEW + '","challenge":"' + NONCE + '","sequence":1}\n').encode()
        self.assertEqual(m.ack_request(c), expected)
        self.assertNotIn(b"expires", expected)
    def test_duplicate_keys_rejected(self):
        data = encoded(challenge()).replace(b'"schema":1', b'"schema":1,"schema":1')
        self.expect("duplicate_json_key", lambda: m.parse_challenge(data))
    def test_invalid_types_and_bounds(self):
        cases = [("schema", True, "unsupported_schema"), ("schema", 2, "unsupported_schema"),
                 ("sequence", True, "invalid_sequence"), ("sequence", 0, "invalid_sequence"),
                 ("sequence", 2**64, "invalid_sequence"), ("sequence", 1.0, "invalid_sequence"),
                 ("expires_in_ms", True, "invalid_challenge_expiry"),
                 ("expires_in_ms", 0, "invalid_challenge_expiry"),
                 ("expires_in_ms", 20001, "invalid_challenge_expiry"),
                 ("challenge", NONCE.upper(), "invalid_challenge"),
                 ("challenge", NONCE[:-1], "invalid_challenge"),
                 ("boot_id", "invalid", "invalid_boot_id")]
        for key, val, code in cases:
            with self.subTest(key=key, val=val):
                self.expect(code, lambda: m.parse_challenge(encoded(challenge(**{key: val}))))
    def test_extra_or_missing_fields_rejected(self):
        a = challenge(extra=1)
        b = challenge(); del b["expires_in_ms"]
        for obj in (a, b):
            self.expect("unexpected_response_fields", lambda: m.parse_challenge(encoded(obj)))
    def test_multiple_lines_and_large_output_rejected(self):
        for data in (encoded(challenge()) + b"{}\n", b" \n", b"[]", b"\xff", b"x" * 4097):
            with self.subTest(data=data[:20]):
                with self.assertRaises(m.ObserverError): m.parse_challenge(data)
    def test_non_json_values_and_depth_rejected(self):
        for data in (b'{"schema":NaN}', b'{"x":' + b'[' * 1100 + b'0' + b']' * 1100 + b'}'):
            with self.assertRaises(m.ObserverError) as cm: m.parse_challenge(data)
            self.assertIn(cm.exception.code, ("invalid_json_response", "unexpected_response_fields"))
    def test_ack_boolean_identity_and_sequence(self):
        for obj, code in [(accepted(accepted=1), "ack_not_accepted"),
                          (accepted(accepted=False), "ack_not_accepted"),
                          (accepted(2), "ack_identity_mismatch"),
                          (accepted(boot=OTHER), "ack_identity_mismatch")]:
            self.expect(code, lambda: m.parse_ack(encoded(obj), challenge()))
    def test_rejection_requires_empty_stdout(self):
        self.assertTrue(self.expect("remote_rejected", lambda: m.successful_output(reply(b"", status=125))).retryable)
        self.expect("unexpected_remote_exit", lambda: m.successful_output(reply(b"bad", status=125)))
        self.expect("unexpected_remote_stderr", lambda: m.successful_output(reply(challenge(), err=b"peer text")))
        self.expect("remote_output_limit", lambda: m.successful_output(reply(b"x" * 4097)))
    def test_two_roundtrips_pin_boot_key_and_monotonic_sequence(self):
        ob = self.observer([reply(challenge()), reply(accepted()), reply(challenge(3)), reply(accepted(3))])
        self.assertTrue(ob.cycle(60)); self.assertTrue(ob.cycle(60))
        self.assertEqual((ob.boot_id, ob.fingerprint, ob.sequence, ob.ack_count), (NEW, KEY, 3, 2))
        self.assertEqual([x[0] for x in self.transport.calls], ["challenge", "ack", "challenge", "ack"])
        self.assertEqual([x[3] for x in self.transport.calls], [None, KEY, KEY, KEY])
        self.assertEqual(self.transport.calls[0][1], b"")
        self.assertEqual(self.transport.calls[1][1], m.ack_request(challenge()))
    def test_previous_boot_never_acknowledged(self):
        ob = self.observer([reply(challenge(boot=OLD))])
        self.assertFalse(ob.cycle(60)); self.assertEqual(len(self.transport.calls), 1)
        self.assertIsNone(ob.boot_id)
    def test_previous_boot_after_ack_is_fatal(self):
        ob = self.observer([reply(challenge()), reply(accepted()), reply(challenge(2, OLD))])
        ob.cycle(60)
        self.expect("boot_reverted_after_ack", lambda: ob.cycle(60))
        self.assertEqual(len(self.transport.calls), 3)
    def test_new_boot_change_after_ack_is_fatal(self):
        ob = self.observer([reply(challenge()), reply(accepted()), reply(challenge(2, OTHER))])
        ob.cycle(60)
        self.expect("boot_changed_after_ack", lambda: ob.cycle(60))
    def test_replayed_sequence_is_never_acknowledged(self):
        ob = self.observer([reply(challenge()), reply(accepted()), reply(challenge())])
        ob.cycle(60)
        self.expect("nonincreasing_sequence", lambda: ob.cycle(60))
        self.assertEqual(len(self.transport.calls), 3)
    def test_challenge_ack_key_change_rejected(self):
        ob = self.observer([reply(challenge()), reply(accepted(), key="SHA256:other")])
        self.expect("challenge_ack_host_key_changed", lambda: ob.cycle(60))
        self.assertIsNone(ob.boot_id)
    def test_pinned_key_change_rejected_before_ack(self):
        ob = self.observer([reply(challenge()), reply(accepted()), reply(challenge(2), key="SHA256:other")])
        ob.cycle(60)
        self.expect("pinned_host_key_changed", lambda: ob.cycle(60))
        self.assertEqual(len(self.transport.calls), 3)
    def test_expiry_includes_challenge_connection_latency(self):
        ob = self.observer([(reply(challenge()), 20.0)])
        self.assertTrue(self.expect("challenge_expired", lambda: ob.cycle(60)).retryable)
        self.assertEqual(len(self.transport.calls), 1)
    def test_ack_uses_conservative_expiry_deadline(self):
        ob = self.observer([(reply(challenge()), 4), (reply(accepted()), 1)])
        ob.cycle(60)
        self.assertEqual(self.transport.calls[1][2], 20)
        self.assertEqual(ob.last_ack_started, 4)
    def test_late_ack_response_does_not_pin(self):
        ob = self.observer([reply(challenge()), (reply(accepted()), 20)])
        self.assertTrue(self.expect("ack_response_expired", lambda: ob.cycle(60)).retryable)
        self.assertIsNone(ob.boot_id)
    def test_rejected_ack_does_not_pin(self):
        ob = self.observer([reply(challenge()), reply(b"", status=125)])
        self.expect("remote_rejected", lambda: ob.cycle(60))
        self.assertEqual(ob.ack_count, 0)
        self.assertIsNone(ob.boot_id)
    def test_bounded_old_boot_wait_stops(self):
        ob = self.observer([reply(challenge(boot=OLD))] * 4)
        self.assertEqual(ob.run(60, 15), 2)
        self.assertEqual(self.clock(), 60)
        self.assertEqual(self.events[-1]["reason"], "duration_without_ack")
        self.assertTrue(self.events[-1]["trial_lan_lease_may_expire"])
    def test_connection_failure_retries_within_bound(self):
        ob = self.observer([m.ObserverError("ssh_transport_failed", True), reply(challenge()), reply(accepted())])
        self.assertEqual(ob.run(30, 15), 0)
        self.assertEqual(ob.ack_count, 1)
        self.assertEqual(self.clock(), 30)
        self.assertFalse(self.events[-1]["permanent_acceptance"])
    def test_fatal_protocol_error_stops(self):
        ob = self.observer([reply(challenge(sequence=0))])
        self.assertEqual(ob.run(600, 15), 2)
        self.assertEqual(self.events[-1]["reason"], "invalid_sequence")
    def test_no_ack_after_lan_lease_safety_deadline(self):
        ob = self.observer([reply(challenge()), reply(accepted())] + [m.ObserverError("ssh_transport_failed", True)] * 4)
        self.assertEqual(ob.run(600, 15), 2)
        self.assertEqual(self.events[-1]["reason"], "lan_lease_renewal_deadline")
        self.assertEqual(ob.ack_count, 1)
        self.assertEqual(self.clock(), 55)
    def test_failed_rpc_sleep_stops_at_55_not_60(self):
        failures = [(m.ObserverError("ssh_transport_failed", True), 5)] * 3
        ob = self.observer([reply(challenge()), reply(accepted())] + failures)
        self.assertEqual(ob.run(600, 15), 2)
        self.assertEqual(self.clock(), 55)
        self.assertEqual(self.events[-1]["reason"], "lan_lease_renewal_deadline")
        self.assertEqual([x[0] for x in self.transport.calls], ["challenge", "ack", "challenge", "challenge", "challenge"])
    def test_duration_coincident_with_stale_lease_is_failure(self):
        failures = [(m.ObserverError("ssh_transport_failed", True), 5)] * 3
        ob = self.observer([reply(challenge()), reply(accepted())] + failures)
        self.assertEqual(ob.run(55, 15), 2)
        self.assertEqual(self.clock(), 55)
        self.assertEqual(self.events[-1]["reason"], "lan_lease_renewal_deadline")
    def test_events_contain_nonce_hash_not_nonce(self):
        ob = self.observer([reply(challenge()), reply(accepted())])
        ob.cycle(60)
        serialized = json.dumps(self.events)
        self.assertNotIn(NONCE, serialized)
        self.assertIn(hashlib.sha256(NONCE.encode()).hexdigest(), serialized)
    def test_keyboard_interrupt_reports_observer_stopped(self):
        ob = self.observer([])
        ob.cycle = lambda _: (_ for _ in ()).throw(KeyboardInterrupt())
        self.assertEqual(ob.run(600, 15), 130)
        self.assertEqual(self.events[-1]["reason"], "interrupted")
    def test_sigterm_reports_stopped_and_expiring_lease(self):
        ob = self.observer([])
        ob.cycle = lambda _: (_ for _ in ()).throw(m.SignalStop(15))
        self.assertEqual(ob.run(600, 15), 143)
        self.assertEqual(self.events[-1]["reason"], "signal_15")
        self.assertTrue(self.events[-1]["trial_lan_lease_may_expire"])
    def test_log_is_exclusive_0600_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            path = Path(temp) / "log.jsonl"
            log = m.EventLog(path, self.clock)
            log("observer_stopped", permanent_acceptance=False)
            log.close()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError): m.EventLog(path)
            link = Path(temp) / "link"; link.symlink_to(path)
            with self.assertRaises(OSError): m.EventLog(link)
    def test_cli_defaults_and_bounds(self):
        base = ["--known-hosts", "/unused", "--previous-boot-id", OLD]
        a = m.arguments(base)
        self.assertEqual((a.host, a.source, a.username, a.port, a.duration, a.interval),
                         ("192.168.100.15", "192.168.100.36", "MastermixStudios", 22, 600, 15))
        for tail in (["--duration", "nan"], ["--duration", "3601"], ["--interval", "60"],
                     ["--host", "not-a-numeric-host"], ["--key-passphrase"], ["--key", "x", "--agent"]):
            with self.subTest(tail=tail), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                m.arguments(base + tail)


class SSHTransportTests(unittest.TestCase):
    """Exercise production SSH adapter with fake sockets/clients, never a server."""
    @classmethod
    def setUpClass(cls):
        import paramiko
        cls.pm = paramiko
        cls.key = paramiko.RSAKey.generate(1024)  # Ephemeral test-only public trust fixture.
        cls.fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(cls.key.asbytes()).digest()).decode().rstrip("=")
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.kh = Path(self.tmp.name) / "known_hosts"
        self.kh.write_text("192.168.100.15 " + self.key.get_name() + " " + self.key.get_base64() + "\n")
        self.kh.chmod(0o600)
        self.args = types.SimpleNamespace(known_hosts=self.kh, host="192.168.100.15", port=22,
            username="MastermixStudios", source="192.168.100.36", key=None, agent=False,
            connect_timeout=0.2, command_timeout=0.2)
    def test_explicit_trust_rejects_unknown_unsafe_and_symlink(self):
        self.args.host = "192.168.100.99"
        with self.assertRaises(m.ObserverError) as cm: m.SSHTransport(self.args, None, None)
        self.assertEqual(cm.exception.code, "target_not_in_known_hosts")
        self.args.host = "192.168.100.15"; self.kh.chmod(0o666)
        with self.assertRaises(m.ObserverError) as cm: m.SSHTransport(self.args, None, None)
        self.assertEqual(cm.exception.code, "unsafe_known_hosts_file")
        self.kh.chmod(0o600); link = self.kh.with_name("link"); link.symlink_to(self.kh)
        self.args.known_hosts = link
        with self.assertRaises(OSError): m.SSHTransport(self.args, None, None)
    def test_explicit_key_rejects_group_readable_or_symlink(self):
        key = self.kh.with_name("key"); key.write_text("dummy-not-real-key"); key.chmod(0o640)
        self.args.key = key
        with self.assertRaises(m.ObserverError) as cm: m.SSHTransport(self.args, None, None)
        self.assertEqual(cm.exception.code, "unsafe_private_key_file")
        key.chmod(0o600); link = key.with_name("key-link"); link.symlink_to(key)
        self.args.key = link
        with self.assertRaises(m.ObserverError) as cm: m.SSHTransport(self.args, None, None)
        self.assertEqual(cm.exception.code, "unsafe_private_key_file")
    def test_known_hosts_fifo_refused_without_blocking(self):
        fifo = self.kh.with_name("fifo"); os.mkfifo(fifo, 0o600)
        self.args.known_hosts = fifo
        started = time.monotonic()
        with self.assertRaises(m.ObserverError) as cm: m.SSHTransport(self.args, None, None)
        self.assertEqual(cm.exception.code, "unsafe_known_hosts_file")
        self.assertLess(time.monotonic() - started, 0.1)
    def fake_network(self, outputs, stall_connect=False, never_exit=False):
        owner = self
        sockets, clients = [], []
        class Sock:
            def __init__(self, *args): self.closed = False; self.closed_event = threading.Event(); sockets.append(self)
            def settimeout(self, t): self.timeout = t
            def bind(self, address): self.source = address
            def connect(self, address): self.target = address
            def shutdown(self, _): self.closed_event.set()
            def close(self): self.closed = True; self.closed_event.set()
        class Channel:
            def __init__(self, data): self.data = data; self.sent = b""
            def settimeout(self, t): self.timeout = t
            def exec_command(self, cmd): self.command = cmd
            def sendall(self, data): self.sent += data
            def shutdown_write(self): self.eof = True
            def recv_ready(self): return bool(self.data)
            def recv(self, n): data, self.data = self.data[:n], self.data[n:]; return data
            def recv_stderr_ready(self): return False
            def exit_status_ready(self): return not never_exit
            def recv_exit_status(self): return 0
        class Client:
            def __init__(self): self.keys = owner.pm.HostKeys(); self.closed = False; clients.append(self)
            def set_log_channel(self, name): self.log_channel = name
            def set_missing_host_key_policy(self, policy): self.policy = policy
            def get_host_keys(self): return self.keys
            def connect(self, host, **kw):
                self.kw = kw
                if stall_connect:
                    kw["sock"].closed_event.wait(1)
                    raise OSError("peer-supplied-sensitive-diagnostic")
            def get_transport(self): return self
            def get_remote_server_key(self): return owner.key
            def open_session(self, **kw): self.channel = Channel(outputs.pop(0)); return self.channel
            def is_active(self): return not self.closed
            def close(self): self.closed = True
        return Sock, Client, sockets, clients
    def test_fresh_tcp_client_each_rpc_fixed_commands_rejectpolicy(self):
        transport = m.SSHTransport(self.args, "test-password-never-log", None)
        sock, client, sockets, clients = self.fake_network([encoded(challenge()), encoded(accepted())])
        with patch.object(m.socket, "socket", sock), patch.object(self.pm, "SSHClient", client):
            first = transport.exchange("challenge", b"", time.monotonic() + 1, None)
            second = transport.exchange("ack", m.ack_request(challenge()), time.monotonic() + 1, first.fingerprint)
        self.assertEqual(len(sockets), 2); self.assertEqual(len(clients), 2)
        self.assertTrue(all(x.closed for x in sockets + clients))
        self.assertTrue(all(isinstance(x.policy, self.pm.RejectPolicy) for x in clients))
        self.assertTrue(all(x.source == ("192.168.100.36", 0) for x in sockets))
        self.assertTrue(all(not x.kw["allow_agent"] and not x.kw["look_for_keys"] for x in clients))
        self.assertEqual([x.channel.command for x in clients], [m.HELPER + " --challenge", m.HELPER + " --ack"])
        self.assertEqual([x.channel.sent for x in clients], [b"", m.ack_request(challenge())])
        self.assertEqual(second.fingerprint, self.fingerprint)
    def test_pinned_host_key_blocks_exec(self):
        transport = m.SSHTransport(self.args, None, None)
        sock, client, sockets, clients = self.fake_network([])
        with patch.object(m.socket, "socket", sock), patch.object(self.pm, "SSHClient", client):
            with self.assertRaises(m.ObserverError) as cm:
                transport.exchange("ack", m.ack_request(challenge()), time.monotonic() + 1, "SHA256:wrong")
        self.assertEqual(cm.exception.code, "pinned_host_key_changed")
        self.assertFalse(hasattr(clients[0], "channel"))
    def test_remote_output_bounded(self):
        transport = m.SSHTransport(self.args, None, None)
        sock, client, _, _ = self.fake_network([b"X" * 10000])
        with patch.object(m.socket, "socket", sock), patch.object(self.pm, "SSHClient", client):
            with self.assertRaises(m.ObserverError) as cm:
                transport.exchange("challenge", b"", time.monotonic() + 1, None)
        self.assertEqual(cm.exception.code, "remote_output_limit")
    def test_command_deadline_closes_connection(self):
        self.args.command_timeout = 0.03
        transport = m.SSHTransport(self.args, None, None)
        sock, client, sockets, _ = self.fake_network([b""], never_exit=True)
        started = time.monotonic()
        with patch.object(m.socket, "socket", sock), patch.object(self.pm, "SSHClient", client):
            with self.assertRaises(m.ObserverError) as cm:
                transport.exchange("challenge", b"", time.monotonic() + 1, None)
        self.assertEqual(cm.exception.code, "transport_deadline")
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertTrue(sockets[0].closed)
    def test_total_connect_deadline_closes_socket(self):
        self.args.connect_timeout = 0.03
        transport = m.SSHTransport(self.args, None, None)
        sock, client, sockets, _ = self.fake_network([], stall_connect=True)
        started = time.monotonic()
        with patch.object(m.socket, "socket", sock), patch.object(self.pm, "SSHClient", client):
            with self.assertRaises(m.ObserverError) as cm:
                transport.exchange("challenge", b"", time.monotonic() + 1, None)
        self.assertEqual(cm.exception.code, "transport_deadline")
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertTrue(sockets[0].closed)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    # Any accidentally unmocked socket creation fails before a TCP packet exists.
    with patch.object(m.socket, "socket", side_effect=AssertionError("network forbidden in offline tests")):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.report:
        import paramiko
        report = {"schema_version": 1, "status": "passed" if result.wasSuccessful() else "failed",
                  "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
                  "network_access": False, "router_connections": False, "actual_ssh_server_tested": False,
                  "paramiko_version": paramiko.__version__,
                  "observer": {"path": str(SOURCE), "sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest()},
                  "tests": {"path": str(Path(__file__)), "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
                  "limits": ["Transport uses production adapter with mocked sockets/Paramiko clients, not a real SSH server.",
                             "The native trial-ack CLI and hardware trial guardian need separate target acceptance.",
                             "No known host is enrolled and no metadata/commit/reset command exists."]}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())

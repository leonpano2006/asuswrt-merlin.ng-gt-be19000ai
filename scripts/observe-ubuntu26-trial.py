#!/usr/bin/env python3
"""Bounded external SSH trial observer; never enroll keys or accept a boot permanently.

Each challenge and ACK uses a fresh TCP/SSH connection. The only remote commands
are the fixed trial-ack helper arguments. Passwords/passphrases stay in memory;
the JSONL log contains neither authentication material nor raw challenges.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable

HELPER = "/usr/libexec/leon-asus/trial-ack"
MAX_OUTPUT = 4096
MAX_KNOWN_HOSTS = 1024 * 1024
MAX_SEQUENCE = (1 << 64) - 1
MAX_CHALLENGE_SECONDS = 20.0
LEASE_SAFETY_SECONDS = 55.0  # Remote LAN lease is 60s; do not knowingly cross it.


class ObserverError(Exception):
    def __init__(self, code: str, retryable: bool = False):
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class SignalStop(KeyboardInterrupt):
    def __init__(self, signum):
        self.signum = signum


def canonical_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise ObserverError("invalid_boot_id")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise ObserverError("invalid_boot_id") from None
    return value


def strict_json(data: bytes, keys: set[str]) -> dict:
    if not data or len(data) > MAX_OUTPUT:
        raise ObserverError("invalid_output_size")
    # A helper returns exactly one JSON object, with an optional final newline.
    body = data[:-1] if data.endswith(b"\n") else data
    if b"\n" in body or b"\r" in body or not body.startswith(b"{") or not body.endswith(b"}"):
        raise ObserverError("invalid_single_json_response")

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ObserverError("duplicate_json_key")
            out[key] = value
        return out

    try:
        obj = json.loads(body.decode("utf-8"), object_pairs_hook=pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise ObserverError("invalid_json_response") from None
    if not isinstance(obj, dict) or set(obj) != keys:
        raise ObserverError("unexpected_response_fields")
    if type(obj["schema"]) is not int or obj["schema"] != 1:
        raise ObserverError("unsupported_schema")
    canonical_uuid(obj["boot_id"])
    if type(obj["sequence"]) is not int or not 1 <= obj["sequence"] <= MAX_SEQUENCE:
        raise ObserverError("invalid_sequence")
    return obj


def parse_challenge(data: bytes) -> dict:
    obj = strict_json(data, {"schema", "boot_id", "challenge", "sequence", "expires_in_ms"})
    if not isinstance(obj["challenge"], str) or not re.fullmatch(r"[0-9a-f]{64}", obj["challenge"]):
        raise ObserverError("invalid_challenge")
    if type(obj["expires_in_ms"]) is not int or not 1 <= obj["expires_in_ms"] <= 20000:
        raise ObserverError("invalid_challenge_expiry")
    return obj


def ack_request(challenge: dict) -> bytes:
    # This insertion order is the frozen native CLI wire contract.
    obj = {"schema": 1, "boot_id": challenge["boot_id"],
           "challenge": challenge["challenge"], "sequence": challenge["sequence"]}
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def parse_ack(data: bytes, challenge: dict) -> dict:
    obj = strict_json(data, {"schema", "accepted", "boot_id", "sequence"})
    if obj["accepted"] is not True:
        raise ObserverError("ack_not_accepted")
    if obj["boot_id"] != challenge["boot_id"] or obj["sequence"] != challenge["sequence"]:
        raise ObserverError("ack_identity_mismatch")
    return obj


@dataclass(frozen=True)
class Reply:
    stdout: bytes
    stderr: bytes
    status: int
    fingerprint: str


def successful_output(reply: Reply) -> bytes:
    if len(reply.stdout) + len(reply.stderr) > MAX_OUTPUT:
        raise ObserverError("remote_output_limit")
    if reply.status == 125 and not reply.stdout:
        raise ObserverError("remote_rejected", retryable=True)
    if reply.status != 0:
        raise ObserverError("unexpected_remote_exit")
    if reply.stderr:
        raise ObserverError("unexpected_remote_stderr")
    return reply.stdout


class EventLog:
    def __init__(self, path: Path | None, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.started = clock()
        self.fd = None
        if path is not None:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            self.fd = os.open(path, flags, 0o600)
            os.fchmod(self.fd, 0o600)

    def __call__(self, event: str, **values):
        line = json.dumps({"event": event, "elapsed_seconds": round(self.clock() - self.started, 3),
                           **values}, separators=(",", ":"), ensure_ascii=True) + "\n"
        if self.fd is not None:
            data = line.encode()
            while data:
                data = data[os.write(self.fd, data):]
        print(line, end="", flush=True)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class SSHTransport:
    """No connection pooling, auto-discovered keys, TOFU, DNS or remote shell input."""
    def __init__(self, args, password: str | None, passphrase: str | None):
        import paramiko
        self.paramiko = paramiko
        self.args = args
        self.password = password
        self.passphrase = passphrase
        if args.key is not None:
            st = args.key.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o077:
                raise ObserverError("unsafe_private_key_file")
        # Snapshot the explicit trust file through a no-follow descriptor. It must
        # already contain the device-local key verified via trusted stock SSH.
        fd = os.open(args.known_hosts, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
                raise ObserverError("unsafe_known_hosts_file")
            with os.fdopen(fd, "rb", closefd=False) as f:
                data = f.read(MAX_KNOWN_HOSTS + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_KNOWN_HOSTS:
            raise ObserverError("known_hosts_too_large")
        self.known_hosts_sha256 = hashlib.sha256(data).hexdigest()
        self.keys = paramiko.HostKeys()
        try:
            for line in data.decode("utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entry = paramiko.hostkeys.HostKeyEntry.from_line(line)
                if entry is None or entry.key is None:
                    raise ObserverError("unsupported_known_hosts_entry")
                for host in entry.hostnames:
                    self.keys.add(host, entry.key.get_name(), entry.key)
        except (ValueError, UnicodeError, paramiko.SSHException):
            raise ObserverError("invalid_known_hosts_file") from None
        hostkey_name = args.host if args.port == 22 else f"[{args.host}]:{args.port}"
        if not self.keys.lookup(hostkey_name):
            raise ObserverError("target_not_in_known_hosts")

    def exchange(self, action: str, stdin: bytes, deadline: float,
                 expected_fingerprint: str | None) -> Reply:
        if action not in ("challenge", "ack") or (action == "challenge" and stdin):
            raise ObserverError("invalid_local_request")
        if len(stdin) > 512:
            raise ObserverError("invalid_local_request")
        a, pm = self.args, self.paramiko
        client = pm.SSHClient()
        # Keep library diagnostics (which may contain peer-controlled text) out
        # of the deliberately restricted observer JSONL log and stderr.
        ssh_logger = logging.getLogger("leon_trial_observer.ssh")
        ssh_logger.handlers = [logging.NullHandler()]
        ssh_logger.propagate = False
        client.set_log_channel("leon_trial_observer.ssh")
        client.set_missing_host_key_policy(pm.RejectPolicy())
        for name in self.keys:
            for kind, key in self.keys[name].items():
                client.get_host_keys().add(name, kind, key)
        family = socket.AF_INET6 if ":" in a.host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        timer = None
        timed_out = threading.Event()

        def abort():
            timed_out.set()
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
            client.close()

        def arm(until):
            nonlocal timer
            if timer is not None:
                timer.cancel()
                timer.join()
            remaining = until - time.monotonic()
            if remaining <= 0 or timed_out.is_set():
                raise ObserverError("transport_deadline", retryable=True)
            timer = threading.Timer(remaining, abort)
            timer.daemon = True
            timer.start()
            return remaining

        try:
            remaining = arm(min(deadline, time.monotonic() + a.connect_timeout))
            sock.settimeout(remaining)
            if a.source is not None:
                sock.bind((a.source, 0))
            sock.connect((a.host, a.port))
            client.connect(a.host, port=a.port, username=a.username, sock=sock,
                           timeout=remaining, banner_timeout=remaining, auth_timeout=remaining,
                           password=self.password, passphrase=self.passphrase,
                           key_filename=str(a.key) if a.key else None,
                           allow_agent=a.agent, look_for_keys=False,
                           gss_auth=False, gss_kex=False)
            transport = client.get_transport()
            key = transport.get_remote_server_key()
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
            if expected_fingerprint is not None and fingerprint != expected_fingerprint:
                raise ObserverError("pinned_host_key_changed")
            remaining = arm(min(deadline, time.monotonic() + a.command_timeout))
            channel = transport.open_session(timeout=remaining)
            channel.settimeout(remaining)
            channel.exec_command(HELPER + " --" + action)
            if stdin:
                channel.sendall(stdin)
            channel.shutdown_write()
            out, err = bytearray(), bytearray()
            while True:
                if timed_out.is_set() or time.monotonic() >= deadline:
                    raise ObserverError("transport_deadline", retryable=True)
                if channel.recv_ready():
                    out.extend(channel.recv(MAX_OUTPUT + 1))
                if channel.recv_stderr_ready():
                    err.extend(channel.recv_stderr(MAX_OUTPUT + 1))
                if len(out) + len(err) > MAX_OUTPUT:
                    raise ObserverError("remote_output_limit")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    status = channel.recv_exit_status()
                    break
                if not transport.is_active():
                    raise ObserverError("ssh_disconnected", retryable=True)
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
            if timed_out.is_set() or time.monotonic() >= deadline:
                raise ObserverError("transport_deadline", retryable=True)
            return Reply(bytes(out), bytes(err), status, fingerprint)
        except pm.BadHostKeyException:
            raise ObserverError("known_host_key_mismatch") from None
        except pm.AuthenticationException:
            raise ObserverError("ssh_authentication_failed") from None
        except pm.PasswordRequiredException:
            raise ObserverError("key_passphrase_required") from None
        except (OSError, EOFError, pm.SSHException):
            code = "transport_deadline" if timed_out.is_set() else "ssh_transport_failed"
            raise ObserverError(code, retryable=True) from None
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()
            client.close()
            sock.close()


class Observer:
    def __init__(self, transport, previous_boot: str, emit: Callable,
                 clock=time.monotonic, sleep=time.sleep):
        self.transport = transport
        self.previous_boot = canonical_uuid(previous_boot)
        self.emit = emit
        self.clock, self.sleep = clock, sleep
        self.boot_id = None
        self.fingerprint = None
        self.sequence = 0
        self.ack_count = 0
        self.last_ack_started = None

    def cycle(self, deadline: float) -> bool:
        started = self.clock()
        reply = self.transport.exchange("challenge", b"", deadline, self.fingerprint)
        if self.fingerprint is not None and reply.fingerprint != self.fingerprint:
            raise ObserverError("pinned_host_key_changed")
        challenge = parse_challenge(successful_output(reply))
        if challenge["boot_id"] == self.previous_boot:
            if self.boot_id is not None:
                raise ObserverError("boot_reverted_after_ack")
            self.emit("waiting_for_new_boot")
            return False
        if self.boot_id is not None and challenge["boot_id"] != self.boot_id:
            raise ObserverError("boot_changed_after_ack")
        if challenge["sequence"] <= self.sequence:
            raise ObserverError("nonincreasing_sequence")
        # Start before opening the challenge connection, not at response receipt:
        # this conservative bound includes all transit/authentication delay.
        expires = min(deadline, started + challenge["expires_in_ms"] / 1000.0)
        if self.clock() >= expires:
            raise ObserverError("challenge_expired", retryable=True)
        ack_started = self.clock()
        ack_reply = self.transport.exchange("ack", ack_request(challenge), expires, reply.fingerprint)
        if ack_reply.fingerprint != reply.fingerprint:
            raise ObserverError("challenge_ack_host_key_changed")
        if self.clock() >= expires:
            raise ObserverError("ack_response_expired", retryable=True)
        parse_ack(successful_output(ack_reply), challenge)
        first = self.boot_id is None
        self.boot_id, self.fingerprint = challenge["boot_id"], reply.fingerprint
        self.sequence = challenge["sequence"]
        self.ack_count += 1
        self.last_ack_started = ack_started
        self.emit("trial_lan_ack", first_ack=first, boot_id=self.boot_id,
                  host_key_sha256=self.fingerprint, sequence=self.sequence,
                  challenge_sha256=hashlib.sha256(challenge["challenge"].encode("ascii")).hexdigest())
        return True

    def run(self, duration: float, interval: float) -> int:
        deadline = self.clock() + duration
        stopped = "duration_complete"
        code = 0
        try:
            while self.clock() < deadline:
                cycle_start = self.clock()
                rpc_deadline = deadline
                if self.last_ack_started is not None:
                    rpc_deadline = min(rpc_deadline, self.last_ack_started + LEASE_SAFETY_SECONDS)
                    if self.clock() >= rpc_deadline:
                        stopped, code = "lan_lease_renewal_deadline", 2
                        break
                try:
                    self.cycle(rpc_deadline)
                except ObserverError as exc:
                    self.emit("observation_failed", reason=exc.code, retryable=exc.retryable)
                    if not exc.retryable:
                        stopped, code = exc.code, 2
                        break
                wake_at = min(deadline, cycle_start + interval)
                if self.last_ack_started is not None:
                    wake_at = min(wake_at, self.last_ack_started + LEASE_SAFETY_SECONDS)
                self.sleep(max(0, wake_at - self.clock()))
            if (code == 0 and self.last_ack_started is not None and
                    self.clock() >= self.last_ack_started + LEASE_SAFETY_SECONDS):
                stopped, code = "lan_lease_renewal_deadline", 2
            elif self.ack_count == 0 and code == 0:
                stopped, code = "duration_without_ack", 2
        except KeyboardInterrupt as exc:
            stopped, code = "interrupted", 130
            if isinstance(exc, SignalStop):
                stopped, code = "signal_" + str(exc.signum), 128 + exc.signum
        finally:
            self.emit("observer_stopped", reason=stopped, acknowledgements=self.ack_count,
                      boot_id=self.boot_id, last_sequence=self.sequence,
                      trial_lan_lease_may_expire=True, permanent_acceptance=False)
        return code


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="192.168.100.15", help="Numeric IP; no DNS resolution")
    p.add_argument("--source", default="192.168.100.36", help="Local numeric source IP, or 'none'")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--username", default="MastermixStudios")
    p.add_argument("--known-hosts", required=True, type=Path,
                   help="Existing trusted key file verified via stock SSH after device-local key provisioning; never TOFU")
    p.add_argument("--previous-boot-id", required=True, type=canonical_uuid)
    auth = p.add_mutually_exclusive_group()
    auth.add_argument("--password", action="store_true", help="Prompt once (also the default)")
    auth.add_argument("--key", type=Path, help="Use only this explicitly selected private key")
    auth.add_argument("--agent", action="store_true", help="Use the explicitly selected SSH agent")
    p.add_argument("--key-passphrase", action="store_true", help="Prompt for --key passphrase in memory")
    p.add_argument("--duration", type=float, default=600, help="1..3600 seconds; default600")
    p.add_argument("--interval", type=float, default=15, help="1..30 seconds between challenge starts")
    p.add_argument("--connect-timeout", type=float, default=5, help="0.1..10s total TCP/SSH/auth deadline")
    p.add_argument("--command-timeout", type=float, default=5, help="0.1..10s total helper deadline")
    p.add_argument("--log", type=Path, help="Create a new0600 JSONL file; existing paths refused")
    a = p.parse_args(argv)
    try:
        host = ipaddress.ip_address(a.host)
        a.host = str(host)
        if a.source == "none":
            a.source = None
        else:
            source = ipaddress.ip_address(a.source)
            if source.version != host.version:
                raise ValueError()
            a.source = str(source)
    except ValueError:
        p.error("host/source must be numeric IPs of the same address family (or source=none)")
    if not 1 <= a.port <= 65535 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", a.username):
        p.error("invalid port or username")
    for name, lo, hi in (("duration", 1, 3600), ("interval", 1, 30),
                         ("connect_timeout", 0.1, 10), ("command_timeout", 0.1, 10)):
        value = getattr(a, name)
        if not math.isfinite(value) or not lo <= value <= hi:
            p.error(f"{name} must be finite and within {lo}..{hi}")
    if a.key_passphrase and not a.key:
        p.error("--key-passphrase requires --key")
    a.known_hosts = a.known_hosts.expanduser()
    if a.key:
        a.key = a.key.expanduser()
    return a


def main(argv=None):
    log = None
    old_term = signal.getsignal(signal.SIGTERM)
    def stop_term(signum, _frame):
        raise SignalStop(signum)
    signal.signal(signal.SIGTERM, stop_term)
    try:
        a = arguments(argv)
        log = EventLog(a.log)
        password = None if a.key or a.agent else getpass.getpass("Router SSH password (memory only): ")
        passphrase = getpass.getpass("SSH key passphrase (memory only): ") if a.key_passphrase else None
        transport = SSHTransport(a, password, passphrase)
        log("observer_started", host=a.host, port=a.port, source=a.source, username=a.username,
            previous_boot_id=a.previous_boot_id, duration_seconds=a.duration,
            interval_seconds=a.interval, known_hosts_sha256=transport.known_hosts_sha256,
            auth_method="key" if a.key else "agent" if a.agent else "password",
            fresh_tcp_per_helper=True, permanent_acceptance=False)
        return Observer(transport, a.previous_boot_id, log).run(a.duration, a.interval)
    except (ObserverError, OSError, ImportError, EOFError, KeyboardInterrupt) as exc:
        reason = exc.code if isinstance(exc, ObserverError) else "local_setup_failed"
        if isinstance(exc, SignalStop):
            reason = "signal_" + str(exc.signum)
        event = {"event": "observer_stopped", "reason": reason,
                 "trial_lan_lease_may_expire": True, "permanent_acceptance": False}
        # Never format underlying exceptions: SSH libraries can embed server text.
        if log:
            log(event.pop("event"), **event)
        else:
            print(json.dumps(event), file=sys.stderr)
        return (128 + exc.signum) if isinstance(exc, SignalStop) else 130 if isinstance(exc, KeyboardInterrupt) else 2
    finally:
        if log:
            log.close()
        signal.signal(signal.SIGTERM, old_term)


if __name__ == "__main__":
    sys.exit(main())

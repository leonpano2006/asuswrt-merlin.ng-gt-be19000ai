# ASUS startup bridge foundation

This is an unintegrated source port from the BE98 `systemd-rc-compat-20260916`
checkpoint. It is not an ASUS startup implementation or a flashable component.
`port-origins.json` records original and ported source hashes. No service unit,
preload configuration, rootfs or upstream source is installed or changed here.

The intended initial ownership chain is systemd PID1 → native ARM64 broker →
board-specific ARMEL rc manager. The manager retains hardware/NVRAM startup
ordering. It must be rebuilt with explicit manager-role checks; stock rc cannot
be made compatible just by running it as a service or faking `getpid()`.

The source preserves a fixed 16-byte `SOCK_SEQPACKET` protocol, root peer checks,
direct-child HELLO/READY checks, bounded socket timeouts and a restricted signal
set. This port rejects nonzero unused protocol values and duplicate READY.
BE98's hardcoded ARMEL trial-bootguard injection was removed. A tested BE19000AI
boot guard and ABI-correct notification shim are mandatory before integration.
The broker clears process-local `LD_PRELOAD` before executing its ARMEL child;
explicit linking or a narrowly scoped ASUS launcher must supply the correct shim
for each selected executable. No global `LD_PRELOAD` or `/etc/ld.so.preload`
configuration is proposed. A missing shim makes the manager entry fail closed.

This copied foundation is Ubuntu-only: missing management marker, broker or shim
never enables a legacy init path. The client does not call `kill(1, ...)` or
`reboot()` directly. Manager entry rejects PID1, and its role requires both the
authenticated stored PID and the management marker. Lost-marker readiness,
shutdown and mount calls fail; rc-only wrappers also reject global broadcasts.
The original standalone ASUS firmware can keep its separate legacy code path,
but it is not a runtime fallback in this Ubuntu binary.

The inherited mount helper only prevents remounting selected API/runtime mounts;
it does not preserve all Ubuntu `/etc` or `/var` files. Stock `sysinit` still
truncates `/etc/hosts` and `/etc/fstab`, rewrites resolv.conf, imports `/rom/etc`,
and initializes ASUS account files. Those paths need explicit file ownership and
source changes before executing real rc. The BE98 patch only guarded fstab in
that block and is insufficient for the new persistent Ubuntu layout.

Ubuntu `/bin/sh` must remain distribution-owned. ASUS scripts relying on BusyBox
ash syntax need explicit private-shell shebangs/call sites or verified POSIX
fixes. Updating a shebang does not fix strings passed to libc `system()` or
`popen()`, which invoke `/bin/sh` directly. Rebuilt rc call sites must either use
an explicit private shell through argv or have their command strings corrected;
the environment's `SHELL` variable does not change that libc contract.

Run the local fixtures with:

```sh
python3 scripts/asus-integration/check-offline.py
```

The native compiler is recorded rather than assumed to be the packaged Ubuntu
GCC16.2 compiler. Outputs live under `build/asus-integration/`; they must be
rebuilt with the accepted candidate toolchain before deployment. The test uses
`mmdebstrap --unshare-helper` to run a mock backend under isolated namespace
credentials. All runtime files are uniquely named under `/tmp`. Test broker
builds compile out real power execution. Only owned fixture processes
receive signals, and the power path records a private text file.

Tests cover malformed/unauthorized requests, manager identity and subreaper,
seven mock notification call shapes, ordinary self-signals, missing broker/shim,
readiness, orderly mock drain and backend failure. They do not execute the
actual ARMEL rc, proprietary libshared, ASUS daemons, device setup, mount calls
or real power requests. The two initial harness failures are retained beside
the final passing report: subordinate UIDs could not traverse the user's home;
then an inherited `/proc` view was incorrectly used for namespace PID checks.
The missing-marker regression separately compiles normal client/manager/shim/
wrapper logic without `LEON_RC_OFFLINE_TEST`; inert syscall boundaries count any
unexpected physical action. It verifies zero physical actions and exercises
marker loss in the running mock broker/manager as well as refusal at startup.

See `reports/ubuntu26/asus-startup-integration.json` for exact source anchors,
later BE98 fixes that must not be lost, and the remaining integration gates.

The current phase-one source port is recorded separately in
`reports/ubuntu26/asus-rc-systemd-port.json`. `prepare-rc-systemd-port.py`
verifies 116 pinned input files before generating patch0003 and the separate
OpenSSH ownership patch0005. Patch0004 is the persistent-layout agent's port;
`prepare-libovpn-systemd-port.py` generates patch0006 for four external VPN
manager-role checks. Apply them in numeric order. These are source candidates,
not a completed rc/libovpn build. They do not activate services.

The foundation now blocks the early SIGALRM raised by ASUS handle_reap(), and
`leon_rc_system()` uses the explicit private ash with a cleared child signal
mask. Local protocol tests cover this in addition to the missing-marker cases
(13 total). The source profile adds an rc-only system() linker wrapper; DSO
internal calls, popen and explicit shell exec still need separate ownership
review. Missing protected mounts are rejected instead of mounting over trees.

`check-source-port.py` independently checks lexical preservation, exact input
hash refusal, deterministic output, the actual isolated SSH entry points,
the extracted reboot/halt dispatcher and the libovpn role header. Full rc is
never executed. Parent-owned kernel10/systemd259 QEMU tests rebuilt the native
mock using GCC16.2/glibc2.44 and also tested an ARMEL mock; seven lifecycle checks
passed for each ABI. See `reports/ubuntu26/asus-systemd-lifecycle.json` for that
bounded result. It does not make real ASUS service startup ready for flashing.

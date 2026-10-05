# Private debug_monitor recovery adapter

This component handles one exact `kill(1, SIGTERM)` instruction in the pinned
GT-BE19000AI ARMEL `debug_monitor`. It requests ASUS `restart_wireless` through
the existing notify shim and authenticated native broker. It never substitutes
a global `kill`, changes `getpid`, rewrites the vendor ELF, or sends that power
signal to systemd. Other signals delegate through the existing notify shim.

The launcher requires systemd PID1, ASUS private `/etc`, and the pinned native
broker. It verifies the original ELF and adapter hash before `fexecve`. The
adapter checks its current executable even after daemon forks, exact return
address, the private namespace, and ready broker before requesting recovery.
Its preload environment is removed before vendor main, so an unrelated exec
descendant does not inherit this component adapter; private notify compatibility
remains available in `/etc/ld.so.preload`.

The budget is a root0600 `once` file inside root0700
`/run/leon-asus-wifi-recovery`. Exclusive creation, file and directory fsync
happen before enqueuing. Failed or ambiguous requests consume the budget.
Neither monitor respawn nor broker restart removes it. No package cleanup hook
should remove it while the same boot remains running.

`build.py --label NAME` uses the existing isolated GCC15.2 ARMEL build
environment, Ubuntu glibc2.44, A53 crypto/CRC and 64-bit time/file interfaces.
It builds `production/` and separate `fixture/` identities. Only the two
`production/` ELF files belong in the eventual package:

- `/usr/libexec/asus/debug-monitor-launch` (0755)
- `/usr/lib/arm-linux-gnueabi/leon-asus/libdebug-monitor-bridge.so` (0644)

The private command map must route `debug_monitor` to the launcher. The original
ELF remains at `/usr/libexec/asus/vendor/usr/sbin/debug_monitor`. The launcher
accepts no arguments or the known optional crash-log directory `/data`; an
unreviewed different directory is rejected. Integration must preserve the
pinned broker and notify library bytes or rebuild this component.

`prepare-qemu.py` creates a no-NIC kernel10 fixture from an inactive runtime07
rootfs. It replaces the vendor monitor **inside the disposable guest only**
with a synthetic ARMEL ET_EXEC and uses the actual broker and notify libraries.
`check-qemu.py` verifies artifact hashes, completion markers, and the adapter's
single exported function. This proves the bridge, ownership gates, signal
chain, and recovery budget. It does not prove actual Broadcom WiFi recovery.

ASUS `restart_wireless` covers more than one radio, including some associated
services and conditional network setup. No claim is made that all wired ports
stay uninterrupted. A repeated firmware fault is logged/suppressed instead of
creating an automatic reset loop; separate health/guardian policy is unchanged.

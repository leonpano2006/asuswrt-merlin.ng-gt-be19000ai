# GT-BE19000AI kernel and node UI development

Private, independent development repository for the GT-BE19000AI. The `source`
Git submodule pins ASUSWRT-Merlin tag `3006.102.9` at
`69838e4a60564e5550e97f11d8a8cf2c6260c4f0`. Its upstream history remains accessible
through that repository; this repository records the ordered modification history
as reviewable patches. It is not a second GitHub fork-network entry.

The previously built kernel trial images change only the BCM6813 Linux 4.19.294 kernel, open-source modules, and SquashFS
compression. All userspace files, symlinks, permissions and timestamps
outside `lib/modules` match the original firmware. The existing BE19000AI vendor
modules, bootloader, ATF and DTBs are retained. The AI board is not modified.
Ubuntu 26.04 and a Docker userspace installation are outside this build.

The kernel feature baseline is the running GT-BE98 kernel #36: memory/swap cgroups,
pids/devices/freezer/cpuacct, namespaces, seccomp, veth/macvlan, OverlayFS, Btrfs,
XFS, modern Zstd, zswap/zsmalloc and zram. Kernel #6 adds CFS CPU quota,
cpuset, block read/write throttling and unprivileged user namespaces. Its task,
scheduler and block layouts retain the existing vendor offsets; 142 block fields
are also checked at compile time. Block queue/request private allocations and a
bio handle keep vendor-facing structure sizes unchanged. BE19000AI stock features
including ICP201XX, CRC8 and MMC oops are retained. Net-device field offsets used
by proprietary drivers are protected separately; this is not a proof of every
proprietary driver's internal ABI.

## Integrated release kernel9-ui1 — running as a one-time trial

Kernel9 adds the ARM32 time64 syscall ABI while preserving the existing ARM32
time32 and native AArch64 interfaces. Nineteen new calls have enabled subsystems;
`io_pgetevents_time64` remains `ENOSYS` because `CONFIG_AIO=n`. Its optional
handler passes a separate compile-only check. Compound 32-bit fd/signal/message
layouts are handled explicitly rather than passed to incompatible native handlers.
`configs/kernel9.config` is byte-identical to kernel8.

QEMU passes direct syscall probes for AArch64, ARM32 soft-float and ARM32
hard-float, armel/armhf glibc probes, and the resource-limit, PSI and
Docker/memory/swap/filesystem regression suites. See
[kernel9 candidate evidence](reports/kernel9/candidate.json),
[handler review](reports/time64/kernel9-handler-review.json), and the incremental
`patches/0007-arm32-time64-compat.patch`.

The 86,709,020-byte integrated image has SHA-256
`d849dd524e40c1426edeca0dbeb9d0f6daa49cb6c7e207c54d609179c1640603`.
It retains all 133 kernel8 modules and the existing web/RGB/history/CCR integration;
only the release manifest and startup script version label change in the rootfs.
The exact integrated Docker/memory/swap/filesystem QEMU run and the separate
metadata write-protection test pass. Original and new RSA-PSS signatures and the
BSP LZO kernel round-trip are verified.

The authorized image now boots on the physical BCM6813 in slot 1. Flash readback,
the running config and 27 live integration files match their expected hashes;
the original slot 2 full hashes remain unchanged. Direct arm64, armel and armhf
probes each pass 17 enabled calls and 11 behavior checks with no unexpected
`ENOSYS`. AIO remains disabled and is tested separately. Isolated armel/armhf
glibc 2.44 accepts a private timer beyond signed 32-bit seconds, and the file-time
probe round-trips year 2100. No probe sets or adjusts the global clock, and all
temporary probe files have been removed.

BE98 reports the node online over Ethernet. All three radios are up, both LACP
members are up at 1 Gbps, the AI internal link responds, and the integrated RGB,
web and collectors run with fresh telemetry. Chrome confirms independent local
login, the editable AI-board hostname field and three running containers; the
reported container uptimes predate this BCM reboot. The boot-log comparison finds
no new fatal kernel fault or error family. At the early health sample AiMesh and
time synchronization were still starting; both converged within the same boot.
This is bounded acceptance, not a long soak, throughput result, physical RGB
colour confirmation or proof that every SSID/IoT client has recovered. See
[kernel9 hardware acceptance](reports/kernel9/hardware-acceptance.json),
[hardware time64 tests](reports/time64/hardware-kernel9.json), and
[boot-log review](reports/kernel9/boot-log-review.json).

**Slot 1 remains uncommitted; the next reboot selects original slot 2.** Both
metadata partitions are read-only. Permanent slot selection is separate from
Git commit. Stock loader/libc/PID 1 and the SL1680 board are unchanged. New socket
timestamp options and unrelated ioctl/driver/file-format time layouts are outside
this change; this is not complete Y2038 coverage.

## Previous integrated release kernel8-ui1 — accepted as a one-time trial

The user authorized this flash on 2026-10-04. At that acceptance the BCM side ran Linux
4.19.294 #8 with full selected cgroup PSI monitoring, CPU-full accounting and
file-working-set refault accounting, retaining the reviewed web/RGB/history/CCR
integration. The AI board firmware and userspace remain unchanged.

The 86,711,104-byte image has SHA-256
`cf74c805927e2128cc26a273980c2af1f470fa34f78fbe0127f94d6fbb4bbe64`.
Exact integrated QEMU, stock/new RSA-PSS signatures, BSP LZO decoding and physical
flash readback passed. The running config and 27 live files match their expected
hashes. On hardware, six PSI interfaces accepted 12 monitors and rejected 24
invalid thresholds; poll/epoll and private-namespace cleanup passed without
injected load. Actual notification delivery/refault workloads remain QEMU tests.

Chrome confirms local management, fresh CCR/port/history telemetry, the unchanged
AI-board name/IP and three running containers. BE98 reports this node online
with an Ethernet uplink. Three radios are up, the AI internal link responds,
and the integrated RGB process and collectors are running. Existing vendor
wireless startup diagnostics also occur on stock; this is not validation of
all SSIDs/IoT clients or a long stability/throughput test.

**At kernel8 acceptance, slot 1 was uncommitted and the next reboot selected
original slot 2.** Both metadata partitions were read-only, and original slot 2
full hashes were unchanged. The
startup hook accepts the exact old and new integration hashes and retains JFFS
fallback fixes. No permanent slot commit or Git commit was made. See
[release acceptance](reports/releases/kernel8-ui1.json),
[live identity](reports/kernel8/live-identity-review.json), and
[boot-log comparison](reports/kernel8/boot-log-review.json).

The kernel build workflow now uses project-local ccache automatically when
available; the Compiler cache section records usage and real cache-hit evidence.
The deployed Image8 bytes were not rebuilt merely to introduce caching.

## Previous integrated release kernel6-ui1 — superseded by kernel8-ui1

On 2026-10-04 the user authorized packaging and flashing the reviewed BCM-side
candidate. `GT-BE19000AI_3006_102.9_leon-kernel6-ui1_TRIAL.pkgtb` is 86,701,964 bytes,
SHA-256 `b4f4a744814929d77a65fd4283507e42d7d485637440194b0bd3ed23466e39a8`.
It retains the tested kernel #6, modules and signed bootfs, and integrates 15 web
assets, the isolated RGB executable and local history/CCR collectors into Zstd
SquashFS. PID 1 and the stock libcodb library remain unchanged; credentials are
kept only in device-local JFFS. `scripts/stage-integrated-candidate.py` stages the
reviewed changes into a fresh extraction of the kernel6 rootfs;
`scripts/pack-integrated-candidate.py` gates packaging on the exact QEMU result.
These scripts intentionally refuse an already-populated output; preserve the
release evidence rather than rerunning them over it.

QEMU Docker/memory/swap/filesystem checks passed before flashing. Physical
readback matched the image, and the original slot 2 full partition hashes stayed
unchanged. That image booted successfully in slot 1. At that acceptance BE98 reported the node
online over wired backhaul; three radios, the AI link, web UI and collectors are
working. All 27 checked live files match the manifest, with no web bind overlays.
The AI Board page shows the unchanged `aiboard-C686` and three running containers.
This is a bounded boot acceptance, not a long soak or throughput result. See
[release acceptance](reports/releases/kernel6-ui1.json).

**Slot 1 remains uncommitted. The next reboot selects original slot 2.**
Metadata partitions are read-only to block the stock automatic commit. Existing
JFFS hooks use exact hashes to select integrated services on this image and the
previous runtime fixes on the fallback image. No permanent boot-slot or Git
commit was made for this release.

SL1680 kernel, modules, userspace, THP and other memory-policy changes remain
deferred. Scoped BCM service restarts remain an audit/design in
`reports/service-scope/assessment.json`; they are not part of this release.
`configs/next-release-candidate.json` records the integrated features and open work.

The third UI batch also adds passive local history in `configs/node-history`: one sample per minute, retained for up to 24 hours in RAM with a 32 MiB writer cap. Dashboard and Traffic Monitor use the existing authenticated diagnostic API. `python3 scripts/verify-node-history.py` checks counter resets, outages and missing values. `reports/ui-audit/round3.json` records the live validation and the one vendor HTTPS crash found during testing. The NULL-safe schema is integrated and passed post-reboot validation. The attempted libcodb source rebuild lacks three stock ABI exports, so it was excluded and the stock library retained; see `reports/ui-audit/libcodb-integration.json`. Full AirIQ FFT scanning remains pending.

The fourth UI batch restores the damaged UTF-8 language-name table and the AI-board hostname editor. It preserves the existing hostname and verifies board-reported names on future applies; frontend changes do not alter Docker settings. The vendor AI apply service still replays its existing settings. `reports/ui-audit/round4.json` records evidence and validation limits.

The fifth UI batch replaces the empty node Ethernet iframe with seven physical ports from the existing local status hook. It distinguishes negotiated rates from port capacity and clears stale values to unknown when a read fails. Kernel link state and Chrome agree; only the dashboard asset changed, without restarting services. `reports/ui-audit/round5.json` records this validation and the separate read-only myStrom investigation.

## Kernel #8 PSI candidate — restores the omitted file-refault accounting

The original BE98 commit `574cafe29c47` explicitly dropped filemap PSI because
inserting PG_workingset at the upstream position renumbered flags used by vendor
blobs. Kernel8 resolves that original restriction by appending PG_workingset at
bit21 and using spare BIO bit12. Existing page/BIO numbers, high-bit metadata,
VM-stat counts, and all checked page/bio/task/block layouts remain unchanged.
No optional WORKINGSET_RESTORE counter is added to vendor-sized arrays.

This candidate records memory pressure while refaulting previously active file
cache, including page waits and read submission. Flag propagation, shadow
retention and page reuse are included. The A/B test uses the same probe and ext4
image: kernel7 reports zero memory PSI during hot refault, while kernel8 records
3.476 seconds and emits a strict POLLPRI notification. Both report zero memory
PSI for cold reads. Neither timed measurement performs reclaim, so the result
isolates the previously omitted path rather than counting allocation reclaim.

Actual I/O some/full events and rearm pass, including eight verified cross-CPU
wakeups after moving an I/O-blocked task between cgroups. Existing PSI, resource,
Docker, OOM, swap/zswap and filesystem suites also pass. The complete 330-VM
module matrix has no stock-loaded regression; documented board/missing-device
exceptions remain. All 4,080 non-module test-rootfs entries are unchanged.

[Kernel8 evidence](reports/kernel8/candidate.json) records exact hashes,
[original history](reports/psi/history-audit.json), and the ABI-safe incremental
`patches/0006-psi-workingset-refault-abi.patch`. The six-patch stack replays to the
pinned upstream source. Kernel8 was subsequently integrated with the reviewed web/RGB/collectors,
packaged and flashed as kernel8-ui1 after the exact combined QEMU gate passed.
Its physical one-time trial acceptance is recorded above.

Anonymous/swap working-set classification remains separate: it requires LRU
admission, swapcache shadow lifetime and memcg adaptations, not an unconditional
swap-read annotation. Its mapped prerequisites and other explicit boundaries
are in [MM feasibility](reports/psi8/mm-feasibility.json). No claim of complete
modern PSI, userspace oomd policy, or SL1680 change is made.

## Kernel #7 PSI candidate — QEMU validated, not flashed

The next BCM candidate adds per-cgroup CPU/memory/I/O pressure and threshold
notifications through poll/epoll. Its PSI core is based on Linux v5.15.222 plus
selected upstream fixes for CPU quota accounting, notification delivery, sampling,
worker scheduling and cgroup teardown. System CPU full remains zero; cgroup CPU
full is measured. No systemd/oomd policy or SL1680 change is included.

New task state uses existing bitfield space. Cgroup/worker private data uses
allocation tails, and kernfs dispatch uses existing callbacks. Existing fields
and sizes match across 491 shared DWARF types; additional critical types were
checked with header probes. This is not complete proof of proprietary driver ABI,
and a full kernel6 rq baseline is unavailable.

Strict PSI event/error, quota/full, hierarchy/migration, memory.high, psi=0 and
32-round deletion/concurrent-write tests pass in QEMU. Existing resource limits,
Docker, OOM, swap/zswap, Zstd rootfs and filesystem tests also pass with rebuilt
kernel7 modules. Eleven representative stock/candidate module pairs load without
regression (22 VMs). I/O event generation and a targeted cross-CPU stalled wake
race are not covered. Memory PSI retains the older reclaim/compaction annotations;
the full workingset refault/swap classification remains separate work.

[Candidate evidence](reports/kernel7/candidate.json) pins the image, config,
patch and results. `patches/0005-psi-cgroup-monitoring-abi.patch` replays after
0001–0004. `build/rootfs-v7.zstd.squashfs` is a kernel-only test rootfs from stock
userspace. Before any later firmware trial, integrate the existing kernel6-ui1
web/RGB/collector changes and update its exact-hash hooks and packaging gates;
do not replace that integrated firmware with this test rootfs.

## Build

Requires ARM64 GCC 10.3 Buildroot SDK, native host build tools, Python 3/pyelftools,
Git, squashfs-tools with Zstd, lzop and OpenSSL. Set `BSP_TOOLCHAIN` to the SDK's
`output/host` directory. No host init/system or shell configuration is changed.

```sh
python3 scripts/prepare-source.py
python3 scripts/build-kernel.py olddefconfig --label config --version 9
python3 scripts/build-kernel.py Image --label image --version 9
# Build each module directory, in this order:
for d in lib crypto fs mm net drivers; do
  python3 scripts/build-kernel.py modules --module-dir "$d" --label "modules-$d" --version 9
done
```

Build input stubs from the GT-BE98 Pro HND directory are used only to parse the
BSP Makefiles; those device binaries must never replace the original AI modules.
Start the output rootfs from the original AI firmware, overlay only rebuilt kernel
modules, run depmod, and use `mksquashfs -all-root -comp zstd -Xcompression-level 22
-b 524288`. `scripts/pack-image.py` verifies the expected original firmware hash,
verifies the original signature and repacks only kernel/rootfs payloads using the
SDK's publicly shipped demo signing key. Keys are not copied into this repository.
Local images, backups and build outputs are excluded from Git.

### Compiler cache

`build-kernel.py` defaults to `--ccache auto`: it searches PATH, the SDK, then
`build/tools/ccache`, and logs a direct-compiler fallback if unavailable.
`--ccache on` requires a working cache executable; `--ccache off` disables it.
Use `--ccache-bin /absolute/path/to/ccache` to select an executable explicitly.
The project-local cache is `build/ccache`, capped at 5 GB. It uses content-based
compiler checks without relaxed correctness settings. The SDK compiler wrapper
stays in place; the real GCC driver and frontend are hashed too, while
`CROSS_COMPILE` continues to select the original assembler and linker.
Settings apply only to build subprocesses.

The local ccache 4.9.1 verification compiled the real `kernel/sched/psi.c` with
its Kbuild flags into a private output directory. Uncached, first cached
(one miss), and repeated cached (one direct hit) objects have identical SHA-256
hashes; the repeat's private log confirms the hit. The original `psi.o`,
`vmlinux`, and `build/Image-v8` stayed unchanged. The kernel8 image used for
packaging remains the previously tested, byte-identical image; enabling ccache
did not rebuild it.

```sh
# Require ccache on a future build:
python3 scripts/build-kernel.py Image --label image-cached --version 9 --ccache on
# Reproduce the private object check without rebuilding the firmware:
python3 scripts/verify-ccache.py
```

See [object and hit verification](reports/ccache/verification.json),
[mode and recursive-make checks](reports/ccache/configuration-checks.json), and
[local package provenance](reports/ccache/local-tool.json). The tool and its
missing library were unpacked into the project without installing system packages.

## Hardware status

Kernel #4 successfully booted on the physical router after restoring the stock
sysfs block-device layout. AiMesh reported online, all three radio interfaces
were up, and the AI API returned HTTP 200. On-device bounded tests passed memory
cgroup OOM isolation, network/UTS/IPC namespaces, seccomp, Btrfs Zstd remount/data
round-trip and OverlayFS copy-up. A subsequent normal reboot was observed to
return to the original second slot, as required by the one-time trial policy.

Kernel #5 additionally builds zsmalloc into the kernel so that zswap's Zstd pool
can be created before userspace starts. It preserves upstream's opt-in zswap
policy: no physical swap device is created or enabled. QEMU explicitly uses
`zswap.enabled=1` to test compression, reclaim and swap data round-trips without
loading the pool or changing its settings from the guest init script.

Kernel #5 passed the same bounded physical memory, namespace, seccomp and
filesystem tests. Its live configuration matches the build exactly, PID 1 remains
`/sbin/rc`, AiMesh is online, all three radios are up, and the AI API responds.
Runner is enabled with nonzero hardware packet/byte counters; no throughput
benchmark was performed. The Zstd/zsmalloc pool is created at boot as intended.
All candidates remain uncommitted. The second slot remains the original committed firmware.
No enclosure opening or serial connection is required by this workflow.

Kernel #6 booted successfully in the first trial slot. Physical CPU quota,
cpuset, direct block read/write throttling, unprivileged user namespaces,
memcg/seccomp, Btrfs Zstd and OverlayFS tests passed. All three radios were up,
the BE98 controller reported this node online, and the AI API returned HTTP 200.
Hardware acceleration remains enabled; the sampled proc flow tables returned no
rows, so no hardware traffic-counter or throughput result is claimed. Its live
configuration exactly matches the build. Metadata partitions remain read-only,
slot 1 remains uncommitted, and the next boot selects the original slot 2.

## Kernel #6 resource validation

QEMU passed actual CPU throttling, cpuset placement and fork inheritance, and
4 MiB direct writes/reads at 1 MiB/s (approximately four seconds each), with
byte-for-byte readback. Docker 29.8.0 also accepted and applied `--cpus`,
`--cpuset-cpus`, `--device-read-bps` and `--device-write-bps`. Its memory/OOM,
swap/zswap, Btrfs, overlay2 and original Tuxera module regression tests passed.
The full #6 matrix ran 330 stock/candidate probes with no stock-loaded module
regression. Tests requiring unavailable board hardware retain their documented
QEMU exceptions. All 4,080 non-module rootfs entries are unchanged.

An offline rootless Docker daemon ran as host UID 1000, reported rootless mode,
and executed a container that wrote/read a file and verified memory. This test
uses VFS storage and no networking, with UID mapping helpers and subordinate IDs
provided only inside the disposable VM. The firmware userspace is unchanged;
it does not yet install those helpers or manage a persistent rootless service.
Rootless Docker resource flags additionally require cgroup v2/systemd delegation;
that userspace integration is outside this kernel-only change. See
[Docker rootless requirements](https://docs.docker.com/engine/security/rootless/)
and [resource-limit support](https://docs.docker.com/engine/security/rootless/tips/).
Buffered per-cgroup writeback and the I/O latency/low-limit policies remain off;
the block bandwidth result above covers direct I/O.

The new tests are in `scripts/resource-probe.c`, `prepare-resource-test.py`, and
`prepare-rootless-test.py`. The hardware variant is explicitly guarded for
kernel #6 and slot 1, runs in a private mount namespace and limits its block
writes to an 8 MiB RAM-file-backed loop device. It does not target an eMMC volume.

## Validation and trial policy

`reports/` contains results tied to exact kernel and rootfs SHA-256 hashes.
QEMU uses two ARM64 CPUs, 1 GiB RAM, no network, no host block devices or passthrough.
Board-only initializers are skipped only in QEMU. Tests cover memory limits,
isolated OOM, swap/data round-trip, Btrfs Zstd, overlay2, seccomp, namespace and
cgroup lifetime behavior. The initial #3 matrix compared 331 stock/candidate module probes without a
stock-loaded/candidate-failed regression. The final #5 reruns the Docker/Tuxera
checks and focused zram/cfg80211/Btrfs dependency probes; this is not a new full
331-probe matrix. Board-only modules can
fail or time out in both variants; QEMU does not emulate Wi-Fi, Runner or the AI
board. Test fixture binaries are local artifacts inherited from the BE98 lab,
with their hashes recorded in results; they are not redistributed here.

Trial builds mark `mmcblk0` GPT partitions named `metadata1` and `metadata2`
read-only before publishing them. This blocks the stock rc's automatic commit
through `/dev/metadata*` during a one-time boot. It is an operational safeguard,
not a security boundary: root can clear BLKROSET or write the entire disk.
The test override `be19000ai_trial_disk=loop0` is for the disposable QEMU GPT only.
The existing committed firmware must be preserved and all partitions backed up
before a hardware trial. Do not permanently commit a trial without verifying the
actual radios, Ethernet/Runner, AI-board link and service stability.

## Versioned evidence

`reports/kernel3` preserves the initial build's historical matrix and manifest.
`reports/kernel4` records the first successful hardware trial. `reports/kernel5`
preserves its results; `reports/kernel6` contains the resource-controller build; each QEMU result identifies the exact kernel
and test initramfs hashes. Full device logs and backups are kept locally only.
The initial trial did not leave a saved panic trace; the exact previous failure
instruction is unknown. The confirmed sysfs incompatibility was corrected and
hardware boot succeeded afterward.

Recreate the final rootfs from the local original extraction with
`python3 scripts/stage-rootfs.py --version 6`. This changes only `lib/modules`,
records the checksums, and produces the Zstd SquashFS. The original image expected
by `pack-image.py` must match the SHA-256 in `UPSTREAM.json`. Never flash the
currently active slot or overwrite the original committed fallback slot.

The BE98 failure review and corresponding AI checks are recorded in
[BE98 lessons](reports/be98-lessons.md). The downloadable kernel #6 TRIAL image
is the exact readback-verified image tested on hardware. It is not approved for
permanent boot-slot commitment.

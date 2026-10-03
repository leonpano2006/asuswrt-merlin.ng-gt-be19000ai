# GT-BE19000AI kernel-only firmware experiment

Private, independent development repository for the GT-BE19000AI. The `source`
Git submodule pins ASUSWRT-Merlin tag `3006.102.9` at
`69838e4a60564e5550e97f11d8a8cf2c6260c4f0`. Its upstream history remains accessible
through that repository; this repository records the ordered modification history
as reviewable patches. It is not a second GitHub fork-network entry.

Only the BCM6813 Linux 4.19.294 kernel, open-source modules, and SquashFS
compression are changed. All userspace files, symlinks, permissions and timestamps
outside `lib/modules` match the original firmware. The existing BE19000AI vendor
modules, bootloader, ATF and DTBs are retained. The AI board is not modified.
Ubuntu 26.04 and a Docker userspace installation are outside this build.

The kernel feature baseline is the running GT-BE98 kernel #36: memory/swap cgroups,
pids/devices/freezer/cpuacct, namespaces, seccomp, veth/macvlan, OverlayFS, Btrfs,
XFS, modern Zstd, zswap/zsmalloc and zram. CPU quota/cpuset/blkio and unprivileged
user namespaces remain disabled as on that baseline. BE19000AI stock features
including ICP201XX, CRC8 and MMC oops are retained. Net-device field offsets used
by proprietary drivers are protected separately; this is not a proof of every
proprietary driver's internal ABI.

## Build

Requires ARM64 GCC 10.3 Buildroot SDK, native host build tools, Python 3/pyelftools,
Git, squashfs-tools with Zstd, lzop and OpenSSL. Set `BSP_TOOLCHAIN` to the SDK's
`output/host` directory. No host init/system or shell configuration is changed.

```sh
python3 scripts/prepare-source.py
python3 scripts/build-kernel.py olddefconfig --label config --version 5
python3 scripts/build-kernel.py Image --label image --version 5
# Build each module directory, in this order:
for d in lib crypto fs mm net drivers; do
  python3 scripts/build-kernel.py modules --module-dir "$d" --label "modules-$d" --version 5
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
Neither candidate has been permanently committed. The second slot remains the original committed firmware.
No enclosure opening or serial connection is required by this workflow.

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
contains the final build's results; each QEMU result identifies the exact kernel
and test initramfs hashes. Full device logs and backups are kept locally only.
The initial trial did not leave a saved panic trace; the exact previous failure
instruction is unknown. The confirmed sysfs incompatibility was corrected and
hardware boot succeeded afterward.

Recreate the final rootfs from the local original extraction with
`python3 scripts/stage-rootfs.py --version 5`. This changes only `lib/modules`,
records the checksums, and produces the Zstd SquashFS. The original image expected
by `pack-image.py` must match the SHA-256 in `UPSTREAM.json`. Never flash the
currently active slot or overwrite the original committed fallback slot.

The BE98 failure review and corresponding AI checks are recorded in
[BE98 lessons](reports/be98-lessons.md). The downloadable kernel #5 TRIAL image
is the exact readback-verified image tested on hardware. It is not approved for
permanent boot-slot commitment.

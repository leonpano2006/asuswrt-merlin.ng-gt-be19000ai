# BE98 failure review applied to BE19000AI

Reviewed the local BE98 records `router-audit-20260915/BOOT-FAILURE.md`,
`leon-cgroup-20260915/README.md`, `leon-memcg-20260915/README.md`,
`leon-docker-20260915/README.md`, and `leon-next-20260915/diagnosis/README.md`.
These are historical evidence, not permission to copy every board configuration.

| BE98 lesson | BE19000AI implementation and evidence |
| --- | --- |
| A committed failing image can loop; a boot-failure counter does not prove rollback. | Candidate boots once, metadata partitions are read-only, original slot 2 stays committed. A normal reboot from #4 actually returned to the original #1 kernel on slot 2. See `kernel4/normal-reboot-fallback.json`. Automatic reset after every possible early failure is not proven. |
| Flashing the inactive slot while running the candidate would overwrite recovery. | Returned to stock slot 2 before writing #5 into slot 1. Readback hashes confirm both original slot-2 partitions remain unchanged; see `kernel5/flash-readback.json`. |
| cgroup and memory patches can shift structures used by proprietary modules. | Retain the BE98 task/page/slab layout fixes and out-of-line mm owner storage; separately fix the AI net-device layout. Keep original AI vendor modules. Tuxera is tested in QEMU; actual radios, wired traffic, AI link and Runner are checked on hardware. This does not prove every private ABI is unchanged. |
| Invoking the dynamic loader as PID 1 changed `/proc/self/exe` and broke ASUS process validation. | No userspace loader wrapper or preload shim. The live PID-1 executable is `/sbin/rc`; 4,080 non-module entries, including 3,228 regular files, match stock. |
| QEMU board-init panics are not reliable evidence of physical failure. | Hardware-only init blacklists apply only to QEMU. Candidate booted on BCM hardware with all three radios up and AiMesh online. |
| Do not assume an LZO file accepted by a desktop tool is accepted by this bootloader. | Decode stock and candidate kernels with the matching BSP U-Boot LZO implementation and compare exact bytes. Bootloader, ATF and DTB payloads are unchanged. |
| Module load success alone does not prove forwarding acceleration works. | Runner enabled; 32 sampled flows have nonzero hardware hit counters, totaling 99,739 hits / 147,610,693 bytes in that snapshot. Activation and L2/L3/multicast error counters are zero. An IPv6 address-deletion counter is 1, also present in historical BE98 baseline. This is functional evidence, not a throughput measurement. |
| OOM tests must isolate the victim and check swap accounting independently. | QEMU Docker checks memory/memsw limits, isolated OOM, survival, and swap data round-trip. Bounded physical tests exercise a 16 MiB cgroup and kill only its 64 MiB test child. |
| Docker needs a usable root view; initramfs and readonly `/run` assumptions can break it. | QEMU uses the established private root-view fixture. No Docker userspace or writable-root transformation is installed on the router in this kernel-only scope. |

Two AI-specific corrections were also required:

- Restore stock `CONFIG_SYSFS_DEPRECATED=n`. The BE98 legacy layout removed
  `/sys/class/block`, which the AI stock eMMC library expects. Hardware boot
  succeeded after this correction, but the initial failed trial left no panic
  trace, so its exact failing instruction is unknown.
- Build zsmalloc into #5. As a module it was unavailable when zswap initialized
  before userspace. The live kernel now reports `zstd/zsmalloc` pool creation.
  Upstream zswap remains opt-in and no physical swap device is enabled; QEMU
  explicitly boots with `zswap.enabled=1` for the swap tests.

The hardware trial remains uncommitted. Next ordinary reboot is configured to
use original slot 2. Neither a long-duration soak nor line-rate testing has been
performed.

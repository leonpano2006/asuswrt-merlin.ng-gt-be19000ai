# BE19000AI maintenance and AI-board support sources

This snapshot preserves the subsequent BCM and SL1680 work through October 20,
2026. It was assembled on October 24 without rebuilding firmware, rerunning
hardware tests or changing either device. Earlier root-level reports describe
historical milestones; the status below reflects later recorded acceptance.

The BCM router and SL1680 AI board are independent systems. Keep their kernels,
module sets, userspaces and installation procedures separate.

## BCM router

The dated directories retain source paths from the local workbench:

- `apt-devfix` and `apt-repair-20261007`: matching custom glibc development
  packages, stable architecture-specific compiler policy and package metadata
  repairs. Generated package payloads and signing keys are external inputs.
- `tar-compat-v1`: GNU tar workaround for the legacy kernel's missing openat2
  syscall. This does not claim to add openat2 support to the kernel.
- `vpn-ssh-v1`: native OpenSSH generator/control correction for VPN clients.
- `be19000ai-ssh-recovery-20261018`: package-upgrade guard preserving native
  OpenSSH ownership while the ASUS compatibility environment remains active.
- `networkmanager-recovery-20261010`: ASUS command-wrapper namespace fix and
  explicit exclusion of ASUS-owned interfaces from NetworkManager. The recorded
  failure was competing management of Wi-Fi interfaces, not proof of hardware
  acceleration incompatibility. The recovery installer contains historical boot
  guards; it is not a general network-reset command.
- `swap-zswap-20261007`: UUID-based SSD swap ordering with zstd/zsmalloc zswap.
  Adapt the recorded device UUID to a separately verified target; do not format
  devices as part of this recipe. Persistence was configured, not reboot-tested
  by that maintenance task.
- `hwmon-central-20261010`: BCM temperature/frequency telemetry exposed through
  hwmon, with libsensors/htop support. Runtime modules were qualified against
  kernel11. The in-tree integration patch is a candidate and was not built as
  part of the recorded deployment. Htop's native build script reuses the local
  build directory; patches and modified source files are preserved here.
- `hostname-separation-20261010`: persisted BCM hostname repair. A Portainer
  cause was not established; the AI-board hostname was preserved.
- `cockpit-packagekit-repair-20261020`: matching custom systemd PAM package
  repository. Include **dbus-user-session** explicitly with libpam-systemd,
  cockpit-packagekit, packagekit and polkitd even under `--no-install-recommends`.
- `cockpit-stability-20261020`: user D-Bus repair. Missing dbus-user-session led
  Cockpit to cache a failed bus and subsequently fail with EINVAL. Installing
  the package and creating a fresh login restored user-service, Podman and
  package-update pages in a short interactive verification.
- `locale-repair-20261020`: persistent **en_US.UTF-8** default, verified in a
  fresh SSH login and login shell. The existing custom locales package was
  reused; locales-all was not installed. Explicit C locale in internal parsers
  remains intentional. The root-level future rootfs recipe is updated too.
- `netpanel-repair-20261020`: BCM-only read-only status helper, exact sudo rule
  and parser. Whole-network collectors, other devices and private telemetry
  are not part of this source snapshot.

## SL1680 AI board

Start with [`sl1680-production/UPSTREAM.json`](sl1680-production/UPSTREAM.json).
It records the exact upstream commits, accepted configuration, patch order,
image hash and limitations. The two consolidated patches were exported from
final source trees and passed reverse application checks against those trees.
They include the ASUS board DTS and the final main-kernel/dhub changes, avoiding
replay of the intermediate failed experiments.

Recorded accepted state:

- Kernel **6.12.62-leonai7+**, built with GCC **16.2.0** and binutils **2.47**.
- THP defaults to `madvise`; zram is a module. The production Image reused the
  accepted 438-module cohort. GPU/VPU compatibility patches are under
  `ai-board-upgrade-20261010/research/kernel`.
- Production switch and a subsequent saved-default boot passed the recorded
  checks. Automatic bounded production recovery is unavailable; manual power
  cycling may be needed. Consult the source notes before any deployment.
- Original Yocto **4.0.17**, glibc **2.35** and hybrid/v1 cgroups were retained.
  Newer userspace and the unified-cgroup/LXC migration remain deferred.
- `ai-docker-upgrade-20261017` preserves the **29.9.1+leonai2** Docker package
  recipe, containerd **2.4.2**, runc **1.5.2**, package tests and transactional
  deployment sources. Original Compose **2.26.0** and existing container data
  were retained. Backup uses a separately prepared GNU tar; ACL and
  security.capability support remained unavailable on the recorded target.

The SL1680 L2 placement change is a board-specific workaround; the underlying
SEA cause and other hardware configurations were not established. Accelerator
checks were bounded workloads, not comprehensive hardware qualification.

## Inputs and publication boundaries

`source-manifest.json` records hashes or symlink targets of copied sources.
Scripts preserve original local paths, package hashes, device identity guards
and missing-input checks. They are support recipes and archived deployment
source, not a self-contained installer. Some recipes require pre-existing
compiler packages, firmware payloads, source checkouts or local signing keys.
No such private keys, captured payloads, firmware/module binaries, container
backups or raw SSH/browser logs are included here. Missing private inputs must
remain failures rather than being replaced with guessed values.

No firmware was built or flashed for this publication. Completed runtime tests
were not repeated. Source syntax checks and patch-export checks are recorded
separately from the earlier hardware acceptance.

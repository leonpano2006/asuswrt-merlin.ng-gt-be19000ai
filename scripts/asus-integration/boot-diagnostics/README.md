The existing `/etc/leon/boot-diagnostics` file is 16,384 initialized zero bytes,
root:root, mode 0600, with one link. Producer 0 (root-init) owns bytes 0–8191;
producer 1 (guardian) owns bytes 8192–16383. Writers cannot create or resize it.

Include `boot-diagnostics.h` after `_GNU_SOURCE`. Open the verified ext4 root as
an ordinary directory FD, then use `leon_diag_open_at(rootfd, producer)` and
`leon_diag_write(fd, producer, boot_uuid, build_sha256, sequence, payload, length)`.
Payloads are at most 8016 bytes. Caller-owned children must bound blocking I/O,
close inherited control sockets, and be stopped/reaped before unmounting root.
Do not include credentials in payloads. Diagnostics never authorize boot commit.

Each little-endian slot contains magic at 0, version at 8, producer at 12,
36-byte boot UUID at 16, 64-byte lowercase build hash at 52, sequence at 116,
payload length at 124, CRC32 at 128, zero padding through 159, payload at 160,
and sequence plus its bitwise inverse at 8176. CRC32 covers all 8192 bytes with
its own four bytes treated as zero. A record may be complete, empty, or torn;
this does not promise recovery of a previous record or arbitrary power loss.

`parse.py FILE` reads the bounded file without trusting either slot. The static
reader supports `--empty FILE PRODUCER`, `--check FILE PRODUCER BOOT_UUID
BUILD_SHA_OR_DASH REQUIRED_SUBSTRING`, and `--dump FILE PRODUCER BOOT_UUID
BUILD_SHA_OR_DASH`. Dash intentionally skips build-hash matching; prefer an
exact build hash when attributing a physical trial.

The stock-side provisioner is fixed to the enrolled stock2 system. It reuses
the frozen slot-proof v7 guards and freshly verifies the ext4 UUID on an open
enrolled block FD, then mounts `/proc/self/fd/N` in a private mount namespace.
It initializes the diagnostic file and adds the reviewed resolver ordering
drop-in. Existing diagnostic records, partial files, or foreign content are
never reset. Existing all-zero allocated files and the exact approved drop-in
are accepted as idempotent no-ops. Publication failures retain files for review.
Clean p11 is required; the tool does not perform fsck or select a boot slot.

See `reports/ubuntu26/boot-diagnostics-foundation.json` for the immutable build
and focused fixture receipts. No router operation is part of those tests.

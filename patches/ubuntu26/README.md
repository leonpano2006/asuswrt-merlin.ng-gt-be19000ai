# Ubuntu userspace patch stack

These patches use the repository's ordered `diff --git` format and the existing
`apply-patch-stack.py` verifier. They are separate from top-level kernel patches:
`prepare-source.py` continues to prepare kernel-only builds without replacing
userspace. Apply this directory only to the disposable source checkout used to
build Ubuntu packages, with the touched paths materialized at the pinned HEAD:

```sh
python3 scripts/apply-patch-stack.py --source /path/to/package-source --patches patches/ubuntu26
python3 scripts/check-busybox-time64.py
```

Input/output hashes and provenance are in
`configs/ubuntu26/userspace-patches.json`. The focused verification extracts the
actual patched monotonic helper functions, reproduces the old ARM32 time64 bug,
and tests modern armel/armhf, legacy armel, and native arm64 branches with the
recorded glibc runtimes. It neither rebuilds all ASUS firmware nor writes to the
router. Passing it does not qualify a complete BusyBox package for deployment;
ASUS daemon/applications, IPC and hotplug behavior need separate integration tests.

The AiMesh shared-memory and `rfctime` ABI migrations remain plans in
`reports/ubuntu26/time64-migration-audit.json`. No unmeasured AI table layout or
changed exported function signature is included here.

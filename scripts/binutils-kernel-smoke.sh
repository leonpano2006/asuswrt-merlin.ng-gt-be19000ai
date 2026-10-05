#!/bin/sh
# Run only in a disposable offline QEMU root. No host or device operations.
set -eu
test -f /QEMU_LAB_GUEST
work=/run/leon-binutils-smoke
mkdir -p "$work"
for tool in aarch64-linux-gnu-as arm-linux-gnueabi-as arm-linux-gnueabihf-as; do
 "$tool" --version | head -1 | grep '2.47'
done
cat > "$work/aarch64.s" <<'ASM'
.text
.global _start
_start:
 mov x0, #47
 mov x8, #93
 svc #0
ASM
cat > "$work/arm.s" <<'ASM'
.syntax unified
.arm
.text
.global _start
_start:
 mov r0, #47
 mov r7, #1
 svc #0
ASM
for target in aarch64-linux-gnu arm-linux-gnueabi arm-linux-gnueabihf; do
 case "$target" in aarch64-*) source=aarch64;; *) source=arm;; esac
 "$target-as" -mcpu=cortex-a53+crypto+crc -g -o "$work/$target.o" "$work/$source.s"
 "$target-ld" -o "$work/$target" "$work/$target.o"
 rc=0
 "$work/$target" || rc=$?
 test "$rc" = 47
 "$target-objcopy" --compress-debug-sections=zstd "$work/$target.o" "$work/$target.zstd.o"
 "$target-objcopy" --decompress-debug-sections "$work/$target.zstd.o" "$work/$target.plain.o"
 "$target-objcopy" --dump-section .debug_info="$work/$target.before" "$work/$target.o"
 "$target-objcopy" --dump-section .debug_info="$work/$target.after" "$work/$target.plain.o"
 cmp "$work/$target.before" "$work/$target.after"
 echo LAB_BINUTILS_KERNEL_TARGET_PASS=$target
done

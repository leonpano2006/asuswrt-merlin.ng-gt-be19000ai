/* Test the actual source-extracted BusyBox monotonic functions. No clock writes. */
#define _GNU_SOURCE 1
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#ifndef EXPECT_TIME_BITS
#error EXPECT_TIME_BITS must describe this test case
#endif
_Static_assert(sizeof(time_t) * 8 == EXPECT_TIME_BITS, "unexpected application time ABI");
#define FAST_FUNC
__attribute__((noreturn)) static void bb_error_msg_and_die(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(20);
}
#include "busybox-monotonic.inc"
static uint64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(21);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}
static int bounded(const char *name, uint64_t value, uint64_t before, uint64_t after, uint64_t divisor)
{
    if (value < before / divisor || value > after / divisor) {
        fprintf(stderr, "%s out_of_range value=%" PRIu64 " min=%" PRIu64 " max=%" PRIu64 "\n",
                name, value, before / divisor, after / divisor);
        return 1;
    }
    return 0;
}
int main(void)
{
    struct { uint64_t left; struct timespec t; uint64_t right; } guarded;
    const uint64_t sentinel = UINT64_C(0xa5a5a5a5a5a5a5a5);
    uint64_t before, after, value;
    memset(&guarded, 0xa5, sizeof(guarded));
    before = now_ns();
    get_mono(&guarded.t);
    after = now_ns();
    printf("ABI time_t=%zu timespec=%zu legacy=%d\n", sizeof(time_t), sizeof(struct timespec), EXPECT_TIME_BITS == 32);
    if (guarded.left != sentinel || guarded.right != sentinel) return 22;
    if (guarded.t.tv_sec < 0 || guarded.t.tv_nsec < 0 || guarded.t.tv_nsec >= 1000000000L) {
        puts("BUSYBOX_TIMESPEC_LAYOUT_MISMATCH");
        return 10;
    }
    value = (uint64_t)guarded.t.tv_sec * 1000000000ULL + (uint64_t)guarded.t.tv_nsec;
    if (bounded("get_mono", value, before, after, 1)) {
        puts("BUSYBOX_TIMESPEC_LAYOUT_MISMATCH");
        return 10;
    }
    for (int i = 0; i < 16; ++i) {
        before = now_ns(); value = monotonic_ns(); after = now_ns();
        if (bounded("monotonic_ns", value, before, after, 1)) return 11;
        before = now_ns(); value = monotonic_us(); after = now_ns();
        if (bounded("monotonic_us", value, before, after, 1000)) return 12;
        before = now_ns(); value = monotonic_ms(); after = now_ns();
        if (bounded("monotonic_ms", value, before, after, 1000000)) return 13;
        before = now_ns(); value = monotonic_sec(); after = now_ns();
        if (bounded("monotonic_sec", value, before, after, 1000000000)) return 14;
    }
    puts("BUSYBOX_MONOTONIC_ABI_PASS checks=65 clock_writes=0");
    return 0;
}

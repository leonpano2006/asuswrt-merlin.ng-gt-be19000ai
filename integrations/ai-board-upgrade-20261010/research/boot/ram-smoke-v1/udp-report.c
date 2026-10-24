/* AArch64 Linux, freestanding one-way diagnostic sender. No libc or receive API.
 * --encode exercises the exact framing without creating a network socket.
 * --send sends only to eth0-10 / 169.254.0.1:49168. It never reads a response.
 */
#include <stddef.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#define MAX_INPUT 65536
#define MAX_FRAMES 256
#define MAX_TEXT 800

static long sc(long n, long a, long b, long c, long d, long e, long f)
{
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c, x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e, x5 __asm__("x5") = f;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                     "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
    return x0;
}

static int equal(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static int append(char *out, int pos, const char *s)
{
    while (*s) out[pos++] = *s++;
    return pos;
}

static int number(char *out, int pos, unsigned int v)
{
    char n[10]; int len = 0;
    do { n[len++] = '0' + v % 10; v /= 10; } while (v);
    while (len) out[pos++] = n[--len];
    return pos;
}

static int emit(long fd, int encode, const char *nonce, char batch,
                unsigned int seq, const char *line, int len, int cut)
{
    char out[1000]; int p = append(out, 0, "AI_RAM_SMOKE nonce=");
    p = append(out, p, nonce);
    p = append(out, p, " batch="); out[p++] = batch;
    p = append(out, p, " seq="); p = number(out, p, seq);
    p = append(out, p, " ");
    for (int i = 0; i < len; i++) out[p++] = line[i];
    if (cut) p = append(out, p, " [TRUNCATED]");
    out[p++] = '\n';
    if (encode) {
        int done = 0;
        while (done < p) {
            long r = sc(__NR_write, 1, (long)(out + done), p - done, 0, 0, 0);
            if (r == -4) continue;
            if (r <= 0) return 1;
            done += r;
        }
        return 0;
    }
    /* sockaddr_in: family native little-endian, port/address in network order. */
    unsigned char dst[16] = {2, 0, 0xc0, 0x10, 169, 254, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    long r = sc(__NR_sendto, fd, (long)out, p, MSG_DONTWAIT | MSG_NOSIGNAL,
                (long)dst, sizeof(dst));
    return r != p;
}

long smoke_main(long *stack)
{
    long argc = stack[0]; char **argv = (char **)(stack + 1);
    if (argc != 4) return 2;
    int encode = equal(argv[1], "--encode");
    if (!encode && !equal(argv[1], "--send")) return 2;
    const char *nonce = argv[2]; int n = 0;
    while (nonce[n]) {
        if (n >= 32 || !((nonce[n] >= '0' && nonce[n] <= '9') ||
                        (nonce[n] >= 'a' && nonce[n] <= 'f'))) return 2;
        n++;
    }
    if (n != 32 || argv[3][0] < '1' || argv[3][0] > '3' || argv[3][1]) return 2;
    long fd = -1;
    if (!encode) {
        fd = sc(__NR_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, 0, 0, 0);
        if (fd < 0) return 20;
        static const char iface[] = "eth0-10";
        if (sc(__NR_setsockopt, fd, SOL_SOCKET, SO_BINDTODEVICE,
               (long)iface, sizeof(iface), 0) < 0) {
            sc(__NR_close, fd, 0, 0, 0, 0, 0); return 21;
        }
    }
    char input[1024], line[MAX_TEXT]; int len = 0, cut = 0, failed = 0;
    unsigned int total = 0, count = 0;
    while (total < MAX_INPUT && count < MAX_FRAMES) {
        long want = MAX_INPUT - total;
        if (want > (long)sizeof(input)) want = sizeof(input);
        long r = sc(__NR_read, 0, (long)input, want, 0, 0, 0);
        if (r == -4) continue;
        if (r < 0) { failed = 1; break; }
        if (!r) break;
        total += r;
        for (long i = 0; i < r && count < MAX_FRAMES; i++) {
            unsigned char c = input[i];
            if (c == '\n') {
                failed |= emit(fd, encode, nonce, argv[3][0], ++count, line, len, cut);
                len = 0; cut = 0;
            } else if (len < MAX_TEXT) {
                line[len++] = c >= 32 && c <= 126 ? c : '?';
            } else cut = 1;
        }
    }
    if ((len || cut) && count < MAX_FRAMES)
        failed |= emit(fd, encode, nonce, argv[3][0], ++count, line, len, cut || total == MAX_INPUT);
    if (fd >= 0) sc(__NR_close, fd, 0, 0, 0, 0, 0);
    return failed;
}

__asm__(".global _start\n.type _start,%function\n_start:\n"
        "mov x0, sp\nbl smoke_main\nmov x8, #93\nsvc #0\nb .\n");

/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Benign namespace/NSS fixture; no ASUS code, network request or real secret. */
#define _GNU_SOURCE
#include "rc-private-etc.h"
#include <assert.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#ifdef LEON_ETC_REQUIRE_STORAGE
#include "rc-storage.h"
#define require_storage() leon_storage_require()
#else
#define require_storage() ((void)0)
#endif
#ifdef LEON_ETC_REQUIRE_PRELOAD
#include <dlfcn.h>
#include <stdint.h>
static void require_preload(void)
{
    uint32_t (*version)(void) = dlsym(RTLD_DEFAULT, "leon_rc_notify_protocol");
    assert(version && version() == UINT32_C(0x4c524331));
}
#else
#define require_preload() ((void)0)
#endif

static void text(const char *path, const char *value, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
    assert(fd >= 0);
    assert(write(fd, value, strlen(value)) == (ssize_t)strlen(value));
    assert(!close(fd));
}

int main(int argc, char **argv)
{
    struct passwd *pw;
    struct group *gr;
    struct spwd *sp;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *answer;
    sigset_t mask;
    int i, status;
    pid_t child;
    if (argc == 2 && !strcmp(argv[1], "--storage-require")) {
        require_storage();
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--outside")) {
        assert(leon_rc_private_etc_check() == -1);
        pw = getpwnam("ubuntuonly"); assert(pw && pw->pw_uid == 1000);
        assert(getpwnam("asusadmin") == NULL);
        puts("LAB_PRIVATE_ETC_HOST_IDENTITY_PASS");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--signal-child")) {
        require_preload();
        require_storage();
        assert(!sigprocmask(SIG_SETMASK, NULL, &mask));
        for (i=1; i<NSIG; i++) assert(sigismember(&mask, i) == 0);
        leon_rc_private_etc_require();
        pw = getpwnam("nas"); assert(pw && pw->pw_uid == 100 && pw->pw_gid == 100);
        puts("LAB_PRIVATE_ETC_DESCENDANT_NSS_SHELL_MASK_PASS");
        return 0;
    }
    assert(argc == 2 && !strcmp(argv[1], "--leon-systemd"));
    require_preload();
    require_storage();
    leon_rc_private_etc_require();
    /* Synthetic vendor IDs match the layout, without any production account. */
    text("/etc/passwd", "asusadmin:x:0:0:ASUS fixture:/root:/bin/sh\nnas:x:100:100:NAS fixture:/dev/null:/dev/null\n", 0644);
    text("/etc/shadow", "asusadmin:!fixture-locked:0:0:99999:7:::\nnas:*:0:0:99999:7:::\n", 0600);
    text("/etc/group", "root:x:0:\nnas:x:100:\n", 0644);
    text("/etc/gshadow", "root:*::\nnas:*::\n", 0600);
    text("/etc/pam-private-fixture", "private only\n", 0644);
    pw = getpwnam("asusadmin"); assert(pw && pw->pw_uid == 0 && pw->pw_gid == 0);
    assert(getpwnam("ubuntuonly") == NULL);
    gr = getgrnam("nas"); assert(gr && gr->gr_gid == 100);
    sp = getspnam("asusadmin"); assert(sp && !strcmp(sp->sp_pwdp, "!fixture-locked"));
    /* Replacing generated hosts must immediately update the private NSS view. */
    text("/run/asus/etc/hosts.tmp", "127.0.0.1 localhost\n192.0.2.39 sl1680\n", 0644);
    assert(!rename("/run/asus/etc/hosts.tmp", "/run/asus/etc/hosts"));
    assert(!getaddrinfo("sl1680", NULL, &hints, &answer));
    assert(((struct sockaddr_in *)answer->ai_addr)->sin_addr.s_addr == htonl(0xc0000227));
    freeaddrinfo(answer);
    text("/data/shared-proof", "data remains shared\n", 0644);
    text("/jffs/shared-proof", "jffs remains shared\n", 0644);
    text("/run/shared-proof", "run remains shared\n", 0644);
    sigemptyset(&mask); sigaddset(&mask, SIGALRM); sigaddset(&mask, SIGTERM);
    assert(!sigprocmask(SIG_BLOCK, &mask, NULL));
    child = fork(); assert(child >= 0);
    if (!child) {
        execl("/bin/sh", "/bin/sh", "-c", "/probe --signal-child", (char *)NULL);
        _exit(127);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* A corrupted marker must stop writers before touching any host file. */
    assert(!chmod(LEON_PRIVATE_ETC_MARKER, 0666));
    assert(leon_rc_private_etc_check() == -1 && errno == EPERM);
    assert(!chmod(LEON_PRIVATE_ETC_MARKER, 0600));
    leon_rc_private_etc_require();
    puts("LAB_PRIVATE_ETC_NSS_ACCOUNT_HOSTS_SHARED_PASS");
    return 0;
}

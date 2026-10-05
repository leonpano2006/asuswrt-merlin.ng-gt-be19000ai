/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Explicit systemd-native prerequisites. No ASUS rc or hardware service runs. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "bounded-spawn.h"

#define BASE "/usr/share/asus/integration/"
#define RULE "70-asus-mmc-aliases.rules"
#define RULE_DEST "/run/udev/rules.d/" RULE
#define STORAGE_PROOF "/run/asus/storage-owned"

static void fail(const char *operation)
{
    perror(operation);
    exit(125);
}

static void directory(const char *path, mode_t mode, int create)
{
    struct stat st;
    if (create && mkdir(path, mode) && errno != EEXIST) fail(path);
    if (lstat(path, &st)) fail(path);
    if (!S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode & 0022)) {
        errno = EPERM; fail(path);
    }
}

static void require_regular(const char *path)
{
    struct stat st;
    if (lstat(path, &st)) fail(path);
    if (!S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 0022)) {
        errno = EPERM; fail(path);
    }
}

static void command(const char *stage, char *const argv[], unsigned int timeout)
{
    int result;
    fprintf(stderr, "ASUS_NATIVE_PREPARE stage=%s begin\n", stage);
    result = leon_bounded_spawn(argv, timeout);
    fprintf(stderr, "ASUS_NATIVE_PREPARE stage=%s status=%d\n", stage, result);
    if (result) exit(result);
}

static void install_rule(void)
{
    char temp[] = "/run/udev/rules.d/.asus-aliases.XXXXXX", buffer[4096];
    int input, output;
    ssize_t count;
    struct stat st;
    require_regular(BASE RULE);
    if (lstat(RULE_DEST, &st) == 0) require_regular(RULE_DEST);
    else if (errno != ENOENT) fail(RULE_DEST);
    input = open(BASE RULE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) fail("read staged udev rule");
    output = mkostemp(temp, O_CLOEXEC);
    if (output < 0) fail("new runtime udev rule");
    while ((count = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t n = write(output, buffer + offset, (size_t)(count - offset));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) fail("write runtime udev rule");
            offset += n;
        }
    }
    if (count < 0 || fchmod(output, 0644) || close(output) || close(input) || rename(temp, RULE_DEST))
        fail("publish runtime udev rule");
}

int main(int argc, char **argv)
{
    struct stat self, pid1;
    if (argc != 2 || (strcmp(argv[1], "--prepare") && strcmp(argv[1], "--revoke"))) return 2;
    if (getuid() || geteuid() || getpid() == 1) { errno = EPERM; fail("native prerequisite identity"); }
    if (stat("/proc/self/ns/mnt", &self) || stat("/proc/1/ns/mnt", &pid1)) fail("mount namespace identity");
    if (self.st_dev != pid1.st_dev || self.st_ino != pid1.st_ino) { errno = EXDEV; fail("prerequisites must use PID1 mount namespace"); }
    directory("/run", 0, 0);
    directory("/run/systemd/system", 0, 0);
    directory("/run/asus", 0755, 1);
    /* Revoke before any check so a failed refresh cannot retain authority. */
    if (unlink(STORAGE_PROOF) && errno != ENOENT) fail("revoke storage proof");
    if (!strcmp(argv[1], "--revoke")) return 0;
    directory("/run/udev", 0, 0);
    directory("/run/udev/rules.d", 0755, 1);
    directory("/usr/share/asus", 0, 0);
    directory("/usr/share/asus/integration", 0, 0);
    require_regular(BASE "asus-bcm-devices.conf");
    command("overlay-module", (char *const[]){ "/usr/sbin/modprobe", "--", "overlay", NULL }, 20);
    command("native-device-nodes", (char *const[]){ "/usr/bin/systemd-tmpfiles", "--create", "--", BASE "asus-bcm-devices.conf", NULL }, 20);
    install_rule();
    command("udev-reload", (char *const[]){ "/usr/bin/udevadm", "control", "--timeout=10", "--reload-rules", NULL }, 15);
    command("udev-alias-refresh", (char *const[]){ "/usr/bin/udevadm", "trigger", "--action=change", "--subsystem-match=block", "--sysname-match=mmcblk*p*", NULL }, 15);
    command("udev-settle", (char *const[]){ "/usr/bin/udevadm", "settle", "--timeout=10", NULL }, 15);
    command("storage-owner", (char *const[]){ "/usr/libexec/asus/storage-owner", "--prepare", NULL }, 30);
    return 0;
}

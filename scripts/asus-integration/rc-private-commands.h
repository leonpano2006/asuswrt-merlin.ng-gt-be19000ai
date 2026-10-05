/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Include in the native launcher after its die()/directory()/regular() helpers.
 * Call after unshare(CLONE_NEWNS), private propagation and private /etc guard,
 * but BEFORE binding ASUS ash over /usr/bin/dash. It changes no host namespace.
 */
#ifndef LEON_RC_PRIVATE_COMMANDS_H
#define LEON_RC_PRIVATE_COMMANDS_H
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define LEON_COMMAND_ROOT "/usr/share/asus/commands"

static void leon_command_tree(const char *path, unsigned depth)
{
        DIR *directory_stream;
        struct dirent *entry;
        struct stat st;
        char child[PATH_MAX], target[PATH_MAX], resolved[PATH_MAX];
        if (depth > 16) { errno = ELOOP; die("command tree depth"); }
        directory(path, 0, 0);
        directory_stream = opendir(path);
        if (!directory_stream) die(path);
        while ((entry = readdir(directory_stream))) {
                ssize_t count;
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
                if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >= (int)sizeof(child)) {
                        errno = ENAMETOOLONG; die("command tree entry");
                }
                if (lstat(child, &st)) die(child);
                if (st.st_uid != 0 || st.st_gid != 0) { errno = EPERM; die(child); }
                if (S_ISDIR(st.st_mode)) { leon_command_tree(child, depth + 1); continue; }
                if (!S_ISLNK(st.st_mode)) { errno = EPERM; die("command lower must contain only directories and links"); }
                count = readlink(child, target, sizeof(target)-1);
                if (count < 0 || count >= (ssize_t)sizeof(target)-1) die("command alias readlink");
                target[count] = 0;
                if (target[0] != '/' || strstr(target, "/../") || !realpath(target, resolved)) {
                        errno = EINVAL; die("command alias target");
                }
                if (strncmp(resolved, "/usr/libexec/asus/", 18) &&
                    strncmp(resolved, "/usr/lib/arm-linux-gnueabi/asus/", 32) &&
                    strncmp(resolved, "/usr/lib/aarch64-linux-gnu/asus/", 32) &&
                    strncmp(resolved, "/usr/bin/", 9) && strncmp(resolved, "/usr/sbin/", 10) &&
                    strcmp(resolved, "/usr/lib/cargo/bin/coreutils/chroot")) {
                        errno = EPERM; die("command alias target outside reviewed roots");
                }
                regular(resolved, 0);
        }
        if (closedir(directory_stream)) die(path);
}

static void leon_private_commands(const char *generation)
{
        static const char *const names[] = { "lib", "bin", "sbin" };
        struct stat self_ns, manager_ns;
        unsigned i;
        /* Do not trust a caller's marker alone to authorize global mounts. */
        if (geteuid() != 0 || getpid() == 1 || stat("/proc/self/ns/mnt", &self_ns) ||
            stat("/proc/1/ns/mnt", &manager_ns) ||
            (self_ns.st_dev == manager_ns.st_dev && self_ns.st_ino == manager_ns.st_ino)) {
                errno = EPERM; die("command projection requires private mount namespace");
        }
        leon_rc_private_etc_require();
        directory(LEON_COMMAND_ROOT, 0, 0);
        /* Validate all sources before changing any lookup path. */
        for (i=0; i<sizeof(names)/sizeof(names[0]); i++) {
                char source[PATH_MAX];
                if (snprintf(source,sizeof(source),"%s/%s",LEON_COMMAND_ROOT,names[i]) >= (int)sizeof(source)) {
                        errno=ENAMETOOLONG; die("command projection source");
                }
                leon_command_tree(source,0);
        }
        for (i=0; i<sizeof(names)/sizeof(names[0]); i++) {
                char lower[PATH_MAX], source[PATH_MAX], target[PATH_MAX], options[PATH_MAX*2+64];
                if (snprintf(lower,sizeof(lower),"%s/commands-%s-lower",generation,names[i]) >= (int)sizeof(lower) ||
                    snprintf(source,sizeof(source),"%s/%s",LEON_COMMAND_ROOT,names[i]) >= (int)sizeof(source) ||
                    snprintf(target,sizeof(target),"/usr/%s",names[i]) >= (int)sizeof(target)) {
                        errno=ENAMETOOLONG; die("command projection paths");
                }
                directory(target,0,0);
                if (mkdir(lower,0700)) die("new command lower");
                directory(lower,0700,0);
                if (mount(target,lower,NULL,MS_BIND,NULL) ||
                    mount(NULL,lower,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL))
                        die("private native command lower");
                if (snprintf(options,sizeof(options),"lowerdir=%s:%s,index=off",source,lower) >= (int)sizeof(options)) {
                        errno=ENAMETOOLONG; die("command overlay options");
                }
                if (mount("overlay",target,"overlay",MS_RDONLY|MS_NOSUID|MS_NODEV,options))
                        die("private command overlay");
        }
        if (setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1)) die("private command PATH");
}
#endif

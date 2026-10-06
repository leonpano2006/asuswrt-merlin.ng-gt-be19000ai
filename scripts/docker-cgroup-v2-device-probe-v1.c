/* Offline QEMU container fixture only: inspect and open its fixed loop0 bind.
 * No data read, write, ioctl, device creation, BPF or namespace operation. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct stat before, after;
	int fd, saved;
	int deny;
	if (argc != 2 || (strcmp(argv[1], "allow") && strcmp(argv[1], "deny")))
		return 64;
	deny = !strcmp(argv[1], "deny");
	if (lstat("/probe-device", &before) || !S_ISBLK(before.st_mode) ||
	    major(before.st_rdev) != 7 || minor(before.st_rdev) != 0)
		return 65;
	errno = 0;
	fd = open("/probe-device", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	saved = errno;
	if (fd < 0) {
		printf("DEVICE_OPEN_DENIED errno=%d major=7 minor=0\n", saved);
		return deny && saved == EPERM ? 0 : 66;
	}
	if (fstat(fd, &after) || !S_ISBLK(after.st_mode) ||
	    after.st_rdev != before.st_rdev || after.st_dev != before.st_dev ||
	    after.st_ino != before.st_ino) {
		(void)close(fd);
		return 67;
	}
	if (close(fd))
		return 68;
	puts("DEVICE_OPEN_ALLOWED errno=0 major=7 minor=0");
	return deny ? 69 : 0;
}

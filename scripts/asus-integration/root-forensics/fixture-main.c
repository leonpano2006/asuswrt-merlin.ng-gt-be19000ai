#define _GNU_SOURCE
#include "export.h"
#include <fcntl.h>
#include <unistd.h>
int main(int argc,char **argv){if(argc!=3||getuid()!=0)return 64;int fd=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return 125;int rc=forensic_export(fd);close(fd);return rc?125:0;}

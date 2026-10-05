/* Only resource/identity fixtures; never execute a vendor script. */
#define main private_accounts_main
#include "private-etc-fixture.c"
#undef main
#include <sys/mount.h>
#include <sys/statvfs.h>

static void readonly_path(const char *path)
{
 int fd;
 assert(access(path,R_OK)==0);
 errno=0;fd=open(path,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
 assert(fd==-1 && errno==EROFS);
}
static int helper(const char *operation,const char *argument)
{
 pid_t child=fork();int status;
 assert(child>=0);
 if(!child) {
  execl("/usr/libexec/asus/bsp-ownership","bsp-ownership",operation,argument,(char *)NULL);
  _exit(127);
 }
 assert(waitpid(child,&status,0)==child && WIFEXITED(status));
 return WEXITSTATUS(status);
}
int main(int argc,char **argv)
{
 if(argc==2 && !strcmp(argv[1],"--leon-systemd")) {
  char header[80];
  FILE *file;
  const char *library_path=getenv("LD_LIBRARY_PATH");
  assert(library_path && !strcmp(library_path,"/usr/$LIB/asus"));
  readonly_path("/rom/etc/init.d/hndnvram.sh");
  readonly_path("/www/pages/aiboard.html");
  assert(access("/rom/native-host-marker",F_OK)==-1);
  assert(access("/www/native-host-marker",F_OK)==-1);
  file=fopen("/etc/hotplug2.rules","r");assert(file);
  assert(fgets(header,sizeof(header),file));fclose(file);
  assert(!strcmp(header,"# ASUS_NATIVE_UDEV_CALLBACKS_V1\n"));
  file=fopen("/etc/profile","a");assert(file);
  assert(fputs("\n# Namespace copy-up probe only\n",file)>=0);assert(!fclose(file));
  puts("LAB_ASUS_RESOURCES_ROM_WEB_READONLY_ETC_COPYUP_PASS");
  assert(helper("--require",NULL)==0);
  puts("LAB_ASUS_BSP_NATIVE_UUID_UDEV_NODES_PASS");
  {
   struct stat a,b;
   struct statvfs fs;
   assert(!stat("/mnt/defaults",&a) && !stat("/tmp/mnt/defaults",&b));
   assert(a.st_dev==b.st_dev && a.st_ino==b.st_ino);
   assert((a.st_mode&0777)==0777);
   assert(!statvfs("/tmp/mnt/defaults",&fs) && (fs.f_flag&ST_RDONLY));
   assert(access("/tmp/mnt/defaults/factory-marker",R_OK)==0);
   assert(access("/tmp/mnt/defaults/native-host-marker",F_OK)==-1);
   errno=0;
   assert(open("/tmp/mnt/defaults/forbidden",O_CREAT|O_WRONLY,0600)==-1 && errno==EROFS);
   puts("LAB_ASUS_DEFAULTS_ALIASES_SAME_READONLY_FACTORY_MOUNT_PASS");
  }
  assert(helper("--nvram-defaults",NULL)==125); /* healthy current board has no factory file */
  assert(helper("--nvram-template","/rom/etc/wlan/nvram/GT-BE19000AI.nvm")==0);
  assert(access("/mnt/nvram/nvram.nvm",R_OK)==0);
  assert(access("/mnt/nvram/native-host-marker",F_OK)==-1);
  errno=0;assert(open("/mnt/nvram/not-allowed",O_CREAT|O_WRONLY,0600)==-1 && errno==EROFS);
  puts("LAB_ASUS_BSP_PRIVATE_CALIBRATION_VIEW_PASS");
 }
 return private_accounts_main(argc,argv);
}

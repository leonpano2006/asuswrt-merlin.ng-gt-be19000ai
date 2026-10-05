#!/usr/bin/env python3
"""Stage persistent Ubuntu ownership source changes; never launch ASUS rc.

This is a partial source port: account/NSS, remaining /etc writers and hardware
orchestration gates remain unresolved. A successful transform is not boot proof.
"""
from pathlib import Path
import difflib
import hashlib
import json
import re
import subprocess

ROOT=Path(__file__).resolve().parents[2]
PIN='69838e4a60564e5550e97f11d8a8cf2c6260c4f0'
FILES=['release/src/router/rc/init.c','release/src/router/rc/services.c']
WORK=ROOT/'build/asus-persistent-layout'
PATCH=ROOT/'patches/ubuntu26/0004-asus-rc-persistent-layout.patch'
REPORT=ROOT/'reports/ubuntu26/asus-persistent-layout-port.json'
HEADER='''/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_RC_PERSISTENT_H
#define LEON_RC_PERSISTENT_H
#if !defined(LEON_SYSTEMD_RC) || LEON_SYSTEMD_RC != 1
#error "Persistent Ubuntu layout requires LEON_SYSTEMD_RC=y"
#endif
#include "rc-bridge.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LEON_RC_RUNTIME_ETC "/run/asus/etc"

static inline const char *leon_rc_hosts_path(void)
{
    return LEON_RC_RUNTIME_ETC "/hosts";
}
static inline const char *leon_rc_hosts_tmp_path(void)
{
    return LEON_RC_RUNTIME_ETC "/hosts.tmp";
}
static inline int leon_rc_persistent_directory(const char *path, int create)
{
    struct stat st;
    if (create && mkdir(path, 0755) && errno != EEXIST) return -1;
    if (lstat(path, &st)) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022)) {
        errno = EPERM;
        return -1;
    }
    return 0;
}
static inline int leon_rc_persistent_preflight(void)
{
    char resolved[PATH_MAX];
    struct stat st;
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    /* Package-owned /etc and /var must never be aliases into a tmpfs tree. */
    if (leon_rc_persistent_directory("/etc", 0) ||
        leon_rc_persistent_directory("/var", 0) ||
        leon_rc_persistent_directory("/run", 0)) return -1;
    if (!realpath("/var/run", resolved)) return -1;
    if (strcmp(resolved, "/run")) { errno = EXDEV; return -1; }
    if (lstat("/tmp", &st)) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 01777) != 01777) {
        errno = EPERM;
        return -1;
    }
    if (leon_rc_persistent_directory("/run/asus", 1) ||
        leon_rc_persistent_directory(LEON_RC_RUNTIME_ETC, 1)) return -1;
    return 0;
}
#endif
'''

def sha(b):return hashlib.sha256(b).hexdigest()
def once(text,old,new):
 assert text.count(old)==1,(old[:100],text.count(old))
 return text.replace(old,new,1)

def transform(path,text):
 if path.endswith('/init.c'):
  text=once(text,'#include "rc.h"','#include "rc.h"\n#include "rc-persistent.h"')
  # This preflight runs before bcm_boot_launcher in sysinit, not after hardware.
  anchor='#ifdef HND_ROUTER\n\t_dprintf("\\nLaunch boot...\\n");'
  text=once(text,anchor,'\tif (leon_rc_persistent_preflight()) {\n'
      '\t\tperror("ASUS persistent layout preflight");\n\t\t_exit(1);\n\t}\n\n'+anchor)
  old='#define MOUNT(src,dest,type,flag,data)\tif (mount(src,dest,type,flag,data))\tperror("## mount " src)'
  new='#define MOUNT(src,dest,type,flag,data) do { \\\n\tif (leon_rc_mount(src,dest,type,flag,data)) { \\\n\t\tperror("## mount " src); \\\n\t\t_exit(1); \\\n\t} \\\n} while (0)'
  text=once(text,old,new)
  assert text.count('\tstime(&tm);')==2
  text=text.replace('\tstime(&tm);','\t/* Ubuntu time synchronization owns the clock; never reset to epoch. */')
  assert text.count('\tstatic const time_t tm = 0;')==2
  text=text.replace('\tstatic const time_t tm = 0;\n','')
  text=once(text,'\tif (is_ax5400_i1()) noconsole = 1; else','\tif (is_ax5400_i1()) noconsole = 1;')
  for device,mode,minor in [('null','0666','3'),('console','0600','1')]:
   old=f'\tif (!f_exists("/dev/{device}"))\n\t\tMKNOD("/dev/{device}", S_IFCHR | {mode}, makedev({1 if device=="null" else 5}, {minor}));'
   text=once(text,old,f'\t/* Ubuntu devtmpfs/udev supplies /dev/{device}. */')
  for d in ['/dev/shm','/dev/pts']:
   old=f'\tMKDIR("{d}", 0777);'
   text=once(text,old,f'\t/* systemd owns {d} and its mode. */')
  text=once(text,'\tchmod("/tmp", 0777);','\t/* systemd retains /tmp mode01777; preflight checked it. */')
  old='\tf_write("/etc/hosts", NULL, 0, 0, 0644);\t\t\t// blank\n\tf_write("/etc/fstab", NULL, 0, 0, 0644);\t\t\t// !!TB - blank'
  new='\t/* Ubuntu owns persistent /etc/hosts and /etc/fstab. */'
  text=once(text,old,new)
  # Do not import whole ROM defaults over Ubuntu /etc. Individual ASUS files
  # need package ownership before enabling the real service.
  start=text.index('\tif ((d = opendir("/rom/etc")) != NULL) {')
  end=text.index('\n#ifdef RTCONFIG_VAR_NVRAM',start)
  block=text[start:end]
  assert 'unlink("/etc/resolv.conf")' in block and '/sbin/ldconfig' in block
  wrapped='\t/* ASUS defaults are package-owned individually. Do not import /rom/etc,\n'\
      '\t * replace Ubuntu mtab/resolv.conf or invoke the stock ldconfig. */\n'
  text=text[:start]+wrapped+text[end:]
  # Later temp-rootfs path has its own mtab handling.
  text=once(text,'\t\tsymlink("/proc/mounts", "/etc/mtab");\n\t}\n\tset_action(ACT_IDLE);',
      '\t\t/* Ubuntu owns /etc/mtab in this source profile. */\n\t}\n\tset_action(ACT_IDLE);')
  start=text.index('\tif ((d = opendir("/usr/codepages")) != NULL) {')
  end=text.index('\n#endif',start)
  text=text[:start]+'\t/* Codepage aliases are owned by packages, never created at boot. */'+text[end:]
  start=text.index('\tstatic const char *dn[] = {')
  end=text.index('\n#ifndef HND_ROUTER',start)
  text=text[:start]+'\t/* Device node modes belong to Ubuntu udev, not a blanket0666 loop. */'+text[end:]
  # Both removed ROM/codepage loops were the only users of these local names.
  start=text.index('static void sysinit(void)')
  end=text.index('\n#if defined(RTCONFIG_TEMPROOTFS)',start)
  body=text[start:end]
  assert body.count('\tDIR *d;\n')==1 and body.count('\tstruct dirent *de;\n')==1
  body=body.replace('\tDIR *d;\n','').replace('\tstruct dirent *de;\n','')
  assert body.count('\tchar t[256];\n')==1
  body=body.replace('\tchar t[256];\n','')
  text=text[:start]+body+text[end:]
  old='\t\tuse_custom_config("fstab", "/etc/fstab");\n\t\trun_postconf("fstab", "/etc/fstab");'
  text=once(text,old,'\t\t/* Ubuntu fstab is administrator/package-owned; migrate custom fstab hooks explicitly. */')
  # This is the board's manufacturing-only ATE alias, not Ubuntu's host table.
  text=once(text,'fopen("/etc/hosts", "a")','fopen(leon_rc_hosts_path(), "a")')
  text=once(text,'else perror("/etc/hosts");','else perror(leon_rc_hosts_path());')
 elif path.endswith('/services.c'):
  text=once(text,'#include <rc.h>','#include <rc.h>\n#include "rc-persistent.h"')
  start=text.index('int write_etc_hosts()\n{')
  end=text.index('\n#ifdef RTCONFIG_WIFI_SON\nvoid gen_apmode_dnsmasq',start)
  block=text[start:end]
  assert block.count('"/etc/hosts.tmp"')==4 and block.count('"/etc/hosts"')==4
  block=block.replace('"/etc/hosts.tmp"','leon_rc_hosts_tmp_path()').replace('"/etc/hosts"','leon_rc_hosts_path()')
  old='\tunlink(leon_rc_hosts_path());\n\trename(leon_rc_hosts_tmp_path(), leon_rc_hosts_path());'
  new='\t/* Same-directory rename preserves the previous generated file on failure. */\n\tif (rename(leon_rc_hosts_tmp_path(), leon_rc_hosts_path())) {\n'
  new+='\t\tperror("ASUS hosts rename");\n\t\tunlink(leon_rc_hosts_tmp_path());\n\t\treturn -1;\n\t}'
  block=once(block,old,new)
  text=text[:start]+block+text[end:]
  text=once(text,'\tfprintf(fp, "addn-hosts=/etc/hosts\\n");',
      '\tfprintf(fp, "addn-hosts=%s\\n", leon_rc_hosts_path());')
 return text


def make_patch(path,old,new):
 return 'diff --git a/'+path+' b/'+path+'\n'+''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+path,tofile='b/'+path))


def main():
 WORK.mkdir(parents=True,exist_ok=True)
 changes=[];patch=[];baseline={}
 for path in FILES:
  raw=subprocess.check_output(['git','-c','gc.auto=0','-C',str(ROOT/'source'),'show',PIN+':'+path])
  old=raw.decode(errors='surrogateescape');new=transform(path,old)
  baseline[path]=old
  target=WORK/'source'/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(new,errors='surrogateescape')
  saved=WORK/'baseline'/path;saved.parent.mkdir(parents=True,exist_ok=True);saved.write_bytes(raw)
  changes.append(dict(path=path,source_sha256=sha(raw),result_sha256=sha(new.encode(errors='surrogateescape'))))
  patch.append(make_patch(path,old,new))
 header_path='release/src/router/rc/rc-persistent.h'
 (WORK/'source'/header_path).write_text(HEADER)
 patch.append('diff --git a/'+header_path+' b/'+header_path+'\n'+''.join(difflib.unified_diff([],HEADER.splitlines(True),fromfile='/dev/null',tofile='b/'+header_path)))
 PATCH.write_text(''.join(patch),errors='surrogateescape')
 # All helper calls and all unrelated NVRAM/radio/AI code are retained. The account
 # writer is deliberately still present to expose the not-launchable integration gate.
 init=baseline[FILES[0]];services=baseline[FILES[1]]
 new_services=(WORK/'source'/FILES[1]).read_text(errors='surrogateescape')
 account_start=services.index('void create_passwd(void)\n{');account_end=services.index('\nvoid get_dhcp_pool',account_start)
 assert services[account_start:account_end] in new_services
 for name in ['start_hw_wdt();','init_devs();','init_syspara();','setup_passwd();']:
  assert init.count(name)==(WORK/'source'/FILES[0]).read_text(errors='surrogateescape').count(name),name
 evidence=[]
 for path,text in baseline.items():
  for n,line in enumerate(text.splitlines(),1):
   if any(s in line for s in ['/etc/passwd','/etc/shadow','/etc/group','/etc/gshadow','create_custom_passwd(', 'create_ovpn_passwd(', 'setup_passwd(', '/etc/hosts','/etc/fstab','/etc/resolv.conf','/var/lib/dbus','/var/run/dbus']):
    evidence.append(dict(path=path,line=n,source=line.strip()))
 report=dict(schema_version=1,status='minimal persistent-layout source port staged; NOT LAUNCHABLE; account/NSS and remaining service integration gates unresolved',
  scope='Exact pinned source transformed locally. No actual rc execution, service start, router access or rootfs/package change.',
  source_commit=PIN,patch=str(PATCH.relative_to(ROOT)),patch_sha256=sha(PATCH.read_bytes()),
  generator='scripts/asus-integration/prepare-persistent-layout-port.py',generator_sha256=sha(Path(__file__).read_bytes()),
  source_changes=changes,new_header=dict(path=header_path,sha256=sha(HEADER.encode())),
  application=dict(order=['0003-asus-rc-systemd-manager.patch','0004-asus-rc-persistent-layout.patch'],
    contract='Requires LEON_SYSTEMD_RC=y (-DLEON_SYSTEMD_RC=1); header rejects legacy build. 0003 supplies rc-bridge.h/leon_rc_managed/leon_rc_mount. Apply contextual patch to a disposable complete source copy; do not replace another agent\'s modified init.c with this pristine-derived file.',
    mount_helper_contract='Protected paths must already be mounted by systemd with the required filesystem. Missing/different protected mount fails; no fallback mount over Ubuntu-owned trees.'),
  implemented=[
   'Ubuntu-only sysinit fails closed without systemd marker, validates real root-owned /etc and /var, existing /run and /var/run -> /run, /tmp01777; creates only /run/asus/etc before BCM launcher.',
   'Route MOUNT macro to existing manager helper; managed mount failure is fatal before continuing initialization.',
   'Ubuntu-only sysinit does not reset clock to epoch, clear /etc/hosts or /etc/fstab, import /rom/etc wholesale, replace /etc/mtab/resolv.conf, run stock ldconfig or add untracked /usr/share codepage aliases.',
   'Later JFFS fstab replacement/postconf is removed from this Ubuntu source profile too; no silent overwrite of Ubuntu persistent fstab.',
   'ASUS-generated hosts use /run/asus/etc/hosts and temporary sibling; dnsmasq addn-hosts uses that file and can still read Ubuntu /etc/hosts normally.',
   'Host-file rename now checks errors and atomically replaces without first deleting the previous file.',
   'Existing hardware, NVRAM, radio, WiFi and AI logic is retained; source is not enabled because consumer/account/hotplug integration remains incomplete.'],
  ownership={
   'ubuntu':['/etc/fstab','/etc/hosts','/etc/resolv.conf policy','/etc/machine-id','/etc/nsswitch.conf','/etc/passwd','/etc/shadow','/etc/group','/etc/gshadow','/var/lib/dpkg','/var/lib/apt','/var/cache/apt','/run','/var/run -> /run','/tmp mode01777','udev-owned /dev and native ld.so.cache'],
   'asus_runtime':['/run/asus/etc/hosts','/run/asus/etc/hosts.tmp','existing /tmp vendor config/data paths individually audited','existing daemon-specific PID files under /run through /var/run'],
   'asus_persistent':['/jffs retained data/configs','/ai existing separate AI files/data','ASUS-specific /var/lib or /var/cache subdirectories only after individual package/service ownership audit']},
  account_design=dict(status='not implemented; enabling real rc is blocked',
   destructive_function='services.c create_passwd rewrites all four Ubuntu identity databases; its exact original body is preserved in this source candidate, not silently skipped.',
   required=[
    'Ubuntu OpenSSH is the sole SSH implementation. Preserve all distribution/service users and groups; no NVRAM-driven replacement of whole passwd/shadow/group/gshadow files.',
    'Integrate explicitly selected ASUS management username through Ubuntu account tools or a locked atomic database editor; validate names, reserve system identities, use stable UID/GID policy and never duplicate UID0 merely because vendor code did so.',
    'Coordinate all four databases with lckpwdf/compatible group locking and atomic writes; preserve metadata and password aging, detect concurrent apt/sysusers/useradd edits, recover partial failure.',
    'Keep password material out of argv/logs; update only the owned account hash with controlled crypt policy. Verify HTTPD/getpwnam/getspnam/PAM/SMB/FTP/OpenVPN consumers against the final NSS view.',
    'Replace every create_passwd/setup_passwd caller, including later JFFS reapply and service restart paths, only once the real bridge returns explicit success/failure.',
    'Review custom passwd/shadow/group/gshadow additions and postconf hooks as account mutations; do not append vendor nas UID100/OpenVPN GID200/Tor UID65533 without collision checks.'
   ]),
  dns_design=dict(status='ASUS hosts writer isolated; OS resolver integration still required',
   requirement='Keep one DNS owner. Select package-owned /etc/resolv.conf policy for the ASUS/CCR topology; do not enable competing systemd-resolved/networkd DNS behavior. ASUS still writes upstream data such as /tmp/resolv.conf.',
   remaining=['Preserving /etc/hosts means libc does not automatically read /run/asus/etc/hosts. Complete NSS/DNS service routing for ASUS names, DHCP names and manufacturing-only sl1680 ATE alias.',
     'Custom hosts.postconf must honor its passed runtime path; hardcoded /etc mutations in external hooks remain outside this transform.',
     'Other generated service configs such as /etc/dnsmasq.conf, PAM/OpenVPN and dbus configs still need path ownership before deployment.']),
  remaining_blockers=[
   'Account bridge absent; real rc launch remains forbidden even if this patch compiles.',
   'bcm_boot_launcher and other boot scripts can still mount/remove paths before or outside reviewed C paths; port their scripts and order units before activation.',
   'mdev coldplug/hotplug2/static-device script paths still compete with Ubuntu udev; explicit Broadcom hardware/device ownership is required.',
   'Stock readonly /rom/etc defaults must become individually owned package files; removed blanket copying does not magically provide make_static_devnodes, ppp, firmware or vendor driver config.',
   'Source syscall mount wrapper only covers the MOUNT macro. Direct mount calls and shell mount commands require independent review.',
   'ASUS setup_passwd body and unreviewed /etc service writers still target legacy paths; do not run this staging candidate.',
   'ASUS global umask0, /var/state LPR, cron spool, dbus/system bus and other service-specific directories still need ownership/lifetime integration.',
   'Static transformations and focused fixtures cannot validate actual ASUS/Broadcom service boot or hardware operation.'],
  be98_reference=dict(path=str(Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100/systemd-rc-compat-20260916/scripts/prepare-rc.py')),
   reused='Explicit managed-mode predicate, mount ownership checks, clock protection and orderly manager boundary.',
   corrected='BE98 checkpoint only guarded fstab and /tmp mode; it left /etc/hosts truncation, ROM symlink import, resolv.conf replacement and later fstab hooks. Those are all addressed here; account generation is explicitly still blocked.'),
  source_evidence=evidence,checks=dict(account_function_byte_identical=True,hardware_and_account_call_counts_preserved=True),
  runtime_integration_accepted=False,real_rc_launch_allowed=False,flash_allowed=False)
 REPORT.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(dict(status=report['status'],patch=str(PATCH.relative_to(ROOT)),source_files=len(changes),account_function_byte_identical=True),indent=2))

if __name__=='__main__':main()

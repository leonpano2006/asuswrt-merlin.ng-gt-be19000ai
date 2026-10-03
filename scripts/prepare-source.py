#!/usr/bin/env python3
"""Prepare the pinned sparse BSP checkout; never build or replace userspace."""
from pathlib import Path
import subprocess,shutil,re,json
r=Path(__file__).resolve().parents[1];src=r/'source';p=src/'release/src-rt-5.04behnd.4916';k=p/'kernel/linux-4.19'
u=json.loads((r/'UPSTREAM.json').read_text())
def run(*a):subprocess.run(a,check=True)
if not (src/'.git').exists():
 run('git','clone','--filter=blob:none','--no-checkout','--depth=1','--branch',u['tag'],u['repository'],str(src))
run('git','-C',str(src),'sparse-checkout','set','release/src-rt-5.04behnd.4916','release/src/router/fltr')
assert subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()==u['commit']
run('python3',str(r/'scripts/apply-patch-stack.py'),'--source',str(src),'--patches',str(r/'patches'))
kconf=['# Generated from BSP autodetect files.'];make=['# Generated from BSP autodetect files.']
for f in sorted((p/'bcmdrivers').rglob('autodetect')):
 m=re.search(r'^(?:DRIVER|FEATURE):\s*(\w+)',f.read_text(),re.M)
 if not m:continue
 name=m.group(1);rel=f.parent.relative_to(p/'bcmdrivers')
 if (f.parent/'Kconfig.autodetect').exists():kconf += [f'menu "{name}"',f'source "../../bcmdrivers/{rel}/Kconfig.autodetect"','endmenu','']
 make += [f'$(eval $(call LN_RULE_AG, CONFIG_BCM_{name}, {rel}, $(LN_NAME)))']
(p/'bcmdrivers/Kconfig.autogen').write_text('\n'.join(kconf)+'\n');(p/'bcmdrivers/Makefile.autogen').write_text('\n'.join(make)+'\n')
link=p/'bcmdrivers/broadcom/net/wl/impl103/Makefile'
if not link.exists():link.symlink_to('../Makefile')
# Makefile parsing only: none of these GT-BE98 Pro binaries are packaged.
for directory in (p/'router-sysdep.gt-be98_pro').glob('hnd*'):
 if directory.is_dir():shutil.copytree(directory,p/'router-sysdep'/directory.name,dirs_exist_ok=True)
for f in [p/'bcmdrivers/broadcom/net/wl/impl103/main/src/.config',src/'release/src/router/.config']:
 if not f.exists():f.write_text('# Kernel-only BSP parse stub.\n')
run('make','-C',str(p/'rdp'),'PROJECT=BCM6813','BRCM_CHIP=6813','rdp_link')
shutil.copyfile(r/'configs/candidate.config',k/'.config')

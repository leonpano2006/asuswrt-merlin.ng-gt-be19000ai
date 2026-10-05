#!/usr/bin/env python3
"""Make systemd-managed ASUS startup require the sole native watchdog owner."""
import argparse,difflib,hashlib,json,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2]
BASE=R/'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-v3/compile-source'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);a=p.parse_args();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-native-watchdog-port'/a.label;out.mkdir(parents=True,exist_ok=False)
 path=BASE/'release/src/router/rc/init.c';old=path.read_text();needle='static void start_hw_wdt(void)\n{\n';assert old.count(needle)==1
 insertion='''#ifdef LEON_SYSTEMD_RC
	/* Sole hardware owner was armed by immutable PID1 before systemd exec.
	 * Query authenticated native IPC: a marker file is not ownership proof.
	 * Never start a second wdtctl/wdtd, and fail the broker child if no owner.
	 * The independent ASUS software watchdog remains managed normally. */
	if (eval("/usr/libexec/leon-asus/trial-health", "--assert-armed") != 0) {
		fprintf(stderr, "LEON_ASUS_NATIVE_WATCHDOG_NOT_ARMED\\n");
		_exit(125);
	}
	return;
#endif
'''
 new=old.replace(needle,needle+insertion)
 rel='release/src/router/rc/init.c';patch=R/'patches/ubuntu26/asuswrt6/0019-asus-native-watchdog-owner.patch';diff='diff --git a/'+rel+' b/'+rel+'\n'+''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+rel,tofile='b/'+rel));patch.write_text(diff)
 target=out/'source'/rel;target.parent.mkdir(parents=True);target.write_text(old);run=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=out/'source',capture_output=True,text=True);assert run.returncode==0 and 'offset' not in run.stdout and target.read_text()==new
 report={'status':'source_patch_applies_exactly_native_helper_runtime_pending','source_pin':'9b25e55ca5c56a6f01d6a56264c0f6c47459ada0','base':str(BASE.relative_to(R)),'before_sha256':sha(path),'after_sha256':sha(target),'patch':{'path':str(patch.relative_to(R)),'sha256':sha(patch)},'contract':{'program':'/usr/libexec/leon-asus/trial-health','argv':['--assert-armed'],'success_exit':0,'failure_exit':125,'query':'Native root server actual ownership state via authenticated AF_UNIX peer; never file-presence proof','scope':'LEON_SYSTEMD_RC only; non-LEON stock path unchanged'},'hardware_touched':False,'runtime_accepted':False,'software_watchdog_unchanged':True,'compile_pending':True,'helper_runtime_pending':True,'builder_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()

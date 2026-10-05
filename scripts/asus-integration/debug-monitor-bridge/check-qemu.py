#!/usr/bin/env python3
"""Bind completed kernel10 bridge proof to immutable build and fixture inputs."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
S=Path(__file__).resolve().parent;R=S.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
 if not __debug__:raise RuntimeError('Python optimization forbidden')
 p=argparse.ArgumentParser();p.add_argument('--build',required=True,type=Path);p.add_argument('--fixture',required=True,type=Path);p.add_argument('--result',required=True,type=Path);a=p.parse_args()
 paths=[(R/x).resolve() if not x.is_absolute() else x.resolve() for x in [a.build,a.fixture,a.result]]
 build,fixture,result=paths;b=json.loads(build.read_text());f=json.loads(fixture.read_text());q=json.loads(result.read_text())
 assert b['status']=='compiled_not_runtime_validated' and not b['vendor_executed']
 for row in b['outputs']+b['source_inputs']:assert sha(R/row['path'])==row['sha256'],row['path']
 assert sha(build)==f['build']['sha256'] and sha(R/f['initramfs']['path'])==q['initramfs_sha256']==f['initramfs']['sha256']
 assert sha(R/f['rootfs']['path'])==f['rootfs']['sha256']
 for row in f['inputs']:assert sha(R/row['path'])==row['sha256']
 assert q['guest_complete'] and not q['panic'] and q['stop_reason']=='complete'
 assert sha(R/'build/Image-v10')==q['kernel_sha256']=='4a15601eada042576aed2a3680dcc48e9228eea70f70c478840767aaa89a9f8e'
 serial=result.parent/'serial.log';assert sha(serial)==q['log_sha256']
 names=['NATIVE_NAMESPACE_REFUSED','PRODUCTION_IDENTITY_NOT_BYPASSED','PRODUCTION_HASH_GATE','NOT_READY_REFUSED','SELF_SIGNAL_UNCHANGED','EXEC_DESCENDANT_NO_ADAPTER','UNKNOWN_CALLSITE_REFUSED','MISSING_BROKER_REFUSED','MISSING_PRIVATE_MARKER_REFUSED','CHANGED_EXECUTABLE_REFUSED','EXISTING_FIFO_BUDGET_REFUSED','DAEMON_FORK_FIXED_EVENT','RESPAWN_BUDGET_REFUSED','CHAIN_FIXED_EVENT_ONE_SIGNAL','BROKER_RESTART_BUDGET_REFUSED','NO_POWER_NATIVE_HOST_UNCHANGED']
 expected=['LAB_DM_'+x+'_PASS' for x in names]+['LAB_DM_REAL_CHAIN_COMPLETE','LAB_DM_EXIT_code=0','LAB_SYSTEMD_FULL_PROBE_EXIT_code=0']
 assert all(x in q['lab_lines'] for x in expected),set(expected)-set(q['lab_lines'])
 library=build.parent/'production/libdebug-monitor-bridge.so';launcher=build.parent/'production/debug-monitor-launch'
 table=subprocess.check_output(['readelf','--dyn-syms','--wide',str(library)],text=True)
 defined=[]
 for line in table.splitlines():
  cols=line.split()
  if len(cols)>=8 and cols[3]=='FUNC' and cols[4]=='GLOBAL' and cols[6]!='UND':defined.append(cols[7])
 assert defined==['kill'],defined
 d={'schema':1,'status':'compiled_armel_and_kernel10_real_notification_chain_validated','production_ready':False,'hardware_recovery_proven':False,'build':ref(build),'fixture':ref(fixture),'qemu':ref(result),'serial':ref(serial),'kernel_sha256':q['kernel_sha256'],'elapsed_seconds':q['elapsed_seconds'],'expected_markers':expected,'production_artifacts':[ref(launcher),ref(library)],'exported_functions':defined,'protocol':'Exact vendor return 0x17224 for kill(1,SIGTERM) -> notify_rc("restart_wireless") -> verified existing notify shim -> native broker SIGUSR1 -> mock manager. No PID1 SIGTERM forwarded.','budget':'Root-owned 0700 /run/leon-asus-wifi-recovery, O_EXCL root0600 once file with boot UUID. Consumed before enqueue; survives daemon and broker restarts; ambiguous failure never retries.','fixture_scope':'Real production native broker and dual-ABI notify libraries, ARMEL same bridge sources with distinct synthetic ET_EXEC hash/return constants. Actual production launcher executes only rejection against synthetic executable. No actual ASUS monitor/rc/NVRAM/BSP/WiFi code runs.','limits':['No Broadcom device, actual WiFi recovery or all-port continuity proven.','Existing ASUS restart_wireless may restart wireless/AiMesh/networkmap/printer and selected firewall/VLAN branches; it is not radio-only.','Constructor validates original ELF and fixed callsite. A new vendor ELF/broker/notify hash requires explicit rebuild/review.','Other monitor signals delegate to existing notify compatibility shim, preserving its TLS SIGUSR1 routing. No global loader configuration or original vendor binary is changed.','Root-owned private namespace checks prevent accidental host invocation; this is not a sandbox against malicious root.','An enqueue failure still consumes this boot\'s automatic recovery allowance; manual explicit management and separate guardian policy are unaffected.'],'router_access':False,'firmware_modified':False,'vendor_binary_modified':False,'checker':ref(Path(__file__))}
 output=build.parent/'validated-manifest.json';assert not output.exists();output.write_text(json.dumps(d,indent=2)+'\n')
 report=R/'reports/ubuntu26/debug-monitor-bridge-kernel10.json';assert not report.exists();report.write_bytes(output.read_bytes())
 print(json.dumps({'validated_manifest':ref(output),'report':ref(report),'artifacts':d['production_artifacts']},indent=2))
if __name__=='__main__':main()

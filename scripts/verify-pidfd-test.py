#!/usr/bin/env python3
"""Fail closed unless all guest pidfd probes passed; a shutdown marker is insufficient."""
import argparse,hashlib,json,re
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inspect(label,negative):
 d=R/'build/qemu'/label;result=json.loads((d/'result.json').read_text());raw=(d/'serial.log').read_text();log=raw.replace('\r','');errors=[]
 if result.get('log_sha256')!=sha(d/'serial.log'):errors.append('serial log digest mismatch')
 if result.get('panic') or not result.get('guest_complete'):errors.append('panic or missing completion')
 expected=77 if negative else 0
 exits=dict((abi,int(rc)) for abi,rc in re.findall(r'^PIDFD_PROBE_EXIT abi=(\S+) rc=(\d+)$',log,re.M))
 if exits!={x:expected for x in ('arm64','armel','armhf','arm64-pthreads')}:errors.append('unexpected probe exit map')
 checks={}
 if negative:
  gates=dict((a,int(e)) for a,e in re.findall(r'^PIDFD_CAPABILITY abi=(\S+) errno=(-?\d+)$',log,re.M))
  if gates!={x:-22 for x in ('arm64','armel','armhf')}:errors.append('negative control did not observe old P_PIDFD EINVAL')
 else:
  if 'result=FAIL' in log:errors.append('guest assertion failed')
  for abi in ('arm64','armel','armhf'):
   m=re.search(r'^PIDFD_SUMMARY abi='+abi+r' checks=(\d+) failures=(\d+)$',log,re.M)
   count=len(re.findall(r'^PIDFD_CHECK abi='+abi+r' .* result=pass$',log,re.M));checks[abi]=count
   if not m or int(m[1])!=count or int(m[2])!=0 or count<71:errors.append(abi+' summary does not prove all raw tests')
  m=re.search(r'^PIDFD_THREAD_SUMMARY checks=(\d+) failures=(\d+)$',log,re.M);count=len(re.findall(r'^PIDFD_THREAD_CHECK .* result=pass$',log,re.M));checks['arm64-pthreads']=count
  if not m or int(m[1])!=count or int(m[2])!=0 or count<83:errors.append('thread/lifecycle summary incomplete')
  for name in ('numeric_pid_reused','stale_handle_esrch','new_process_still_alive','last_thread_wakes_pidfd','leader_exit_not_group_exit','autoreap_epoll_wakeup','epoll_close_exit_race_64','namespace_clone','cgroup_clone_eagain_32','cgroup_failure_fd_cleanup','cgroup_clone_after_restore'):
   if not re.search(r'^PIDFD_THREAD_CHECK name='+name+r' .* result=pass$',log,re.M):errors.append('missing required assertion: '+name)
 return {'label':label,'negative_control':negative,'pass':not errors,'errors':errors,'checks':checks,'probe_exits':exits,'qemu':result}
def main():
 p=argparse.ArgumentParser();p.add_argument('--positive',required=True);p.add_argument('--negative');p.add_argument('--output',default='reports/ubuntu26/pidfd-regression.json');a=p.parse_args()
 results=[inspect(a.positive,False)]
 if a.negative:results.append(inspect(a.negative,True))
 if len(results)>1 and results[0]['qemu']['initramfs_sha256']!=results[1]['qemu']['initramfs_sha256']:results[0]['errors'].append('positive/negative fixtures differ');results[0]['pass']=False
 report={'all_pass':all(x['pass'] for x in results),'results':results,'physical_hardware_tested':False};out=R/a.output;out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'all_pass':report['all_pass'],'report':str(out),'checks':results[0]['checks']},indent=2));return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env python3
"""Install the complete runtime/NSS candidate in a fresh official resolute root."""
import argparse,hashlib,json,pathlib,shlex,subprocess,time
a=argparse.ArgumentParser();a.add_argument('--attempt',type=int,default=1);args=a.parse_args();assert args.attempt>0
R=pathlib.Path(__file__).resolve().parents[1];W=R/'build/ubuntu26-systemd';V='259.5-0ubuntu3.4+leonb53.2';E=pathlib.Path('/tmp/be19000ai-ubuntu26-systemd-acceptance-leonb53.2-attempt'+str(args.attempt))
p=R/'reports/ubuntu26/systemd-credentials-build.json';report=json.loads(p.read_text());assert report['candidate_version']==V and report['metadata_validation']['result']=='pass'
assert not E.exists(),'Preserve earlier test root and its evidence'
minimal=['libsystemd-shared','libsystemd0','libudev1','systemd','systemd-sysv','udev']
tested=minimal+['libnss-myhostname','libnss-mymachines','libnss-resolve','libnss-systemd','systemd-resolved']
packages=[R/x['path'] for x in report['packages'] if x['control']['Package'] in tested];assert len(packages)==len(tested)
script='''#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
test -c /dev/null
test -c /dev/zero
test -c /dev/urandom
mountpoint -q /proc
printf '%s\\n' 'Fresh official Ubuntu root; before local upgrade:'
dpkg-query -W systemd libsystemd0 udev
apt-get -y --no-install-recommends install /opt/leon-packages/*.deb
apt-get check
test -z "$(dpkg --audit)"
for p in TESTED; do
 test "$(dpkg-query -W -f='${Version}' "$p")" = 'VERSION'
 test "$(dpkg-query -W -f='${Status}' "$p")" = 'install ok installed'
done
/usr/lib/systemd/systemd --version
udevadm --version
getent passwd root
# Exercise all four NSS package removal scripts, then install exactly the same
# local artifacts again. The core init/udev package set remains installed.
apt-get -y remove libnss-myhostname libnss-mymachines libnss-resolve libnss-systemd
apt-get -y --no-install-recommends install /opt/leon-packages/libnss-*.deb
apt-get check
test -z "$(dpkg --audit)"
for p in TESTED; do
 test "$(dpkg-query -W -f='${Version}' "$p")" = 'VERSION'
 test "$(dpkg-query -W -f='${Status}' "$p")" = 'install ok installed'
done
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n' > /opt/leon-acceptance-packages.tsv
printf '%s\\n' SYSTEMD_ISOLATED_APT_METADATA_PASS
'''.replace('TESTED',' '.join(tested)).replace('VERSION',V)
hook=W/('isolated-apt-attempt'+str(args.attempt)+'.sh');assert not hook.exists();hook.write_text(script);hook.chmod(0o755)
cmd=['mmdebstrap','--mode=unshare','--architectures=arm64','--variant=minbase','--format=directory','--include=apt,ca-certificates,ubuntu-keyring,systemd-sysv,udev','--customize-hook=mkdir -p "$1/opt/leon-packages"']
for f in packages:cmd.append('--customize-hook=upload '+shlex.quote(str(f))+' /opt/leon-packages/'+f.name)
cmd+=['--customize-hook=upload '+shlex.quote(str(hook))+' /opt/isolated-apt.sh','--customize-hook=chroot "$1" /bin/bash /opt/isolated-apt.sh','resolute',str(E)]
for suite in ['resolute','resolute-updates','resolute-security']:cmd.append(f'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://ports.ubuntu.com/ubuntu-ports {suite} main universe')
start=time.monotonic();log=W/('isolated-apt-attempt'+str(args.attempt)+'.log');assert not log.exists()
with log.open('wb') as out:result=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
if 'isolated_apt_test' in report:report.setdefault('earlier_isolated_apt_attempts',[]).append(report['isolated_apt_test'])
report['isolated_apt_test']={'returncode':result.returncode,'elapsed_seconds':round(time.monotonic()-start,2),'packages':tested,'environment':'Fresh resolute minbase with official systemd and udev, local candidate upgrade, NSS remove/reinstall; all actions inside mmdebstrap customize hook with device/proc mounts','log':str(log.relative_to(R)),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'command':cmd,'limitations':'Host kernel namespace test; not PID1 boot or actual kernel10 credentials acceptance'}
report['status']='metadata_and_isolated_apt_passed_runtime_acceptance_pending' if result.returncode==0 else 'isolated_apt_failed'
p.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'test':report['isolated_apt_test']},indent=2));raise SystemExit(result.returncode)

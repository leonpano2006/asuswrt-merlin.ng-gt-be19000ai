#!/usr/bin/env python3
"""Exercise only new direct stage logging with synthetic scripts and null stdio."""
import argparse,hashlib,json,re,shutil,socket,subprocess,tempfile,threading,time
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
    p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
    assert __debug__ and re.fullmatch('[a-z0-9-]+',a.label)
    out=R/'build/ubuntu26-bsp-journal'/a.label;out.mkdir(parents=True,exist_ok=False)
    temp=Path(tempfile.mkdtemp(prefix='bsp-journal-'));rom=temp/'rom';(rom/'init.d').mkdir(parents=True);(rom/'rc3.d').mkdir()
    shell=temp/'dash';shutil.copyfile('/usr/bin/dash',shell);shell.chmod(0o755)
    source=R/'scripts/asus-integration/bsp-runner.c'; stages=re.findall(r'\{"([SK][0-9]+[^"]+)","([^"]+)"\}',source.read_text())
    assert len(stages)==16
    for name,target in stages:
        (rom/'rc3.d'/name).symlink_to('../init.d/'+target)
        if name!='S50ssl':(rom/'init.d'/target).write_text('exit 0\n');(rom/'init.d'/target).chmod(0o755)
    binary=out/'runner';sockpath=temp/'journal'
    command=['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-DLEON_BSP_RUNNER_UNIT_TEST=1','-DLEON_BSP_STAGE_TIMEOUT_MS=200','-DLEON_BSP_KILL_GRACE_MS=100',
             '-DLEON_BSP_ROM="'+str(rom)+'"','-DLEON_BSP_SHELL="'+str(shell)+'"','-DLEON_BSP_JOURNAL_SOCKET="'+str(sockpath)+'"',str(source),'-o',str(binary)]
    subprocess.run(command,check=True)
    results=[]
    def run(case,expected,receive=True,absent=False):
        server=None;rows=[];done=threading.Event()
        if not absent:
            server=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);server.bind(str(sockpath));server.settimeout(.1)
            server.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,256)
        def drain():
            while not done.is_set():
                try:rows.append(server.recv(4096).decode())
                except socket.timeout:pass
        reader=threading.Thread(target=drain) if receive and server else None
        if reader:reader.start()
        start=time.monotonic()
        proc=subprocess.run([str(binary),'start'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=4)
        elapsed=time.monotonic()-start;assert proc.returncode==expected and elapsed<2,(case,proc.returncode,elapsed)
        if reader:time.sleep(.1);done.set();reader.join()
        if server:server.close();sockpath.unlink()
        messages=[row.split('\n',1)[0].removeprefix('MESSAGE=') for row in rows]
        assert all(row.endswith('\nSYSLOG_IDENTIFIER=leon-asus-bsp\nPRIORITY=6') for row in rows)
        if case=='hidden-stdio':
            expected_rows=[]
            for name,target in stages:
                if not name.startswith('S'):continue
                if name=='S50ssl':expected_rows.append('ASUS_BSP_STAGE start S50ssl skipped=stock-absent-ssl')
                else:expected_rows.extend(['ASUS_BSP_STAGE start '+name+' begin','ASUS_BSP_STAGE start '+name+' rc=0'])
            assert messages==expected_rows,(messages,expected_rows)
        if case=='timeout-hidden-stdio':assert messages==['ASUS_BSP_STAGE start S25mount-fs begin','ASUS_BSP_STAGE start S25mount-fs rc=124'],messages
        (out/(case+'.json')).write_text(json.dumps({'messages':messages,'returncode':proc.returncode,'seconds':round(elapsed,3)},indent=2)+'\n')
        results.append({'case':case,'evidence':ref(out/(case+'.json')),'returncode':proc.returncode,'seconds':round(elapsed,3)})
    run('hidden-stdio',0)
    run('missing-socket-does-not-change-result',0,absent=True)
    run('socket-backpressure-does-not-block',0,receive=False)
    (rom/'init.d/mount-fs.sh').write_text('trap "" TERM\nsleep 20 &\nwait\n')
    run('timeout-hidden-stdio',124)
    record={'schema':1,'status':'changed_stage_journal_checks_passed','source':ref(source),'binary':ref(binary),'cases':results,
            'scope':'Synthetic script bodies only. Native journal packet format, null stdio visibility and nonblocking failure/backpressure checked; actual journald and BCM hardware not executed.',
            'unchanged_tests_repeated':False,'device_operated':False,'checker':ref(Path(__file__))}
    (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'status':record['status'],'cases':len(results),'manifest':ref(out/'manifest.json')}))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Materialize exact AI model rc/header inputs without using the Git index.

Network fetching, when requested, only requests explicit pinned Git blob IDs.
This is not a firmware build and does not invoke upstream make recipes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PIN = '9b25e55ca5c56a6f01d6a56264c0f6c47459ada0'
REPO = ROOT/'build/asus-rc-recovery/source'
HND = 'release/src-rt-5.04behnd.4916/'
WL = HND+'bcmdrivers/broadcom/net/wl/impl103/'


def git(*args, **kwargs):
    return subprocess.check_output(['git', '-C', str(REPO), *args], **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--paths-file', type=Path)
    args = parser.parse_args()
    rows = []
    requested = set(args.paths_file.read_text().splitlines()) if args.paths_file else None
    router_dirs = {'shared','networkmap','libdisk','libbcm','libletsencrypt','nt_center','libasc',
                   'bwdpi_source','cfg_mnt','json-c','libasuslog','libcodb','bcmcrypto','pse_lib',
                   'protect_srv','amas-utils','ateed','libwebapi','libovpn','sw-hw-auth','sqlCipher',
                   'sqlite','smspdu','uploader','httpd','asusdiscovery','util-linux','iproute2',
                   'iproute2-3.x','libcurl','openssl','openssl-3.5','openssl-3.0','cJSON'}
    for line in git('ls-tree','-r',PIN,text=True).splitlines():
        meta, path = line.split('\t'); mode, kind, blob = meta.split()
        if kind != 'blob': continue
        selected = requested is not None and path in requested
        if requested is None:
            if path.startswith('release/src/router/'):
                tail = path.removeprefix('release/src/router/')
                part = tail.split('/')[0]
                selected = (part == 'rc' and ('/prebuild/' not in path or '/GT-BE19000AI/' in path))
                selected |= part == 'libovpn'
                selected |= part in router_dirs and path.endswith(('.h','.inc'))
            if path.startswith(WL):
                selected |= path.endswith(('.h','.inc'))
                selected |= '/makefiles/' in path and path.endswith('.mk')
            if path.startswith(HND):
                selected |= any(path.startswith(HND+x) for x in ['userspace/public/include/','userspace/private/include/',
                         'shared/opensource/include/','bcmdrivers/opensource/include/', 'bcmdrivers/broadcom/include/'])
                selected |= '/router-sysdep.gt-be19000ai/' in path and path.endswith('.h')
                selected |= path == HND+'kernel/linux-4.19/Makefile'
            selected |= path in ['release/src/router/common.mak',HND+'sdk_profile.mak',
                                  HND+'targets/96813GW/96813GW.GT-BE19000AI']
        if selected:
            rows.append({'path':path,'mode':mode,'git_blob':blob})
    have = set(git('cat-file','--batch-all-objects','--batch-check=%(objectname)',text=True).splitlines())
    missing = sorted({x['git_blob'] for x in rows} - have)
    print(f'Selected {len(rows)} files; missing {len(missing)} blobs', flush=True)
    if missing and not args.fetch:
        raise SystemExit('Use --fetch to retrieve these exact public blobs')
    for i in range(0, len(missing), 96):
        subprocess.run(['git','-C',str(REPO),'-c','fetch.negotiationAlgorithm=noop',
            'fetch','origin','--no-tags','--no-write-fetch-head','--recurse-submodules=no',
            '--filter=blob:none','--stdin'], input='\n'.join(missing[i:i+96])+'\n', text=True, check=True)
        print(f'Fetched {min(i+96,len(missing))}/{len(missing)}',flush=True)
    for row in rows:
        raw = git('cat-file','blob',row['git_blob'])
        actual = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if actual != row['git_blob']: raise SystemExit('Blob hash mismatch')
        row['sha256'] = hashlib.sha256(raw).hexdigest()
        row['size'] = len(raw)
        dst = REPO/row['path']; dst.parent.mkdir(parents=True,exist_ok=True)
        if row['mode'] == '120000':
            target = raw.decode()
            row['symlink_target'] = target
            if dst.is_symlink() and os.readlink(dst) == target: continue
            if dst.exists(): raise SystemExit('Refusing non-symlink replacement: '+str(dst))
            dst.symlink_to(target)
        else:
            if dst.is_symlink(): raise SystemExit('Refusing write through symlink: '+str(dst))
            dst.write_bytes(raw)
            dst.chmod(0o755 if row['mode']=='100755' else 0o644)
    report = {'commit':PIN,'branch':'asuswrt6','version':'3006.102.9','files':rows,
              'not_a_complete_sdk':True,'model_object_source':'rc/prebuild/GT-BE19000AI'}
    name = 'recovered-inputs.json' if requested is None else 'extra-inputs-'+hashlib.sha256(args.paths_file.read_bytes()).hexdigest()[:12]+'.json'
    (ROOT/'build/asus-rc-recovery'/name).write_text(json.dumps(report,indent=2)+'\n')
    print('Verified and materialized',len(rows),'files',flush=True)


if __name__=='__main__': main()

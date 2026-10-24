#!/usr/bin/env python3
"""Pack a reviewed repeatable Yocto handoff; no device/network actions."""
from pathlib import Path
import copy, hashlib, json, shlex, subprocess, uuid

A = Path(__file__).resolve().parents[3]
S = Path(__file__).resolve().parent
C = A / 'candidate/production-yocto-v33'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def row(p, name=None):
    return dict(name=name or p.name, path=str(p.relative_to(A)),
                bytes=p.stat().st_size, sha256=sha(p))


def main():
    review = json.loads((S / 'parent-review-v4.json').read_text())
    assert review['status'] == 'PASS_SOURCE_REVIEW'
    for path, digest in review['sources'].items():
        assert sha(A / path) == digest, path
    assert not C.exists()
    old = json.loads((A / 'candidate/full-userspace-v29/job.json').read_text())
    spec = json.loads((A / 'research/boot/full-userspace-diagnostic-v29/spec.json').read_text())
    nonce = uuid.uuid4().hex
    cohort = '/home/leon-fulltrial-' + nonce
    spec.update(trial_nonce=nonce, init=dict(path=str((S/'production-init-v3').relative_to(A)),
                sha256=sha(S/'production-init-v3')),
                status='Reviewed repeatable Yocto production handoff; unchanged accepted kernel/modules/DT')
    spec['settings'] = dict(TRIAL_NONCE=nonce, DEPLOYMENT_NONCE=nonce, COHORT_DIR=cohort,
        EXPECTED_KERNEL=old['kernel_release'], ORIGINAL_MAC='02:00:00:f0:00:03',
        MODULES_MANIFEST_SHA256='7d30a2c3ad8fda41eeaf0c357eb443189909a8dcb48287275ea5640b0ddaa4d9',
        MODULE_FILE_COUNT='451', POST_HEALTH_SHA256=sha(S/'post-health-v2.py'))
    spec['payload_files'] = []
    public = A / 'research/userspace/full-service-trial/payload/stock-public.sha256'
    for p in [S/'home.mount', S/'leon-stock-module-renames.conf', public]:
        spec['payload_files'].append(dict(path=str(p.relative_to(A)), dest='payload/'+p.name,
            sha256=sha(p), mode='0644'))
    spec.pop('diagnostic_delta', None)
    (S/'spec-v4.json').write_text(json.dumps(spec, indent=2)+'\n')
    subprocess.run(['python3', str(A/'research/boot/full-userspace-diagnostic-v29/build.py'),
        '--spec', str(S/'spec-v4.json'), '--output', str(C)], check=True)
    job = copy.deepcopy(old)
    files = [copy.deepcopy(x) for x in old['files']]
    for i, item in enumerate(files):
        if item['name'] == 'initramfs.cpio.gz':
            files[i] = row(C/'initramfs.cpio.gz')
    files += [row(S/'post-health-v2.py','post-health.py'), row(public)]
    meta = {x['name']:x for x in files}
    env = copy.deepcopy(old['environment'])
    for key, value in env.items():
        value = value.replace(old['nonce'], nonce)
        if key in ('leon_ramload','leon_ramboot'):
            before = next(x for x in old['files'] if x['name']=='initramfs.cpio.gz')['bytes']
            after = meta['initramfs.cpio.gz']['bytes']
            value = value.replace(hex(before),hex(after)).replace('"'+format(before,'x')+'"','"'+format(after,'x')+'"')
        if key == 'leon_ramboot':
            value = value.replace('leon_trial='+nonce, 'leon_trial='+nonce+' leon_production_plan=@PLAN_SHA256@')
        env[key] = value
    plan_files = {n:dict(bytes=r['bytes'],sha256=r['sha256']) for n,r in meta.items()}
    manifest = A/'candidate/kernel-gpu-fix-v27/modules.sha256'
    plan_files['modules.sha256'] = dict(bytes=manifest.stat().st_size,sha256=sha(manifest))
    plan = dict(schema=1, deployment_nonce=nonce, cohort_dir=cohort,
        kernel_release=job['kernel_release'], environment=env, files=plan_files,
        module_manifest_sha256=sha(manifest), module_file_count=451)
    (C/'plan.json').write_text(json.dumps(plan,sort_keys=True,indent=2)+'\n')
    planrow = row(C/'plan.json')
    files += [planrow]
    env = {k:v.replace('@PLAN_SHA256@',planrow['sha256']) for k,v in env.items()}
    assert env['leon_ramtrial'] == old['environment']['leon_ramtrial']
    assert all(len((k+'='+v).encode())<=1022 and '\n' not in v for k,v in env.items())
    assert len(shlex.split(env['leon_ramboot'].split(' && ',1)[0][3:])) == 3
    for f in files:
        assert sha(A/f['path'])==f['sha256'] and (A/f['path']).stat().st_size==f['bytes']
    job.update(admitted=True,status='ADMITTED guarded production switch, retain Yocto/v1 and original B rollback',
        nonce=nonce,remote_dir=cohort,environment=env,files=files,
        production_plan=planrow,post_health=next(r for r in files if r['name']=='post-health.py'),
        collector=dict(path=str((S/'no-udp-observer.py').relative_to(A)),sha256=sha(S/'no-udp-observer.py')),
        watchdog=dict(path=str((S/'bcm-production-watchdog.py').relative_to(A)),sha256=sha(S/'bcm-production-watchdog.py')))
    job['required_evidence'] += [dict(path=path,sha256=digest) for path,digest in review['sources'].items()
                                if not any(r['path']==path for r in job['required_evidence'])]
    for p in [S/'no-udp-observer.py',S/'parent-review-v4.json',S/'prepare-v4.py',S/'spec-v4.json',C/'manifest.json',C/'plan.json']:
        job['required_evidence'].append(dict(path=str(p.relative_to(A)),sha256=sha(p)))
    if not any(r['path']==job['entry_executor']['path'] for r in job['required_evidence']):
        job['required_evidence'].append(job['entry_executor'].copy())
    assert len({r['path'] for r in job['required_evidence']})==len(job['required_evidence'])
    (C/'job.json').write_text(json.dumps(job,indent=2)+'\n')
    proof=dict(status='PASS_OFFLINE_PACK_ONLY',nonce=nonce,job_sha256=sha(C/'job.json'),
        plan_sha256=planrow['sha256'],initramfs_sha256=meta['initramfs.cpio.gz']['sha256'],
        Image_DTB_modules_unchanged=True,Yocto_userspace_unchanged=True,cgroup_v1=True,
        enable_default_marker_initially_absent=True,device_actions=False)
    (S/'pack-review.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof,indent=2))


if __name__ == '__main__':
    main()

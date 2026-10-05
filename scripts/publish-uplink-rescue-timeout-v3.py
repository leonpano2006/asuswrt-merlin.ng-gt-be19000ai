#!/usr/bin/env python3
"""Add four private rescue leaves on .51; preserve every v1 leaf.

The default is a local plan. Execution requires the exact plan digest and
completed timeout verification bindings. No tool, controller or trust
transaction runs during publication. Partial files are retained on failure.
"""
import argparse
import ast
import hashlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
DEST = '/tmp/leon-uplink-rescue-tools'
OUT = R / 'evidence/ubuntu26/host51-uplink-rescue-tools-live/add-timeout-v3'
OLD_RECEIPT = ('evidence/ubuntu26/host51-uplink-rescue-tools-live/publish-v1/result.json',
               '50b2487ca35370e21084ffad1bfea66e4741e3fa39db3a0d38d661ff2d83f5ef')
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py',
             'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
TIMEOUT_MANIFEST = ('build/asus-uplink-rescue/controller-timeout-v1/manifest.json',
                    '9231a823572804220a9556a99cd6c91c132e40dc2db69f6301e06d4c1e0efe89')
TIMEOUT_PROOF = ('build/asus-uplink-rescue/controller-timeout-v1/fixture-v1/result.json',
                 'c54869da3f5b845ea7db554d04e95ed5de411c46090b5b748a0978fec77bbaa8')
NEW_FILES = [
    ('build/asus-uplink-rescue/controller-timeout-v1/bin/timeout', 'eee267c8317aff3902f573c1e5f0052a723b2a3521cb2903377caea04ec8c7df', 'bin/timeout'),
    ('scripts/asus-integration/uplink-rescue/timeout-private-run.sh', 'f887d0cdd35e3b87429e6553ee86cc83e9018315f3eac644813859d56e8ae27c', 'timeout-run.sh'),
    ('scripts/asus-integration/uplink-rescue/controller-transient-v3.sh', '4878f47d6218281fc31e8b30af7a430f6c85b9d3d0e011bf3f08990d57c83f24', 'controller-v3.sh'),
    ('scripts/asus-integration/uplink-rescue/resume-public-known-host-v2.sh', '47fdb11b0c1f115998250d29ef1960b2e12fd3e448c2f96588128e404895d308', 'resume-public-known-host-v2.sh'),
]
BUSYBOX_SHA = '8c4bfc9f0eea3d3eccba647e9ca814ae1359b988743cad58914196ae2c74aabd'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def ref(name, expected):
    p = R / name
    require(p.is_file() and not p.is_symlink(), 'regular local input required: ' + name)
    raw = p.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected, 'pinned input changed: ' + name)
    return {'path': name, 'sha256': expected, 'bytes': len(raw)}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def prepare():
    require(__debug__, 'Python -O forbidden')
    old_ref = ref(*OLD_RECEIPT)
    old = json.loads((R / OLD_RECEIPT[0]).read_text())
    require(old['status'] == 'private_controller_tools_published' and old['published'] is True
            and old['returncode'] == 0 and len(old['files']) == 11, 'successful v1 publication required')
    ready = TIMEOUT_PROOF is not None and NEW_FILES is not None
    files = []
    proof = None
    timeout_source = ref(*TIMEOUT_MANIFEST)
    timeout = json.loads((R / TIMEOUT_MANIFEST[0]).read_text())
    require(timeout['status'] == 'official_signed_timeout_metadata_and_elf_authenticated_source_only_not_executed'
            and timeout['elf']['sha256'] == 'eee267c8317aff3902f573c1e5f0052a723b2a3521cb2903377caea04ec8c7df'
            and timeout['elf']['needed'] == ['libgcc_s.so.1', 'libc.so']
            and timeout['signer'] == '92C561DE55AE6552F3C736B82B0151090606D1D9', 'authenticated fixed timeout source required')
    if ready:
        proof = ref(*TIMEOUT_PROOF)
        tested = json.loads((R / TIMEOUT_PROOF[0]).read_text())
        require(tested['status'] == 'one_three_case_timeout_fixture_passed'
                and tested['fixture_invocations'] == 1 and len(tested['cases']) == 3
                and all(case['passed'] is True and case['outer_timeout'] is False for case in tested['cases'])
                and tested['network_used'] is False and tested['real_controller_or_keys_accessed'] is False,
                'one successful isolated timeout fixture required')
        for source, digest, target in NEW_FILES:
            require(target in ('bin/timeout', 'timeout-run.sh', 'controller-v3.sh',
                               'resume-public-known-host-v2.sh'), 'unexpected new leaf')
            files.append(dict(ref(source, digest), destination=target, mode=0o755))
        require(len(files) == 4 and len({f['destination'] for f in files}) == 4, 'exactly four new leaves required')
    return {'schema': 1, 'status': 'private_timeout_leaf_addition_plan',
            'source': ref(str(Path(__file__).relative_to(R)), hashlib.sha256(Path(__file__).read_bytes()).hexdigest()),
            'old_publication': old_ref, 'old_files': old['files'], 'transport': ref(*TRANSPORT),
            'timeout_source': timeout_source, 'timeout_proof': proof, 'new_files': files, 'ready_for_execution': ready,
            'destination': DEST, 'output': str(OUT.relative_to(R)),
            'auxiliary_private_script': DEST+'/.timeout-add-v3.sh', 'auxiliary_script_mode':'0600',
            'ssh_exec_request_limit_bytes':4096,
            'network_changed': False, 'trust_changed': False, 'existing_files_replaced': 0}


def execute(plan, gate):
    require(plan['ready_for_execution'], 'completed timeout proof/source bindings required')
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'exact reviewed plan digest required')
    # Only four regular leaves; no directory records can change old modes.
    bundle = io.BytesIO()
    with tarfile.open(fileobj=bundle, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for row in plan['new_files']:
            raw = (R / row['path']).read_bytes()
            require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'], 'new input changed')
            entry = tarfile.TarInfo(row['destination'])
            entry.mode = 0o755; entry.uid = entry.gid = 0; entry.mtime = 0; entry.size = len(raw)
            tar.addfile(entry, io.BytesIO(raw))
    raw = bundle.getvalue()
    require(len(raw) <= 1024 * 1024, 'new private bundle too large')
    digest = hashlib.sha256(raw).hexdigest()
    node = next(n for n in ast.parse((R / TRANSPORT[0]).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == 'transport')
    env = {'__builtins__': {}, 'shlex': shlex}
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'frozen-transport-only', 'exec'), env)
    commands = ['set -eu', 'set -o pipefail', 'umask 077', 'export LC_ALL=C', 'BB=/bin/busybox',
                'test "$($BB id -u)" = 0', 'test "$($BB uname -m)" = armv7l',
                'test "$($BB cat /sys/class/net/br-lan/address)" = 02:00:00:f0:00:02',
                "hash() { \"$BB\" sha256sum \"$1\" | \"$BB\" awk 'NR==1&&$1~/^[0-9a-f]+$/&&length($1)==64{h=$1} END{if(NR!=1||h==\"\")exit 1;print h}'; }",
                'test "$(hash /bin/busybox)" = ' + BUSYBOX_SHA]
    for suffix, inode, mode in (('', 170477, 'drwx------'), ('/bin', 170479, 'drwxr-xr-x'), ('/lib', 170480, 'drwxr-xr-x')):
        path = DEST + suffix
        expr = 'NR==1{ok=(NF==10&&$1=='+str(inode)+'&&$2=="'+mode+'"&&$3>0&&$4==0&&$5==0&&$10=="'+path+'")}END{exit(NR!=1||!ok)}'
        commands += ['test -d '+path, 'test ! -L '+path, '$BB ls -ldni '+path+' | $BB awk '+shlex.quote(expr)]
    def checks(row):
        path = DEST + '/' + row['destination']
        mode = '-rwxr-xr-x' if row['mode'] == 0o755 else '-rw-r--r--'
        expr = 'NR==1{ok=(NF==10&&$1~/^[0-9]+$/&&$2=="'+mode+'"&&$3==1&&$4==0&&$5==0&&$6=='+str(row['bytes'])+'&&$10=="'+path+'")}END{exit(NR!=1||!ok)}'
        return ['test -f '+path, 'test ! -L '+path,
                '$BB ls -ldni '+path+' | $BB awk '+shlex.quote(expr),
                'test "$(hash '+path+')" = '+row['sha256']]
    for row in plan['old_files']:
        commands += checks(row)
    for row in plan['new_files']:
        path = DEST + '/' + row['destination']
        commands += ['test ! -e '+path, 'test ! -L '+path]
    archive = DEST + '/.timeout-add-v3.tar'
    commands += ['test ! -e '+archive, 'test ! -L '+archive, 'set -C', '$BB cat > '+archive, 'set +C',
                 'test "$(hash '+archive+')" = '+digest,
                 '$BB tar -xf '+archive+' -C '+DEST]
    for row in plan['new_files']:
        commands += ['$BB chmod 755 '+DEST+'/'+row['destination']] + checks(row)
    for row in plan['old_files']:
        commands += checks(row)
    commands += ['printf \'{"status":"private_timeout_leaves_added","new_files":4,"old_files_preserved":11,"network_changed":false,"trust_changed":false}\\n\'']
    # Keep SSH exec requests short. Transfer the reviewed shell script into
    # one new private leaf, then run that file with only the archive on stdin.
    # v2 failed SSH before any remote leaf; its read-only stdin preflight passed.
    script_raw = ('\n'.join(commands)+'\n').encode()
    script_sha = hashlib.sha256(script_raw).hexdigest()
    script_path = DEST + '/.timeout-add-v3.sh'
    upload = ['set -eu', 'umask 077', 'BB=/bin/busybox', 'test "$($BB id -u)" = 0',
              'test ! -L '+DEST, 'test -d '+DEST,
              '$BB ls -ldni '+DEST+' | $BB awk '+shlex.quote(
                  'NR==1{ok=(NF==10&&$1==170477&&$2=="drwx------"&&$4==0&&$5==0&&$10=="'+DEST+'")}END{exit(NR!=1||!ok)}'),
              'test ! -e '+script_path, 'test ! -L '+script_path, 'set -C',
              '$BB cat > '+script_path, 'set +C',
              '$BB ls -ldni '+script_path+' | $BB awk '+shlex.quote(
                  'NR==1{ok=(NF==10&&$1~/^[0-9]+$/&&$2=="-rw-------"&&$3==1&&$4==0&&$5==0&&$6=='+str(len(script_raw))+'&&$10=="'+script_path+'")}END{exit(NR!=1||!ok)}'),
              'set -- $($BB sha256sum '+script_path+')', 'test "$1" = '+script_sha]
    upload_argv = env['transport']('true')
    upload_argv[-1] = '\n'.join(upload)
    argv = env['transport']('true')
    argv[-1] = 'set -eu; test ! -L '+script_path+'; set -- $(/bin/busybox sha256sum '+script_path+'); test "$1" = '+script_sha+'; exec /bin/busybox ash '+script_path
    require(len(upload_argv[-1].encode()) <= 4096 and len(argv[-1].encode()) <= 4096,
            'short SSH exec requests required')
    OUT.mkdir(parents=True, exist_ok=False)
    result = dict(plan, approved_plan_sha256=gate, bundle_sha256=digest, bundle_bytes=len(raw),
                  status='private_timeout_addition_started_outcome_unknown')
    try:
        result.update(private_script_path=script_path, private_script_sha256=script_sha,
                      private_script_bytes=len(script_raw), ssh_exec_max_bytes=max(len(upload_argv[-1].encode()),len(argv[-1].encode())))
        sent = subprocess.run(upload_argv, input=script_raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35)
        (OUT/'script-upload.stdout').write_bytes(sent.stdout); (OUT/'script-upload.stderr').write_bytes(sent.stderr)
        result['script_upload_returncode'] = sent.returncode
        require(sent.returncode == 0, 'private script transfer failed; retain any leaf, no retry')
        run = subprocess.run(argv, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        (OUT/'stdout').write_bytes(run.stdout); (OUT/'stderr').write_bytes(run.stderr)
        result['returncode'] = run.returncode
        require(run.returncode == 0, 'private addition failed; retain partial files, no retry')
        reply = json.loads(run.stdout)
        require(reply == {'status':'private_timeout_leaves_added','new_files':4,'old_files_preserved':11,
                          'network_changed':False,'trust_changed':False}, 'exact addition receipt required')
        result.update(reply)
    except subprocess.TimeoutExpired as exc:
        (OUT/'stdout').write_bytes(exc.stdout or b''); (OUT/'stderr').write_bytes(exc.stderr or b'')
        result.update(status='private_timeout_addition_timeout_retained_no_retry'); raise
    except Exception as exc:
        result.update(status='private_timeout_addition_failed_retained_no_retry', error=str(exc)); raise
    finally:
        (OUT/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps({'status':result['status'],'output':str(OUT.relative_to(R))}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args(); plan = prepare()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256':hashlib.sha256(canonical(plan)).hexdigest(),'plan':plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()

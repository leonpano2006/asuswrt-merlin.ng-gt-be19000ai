#!/usr/bin/env python3
"""Source candidate: private tools on .51, with no network or trust changes.

Default only reads local inputs. Publication needs the exact reviewed plan;
pending helper/enrollment bindings make this version non-executable.
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
TOOLS = ('build/asus-uplink-rescue/controller-tools-v1/manifest.json',
         '86b33a71845343a03313975a0be137e3471c692f513c53b9745d3f9171b245d7')
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py',
             'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
WRAPPER = ('scripts/asus-integration/uplink-rescue/ip-full-private-run.sh',
           '53b21a39f5de6393725ca63a38378b4e772faa1f8ef378087ef470a36be337e1')
CONTROLLER = ('scripts/asus-integration/uplink-rescue/controller-transient-v2.sh',
              'a65f19252c33a7f9e9118ffeab85c6b15ba7c0527e383918c1f0689942fa9bc1')
HELPER_MANIFEST = ('build/asus-uplink-rescue/controller-fsync-v1/manifest.json',
                   '30d920be146054b8af80b8c16e11a7359253f14c99a8ff0493308d07e4a472f7')
ENROLLMENT = ('scripts/asus-integration/uplink-rescue/enroll-public-known-host-v1.sh',
              '066e26c7673db16fac17f7a628a8584c791aaaf6105ecc8936aadfbb954b0ec4')
DEST = '/tmp/leon-uplink-rescue-tools'
OUT = R / 'evidence/ubuntu26/host51-uplink-rescue-tools-live/publish-v1'
BUSYBOX_SHA = '8c4bfc9f0eea3d3eccba647e9ca814ae1359b988743cad58914196ae2c74aabd'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def ref(name, expected=None):
    p = R / name
    require(p.is_file() and not p.is_symlink(), 'Regular input required: ' + name)
    raw = p.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    require(expected is None or expected == digest, 'Changed pinned input: ' + name)
    return {'path': name, 'sha256': digest, 'bytes': len(raw)}


def prepare():
    require(__debug__, 'Python -O forbidden')
    manifest_ref = ref(*TOOLS)
    data = json.loads((R / TOOLS[0]).read_text())
    require(data['status'] == 'official_signed_metadata_and_all_seven_elf_hashes_verified_static_closure_only'
            and len(data['artifacts']) == 7 and len(data['signed_indices']) == 2,
            'Frozen signed seven-ELF closure required')
    files = []
    base = Path('build/asus-uplink-rescue/controller-tools-v1')
    for artifact in data['artifacts']:
        row = artifact['elf']
        require(ref(row['path'], row['sha256']) == row, 'ELF size differs')
        dest = Path(row['path']).relative_to(base).as_posix()
        require(dest in ('bin/ip-full', 'lib/libbpf.so.1', 'lib/libelf.so.1', 'lib/libmnl.so.0',
                         'lib/libz.so.1', 'lib/libgcc_s.so.1', 'lib/libc.so'), 'Unexpected ELF destination')
        files.append(dict(row, destination=dest, mode=0o755 if dest in ('bin/ip-full', 'lib/libc.so') else 0o644))
    files += [dict(ref(*WRAPPER), destination='ip-run.sh', mode=0o755),
              dict(ref(*CONTROLLER), destination='controller.sh', mode=0o755)]
    ready = HELPER_MANIFEST[1] is not None and ENROLLMENT[1] is not None
    helper_ref = enrollment_ref = None
    if ready:
        helper_ref = ref(*HELPER_MANIFEST)
        helper = json.loads((R / HELPER_MANIFEST[0]).read_text())
        require(helper['status'] == 'one_armel_compile_and_one_focused_fsync_fixture_passed'
                and helper['compile_count'] == helper['fixture_run_count'] == 1
                and helper['compile_returncode'] == helper['fixture_returncode'] == 0
                and helper['static_armel_no_interp_no_needed_no_undefined'] is True
                and len(helper['fixture_cases']) == 9 and all(row['pass'] is True for row in helper['fixture_cases'])
                and helper['device_or_controller_accessed'] is False
                and helper['real_root_ssh_or_keys_accessed'] is False,
                'Completed static helper and isolated syscall fixture required')
        row = helper['helper']
        require(ref(row['path'], row['sha256']) == row, 'fsync ELF differs')
        enrollment_ref = ref(*ENROLLMENT)
        enrollment_raw = (R / ENROLLMENT[0]).read_text()
        require('__FIXED_HELPER' not in enrollment_raw and row['sha256'] in enrollment_raw,
                'Enrollment must bind completed fsync binary')
        files += [dict(row, destination='known-host-fsync', mode=0o755),
                  dict(enrollment_ref, destination='enroll-public-known-host.sh', mode=0o755)]
    transport_ref = ref(*TRANSPORT)
    nodes = [n for n in ast.parse((R / TRANSPORT[0]).read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    require(len(nodes) == 1 and not nodes[0].decorator_list, 'Only frozen transport function required')
    return {'schema': 1, 'status': 'private_controller_tools_publication_plan_only',
            'wrapper': ref(str(Path(__file__).relative_to(R))), 'signed_closure': manifest_ref,
            'transport': transport_ref, 'helper_manifest': helper_ref, 'enrollment_source': enrollment_ref,
            'files': files, 'destination': DEST, 'evidence_output': str(OUT.relative_to(R)),
            'ready_for_execution': ready, 'device_network_changed': False, 'public_trust_changed': False,
            'global_tool_or_library_replaced': False,
            'limits': ['Exclusive root0700 directory; retain incomplete publication on any failure; no automatic retry.',
                       'Only the signed tool files and reviewed scripts are extracted. No executable runs during publication.',
                       'This is a sequential private-file publication, not an atomic bundle or an exclusion of hostile root writers.',
                       'Neither controller setup nor known_hosts enrollment is invoked.']}


def execute(plan, gate):
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'Exact reviewed plan SHA required')
    require(plan['ready_for_execution'], 'Completed helper and enrollment source bindings required')
    # Build a bounded deterministic archive only after the execution gate.
    bundle = io.BytesIO()
    with tarfile.open(fileobj=bundle, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name in ('bin', 'lib'):
            entry = tarfile.TarInfo(name); entry.type = tarfile.DIRTYPE; entry.mode = 0o755
            entry.uid = entry.gid = 0; entry.mtime = 0; tar.addfile(entry)
        for row in plan['files']:
            raw = (R / row['path']).read_bytes()
            require(hashlib.sha256(raw).hexdigest() == row['sha256'] and len(raw) == row['bytes'], 'Changed archive input')
            entry = tarfile.TarInfo(row['destination']); entry.mode = row['mode']; entry.size = len(raw)
            entry.uid = entry.gid = 0; entry.mtime = 0; tar.addfile(entry, io.BytesIO(raw))
    raw = bundle.getvalue(); require(len(raw) <= 2 * 1024 * 1024, 'Private bundle limit exceeded')
    digest = hashlib.sha256(raw).hexdigest()
    require(len(plan['files']) == 11, 'Exactly eleven private regular leaves required')
    nodes = [n for n in ast.parse((R / TRANSPORT[0]).read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    env = {'__builtins__': {}, 'shlex': shlex}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), TRANSPORT[0]+':transport-only', 'exec'), env)
    command = ['set -eu', 'set -o pipefail', 'umask 077', 'export LC_ALL=C', 'BB=/bin/busybox',
               'test "$($BB id -u)" = 0', 'test "$($BB uname -m)" = armv7l',
               'test "$($BB cat /sys/class/net/br-lan/address)" = 02:00:00:f0:00:02',
               'set -- $($BB sha256sum /bin/busybox)', 'test "$1" = '+BUSYBOX_SHA,
               'test ! -e '+DEST, 'test ! -L '+DEST, '$BB mkdir -m 700 '+DEST,
               'set -C', '$BB cat > '+DEST+'/.bundle.tar', 'set +C',
               'set -- $($BB sha256sum '+DEST+'/.bundle.tar)', 'test "$1" = '+digest,
               '$BB tar -xf '+DEST+'/.bundle.tar -C '+DEST]
    for d in (DEST, DEST+'/bin', DEST+'/lib'):
        mode = '700' if d == DEST else '755'
        permissions = 'drwx------' if d == DEST else 'drwxr-xr-x'
        command += ['test -d '+d, 'test ! -L '+d, '$BB chmod '+mode+' '+d,
                    '$BB ls -ldni '+d+' | $BB awk '+shlex.quote(
                        'NR==1{ok=(NF==10&&$1~/^[0-9]+$/&&$2=="'+permissions+'"&&$3>0&&$4==0&&$5==0&&$10=="'+d+'")}END{exit(NR!=1||!ok)}')]
    for row in plan['files']:
        p = DEST+'/'+row['destination']
        permissions = '-rwxr-xr-x' if row['mode'] == 0o755 else '-rw-r--r--'
        command += ['test ! -L '+p, 'set -- $($BB sha256sum '+p+')', 'test "$1" = '+row['sha256'],
                    '$BB chmod '+format(row['mode'], 'o')+' '+p,
                    '$BB ls -ldni '+p+' | $BB awk '+shlex.quote(
                        'NR==1{ok=(NF==10&&$1~/^[0-9]+$/&&$2=="'+permissions+'"&&$3==1&&$4==0&&$5==0&&$6=='+str(row['bytes'])+'&&$10=="'+p+'")}END{exit(NR!=1||!ok)}')]
    command.append('printf \'{"schema":1,"status":"private_controller_tools_published","files":11,"network_changed":false,"known_hosts_changed":false}\\n\'')
    argv = env['transport']('true'); argv[-1] = 'exec /bin/busybox ash -c '+shlex.quote('\n'.join(command))
    OUT.mkdir(parents=True, exist_ok=False)
    result = dict(plan, approved_plan_sha256=gate, bundle_sha256=digest, bundle_bytes=len(raw),
                  status='private_publication_started_outcome_unknown')
    try:
        run = subprocess.run(argv, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        (OUT/'stdout').write_bytes(run.stdout); (OUT/'stderr').write_bytes(run.stderr)
        result['returncode'] = run.returncode
        require(run.returncode == 0, 'Private publication failed; retain partial directory, no retry')
        reply = json.loads(run.stdout)
        require(reply == {'schema':1,'status':'private_controller_tools_published','files':11,
                          'network_changed':False,'known_hosts_changed':False}, 'Exact publication receipt required')
        result.update(status=reply['status'], published=True)
    except subprocess.TimeoutExpired as exc:
        (OUT/'stdout').write_bytes(exc.stdout or b''); (OUT/'stderr').write_bytes(exc.stderr or b'')
        result.update(status='private_publication_timeout_retained_no_retry'); raise
    except Exception as exc:
        result.update(status='private_publication_failed_retained_no_retry', error=str(exc)); raise
    finally:
        (OUT/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps({'status': result['status'], 'evidence': str(OUT.relative_to(R))}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args(); plan = prepare()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256':hashlib.sha256(canonical(plan)).hexdigest(), 'plan':plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()

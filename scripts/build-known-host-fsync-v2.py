#!/usr/bin/env python3
"""Compile one frozen libc-free ARMEL helper and run one isolated new fixture."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-uplink-rescue/controller-fsync-v1'
SOURCE = R / 'scripts/asus-integration/uplink-rescue/known-host-fsync.c'
SOURCE_SHA = 'd6f452c4942a2ebd52652e03b1f80d544a3dcc27ed03b3f7d2205c6b10ad7b38'
BASE = R / 'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v6/compile-result.json'
BASE_SHA = '09f18e359e19fe4d78e2f47094dcd0fde073acbf2f4a84a2d12dc06259045493'
COMPILER_SHA = 'e365a6b1721565fe88f9d11a9d28b144d9c12b0279c82fece55ac5c660ab2c59'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
ENVIRONMENT_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
FIXTURE = R / 'scripts/asus-integration/uplink-rescue/known-host-fsync-fixture-v1.py'
QEMU = Path('/usr/bin/qemu-arm-static')
QEMU_SHA = '3997fb761bf0144da85837af5f2d590adc4140cf09eab8f97cd6f06f7b2294da'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': path.relative_to(R).as_posix() if path.is_relative_to(R) else str(path),
            'sha256': sha(path), 'bytes': path.stat().st_size}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    if OUT.exists():
        raise RuntimeError('Immutable helper output already exists')
    assert sha(SOURCE) == SOURCE_SHA and sha(ENVIRONMENT) == ENVIRONMENT_SHA and sha(QEMU) == QEMU_SHA and sha(BASE) == BASE_SHA
    old = json.loads(BASE.read_text())
    compiler, sysroot = Path(old['compiler']), Path(old['sysroot'])
    assert sha(compiler) == old['compiler_sha256'] == COMPILER_SHA
    assert sysroot == R / 'build/asus-rc-recovery/ubuntu-armel-sysroot'
    cache = BASE.parent / 'ccache.conf'
    assert sha(cache) == old['ccache']['configuration_sha256']
    prefix = old['ccache']['prefix']
    assert prefix == ['/tmp/be19000ai-asus-native-build-v2/lib/ld-linux-aarch64.so.1', '--library-path',
                      '/tmp/be19000ai-asus-native-build-v2/usr/lib/aarch64-linux-gnu',
                      '/tmp/be19000ai-asus-native-build-v2/usr/bin/ccache']
    flags = ['--sysroot=' + str(sysroot), '-isystem', str(sysroot / 'usr/include/arm-linux-gnueabi'),
             '-isystem', str(sysroot / 'usr/include'), '-mcpu=cortex-a9', '-marm', '-mfloat-abi=soft',
             '-nostdlib', '-static', '-no-pie', '-fno-pie', '-ffreestanding', '-fno-builtin',
             '-fno-stack-protector', '-fomit-frame-pointer', '-O2', '-Wall', '-Wextra', '-Werror',
             '-Wl,-e,_start,-z,noexecstack']
    OUT.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(SOURCE, OUT / 'known-host-fsync.c')
    shutil.copyfile(FIXTURE, OUT / 'fixture-invoked.py')
    assert sha(OUT / 'known-host-fsync.c') == SOURCE_SHA and sha(OUT / 'fixture-invoked.py') == sha(FIXTURE)
    command = [*prefix, str(compiler), *flags, '-MD', '-MF', str(OUT / 'dependencies.d'),
               str(OUT / 'known-host-fsync.c'), '-o', str(OUT / 'known-host-fsync')]
    env = dict(os.environ, LD_LIBRARY_PATH=str(compiler.parents[1] / 'lib/aarch64-linux-gnu'),
               CCACHE_CONFIGPATH=str(cache), CCACHE_DIR='/tmp/be19000ai-armel-ccache-v1', CCACHE_REMOTE_STORAGE='')
    record = {'schema': 1, 'status': 'started_one_compile_then_one_focused_fixture', 'source': ref(SOURCE),
              'builder': ref(Path(__file__)), 'fixture_source': ref(FIXTURE), 'compiler': ref(compiler),
              'frozen_v6_compile_receipt': ref(BASE), 'native_environment': ref(ENVIRONMENT),
              'compile_command': command, 'compile_count': 1, 'compiler_release_version_probes': False,
              'old_ABI_or_fixture_QEMU_suites_rerun': False, 'device_or_controller_accessed': False,
              'automatic_retry': False, 'fixture_run_count': 0}
    try:
        with (OUT / 'compile.log').open('wb') as log:
            result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        record['compile_returncode'] = result.returncode
        if result.returncode:
            raise RuntimeError('Sole compilation refused; no retry or fixture')
        for label, args in [('elf', ['readelf', '-h', '-l', '-d', '-A', str(OUT / 'known-host-fsync')]),
                            ('symbols', ['nm', '-a', str(OUT / 'known-host-fsync')]),
                            ('undefined-symbols', ['nm', '-u', str(OUT / 'known-host-fsync')])]:
            (OUT / (label + '.txt')).write_bytes(subprocess.check_output(args))
        elf = (OUT / 'elf.txt').read_text()
        assert 'ARM' in elf and 'INTERP' not in elf and 'NEEDED' not in elf and 'EXEC' in elf
        assert not (OUT / 'undefined-symbols.txt').read_bytes()
        assert ' _start' in (OUT / 'symbols.txt').read_text()
        deps = (OUT / 'dependencies.d').read_text().replace('\\\n', ' ').split(':', 1)[1]
        dependencies = []
        for name in shlex.split(deps):
            path = Path(name)
            assert path == OUT / 'known-host-fsync.c' or path.is_relative_to(sysroot) or path.is_relative_to(compiler.parents[2])
            dependencies.append(ref(path))
        record.update(helper=ref(OUT / 'known-host-fsync'), actual_dependencies=dependencies,
                      libc_and_link_helpers=False, static_armel_no_interp_no_needed_no_undefined=True)
        user = os.readlink('/proc/self/ns/user'); mount = os.readlink('/proc/self/ns/mnt')
        fixture_command = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=1s', '60s',
                           '/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--net', '--fork',
                           'python3', str(OUT / 'fixture-invoked.py'), str(OUT),
                           str(OUT / 'known-host-fsync'), str(QEMU), user, mount]
        record.update(fixture_command=fixture_command, fixture_run_count=1)
        with (OUT / 'fixture.log').open('wb') as log:
            result = subprocess.run(fixture_command, stdout=log, stderr=subprocess.STDOUT, timeout=65)
        record['fixture_returncode'] = result.returncode
        if result.returncode:
            raise RuntimeError('Focused fixture refused; evidence retained, no retry')
        fixture = json.loads((OUT / 'fixture-result.json').read_text())
        assert fixture['status'] == 'one_focused_fsync_fixture_passed' and fixture['case_count'] == 9
        assert all(row['pass'] is True for row in fixture['cases'])
        record.update(status='one_armel_compile_and_one_focused_fsync_fixture_passed',
                      fixture_result=ref(OUT / 'fixture-result.json'), fixture_cases=fixture['cases'],
                      qemu=ref(QEMU), elf=ref(OUT / 'elf.txt'), symbols=ref(OUT / 'symbols.txt'),
                      compile_log=ref(OUT / 'compile.log'), fixture_log=ref(OUT / 'fixture.log'),
                      real_root_ssh_or_keys_accessed=False,
                      limits=['Synthetic chroot under private user/mount/network namespaces only.',
                              'Successful host-kernel fsync syscall traces do not prove controller flash durability.',
                              'Caller still verifies parent ownership and file identity; wrong-kind case is CLI/path policy.'])
    except Exception as exc:
        record.update(status='failed_evidence_retained_no_retry', error=str(exc))
        raise
    finally:
        (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'helper': record['helper'],
                      'compile_count': 1, 'fixture_run_count': 1, 'pass': True}))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Generate a narrow, hash-pinned managed shutdown patch; never execute ASUS rc."""
import argparse
import difflib
import hashlib
import json
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[2]
BASE = R / 'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-v1/compile-source'
PIN = '9b25e55ca5c56a6f01d6a56264c0f6c47459ada0'
HASHES = {
    'init.c': '418ff357d32a39534be4488531cf8c27212dd7ca12dc979838623ad77d6b721d',
    'services.c': '8176fe9a44cb37dfb095d64eaf063535af34114e04029c5ad7b8fadd1b0badb2',
}

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    assert args.label and all(c.isalnum() or c in '-_' for c in args.label)
    out = R / 'build/asus-managed-stop' / args.label
    out.mkdir(parents=True, exist_ok=False)
    changed, diffs = {}, []
    for name, digest in HASHES.items():
        relative = Path('release/src/router/rc') / name
        source = BASE / relative
        assert sha(source) == digest, name
        old = source.read_text(errors='surrogateescape')
        if name == 'init.c':
            anchor = '''	if (leon_rc_shutdown_gate(rb != 0)) {
		perror("ASUS rc shutdown gate");
		_exit(1);
	}
#endif
	_dprintf("shutdn rb=%d\\n", rb);'''
            replacement = '''	if (leon_rc_shutdown_gate(rb != 0)) {
		perror("ASUS rc shutdown gate");
		_exit(1);
	}
	/* The main loop already drains ASUS-owned services. systemd owns
	 * host shutdown, native SSH, persistent mounts and flash policy.
	 * Keep the stock K-script order, but never enter the legacy board
	 * shutdown tail (raw erase, port power, global kill or reboot). */
	if (eval("/usr/libexec/asus/bsp-runner", "stop")) {
		fprintf(stderr, "ASUS managed BSP stop incomplete; see stage diagnostics\\n");
		_exit(125);
	}
	sync();
	_exit(0);
#endif
	_dprintf("shutdn rb=%d\\n", rb);'''
            assert old.count(anchor) == 1
            new = old.replace(anchor, replacement)
        else:
            start = old.index('void\nstop_services(void)') if 'void\nstop_services(void)' in old else old.index('void stop_services(void)')
            end = old.index('stop_services_mfg(void)', start)
            region = old[start:end]
            anchor = '#ifdef RTCONFIG_SSH\n\tstop_sshd();\n#endif'
            replacement = '''#if defined(RTCONFIG_SSH) && !defined(LEON_SYSTEMD_RC)
	/* Native OpenSSH is independent of an ASUS subtree stop. Explicit
	 * Web SSH configuration handlers still call stop_sshd normally. */
	stop_sshd();
#endif'''
            assert region.count(anchor) == 1
            new = old[:start] + region.replace(anchor, replacement) + old[end:]
            assert old.count('stop_sshd();') == new.count('stop_sshd();')
        changed[name] = (old, new)
        target = out / 'source' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        diffs.append('diff --git a/' + str(relative) + ' b/' + str(relative) + '\n')
        diffs.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        fromfile='a/' + str(relative), tofile='b/' + str(relative)))
    patch = R / 'patches/ubuntu26/asuswrt6/0017-asus-managed-stop-ownership.patch'
    patch.write_text(''.join(diffs), errors='surrogateescape')
    applied = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                             cwd=out / 'source', text=True, capture_output=True)
    assert applied.returncode == 0, applied.stdout + applied.stderr
    assert 'offset' not in applied.stdout and 'fuzz' not in applied.stdout
    files = []
    for name, (_, new) in changed.items():
        relative = Path('release/src/router/rc') / name
        target = out / 'source' / relative
        assert target.read_text(errors='surrogateescape') == new
        files.append({'path': str(relative), 'before_sha256': HASHES[name], 'after_sha256': sha(target)})

    # Compile only the exact managed branch with inert function doubles.
    init = changed['init.c'][1]
    a = init.index('#ifdef LEON_SYSTEMD_RC', init.index('static void shutdn(int rb)'))
    b = init.index('\n#endif', a) + len('\n#endif')
    branch = init[a:b]
    fixture = out / 'managed-stop-fixture.c'
    fixture.write_text('''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define LEON_SYSTEMD_RC 1
static int mode;
static int leon_rc_shutdown_gate(int rb) { dprintf(1,"gate:%d\\n",rb); return mode == 1; }
static int eval(const char *p,const char *a) { dprintf(1,"runner:%s:%s\\n",p,a); return mode == 2; }
static void fixture_sync(void) { dprintf(1,"sync\\n"); }
#define sync fixture_sync
static void shutdn(int rb) {
''' + branch + '''
dprintf(1,"FORBIDDEN_LEGACY_TAIL\\n"); _exit(99);
}
int main(int argc,char **argv) { if(argc!=3)return 2; mode=atoi(argv[1]); shutdn(atoi(argv[2])); return 98; }
''')
    binary = out / 'managed-stop-fixture'
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', str(fixture), '-o', str(binary)], check=True)
    cases = []
    for mode, rb, expected, lines in [
            (0, 0, 0, ['gate:0', 'runner:/usr/libexec/asus/bsp-runner:stop', 'sync']),
            (0, 1, 0, ['gate:1', 'runner:/usr/libexec/asus/bsp-runner:stop', 'sync']),
            (1, 0, 1, ['gate:0']),
            (2, 0, 125, ['gate:0', 'runner:/usr/libexec/asus/bsp-runner:stop'])]:
        run = subprocess.run([str(binary), str(mode), str(rb)], capture_output=True, text=True, timeout=3)
        assert run.returncode == expected and run.stdout.splitlines() == lines, run
        cases.append({'mode': mode, 'reboot_argument': rb, 'exit': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr})
    services = changed['services.c'][1]
    a = services.index('#if defined(RTCONFIG_SSH) && !defined(LEON_SYSTEMD_RC)')
    b = services.index('\n#endif', a) + len('\n#endif')
    ssh_guard = services[a:b] + '\n'
    ssh_tests = []
    for managed in [False, True]:
        command = ['cc', '-E', '-P', '-x', 'c', '-DRTCONFIG_SSH=1']
        if managed: command.append('-DLEON_SYSTEMD_RC=1')
        result = subprocess.run(command + ['-'], input=ssh_guard, text=True, capture_output=True, check=True)
        assert ('stop_sshd' in result.stdout) == (not managed)
        ssh_tests.append({'managed': managed, 'expanded': result.stdout.strip()})

    obj = R / 'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-v1/objects/ai_service.o'
    assert sha(obj) == 'cecd8d888f0cd91c8a5847588edbff4d4bb363408f508fa1b3e5e35bec3cf043'
    dump = subprocess.check_output(['aarch64-linux-gnu-objdump', '-dr', str(obj)], text=True)
    selected = []
    for name in ['stop_ai_service', 'stop_ai_response_check', 'stop_ai_request_consumer', 'stop_ai_tftpd', 'ai_sig_handler', 'start_ai_reboot']:
        anchor = '<' + name + '>:'
        start = dump.index(anchor)
        end = dump.find('\n\n', start)
        selected.append(dump[start:len(dump) if end < 0 else end])
    evidence = out / 'ai-stop-static.txt'
    evidence.write_text('\n\n'.join(selected) + '\n')
    report = {
        'status': 'source_patch_and_controlled_managed_branch_tests_pass', 'source_pin': PIN,
        'source_base': str(BASE.relative_to(R)), 'patch': {'path': str(patch.relative_to(R)), 'sha256': sha(patch)},
        'changes': files, 'apply': {'fuzz': 0, 'stdout': applied.stdout, 'stderr': applied.stderr},
        'managed_branch_tests': cases, 'general_stop_ssh_preprocessor_tests': ssh_tests,
        'main_init_loop_service_cleanup_unchanged': True,
        'legacy_tail_excluded_in_managed_build': ['check_action 30-second wait', 'set_action ACT_REBOOT',
          'knvram_recover_war', 'duplicate stop_wan', 'rtkswitch_LanPort_linkDown / rtkswitch 45',
          'aura RGB off', 'global kill(-1) TERM/KILL', 'setAllLedOff', 'config_jumbo_frame',
          'ed_thresh_clear', 'mtd_erase_misc2 from /jffs/remove_hidden_flag',
          'stop_bcm_boot_launcher NVRAM mutation', 'reboot/halt and infinite sleep'],
        'ai_stop_evidence': {'object': str(obj.relative_to(R)), 'object_sha256': sha(obj),
          'disassembly': str(evidence.relative_to(R)), 'disassembly_sha256': sha(evidence),
          'finding': 'stop_ai_service stops three local services; explicit start_ai_reboot alone invokes trigger_aisom. Background consumer behavior is outside this static claim.'},
        'fixture_scope': 'Only extracted managed branch and SSH compile-time guard with inert doubles; no real eval, sync, ASUS services or device commands.',
        'limitations': ['Full source rebuild/link and actual hardware shutdown not performed here.',
          'Normal ASUS cleanup remains as stock, including per-service stop helpers and K scripts; runner success alone does not prove hardware health.',
          'Fatal-signal callers already bypassed general stop_services in stock; cgroup cleanup is the final systemd bound.'],
        'actual_asus_services_executed': False, 'flash_allowed': False,
        'builder_sha256': sha(Path(__file__)), 'fixture_sha256': sha(fixture),
    }
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    (R / 'reports/ubuntu26/asus-managed-stop-ownership.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'patch': str(patch), 'sha256': sha(patch), 'test_cases': len(cases) + len(ssh_tests)}))

if __name__ == '__main__':
    main()

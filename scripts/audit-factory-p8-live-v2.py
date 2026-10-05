#!/usr/bin/env python3
"""One fixed read-only factory audit through the existing enrolled SSH key."""
import hashlib
import importlib.util
import json
import shlex
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000022'
ELF = R / 'build/factory-p8-audit/native-v2/auditor'
SHA = '5a009b2b53b64a0e064b8a6278dd60b89086721ebf4362f955adb5fff9c05853'
SOURCE = R / 'scripts/asus-integration/acceptance/factory-p8-audit-v2.c'
SOURCE_SHA = '544af79eb3b20e03940c5c061cbfcb9049a5c5bd4c1086074e96a5be07af062c'
OUT = R / 'evidence/ubuntu26/trial-live/tenth-factory-p8-audit-v2'


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    for path, digest in ((ELF, SHA), (SOURCE, SOURCE_SHA)):
        assert path.is_file() and not path.is_symlink()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    spec = importlib.util.spec_from_file_location('enrolled_transport', R / 'scripts/deploy-cfe-recovery-p11.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    OUT.mkdir(parents=True, exist_ok=False)
    remote = '/tmp/leon-factory-p8-audit-' + SHA[:16]
    guard = 'test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT)
    upload_command = 'set -eu; ' + guard + '; umask 077; test ! -e ' + shlex.quote(remote) + '; test ! -L ' + shlex.quote(remote) + '; set -C; cat > ' + shlex.quote(remote) + '; set +C; set -- $(sha256sum ' + shlex.quote(remote) + '); test "$1" = ' + shlex.quote(SHA) + '; chmod 700 ' + shlex.quote(remote)
    result = {'schema': 1, 'boot_id': BOOT, 'auditor_sha256': SHA, 'source_sha256': SOURCE_SHA,
              'device_audit_started': False, 'factory_contents_exported': False, 'filesystem_recovery': False,
              'reboot_or_slot_selection': False, 'git_commit_or_push': False}
    try:
        with ELF.open('rb') as stream:
            upload = subprocess.run(module.transport(upload_command), stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        (OUT / 'transfer.stdout').write_bytes(upload.stdout)
        (OUT / 'transfer.stderr').write_bytes(upload.stderr)
        result['transfer_returncode'] = upload.returncode
        if upload.returncode:
            raise RuntimeError('Fixed transfer refused; inspect evidence, do not repeat blindly')
        result['device_audit_started'] = True
        call = 'set -eu; ' + guard + '; exec ' + shlex.join([remote, '--audit-p8-readonly'])
        audit = subprocess.run(module.transport(call), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
        (OUT / 'audit.stdout').write_bytes(audit.stdout)
        (OUT / 'audit.stderr').write_bytes(audit.stderr)
        result['audit_returncode'] = audit.returncode
        if audit.returncode:
            raise RuntimeError('Fixed factory audit refused; inspect the saved stage before another action')
        proof = json.loads(audit.stdout)
        assert proof['auditor_version'] == 2
        assert proof['boot_id'] == BOOT and proof['leaf'] == '/wl/nvram.nvm'
        assert all(proof.get(key) is True for key in ('private_readonly_bind', 'no_fs_recovery', 'private_mount_released', 'token_structure', 'unique_enrolled_et0macaddr'))
        assert audit.stderr == b'LEON_FACTORY_COMPLETE stage=private-mount-released readonly_bind=true no_fs_recovery=true guest_exec=false\n'
        result['status'] = 'factory_leaf_and_unique_enrolled_mac_proved_readonly'
        result['proof'] = proof
    except subprocess.TimeoutExpired as exc:
        (OUT / 'timeout.stdout').write_bytes(exc.stdout or b'')
        (OUT / 'timeout.stderr').write_bytes(exc.stderr or b'')
        result['status'] = 'timeout_preserved_no_repeat'
        raise
    except Exception as exc:
        result['status'] = 'refused_preserved_no_repeat'
        result['error'] = str(exc)
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()

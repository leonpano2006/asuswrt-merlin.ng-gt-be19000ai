#!/usr/bin/env python3
"""Small, unprivileged tests of UUID selection; no mounts, devices or QEMU.

The real resolver reads file-backed superblocks and sysfs-shaped directories.
Block-device/layout validation remains a separate production gate afterwards.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / 'configs/ubuntu26/root-init-device-policy.json').read_text())


def main():
    with tempfile.TemporaryDirectory(prefix='root-uuid-test-') as temporary:
        work = Path(temporary)
        # Reuse the unchanged policy fields from the last built helper; append
        # only the new resolver policy, without rebuilding any firmware.
        header = ROOT / 'build/ubuntu26-root-init/device-guarded-kmsg-v5/ubuntu-root-policy.h'
        (work / 'ubuntu-root-policy.h').write_text(header.read_text() +
            '\n#define ROOT_UUID_LOOKUP 1\n#define ROOT_EMMC_CID ' + json.dumps(POLICY['emmc_cid']) + '\n')
        source = ROOT / 'scripts/asus-integration/ubuntu-root-init.c'
        (work / 'probe.c').write_text('#define main unused_root_init_main\n#include ' + json.dumps(str(source)) +
            '\n#undef main\nint main(int argc,char **argv) { if(argc!=3)return 64; '
            'if(resolve_root_uuid_at(argv[1],argv[2]))return 1; puts(root_device);return 0; }\n')
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-I', str(work), '-I', str(ROOT / 'scripts/asus-integration/trial-guard'),
                        str(work / 'probe.c'), '-o', str(work / 'probe')], check=True)
        results = []

        def case(name, devices, success):
            base = work / name
            sysfs, devdir = base / 'sys', base / 'dev'
            sysfs.mkdir(parents=True)
            devdir.mkdir()
            for index, entry in enumerate(devices):
                devname, fs_uuid, cid, symlink = entry
                disk = base / ('disk' + str(index))
                (disk / 'device').mkdir(parents=True)
                (disk / 'device/cid').write_text(cid + '\n')
                (disk / devname).mkdir()
                (disk / devname / 'partition').write_text('42\n')
                (sysfs / devname).symlink_to(disk / devname)
                data = bytearray(2048)
                data[1024 + 56:1024 + 58] = b'\x53\xef'
                data[1024 + 104:1024 + 120] = uuid.UUID(fs_uuid).bytes
                target = devdir / devname
                if symlink:
                    backing = base / ('backing' + str(index))
                    backing.write_bytes(data)
                    target.symlink_to(backing)
                else:
                    target.write_bytes(data)
            result = subprocess.run([str(work / 'probe'), str(sysfs), str(devdir)],
                                    capture_output=True, text=True, timeout=3)
            assert (result.returncode == 0) is success, (name, result.returncode, result.stderr)
            if success:
                assert result.stdout.strip() == str(devdir / 'mmcblk7p42'), name
            results.append({'case': name, 'passed': True})

        wanted, cid = POLICY['uuid'], POLICY['emmc_cid']
        correct = ('mmcblk7p42', wanted, cid, False)
        wrong_uuid = '00000000-0000-0000-0000-000000000001'
        case('renumbered_device', [correct], True)
        case('missing_uuid', [], False)
        case('wrong_uuid', [('mmcblk7p42', wrong_uuid, cid, False)], False)
        case('wrong_emmc', [('mmcblk7p42', wanted, '0' * len(cid), False)], False)
        case('duplicate_uuid', [correct, ('mmcblk7p43', wanted, cid, False)], False)
        case('symlink_device', [('mmcblk7p42', wanted, cid, True)], False)
        case('foreign_clone_ignored', [correct, ('sda1', wanted, '0' * len(cid), False)], True)
        print(json.dumps({'status': 'passed', 'cases': results,
                          'scope': 'UUID selection only; existing hardware/layout gate unchanged',
                          'device_accessed': False, 'firmware_built': False}, indent=2))


if __name__ == '__main__':
    main()

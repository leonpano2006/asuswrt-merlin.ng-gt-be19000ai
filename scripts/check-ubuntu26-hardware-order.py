#!/usr/bin/env python3
"""Check alias blacklisting without loading anything; package the exact policy."""
import argparse, hashlib, io, json, os, re, shutil, subprocess, tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'configs/ubuntu26/asus-hardware-order/90-leon-asus-hardware-order.conf'
EXPECTED_SHA = '27d8aec699f3e8c44288d1a02b3a02e2e8f05a324496413ae76ebde8d46705b4'
NAMES = {'bcm_bca_usb', 'bcm_pcie_hcd', 'bcmflex', 'bcmspu', 'dhd',
         'hs_uart_drv', 'rdpa_cmd', 'rdpa_gpl'}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--reuse-alias-manifest', type=Path)
    args = parser.parse_args()
    assert re.fullmatch('[a-z0-9-]+', args.label)
    assert sha(POLICY) == EXPECTED_SHA
    rules = [line.split() for line in POLICY.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    assert len(rules) == 8 and all(len(r) == 2 and r[0] == 'blacklist' for r in rules)
    assert {r[1] for r in rules} == NAMES
    out = ROOT / 'build/ubuntu26-hardware-order' / args.label
    out.mkdir(parents=True, exist_ok=False)
    modules = ROOT / 'build/kernel10-module-root/lib/modules/4.19.294'
    vendor = {p.stem.replace('-', '_') for p in (modules / 'extra').glob('*.ko')}
    aliases = []
    for line in (modules / 'modules.alias').read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == 'alias' and fields[2] in vendor:
            aliases.append((fields[1], fields[2]))
    assert {name for _, name in aliases} == NAMES
    lookup = out / 'lookup-root'
    (lookup / 'lib/modules').mkdir(parents=True)
    (lookup / 'lib/modules/4.19.294').symlink_to(modules.resolve())
    empty = out / 'empty.conf'
    empty.write_text('# No module policy for baseline lookup.\n')

    def probe(config, selector, blacklist):
        command = ['modprobe', '--dirname', str(lookup), '--set-version', '4.19.294',
                   '--config', str(config), '--dry-run', '--show-depends']
        if blacklist:
            command.append('--use-blacklist')
        result = subprocess.run(command + ['--', selector], capture_output=True, timeout=10)
        assert result.returncode == 0, (selector, result.stderr.decode())
        assert not result.stderr, (selector, result.stderr)
        return result.stdout.decode().splitlines()

    if args.reuse_alias_manifest:
        prior = json.loads(args.reuse_alias_manifest.read_text())
        assert prior['status'] == 'all_vendor_aliases_blocked_no_load'
        assert prior['payload']['sha256'] == sha(POLICY)
        assert prior['module_alias_sha256'] == sha(modules / 'modules.alias')
        assert prior['module_dep_sha256'] == sha(modules / 'modules.dep')
        checks, explicit, generic = (prior[k] for k in
                                    ['alias_checks', 'explicit_name_lookup', 'generic_lookup_unchanged'])
        assert [(r['alias_pattern'], r['module']) for r in checks] == aliases
        assert all(r['baseline'] and not r['with_policy'] for r in checks)
        assert set(explicit) == NAMES and set(generic) == {'overlay', 'peak_usb', 'zram'}
    else:
        checks = []
        for pattern, name in aliases:
            # A concrete lookup matching this exact alias; no device enumeration.
            selector = pattern.replace('*', '0')
            baseline = probe(empty, selector, True)
            blocked = probe(POLICY, selector, True)
            assert any('/' + name + '.ko' in line for line in baseline), (pattern, baseline)
            assert not blocked, (pattern, blocked)
            checks.append({'alias_pattern': pattern, 'selector': selector, 'module': name,
                           'baseline': baseline, 'with_policy': blocked})
        explicit = {name: probe(POLICY, name, False) for name in sorted(NAMES)}
        assert all(any('/' + name + '.ko' in line for line in rows)
                   for name, rows in explicit.items())
        generic = {}
        for name in ['overlay', 'peak_usb', 'zram']:
            before, after = probe(empty, name, True), probe(POLICY, name, True)
            assert before == after and before
            generic[name] = after

    stage = out / 'package-root'
    control = stage / 'DEBIAN'
    control.mkdir(parents=True)
    target = stage / 'etc/modprobe.d' / POLICY.name
    target.parent.mkdir(parents=True)
    shutil.copyfile(POLICY, target)
    target.chmod(0o644)
    alias = stage / 'usr/share/asus/commands/sbin/insmod'
    alias.parent.mkdir(parents=True)
    alias.symlink_to('/usr/libexec/asus/busybox')
    (control / 'control').write_text('''Package: leon-asus-hardware-order
Version: 0.1+asus3006.102.9
Architecture: all
Section: admin
Priority: optional
Maintainer: BE19000AI local integration <local@invalid>
Depends: kmod, leon-bcm-kernel-modules (= 4.19.294-10+leonb53.1), leon-asus-shell (= 0.2+asus3006.102.9), leon-asus-command-map (= 0.3)
Description: Preserve ASUS ordered initialization of BCM hardware modules
 Suppress automatic vendor modalias loading by udev. In the ASUS private
 namespace, use its packaged BusyBox insmod to preserve name lookup and
 parameters. Ubuntu's global kmod remains unchanged. Installation does not load modules,
 restart services, select a firmware slot or reboot the machine.
''')
    (control / 'conffiles').write_text('/etc/modprobe.d/' + POLICY.name + '\n')
    (control / 'md5sums').write_text(hashlib.md5(target.read_bytes()).hexdigest()
                                  + '  etc/modprobe.d/' + POLICY.name + '\n')
    for path in [stage, *stage.rglob('*')]:
        if path.is_symlink():
            os.utime(path, (1791158400, 1791158400), follow_symlinks=False)
            continue
        path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (1791158400, 1791158400))
    package = out / 'leon-asus-hardware-order_0.1+asus3006.102.9_all.deb'
    subprocess.run(['dpkg-deb', '--root-owner-group', '-Zzstd', '-z6', '--build',
                    str(stage), str(package)], check=True, stdout=subprocess.DEVNULL,
                   env={**os.environ, 'SOURCE_DATE_EPOCH': '1791158400'})
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(
            ['dpkg-deb', '--ctrl-tarfile', str(package)]))) as archive:
        members = {m.name.removeprefix('./') for m in archive}
        assert members <= {'', '.', 'control', 'conffiles', 'md5sums'}
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(
            ['dpkg-deb', '--fsys-tarfile', str(package)]))) as archive:
        files = [m for m in archive if m.isfile()]
        assert len(files) == 1 and files[0].name.removeprefix('./') == 'etc/modprobe.d/' + POLICY.name
        assert files[0].uid == files[0].gid == 0 and files[0].mode == 0o644
        assert archive.extractfile(files[0]).read() == POLICY.read_bytes()
        links = [m for m in archive if m.issym()]
        assert len(links) == 1 and links[0].name.removeprefix('./') == 'usr/share/asus/commands/sbin/insmod'
        assert links[0].uid == links[0].gid == 0 and links[0].linkname == '/usr/libexec/asus/busybox'
    report = {'schema': 1, 'status': 'all_vendor_aliases_blocked_no_load',
              'payload': {'path': str(POLICY.relative_to(ROOT)), 'sha256': sha(POLICY)},
              'module_alias_sha256': sha(modules / 'modules.alias'),
              'module_dep_sha256': sha(modules / 'modules.dep'),
              'alias_checks': checks, 'explicit_name_lookup': explicit,
              'generic_lookup_unchanged': generic,
              'alias_evidence_reused': ({'path': str(args.reuse_alias_manifest),
                                         'sha256': sha(args.reuse_alias_manifest)}
                                        if args.reuse_alias_manifest else None),
              'private_insmod': {'path': '/usr/share/asus/commands/sbin/insmod',
                                'target': '/usr/libexec/asus/busybox',
                                'target_sha256': '686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6',
                                'global_insmod_changed': False},
              'package': {'path': str(package.relative_to(ROOT)), 'sha256': sha(package)},
              'maintainer_scripts': False, 'modules_loaded': False,
              'router_accessed': False, 'physical_boot_proven': False,
              'builder_sha256': sha(Path(__file__)),
              'limits': ['Dry-run lookup proves blacklist coverage, not hardware initialization.',
                         'Explicit lookups remain possible; ASUS must still use its own ordered loader.',
                         'The two-path device diagnostic overlay is separate from installing this deb.']}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': str(out / 'manifest.json'),
                      'alias_checks': len(checks), 'module_roots': len(NAMES),
                      'package_sha256': sha(package)}))

if __name__ == '__main__':
    main()

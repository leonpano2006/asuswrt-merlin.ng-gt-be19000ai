#!/usr/bin/env python3
"""Exercise owned-symlink installation/removal without invoking host systemd."""
import json
import os
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

here = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--scripts', type=Path, default=here / 'root/DEBIAN')
parser.add_argument('--busybox', type=Path)
args = parser.parse_args()
scripts = args.scripts.resolve()
target = '/usr/libexec/leon-ai-docker/29.9.1/bin/'
checks = []
commands = ('sh', 'cat', 'chmod', 'ln', 'mkdir', 'readlink', 'rm', 'rmdir')
command_environment = dict(os.environ)
command_directory = None
if args.busybox:
    command_directory = tempfile.TemporaryDirectory(prefix='busybox-commands-', dir=here)
    for command in commands:
        (Path(command_directory.name) / command).symlink_to(args.busybox.resolve())
    command_environment['PATH'] = command_directory.name
command_paths = {command: shutil.which(command, path=command_environment.get('PATH')) for command in commands}
assert all(command_paths.values()), command_paths
assert not any('install -d' in (scripts / name).read_text() for name in ('preinst', 'postinst', 'prerm', 'postrm'))

def run(root, script, arg, expected=0):
    assert root.is_absolute() and root != Path('/') and root.is_dir()
    proc = subprocess.run(['sh', str(scripts / script), arg], env={**command_environment, 'DPKG_ROOT': str(root)}, capture_output=True, text=True)
    assert proc.returncode == expected, (script, arg, proc.returncode, proc.stderr)

with tempfile.TemporaryDirectory(prefix='maintscript-check-', dir=here) as tmp:
    root = Path(tmp)
    run(root, 'preinst', 'install')
    run(root, 'postinst', 'configure')
    for name in ('docker', 'ctr'):
        assert os.readlink(root / 'usr/local/bin' / name) == target + name
        assert (root / 'var/lib/leon-ai-docker' / (name + '.link')).read_text().strip() == target + name
    run(root, 'postinst', 'configure')
    run(root, 'prerm', 'upgrade')
    assert (root / 'usr/local/bin/docker').is_symlink()
    run(root, 'prerm', 'remove')
    run(root, 'postrm', 'remove')
    assert not (root / 'usr/local/bin/docker').is_symlink()
    assert not (root / 'usr/local/bin/ctr').is_symlink()
    checks.append('new links tracked, configure idempotent, upgrade preserves links, remove cleans owned links')

with tempfile.TemporaryDirectory(prefix='maintscript-check-', dir=here) as tmp:
    root = Path(tmp)
    (root / 'usr/local/bin').mkdir(parents=True)
    existing = root / 'usr/local/bin/docker'
    existing.write_text('owned by someone else\n')
    run(root, 'preinst', 'install', 1)
    assert existing.read_text() == 'owned by someone else\n'
    existing.unlink()
    existing.symlink_to('/nonexistent/other-docker')
    run(root, 'preinst', 'install', 1)
    assert os.readlink(existing) == '/nonexistent/other-docker'
    checks.append('existing file and foreign dangling symlink rejected without modification')

with tempfile.TemporaryDirectory(prefix='maintscript-check-', dir=here) as tmp:
    root = Path(tmp)
    (root / 'usr/local/bin').mkdir(parents=True)
    existing = root / 'usr/local/bin/docker'
    existing.symlink_to(target + 'docker')
    run(root, 'preinst', 'install')
    run(root, 'postinst', 'configure')
    assert not (root / 'var/lib/leon-ai-docker/docker.link').exists()
    run(root, 'prerm', 'remove')
    run(root, 'postrm', 'purge')
    assert os.readlink(existing) == target + 'docker'
    checks.append('pre-existing exact symlink preserved because package did not create it')

with tempfile.TemporaryDirectory(prefix='maintscript-check-', dir=here) as tmp:
    root = Path(tmp)
    run(root, 'postinst', 'configure')
    changed = root / 'usr/local/bin/docker'
    changed.unlink()
    changed.write_text('later administrator replacement\n')
    run(root, 'prerm', 'remove')
    run(root, 'postrm', 'purge')
    assert changed.read_text() == 'later administrator replacement\n'
    checks.append('later administrator replacement preserved on removal')

result = {'passed': True, 'checks': checks, 'systemctl_invoked': False, 'command_paths': command_paths,
          'busybox_only': bool(args.busybox), 'scripts': str(scripts)}
(here / 'maintainer-script-validation.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
if command_directory:
    command_directory.cleanup()

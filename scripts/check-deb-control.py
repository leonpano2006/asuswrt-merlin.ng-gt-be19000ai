#!/usr/bin/env python3
"""Read-only inspection of .deb control archives; never run maintainer scripts.

Checks control/triggers/md5sums syntax, script headers and shell parsing, and
diagnostic contamination. This is not an installation or semantic script audit.
Each report run preserves hashes and appends to the local audit history.
"""
import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = {'preinst', 'postinst', 'prerm', 'postrm', 'config'}
TRIGGER_DIRECTIVES = {'interest', 'interest-await', 'interest-noawait',
                      'activate', 'activate-await', 'activate-noawait'}
KNOWN_MEMBERS = SCRIPTS | {'control', 'triggers', 'conffiles', 'md5sums',
                          'shlibs', 'symbols', 'templates'}
DIAGNOSTIC = re.compile(r'^\s*(?:find:\s|dpkg(?:-[\w-]+)?:\s(?:error|warning)|'
                        r'(?:/bin/)?(?:ba)?sh:\s|make(?:\[\d+\])?:\s\*\*\*|'
                        r'E:\s(?:Unable|Internal|Could not)|Traceback \(most recent call last\):)')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def audit_package(path, family, expected_version=None):
    record = {'path': str(path.relative_to(ROOT)), 'family': family,
              'sha256': sha256(path.read_bytes()), 'members': [], 'issues': []}

    def issue(member, kind, detail, line=None):
        entry = {'member': member, 'kind': kind, 'detail': detail}
        if line is not None:
            entry['line'] = line
        record['issues'].append(entry)

    process = subprocess.run(['dpkg-deb', '--ctrl-tarfile', str(path)], capture_output=True)
    if process.returncode:
        issue(None, 'control_archive_read_error', process.stderr.decode(errors='replace'))
        return record
    record['control_archive_sha256'] = sha256(process.stdout)
    with tarfile.open(fileobj=io.BytesIO(process.stdout)) as archive:
        seen = set()
        for member in archive:
            name = member.name.removeprefix('./')
            if member.isdir():
                continue
            pure = PurePosixPath(name)
            if pure.is_absolute() or '..' in pure.parts or len(pure.parts) != 1:
                issue(name, 'unsafe_control_member_path', member.name)
            if name in seen:
                issue(name, 'duplicate_control_member', name)
            seen.add(name)
            if not member.isfile():
                issue(name, 'unexpected_control_member_type', repr(member.type))
                continue
            data = archive.extractfile(member).read()
            info = {'name': name, 'sha256': sha256(data), 'bytes': len(data),
                    'mode': oct(member.mode), 'uid': member.uid, 'gid': member.gid}
            record['members'].append(info)
            if (member.uid, member.gid) != (0, 0):
                issue(name, 'unexpected_control_owner', f'{member.uid}:{member.gid}')
            if member.mode & 0o022:
                issue(name, 'writable_control_payload', oct(member.mode))
            if name not in KNOWN_MEMBERS:
                info['unrecognized_member'] = True
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                issue(name, 'non_utf8_control_payload', 'Cannot inspect as UTF-8 text')
                continue
            if '\0' in text:
                issue(name, 'nul_in_control_text', 'NUL byte in control payload')
            if '\r' in text:
                issue(name, 'carriage_return_in_control_text', 'Unexpected CR/CRLF control payload')
            lines = text.splitlines()
            for number, line in enumerate(lines, 1):
                if DIAGNOSTIC.match(line):
                    issue(name, 'diagnostic_contamination', line, number)
            if name == 'control':
                fields = {}
                previous = None
                for number, line in enumerate(lines, 1):
                    if line.startswith((' ', '\t')):
                        if previous is None:
                            issue(name, 'orphan_control_continuation', line, number)
                        continue
                    if not line:
                        continue
                    match = re.fullmatch(r'([A-Za-z0-9][-A-Za-z0-9]*):\s*(.*)', line)
                    if not match:
                        issue(name, 'invalid_control_field', line, number)
                        continue
                    previous, value = match.groups()
                    if previous in fields:
                        issue(name, 'duplicate_control_field', previous, number)
                    fields[previous] = value
                for required in ('Package', 'Version', 'Architecture', 'Maintainer', 'Description'):
                    if not fields.get(required):
                        issue(name, 'missing_required_control_field', required)
                record['package'] = fields.get('Package')
                record['version'] = fields.get('Version')
                record['architecture'] = fields.get('Architecture')
                if expected_version is not None and record['version'] != expected_version:
                    issue(name, 'unexpected_package_version', f"Expected {expected_version}, found {record['version']}")
                if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', fields.get('Package', '')):
                    issue(name, 'invalid_package_name', fields.get('Package', ''))
            elif name == 'triggers':
                directives = []
                for number, line in enumerate(lines, 1):
                    clean = line.split('#', 1)[0].strip()
                    if not clean:
                        continue
                    parts = clean.split(None, 1)
                    if len(parts) != 2 or parts[0] not in TRIGGER_DIRECTIVES:
                        issue(name, 'invalid_trigger_directive', clean, number)
                    elif not parts[1] or any(ch.isspace() for ch in parts[1]):
                        issue(name, 'invalid_trigger_name', clean, number)
                    else:
                        directives.append(clean)
                info['directives'] = directives
            elif name == 'md5sums':
                for number, line in enumerate(lines, 1):
                    if line and not re.fullmatch(r'[0-9a-f]{32}  .+', line):
                        issue(name, 'invalid_md5sums_line', line, number)
            elif name == 'conffiles':
                for number, line in enumerate(lines, 1):
                    if line and not (line.startswith('/') or line.startswith('remove-on-upgrade /')):
                        issue(name, 'unexpected_conffile_line', line, number)
            elif name in SCRIPTS:
                header = lines[0] if lines else ''
                info['interpreter_header'] = header
                if member.mode & 0o111 != 0o111:
                    issue(name, 'maintainer_script_not_executable', oct(member.mode))
                if header in ('#!/bin/sh', '#! /bin/sh'):
                    command = ['/bin/sh', '-n']
                elif header in ('#!/bin/bash', '#! /bin/bash'):
                    command = ['/bin/bash', '--noprofile', '--norc', '-n']
                else:
                    issue(name, 'unexpected_interpreter_header', header)
                    # Do not invoke perl -c/python or any unknown interpreter:
                    # some compile modes execute initialization code.
                    continue
                check = subprocess.run(command, input=data, capture_output=True,
                                       env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                                            'ENV': '', 'BASH_ENV': ''}, timeout=10)
                info['syntax_check'] = {'command': command, 'returncode': check.returncode,
                                        'stderr': check.stderr.decode(errors='replace')}
                if check.returncode:
                    issue(name, 'shell_syntax_error', info['syntax_check']['stderr'])
        if 'control' not in seen:
            issue('control', 'missing_control_file', 'No control member in archive')
    record['status'] = 'issues_found' if record['issues'] else 'passed'
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--systemd-version', default='259.5-0ubuntu3.4+leonb53.1')
    parser.add_argument('--expected-systemd-count', type=int, default=30)
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/ubuntu26/deb-control-audit.json')
    args = parser.parse_args()
    report = json.loads(args.report.read_text()) if args.report.exists() else {'schema_version': 1, 'runs': []}
    roots = {'systemd': ROOT / 'build/ubuntu26-systemd/packages',
             'glibc': ROOT / 'build/ubuntu26-glibc/results',
             'binutils': ROOT / 'build/ubuntu26-binutils/packages',
             'gcc': ROOT / 'build/ubuntu26-gcc/packages'}
    packages = []
    for family, directory in roots.items():
        pattern = f'*_{args.systemd_version}_*.deb' if family == 'systemd' else '*.deb'
        paths = sorted(directory.glob(pattern))
        if not paths:
            raise SystemExit(f'No packages found for {family}: {directory / pattern}')
        if family == 'systemd' and len(paths) != args.expected_systemd_count:
            raise SystemExit(f'Refusing partial systemd audit: expected {args.expected_systemd_count} packages, found {len(paths)}')
        packages.extend(audit_package(path, family, args.systemd_version if family == 'systemd' else None)
                        for path in paths)
    prior_systemd = next((run for run in reversed(report['runs'])
                          if run['systemd_version'] != args.systemd_version), None)
    trigger_comparison = None
    if prior_systemd is not None:
        # The rebuild corrects its environment without changing trigger semantics.
        # Compare valid directives only; malformed diagnostic lines are retained
        # as findings in the earlier run, never adopted as expected directives.
        before = {p['package']: sorted(d for m in p['members'] for d in m.get('directives', []))
                  for p in prior_systemd['packages'] if p['family'] == 'systemd'}
        compared = 0
        for package in packages:
            if package['family'] != 'systemd' or package['package'] not in before:
                continue
            actual = sorted(d for m in package['members'] for d in m.get('directives', []))
            expected = before[package['package']]
            compared += 1
            if actual != expected:
                package['issues'].append({'member': 'triggers', 'kind': 'trigger_semantic_change',
                                          'detail': {'expected': expected, 'actual': actual}})
                package['status'] = 'issues_found'
        trigger_comparison = {'baseline_version': prior_systemd['systemd_version'],
                              'packages_compared': compared,
                              'valid_directive_count': sum(map(len, before.values()))}
    summary = {}
    for family in roots:
        subset = [p for p in packages if p['family'] == family]
        members = [m for p in subset for m in p['members']]
        summary[family] = {'packages': len(subset), 'control_members': len(members),
                           'maintainer_scripts': sum(m['name'] in SCRIPTS for m in members),
                           'script_headers': dict(Counter(m['interpreter_header'] for m in members if 'interpreter_header' in m)),
                           'affected_packages': [p['package'] for p in subset if p['issues']],
                           'issue_kinds': dict(Counter(i['kind'] for p in subset for i in p['issues']))}
    run = {'date_utc': datetime.now(timezone.utc).isoformat(),
           'systemd_version': args.systemd_version,
           'scope': 'Read-only control archive and shell syntax audit; maintainer scripts never executed; payload binaries and dependency solver semantics not covered.',
           'checker_sha256': sha256(Path(__file__).read_bytes()),
           'grammar_reference': 'Local dpkg deb-triggers(5), deb-control(5); six valid trigger directives, comment trimming and one directive per line.',
           'trigger_comparison': trigger_comparison,
           'summary': summary, 'packages': packages,
           'status': 'issues_found' if any(p['issues'] for p in packages) else 'passed'}
    report['runs'].append(run)
    report['latest_status'] = run['status']
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': run['status'], 'summary': summary, 'report': str(args.report)}, indent=2))
    return 1 if run['status'] == 'issues_found' else 0


if __name__ == '__main__':
    raise SystemExit(main())

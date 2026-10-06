#!/usr/bin/env python3
"""Emit a pinned device-only cgroup-BPF source patch; never edit the kernel tree."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / 'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
OUT = ROOT / 'build/kernel-device-bpf/source-v2'
PATCH = ROOT / 'patches/0010-bcm-cgroup-device-bpf-v2.patch'
FRAGMENT = ROOT / 'configs/bcm-cgroup-device-bpf-v2.config'
PINS = {
    'init/Kconfig': '502655abf2f98a5cf3c4cd9a77f2312763a43028149a7572f1e63398f692d510',
    'kernel/bpf/Makefile': 'd93186c619e99da254407ba0b0aaf1c0f1671453bddc89b5b335f49baf6a89bc',
    'include/linux/bpf_types.h': 'fdcfaf066925c7e4472ea0274a64ca894a989ab73ab58d1f3b9d5809b35031f2',
    'include/linux/bpf-cgroup.h': 'efb4483f512e70ed84d36dd8a0130cc8158b11e37f10d6ad2f9c73cfcd0d49ac',
    'include/linux/device_cgroup.h': '5b2fbfc928d25729473c00225920ed1cdcebb24664d1db2fd4b5e98e3989c0ce',
    'kernel/bpf/local_storage.c': 'eb7039bc31a5a9fe9497101af1ef29711045a4b2fe8a64af8c96b9e216912d37',
    'kernel/bpf/cgroup.c': '344307f464fdbd1c59ad13d330758a027107988924f71b71620a62cc311adcd4',
    'kernel/bpf/syscall.c': '6dab4709e818b1269415adbd81ae2369535628bf437b1b3dbdf22cb50272f306',
    'kernel/cgroup/cgroup.c': 'be10247a9353f6fc2f18c205ac022d193737d0e5ad84e899c2da09a43e30dd17',
}
UNCHANGED = {
    'include/linux/sched.h': '4655dc681052de94312e0de6b05431735437cb3fba3aa0ca6a3254ec82266241',
    'include/net/sock.h': 'bf919a088485d5ac3782e9d4943f53f42c138671a6bbc6c2f898b4e99f9d4355',
    'include/linux/cgroup-defs.h': 'b62ca7b98a0a3599a462b7a6183180971b2557c53901c62a607fc5655dc27457',
    'include/linux/sched/user.h': 'd2802ce87c69ffacd874a30a6ea05aead8c96fadcdfe00691fad5c11d4fb12e3',
    'net/ipv4/udp.c': '2e9d3b3b9cc30b77862e00e8fe36a1bafcee9effa4924358dba2d345991d74eb',
    'net/ipv6/udp.c': '2d0d69a2be7c7052c897354c0d62e288f748f186e66a9101c9f5b20178a70abb',
}
COMBINED = '#if defined(CONFIG_CGROUP_BPF) || defined(CONFIG_BCM_CGROUP_DEVICE_BPF)'
CONFIG = '''# Source-only proposed addition to the unchanged kernel10 configuration.
CONFIG_BPF_SYSCALL=y
CONFIG_BCM_CGROUP_DEVICE_BPF=y
CONFIG_GTBE98_CGROUP_ABI=y
# CONFIG_CGROUP_BPF is not set
# CONFIG_SOCK_CGROUP_DATA is not set
# CONFIG_CGROUP_NET_PRIO is not set
# CONFIG_CGROUP_NET_CLASSID is not set
# CONFIG_BPF_JIT is not set
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError('Non-unique literal source anchor')
    return text.replace(old, new, 1)


def transform(name, source):
    s = source
    if name == 'init/Kconfig':
        addition = '''config BCM_CGROUP_DEVICE_BPF
	bool "Broadcom ABI-preserving cgroup device BPF"
	depends on BPF_SYSCALL && CGROUP_DEVICE && GTBE98_CGROUP_ABI
	depends on !CGROUP_BPF && !SOCK_CGROUP_DATA
	help
	  Enable the real cgroup device BPF verifier, permission filter and
	  load/attach/detach/query interfaces without socket cgroup data or
	  cgroup network hooks. Non-device program load and attachment types
	  are rejected. Cgroup program inheritance and local storage retain
	  the existing implementation. This deliberately changes internal
	  cgroup state but leaves the verified task and socket layout intact.

'''
        s = replace_once(s, 'config CGROUP_DEBUG\n', addition + 'config CGROUP_DEBUG\n')
    elif name == 'kernel/bpf/Makefile':
        s = replace_once(s, 'obj-$(CONFIG_CGROUP_BPF) += cgroup.o\n',
                         'ifneq ($(filter y,$(CONFIG_CGROUP_BPF) $(CONFIG_BCM_CGROUP_DEVICE_BPF)),)\nobj-y += cgroup.o\nendif\n')
    elif name == 'include/linux/bpf_types.h':
        if s.count('#ifdef CONFIG_CGROUP_BPF\n') != 2:
            raise RuntimeError('Unexpected device/storage type registration gates')
        s = s.replace('#ifdef CONFIG_CGROUP_BPF\n', COMBINED + '\n')
    elif name == 'include/linux/bpf-cgroup.h':
        # Only the shared lifecycle/device/storage portion gets the new guard.
        # Network declarations and active hook macros remain full-mode-only.
        s = replace_once(s, '#ifdef CONFIG_CGROUP_BPF\n', COMBINED + '\n')
        s = replace_once(s,
            '#define cgroup_bpf_enabled static_branch_unlikely(&cgroup_bpf_enabled_key)\n',
            '#define cgroup_bpf_device_enabled static_branch_unlikely(&cgroup_bpf_enabled_key)\n#ifdef CONFIG_CGROUP_BPF\n#define cgroup_bpf_enabled static_branch_unlikely(&cgroup_bpf_enabled_key)\n#else\n/* UDP paths test this predicate directly, outside the hook macros. */\n#define cgroup_bpf_enabled (0)\n#endif\n')
        device_macro = '#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type, major, minor, access)'
        a, b = s.index(device_macro), s.index('int cgroup_bpf_prog_attach(', s.index(device_macro))
        device_region = s[a:b]
        if device_region.count('if (cgroup_bpf_enabled)') != 1:
            raise RuntimeError('Unexpected device enable predicate')
        s = s[:a] + device_region.replace('if (cgroup_bpf_enabled)', 'if (cgroup_bpf_device_enabled)') + s[b:]
        begin = 'int __cgroup_bpf_run_filter_skb(struct sock *sk,\n'
        end = 'int __cgroup_bpf_check_dev_permission(short dev_type, u32 major, u32 minor,\n'
        a, b = s.index(begin), s.index(end)
        s = s[:a] + '#ifdef CONFIG_CGROUP_BPF\n' + s[a:b] + '#endif /* CONFIG_CGROUP_BPF */\n\n' + s[b:]
        stub_begin = '#define BPF_CGROUP_PRE_CONNECT_ENABLED(sk) (0)\n'
        stub_end = '#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type,major,minor,access) ({ 0; })\n'
        a, b = source.index(stub_begin), source.index(stub_end)
        network_stubs = source[a:b]
        macro_begin = '/* Wrappers for __cgroup_bpf_run_filter_skb() guarded by cgroup_bpf_enabled. */\n'
        macro_end = '#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type, major, minor, access)'
        a, b = s.index(macro_begin), s.index(macro_end)
        s = s[:a] + '#ifdef CONFIG_CGROUP_BPF\n' + s[a:b] + '#else\n' + network_stubs + '#endif /* CONFIG_CGROUP_BPF: network hooks */\n\n' + s[b:]
        s = replace_once(s, '#endif /* CONFIG_CGROUP_BPF */\n\n#endif /* _BPF_CGROUP_H */',
                         '#endif /* CONFIG_CGROUP_BPF || CONFIG_BCM_CGROUP_DEVICE_BPF */\n\n#endif /* _BPF_CGROUP_H */')
    elif name == 'include/linux/device_cgroup.h':
        s = replace_once(s, '#if defined(CONFIG_CGROUP_DEVICE) || defined(CONFIG_CGROUP_BPF)\n',
                         '#if defined(CONFIG_CGROUP_DEVICE) || defined(CONFIG_CGROUP_BPF) || \\\n    defined(CONFIG_BCM_CGROUP_DEVICE_BPF)\n')
    elif name == 'kernel/bpf/local_storage.c':
        s = replace_once(s, '#ifdef CONFIG_CGROUP_BPF\n', COMBINED + '\n')
    elif name == 'kernel/cgroup/cgroup.c':
        s = replace_once(s, '#ifdef CONFIG_CGROUP_BPF\n', COMBINED + '\n')
        s = replace_once(s, '#endif /* CONFIG_CGROUP_BPF */\n',
                         '#endif /* CONFIG_CGROUP_BPF || CONFIG_BCM_CGROUP_DEVICE_BPF */\n')
    elif name == 'kernel/bpf/cgroup.c':
        # Validate the only supported index before evaluating progs[type] or flags[type].
        s = replace_once(s,
            'struct list_head *progs = &cgrp->bpf.progs[type];\n\tstruct bpf_prog *old_prog = NULL;',
            'struct list_head *progs;\n\tstruct bpf_prog *old_prog = NULL;')
        s = replace_once(s,
            '\tbool pl_was_allocated;\n\tint err;\n\n\tif ((flags & BPF_F_ALLOW_OVERRIDE)',
            '\tbool pl_was_allocated;\n\tint err;\n\n#ifdef CONFIG_BCM_CGROUP_DEVICE_BPF\n\tif (type != BPF_CGROUP_DEVICE || !prog ||\n\t    prog->type != BPF_PROG_TYPE_CGROUP_DEVICE)\n\t\treturn -EINVAL;\n#endif\n\tprogs = &cgrp->bpf.progs[type];\n\n\tif ((flags & BPF_F_ALLOW_OVERRIDE)')
        s = replace_once(s,
            'struct list_head *progs = &cgrp->bpf.progs[type];\n\tu32 flags = cgrp->bpf.flags[type];\n\tstruct bpf_prog *old_prog = NULL;',
            'struct list_head *progs;\n\tu32 flags;\n\tstruct bpf_prog *old_prog = NULL;')
        s = replace_once(s,
            '\tstruct bpf_prog_list *pl;\n\tint err;\n\n\tif (flags & BPF_F_ALLOW_MULTI)',
            '\tstruct bpf_prog_list *pl;\n\tint err;\n\n#ifdef CONFIG_BCM_CGROUP_DEVICE_BPF\n\tif (type != BPF_CGROUP_DEVICE ||\n\t    (prog && prog->type != BPF_PROG_TYPE_CGROUP_DEVICE))\n\t\treturn -EINVAL;\n#endif\n\tprogs = &cgrp->bpf.progs[type];\n\tflags = cgrp->bpf.flags[type];\n\n\tif (flags & BPF_F_ALLOW_MULTI)')
        s = replace_once(s,
            '\tstruct list_head *progs = &cgrp->bpf.progs[type];\n\tu32 flags = cgrp->bpf.flags[type];\n\tint cnt, ret = 0, i;\n\n',
            '\tstruct list_head *progs;\n\tu32 flags;\n\tint cnt, ret = 0, i;\n\n#ifdef CONFIG_BCM_CGROUP_DEVICE_BPF\n\tif (type != BPF_CGROUP_DEVICE)\n\t\treturn -EINVAL;\n#endif\n\tprogs = &cgrp->bpf.progs[type];\n\tflags = cgrp->bpf.flags[type];\n\n')
        begin = '/**\n * __cgroup_bpf_run_filter_skb() - Run a program for packet filtering\n'
        end = 'int __cgroup_bpf_check_dev_permission(short dev_type, u32 major, u32 minor,\n'
        a, b = s.index(begin), s.index(end)
        s = s[:a] + '#ifdef CONFIG_CGROUP_BPF\n' + s[a:b] + '#endif /* CONFIG_CGROUP_BPF: network execution */\n\n' + s[b:]
    elif name == 'kernel/bpf/syscall.c':
        s = replace_once(s, '\t/* copy eBPF program license from user space */\n',
            '#ifdef CONFIG_BCM_CGROUP_DEVICE_BPF\n\t/* This profile exposes device filtering only, never network/offload programs. */\n\tif (type != BPF_PROG_TYPE_CGROUP_DEVICE || attr->prog_ifindex ||\n\t    (attr->expected_attach_type &&\n\t     attr->expected_attach_type != BPF_CGROUP_DEVICE))\n\t\treturn -EINVAL;\n#endif\n\n\t/* copy eBPF program license from user space */\n')
        s = replace_once(s,
            '\tif (attr->attach_flags & ~BPF_F_ATTACH_MASK)\n\t\treturn -EINVAL;\n\n\tswitch (attr->attach_type)',
            '\tif (attr->attach_flags & ~BPF_F_ATTACH_MASK)\n\t\treturn -EINVAL;\n\n#ifdef CONFIG_BCM_CGROUP_DEVICE_BPF\n\tif (attr->attach_type != BPF_CGROUP_DEVICE)\n\t\treturn -EINVAL;\n#endif\n\n\tswitch (attr->attach_type)')
        s = replace_once(s,
            '\tif (CHECK_ATTR(BPF_PROG_DETACH))\n\t\treturn -EINVAL;\n\n\tswitch (attr->attach_type)',
            '\tif (CHECK_ATTR(BPF_PROG_DETACH))\n\t\treturn -EINVAL;\n\n#ifdef CONFIG_BCM_CGROUP_DEVICE_BPF\n\tif (attr->attach_type != BPF_CGROUP_DEVICE)\n\t\treturn -EINVAL;\n#endif\n\n\tswitch (attr->attach_type)')
        s = replace_once(s,
            '\tif (attr->query.query_flags & ~BPF_F_QUERY_EFFECTIVE)\n\t\treturn -EINVAL;\n\n\tswitch (attr->query.attach_type)',
            '\tif (attr->query.query_flags & ~BPF_F_QUERY_EFFECTIVE)\n\t\treturn -EINVAL;\n\n#ifdef CONFIG_BCM_CGROUP_DEVICE_BPF\n\tif (attr->query.attach_type != BPF_CGROUP_DEVICE)\n\t\treturn -EINVAL;\n#endif\n\n\tswitch (attr->query.attach_type)')
    else:
        raise RuntimeError('Unlisted transformation')
    if s == source:
        raise RuntimeError('Missing required source delta')
    return s


def prepare():
    old, new = {}, {}
    for name, digest in {**PINS, **UNCHANGED}.items():
        data = (KERNEL / name).read_bytes()
        if sha(data) != digest:
            raise RuntimeError('Frozen source hash mismatch: ' + name)
        if name in PINS:
            old[name] = data
            new[name] = transform(name, data.decode('utf-8')).encode('utf-8')
    patch = ''.join(''.join(difflib.unified_diff(
        old[name].decode().splitlines(keepends=True),
        new[name].decode().splitlines(keepends=True),
        fromfile='a/' + name, tofile='b/' + name, n=3)) for name in PINS).encode()
    plan = {
        'schema': 1, 'status': 'source_only_device_cgroup_bpf_patch_prepared',
        'kernel_source': str(KERNEL), 'output': str(OUT),
        'source_files': [{'path': name, 'original_sha256': sha(old[name]),
                          'original_bytes': len(old[name]), 'successor_sha256': sha(new[name]),
                          'successor_bytes': len(new[name])} for name in PINS],
        'unchanged_headers': [{'path': name, 'sha256': digest} for name, digest in UNCHANGED.items()],
        'patch': {'path': str(PATCH), 'sha256': sha(patch), 'bytes': len(patch)},
        'config_fragment': {'path': str(FRAGMENT), 'sha256': sha(CONFIG.encode()), 'bytes': len(CONFIG.encode())},
        'profile': {'BPF_SYSCALL': True, 'BCM_CGROUP_DEVICE_BPF': True,
                    'CGROUP_BPF': False, 'SOCK_CGROUP_DATA': False, 'GTBE98_CGROUP_ABI': True},
        'network_cgroup_hooks': 'unchanged full-mode-only execution; original no-op macros and literal-zero cgroup_bpf_enabled in device-only mode',
        'ancestry': {'supersedes_source_v1': True, 'v1_retained': True, 'reason': 'direct UDP predicate must remain disabled when device key is active'},
        'device_policy': 'real verifier/permission filter; real inherited attach/detach/query and storage; reject non-device endpoints before indexing',
        'abi': {'task_and_socket_source_unchanged': True, 'cgroup_struct_bpf_expansion_intentional': True,
                'new_compiled_layout_verified': False, 'module_compatibility_verified': False},
        'limitations': ['Source patch and literal/hash closure only; no kernel compilation or tests.',
                        'BPF_SYSCALL enables generic BPF maps/object interfaces; program load is restricted to device in this profile.',
                        'Runtime Docker/runc/device allow-deny, inheritance and ABI checks remain pending.'],
        'kernel_source_mutated': False, 'compile_count': 0, 'test_count': 0, 'device_accessed': False,
    }
    gate = sha(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode())
    return old, new, patch, plan, gate


def emit(old, new, patch, plan, gate):
    if any(p.exists() for p in [OUT, PATCH, FRAGMENT]):
        raise RuntimeError('Exclusive source output already exists; never replace or retry')
    OUT.mkdir(parents=True)
    for kind, inventory in [('original', old), ('successor', new)]:
        for name, data in inventory.items():
            path = OUT / kind / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)
    for path, data in [(PATCH, patch), (FRAGMENT, CONFIG.encode())]:
        with path.open('xb') as f:
            f.write(data)
        path.chmod(0o644)
    report = dict(plan, plan_sha256=gate,
                  generator={'path': str(Path(__file__).resolve()), 'sha256': sha(Path(__file__).read_bytes())})
    with (OUT / 'manifest.json').open('x') as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write('\n')
    (OUT / 'manifest.json').chmod(0o644)


def main():
    if not __debug__:
        raise RuntimeError('Python optimization would remove source guards')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emit-source-only', action='store_true')
    parser.add_argument('--plan-sha256')
    args = parser.parse_args()
    old, new, patch, plan, gate = prepare()
    if args.emit_source_only:
        if args.plan_sha256 != gate:
            raise RuntimeError('Exact source plan hash required before source emission')
        emit(old, new, patch, plan, gate)
    elif args.plan_sha256 is not None:
        raise RuntimeError('Plan hash alone does not authorize output')
    print(json.dumps({'plan': plan, 'plan_sha256': gate,
                      'source_output_emitted': args.emit_source_only}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

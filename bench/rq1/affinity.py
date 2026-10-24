#!/usr/bin/env python3
"""Validate and apply the CPU assignment used by one convergence experiment."""

import argparse
import json
import os
from pathlib import Path
import sys

ROLES = ("daemon", "sender", "receiver_a", "receiver_b", "bgp")


def cpu_topology(cpus, sysfs=Path('/sys/devices/system/cpu')):
    result = {}
    for cpu in sorted(cpus):
        root = sysfs / f'cpu{cpu}'
        nodes = sorted(root.glob('node[0-9]*'))
        if len(nodes) > 1:
            raise ValueError(f'CPU {cpu} belongs to multiple NUMA nodes')
        result[cpu] = {
            'package': int((root / 'topology/physical_package_id').read_text()),
            'core': int((root / 'topology/core_id').read_text()),
            'node': int(nodes[0].name[4:]) if nodes else 0,
        }
    return result


def validate(config, allowed=None, topology=None):
    allowed = set(os.sched_getaffinity(0) if allowed is None else allowed)
    if config.get('version') != 1 or not isinstance(config.get('allow_shared_cores'), bool):
        raise ValueError('affinity needs version=1 and boolean allow_shared_cores')
    roles = config.get('cpus', {})
    if set(roles) != set(ROLES):
        raise ValueError('affinity must specify exactly: ' + ', '.join(ROLES))
    selected = set()
    for role, cpus in roles.items():
        if not isinstance(cpus, list) or not cpus or any(type(c) is not int or c < 0 for c in cpus):
            raise ValueError(f'{role}: CPUs must be a nonempty list of nonnegative integers')
        if len(set(cpus)) != len(cpus) or not set(cpus) <= allowed:
            raise ValueError(f'{role}: duplicate CPU or CPU outside the allowed affinity')
        selected.update(cpus)
    gomax = config.get('gomaxprocs')
    if type(gomax) is not int or not 1 <= gomax <= len(roles['daemon']):
        raise ValueError('gomaxprocs must be between 1 and the daemon CPU count')
    topology = cpu_topology(selected) if topology is None else topology
    if not config['allow_shared_cores']:
        used = set()
        nodes = set()
        for role, cpus in roles.items():
            for cpu in cpus:
                info = topology[cpu]
                key = (info['package'], info['core'])
                if key in used:
                    raise ValueError(f'{role}: a physical core or its SMT sibling is already assigned')
                used.add(key)
                nodes.add(info['node'])
        if len(nodes) != 1:
            raise ValueError('measurement CPUs must share a NUMA node')
    return {str(cpu): topology[cpu] for cpu in sorted(selected)}


def suggest(daemon_cores=4, shared=False):
    cpus = sorted(os.sched_getaffinity(0))
    topology = cpu_topology(cpus)
    if shared:
        return {'version': 1, 'allow_shared_cores': True, 'gomaxprocs': len(cpus),
                'cpus': {role: cpus for role in ROLES}}
    if daemon_cores < 1:
        raise ValueError('daemon-cores must be positive')
    needed = daemon_cores + len(ROLES) - 1
    for node in sorted({v['node'] for v in topology.values()}):
        distinct = {}
        for cpu, info in topology.items():
            if info['node'] == node:
                distinct.setdefault((info['package'], info['core']), cpu)
        available = list(distinct.values())
        if len(available) >= needed:
            roles = {'daemon': available[:daemon_cores]}
            roles.update({role: [cpu] for role, cpu in zip(ROLES[1:], available[daemon_cores:needed])})
            return {'version': 1, 'allow_shared_cores': False, 'gomaxprocs': daemon_cores, 'cpus': roles}
    raise ValueError(f'need {needed} distinct allowed physical cores on one NUMA node; '
                     'use --shared only for a functional smoke test')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    proposal = sub.add_parser('suggest', help='print a candidate; this does not reserve CPUs')
    proposal.add_argument('--daemon-cores', type=int, default=4)
    proposal.add_argument('--shared', action='store_true')
    inspect = sub.add_parser('validate')
    inspect.add_argument('config', type=Path)
    launch = sub.add_parser('exec')
    launch.add_argument('--config', type=Path, required=True)
    launch.add_argument('--role', choices=ROLES, required=True)
    launch.add_argument('--record', type=Path, required=True)
    launch.add_argument('argv', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command == 'suggest':
        print(json.dumps(suggest(args.daemon_cores, args.shared), indent=2))
        return
    config = json.loads(args.config.read_text())
    topology = validate(config)
    if args.command == 'validate':
        print(json.dumps({'config': config, 'topology': topology}, indent=2))
        return
    argv = args.argv[1:] if args.argv[:1] == ['--'] else args.argv
    if not argv:
        raise ValueError('exec needs a program after --')
    assigned = set(config['cpus'][args.role])
    os.sched_setaffinity(0, assigned)
    if set(os.sched_getaffinity(0)) != assigned:
        raise ValueError('the effective CPU assignment differs from the requested assignment')
    gomax = config['gomaxprocs'] if args.role == 'daemon' else len(assigned)
    os.environ['GOMAXPROCS'] = str(gomax)
    with args.record.open('x') as stream:
        json.dump({'role': args.role, 'pid': os.getpid(), 'cpus': sorted(assigned),
                   'gomaxprocs': gomax}, stream)
        stream.write('\n')
    os.execvpe(argv[0], argv, os.environ)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f'affinity: {error}')

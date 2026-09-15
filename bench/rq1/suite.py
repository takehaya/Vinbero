#!/usr/bin/env python3
"""Run a balanced builtin / idle-plugin / cplane convergence experiment."""

import argparse
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import random
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

import affinity

ROOT = Path(__file__).resolve().parents[2]
MODES = ('builtin', 'builtin-idle', 'cplane')
SCRIPTS = [
    'bench/rq1/suite.py', 'bench/rq1/analysis.py', 'bench/rq1/affinity.py',
    'bench/rq1/topo/run_bgp.sh', 'bench/rq1/topo/setup.sh', 'bench/rq1/topo/teardown.sh',
    'bench/rq1/topo/check.py', 'bench/rq1/topo/vinbero-bgp.yml', 'examples/common/netns.sh',
    'go.mod', 'go.sum',
]
BINARIES = ['out/bin/vinberod', 'out/bin/vinbero', 'out/bench/rq1probe',
            'out/bench/rq1bgp', 'out/bench/rq1relay',
            'sdk/examples/cplane-custom-behavior/plugin.wasm']


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def schedule(blocks, warmups, seed, smoke=False):
    if type(blocks) is not int or blocks < 1 or blocks > 300:
        raise ValueError('blocks must be between 1 and 300')
    if not smoke and blocks % 6:
        raise ValueError('blocks must be a multiple of 6 to balance all mode orders')
    if not 0 <= warmups <= 30:
        raise ValueError('warmups must be between 0 and 30')
    if not 0 <= seed < 2**64:
        raise ValueError('seed must be an unsigned 64-bit integer')
    if smoke:
        orders = [MODES, tuple(reversed(MODES))]
    else:
        orders = list(itertools.permutations(MODES)) * (blocks // 6)
        random.Random(seed).shuffle(orders)
    result = []
    for phase, sequences in [('warmup', [MODES] * warmups), ('measure', orders)]:
        for block, modes in enumerate(sequences, 1):
            for mode in modes:
                result.append({'id': f'{len(result)+1:03d}-{mode}', 'phase': phase,
                               'block': block, 'mode': mode, 'state': 'pending'})
    return result


def trusted_directory(path):
    # Match the trial driver's policy; do not follow even parent symlinks.
    path = Path(os.path.abspath(path))
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
            raise ValueError(f'need root-owned directories without symlinks: {part}')
    return path


def new_work(path):
    if path is None:
        trusted_directory('/tmp')
        return Path(tempfile.mkdtemp(prefix='vinbero-rq1-suite.', dir='/tmp'))
    path = Path(os.path.abspath(path))
    trusted_directory(path.parent)
    path.mkdir(mode=0o700)  # Existing paths, including symlinks, are refused.
    return path


def host_info():
    governors = {}
    for cpu in sorted(os.sched_getaffinity(0)):
        path = Path(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor')
        governors[str(cpu)] = path.read_text().strip() if path.exists() else None
    return {'kernel': platform.release(), 'machine': platform.machine(),
            'python': platform.python_version(), 'cpu_affinity': sorted(os.sched_getaffinity(0)),
            'cpu_governors': governors, 'loadavg': list(os.getloadavg()),
            'cpuinfo': Path('/proc/cpuinfo').read_text(),
            'kernel_cmdline': Path('/proc/cmdline').read_text().strip()}


def calibration_errors(result, rate):
    errors = []
    for key in ('lost', 'duplicates', 'unknown', 'negative_delays', 'unsent_schedule_slots'):
        if result[key] != 0:
            errors.append(f'{key}={result[key]}')
    if result['rate'] != rate or result['sent'] < 2 or result['received'] < 2:
        errors.append('missing samples or wrong calibration rate')
    if not rate * 0.95 <= result['achieved_pps'] <= rate * 1.05:
        errors.append('achieved pps is outside 95%..105% of target')
    if not 0 < result['gap_median_us'] <= 1.5e6 / rate:
        errors.append('median arrival gap exceeds 1.5 target intervals')
    if not 0 < result['gap_p99_us'] <= 5e6 / rate:
        errors.append('p99 arrival gap exceeds 5 target intervals')
    return errors


class ChildRunner:
    """Forward cancellation to the owned driver and let its cleanup finish."""

    def __init__(self):
        self.child = None
        self.cancelled = 0

    def interrupt(self, signum, _frame):
        self.cancelled = 128 + signum
        if self.child is not None:
            try:
                self.child.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass

    def run(self, command, log, env, timeout):
        if self.cancelled:
            return self.cancelled
        with Path(log).open('x') as stream:
            # No cancellation may land between fork and publishing the child.
            prior = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            def reset_signals():
                for sig in (signal.SIGINT, signal.SIGTERM):
                    signal.signal(sig, signal.SIG_DFL)
                signal.pthread_sigmask(signal.SIG_SETMASK, prior)

            try:
                self.child = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                              env=env, start_new_session=True,
                                              # The child must not inherit the temporary mask.
                                              preexec_fn=reset_signals)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, prior)
            try:
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        code = self.child.wait(timeout=min(0.2, max(0, deadline-time.monotonic())))
                        return self.cancelled or code
                    except subprocess.TimeoutExpired:
                        if not self.cancelled and time.monotonic() < deadline:
                            continue
                        break
                try:
                    self.child.send_signal(signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    self.child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(self.child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.child.wait()
                return self.cancelled or 124
            finally:
                self.child = None


def recover_topology(run_dir, source, log):
    owned = run_dir / 'topology-owned'
    if not owned.exists() or not owned.read_text().strip():
        return
    metadata = json.loads((run_dir / 'run.json').read_text())
    env = dict(os.environ, TOPO_NS_PREFIX=metadata['namespace_prefix'],
               TOPOLOGY_OWNED_FILE=str(owned), NETNS_HELPER=str(source / 'examples/common/netns.sh'))
    with log.open('a') as stream:
        subprocess.run(['bash', str(source / 'bench/rq1/topo/teardown.sh')],
                       env=env, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=15)
    owned.unlink()


def prepare(args):
    config = affinity.suggest(shared=True) if args.smoke else json.loads(args.affinity.read_text())
    topology = affinity.validate(config)
    if config['allow_shared_cores'] and not args.smoke:
        raise ValueError('shared cores are supported only with --smoke')
    tasks = schedule(2 if args.smoke else args.blocks, 0 if args.smoke else args.warmups,
                     args.seed, args.smoke)
    rate = 10000 if args.smoke else args.rate
    if not 2 <= rate <= 1000000:
        raise ValueError('rate must be between 2 and 1000000 for one-second calibration')
    manifest = {'version': 1, 'kind': 'smoke' if args.smoke else 'performance',
                'state': 'planned', 'seed': args.seed, 'rate': rate,
                'affinity': config, 'topology': topology, 'tasks': tasks,
                'trial_timeout_s': 180, 'created_at': now()}
    if args.plan:
        print(json.dumps(manifest, indent=2))
        return
    if os.geteuid() != 0:
        raise ValueError('run the suite with sudo after make bench-rq1-build')
    os.umask(0o077)
    for name in SCRIPTS + BINARIES:
        if not (ROOT / name).is_file():
            raise ValueError(f'missing {name}; run make bench-rq1-build')
    for command in ('bash', 'ip', 'ethtool', 'timeout', 'flock', 'ping6', 'git', 'cp', 'taskset'):
        if not shutil.which(command):
            raise ValueError(f'missing executable: {command}')
    # Every trial keeps its own executable snapshots, even on filesystems
    # without reflinks. Account for them before starting a long experiment.
    copies = sum((ROOT / name).stat().st_size for name in BINARIES)
    required = int((copies + rate * 3 * 100) * (len(tasks) + 1) * 1.2)
    parent = Path(args.work).absolute().parent if args.work else Path('/tmp')
    if shutil.disk_usage(parent).free < required:
        raise ValueError(f'need approximately {required / 2**30:.1f} GiB free for snapshots and raw CSV')
    work = new_work(args.work)
    manifest['estimated_bytes'] = required
    manifest['state'] = 'preparing'
    write_json(work / 'suite.json', manifest)
    try:
        manifest['host'] = host_info()
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        status = subprocess.check_output(['git', '--no-optional-locks', 'status', '--porcelain'],
                                         cwd=ROOT, text=True).strip()
        manifest['source'] = {'commit': commit, 'dirty': bool(status), 'status': status}
        (work / 'source.diff').write_bytes(subprocess.check_output(['git', 'diff', 'HEAD'], cwd=ROOT))
        source = work / 'source'
        hashes = {}
        for name in SCRIPTS + BINARIES:
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
            hashes[name] = digest(target)
        manifest['sha256'] = hashes
        write_json(work / 'source.json', manifest['source'])
        write_json(work / 'affinity.json', config)
        (work / 'runs').mkdir()
        manifest['state'] = 'prepared'
        write_json(work / 'suite.json', manifest)
    except BaseException as error:
        manifest.update(state='failed', error=str(error), finished_at=now())
        write_json(work / 'suite.json', manifest)
        raise
    print(f'suite artifacts: {work}', flush=True)
    # Run the exact Python source included in the artifact hashes as well.
    os.execv(sys.executable, [sys.executable, str(source / 'bench/rq1/suite.py'), '--execute', str(work)])


def execute(work):
    work = trusted_directory(work)
    if os.geteuid() != 0 or work.stat().st_mode & 0o077:
        raise ValueError('execute requires a private root-owned suite directory')
    manifest = json.loads((work / 'suite.json').read_text())
    if manifest['version'] != 1 or manifest['state'] != 'prepared':
        raise ValueError('only a newly prepared suite can execute')
    source = work / 'source'
    runner = ChildRunner()
    old_handlers = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        old_handlers[sig] = signal.signal(sig, runner.interrupt)
    env = dict(os.environ)
    # A caller's single-run overrides must not redirect any suite child.
    for key in ('OUT', 'WORK', 'MODE', 'RATE', 'TOPO_NS_PREFIX', 'TOPOLOGY_OWNED_FILE',
                'VINBEROD', 'VBCTL', 'WASM', 'AFFINITY_FILE', 'SOURCE_METADATA', 'GOMAXPROCS'):
        env.pop(key, None)
    manifest.update(state='calibrating', started_at=now())
    write_json(work / 'suite.json', manifest)
    active = None
    active_task = None
    exit_code = 0
    try:
        for name, expected in manifest['sha256'].items():
            if digest(source / name) != expected:
                raise ValueError(f'snapshot changed before execution: {name}')
        if json.loads((work / 'affinity.json').read_text()) != manifest['affinity']:
            raise ValueError('affinity changed after preparation')
        affinity.validate(manifest['affinity'])
        cpus = sorted(set(manifest['affinity']['cpus']['sender'] + manifest['affinity']['cpus']['receiver_a']))
        calibration_env = dict(env, GOMAXPROCS=str(len(cpus)))
        command = ['taskset', '-c', ','.join(map(str, cpus)), str(source / 'out/bench/rq1probe'),
                   'calibrate', '-rate', str(manifest['rate'])]
        code = runner.run(command, work / 'calibration.log', calibration_env, 15)
        if code:
            raise ValueError(f'calibration process failed with exit {code}; see calibration.log')
        calibration = json.loads((work / 'calibration.log').read_text())
        errors = calibration_errors(calibration, manifest['rate'])
        manifest['calibration'] = {'result': calibration, 'quality_errors': errors,
                                   'enforced': manifest['kind'] == 'performance', 'cpus': cpus}
        write_json(work / 'suite.json', manifest)
        if errors and manifest['kind'] == 'performance':
            raise ValueError('calibration failed: ' + '; '.join(errors))
        for task in manifest['tasks']:
            if runner.cancelled:
                raise InterruptedError('suite cancelled before next trial')
            active = work / 'runs' / task['id']
            active_task = task
            task.update(state='running', started_at=now(), loadavg=list(os.getloadavg()))
            manifest['state'] = 'running'
            write_json(work / 'suite.json', manifest)
            child_env = dict(env, MODE=task['mode'], RATE=str(manifest['rate']), WORK=str(active),
                             AFFINITY_FILE=str(work / 'affinity.json'), SOURCE_METADATA=str(work / 'source.json'))
            print(f"{task['id']} {task['phase']} block={task['block']}", flush=True)
            log = work / f"{task['id']}.log"
            code = runner.run(['bash', str(source / 'bench/rq1/topo/run_bgp.sh'), '1'],
                              log, child_env, manifest['trial_timeout_s'])
            task.update(exit_code=code, finished_at=now())
            if code:
                task['state'] = 'failed'
                write_json(work / 'suite.json', manifest)
                raise ValueError(f"{task['id']} failed with exit {code}; stopping without excluding it")
            status = json.loads((active / 'status.json').read_text())
            if status != {'exit_code': 0, 'completed_trials': 1, 'requested_trials': 1}:
                raise ValueError(f"{task['id']} did not complete exactly one trial")
            task['state'] = 'complete'
            write_json(work / 'suite.json', manifest)
            active = None
            active_task = None
        if runner.cancelled:
            raise InterruptedError('suite cancelled after last trial')
        manifest['state'] = 'complete'
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        exit_code = runner.cancelled or 1
        manifest.update(state='interrupted' if runner.cancelled else 'failed', error=str(error))
        if active_task is not None:
            active_task.update(state='failed', error=str(error), finished_at=now())
        print(f'suite: {error}', file=sys.stderr)
    finally:
        if active is not None:
            try:
                recover_topology(active, source, work / 'recovery.log')
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                manifest['cleanup_error'] = str(error)
                manifest['state'] = 'failed'
                exit_code = 1
        manifest.update(finished_at=now(), exit_code=exit_code)
        write_json(work / 'suite.json', manifest)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    # Aggregation is run after traffic and cleanup, never alongside a trial.
    import analysis
    try:
        _rows, summary = analysis.summarize(work)
        if manifest['state'] == 'complete' and not summary['complete']:
            raise ValueError('completed trial artifacts failed validation; see trials.csv')
    except (OSError, ValueError, KeyError) as error:
        manifest.update(state='failed', analysis_error=str(error), exit_code=1)
        write_json(work / 'suite.json', manifest)
        print(f'analysis: {error}', file=sys.stderr)
        exit_code = 1
    print(f'suite artifacts: {work}', flush=True)
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--affinity', type=Path, help='CPU assignment from affinity.py suggest, reviewed for this host')
    parser.add_argument('--work', type=Path, help='new private output directory; defaults to a fresh /tmp directory')
    parser.add_argument('--seed', type=int, default=20260915)
    parser.add_argument('--blocks', type=int, default=30, help='trials per mode; must be a multiple of 6')
    parser.add_argument('--warmups', type=int, default=3, help='warm-up trials per mode')
    parser.add_argument('--rate', type=int, default=100000)
    parser.add_argument('--plan', action='store_true', help='print the schedule without changing the network or filesystem')
    parser.add_argument('--smoke', action='store_true', help='two blocks at 10k pps, shared CPUs, no warm-up or speed gate')
    parser.add_argument('--execute', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.execute:
        return execute(args.execute)
    if not args.smoke and args.affinity is None:
        parser.error('--affinity is required for performance measurements')
    if args.smoke and args.affinity is not None:
        parser.error('--smoke supplies its own shared CPU assignment; omit --affinity')
    prepare(args)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(f'suite: {error}')

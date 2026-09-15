#!/usr/bin/env python3
"""Validate raw convergence captures and summarize one complete or failed suite."""

import argparse
import csv
import json
import math
from pathlib import Path
import random
import re
import statistics
import sys

import affinity

MODES = ('builtin', 'builtin-idle', 'cplane')


def read_json(path):
    return json.loads(Path(path).read_text())


def csv_rows(path, header):
    with Path(path).open(newline='') as stream:
        reader = csv.reader(stream)
        if next(reader, None) != header:
            raise ValueError(f'{path}: invalid CSV header')
        for line, row in enumerate(reader, 2):
            if len(row) != len(header):
                raise ValueError(f'{path}:{line}: invalid column count')
            yield row


def unsigned(value):
    if not re.fullmatch(r'[0-9]+', value):
        raise ValueError(f'invalid unsigned integer: {value!r}')
    return int(value)


def quantile(values, fraction):
    ordered = sorted(values)
    if not ordered:
        raise ValueError('quantile needs observations')
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def capture_metrics(directory):
    matches = re.findall(r'^change_ns=([0-9]+)$', (directory / 'churn.log').read_text(), re.MULTILINE)
    if len(matches) != 1 or int(matches[0]) <= 0:
        raise ValueError(f'{directory}: missing or ambiguous change timestamp')
    change = int(matches[0])
    sent = {}
    for seq, tag, at in csv_rows(directory / 'sent.csv', ['seq', 'tag', 'sent_unix_ns']):
        seq, tag, at = unsigned(seq), unsigned(tag), unsigned(at)
        if seq in sent or at <= 0:
            raise ValueError(f'{directory}: invalid or duplicate sender record')
        sent[seq] = (at, tag)
    if len(sent) < 2:
        raise ValueError(f'{directory}: too few send records')
    post = {seq for seq, (at, _tag) in sent.items() if at >= change}
    if not post or len(post) == len(sent):
        raise ValueError(f'{directory}: probes are required before and after the change')
    arrivals, all_arrivals, old, late_old = {}, {}, {}, []
    first_new = None
    initial_old = False
    negatives = duplicates = 0
    for filename, endpoint in (('pea.csv', 'pe-a'), ('peb.csv', 'pe-b')):
        for seq, tag, name, at in csv_rows(directory / filename, ['seq', 'tag', 'endpoint', 'recv_unix_ns']):
            seq, tag, at = unsigned(seq), unsigned(tag), unsigned(at)
            if at <= 0 or name != endpoint or seq not in sent or sent[seq][1] != tag:
                raise ValueError(f'{directory}: unknown probe, tag, timestamp or endpoint')
            negatives += at < sent[seq][0]
            duplicates += seq in all_arrivals
            all_arrivals[seq] = min(at, all_arrivals.get(seq, at))
            if at < change:
                if name == 'pe-b':
                    raise ValueError(f'{directory}: new path was active before the change')
                initial_old = True
                continue
            arrivals[seq] = min(at, arrivals.get(seq, at))
            if name == 'pe-b':
                first_new = at if first_new is None else min(at, first_new)
            elif seq in post:
                old[seq] = min(at, old.get(seq, at))
                late_old.append((seq, at))
    if not initial_old or first_new is None or len(arrivals) < 2:
        raise ValueError(f'{directory}: incomplete forwarding transition')
    stamps = sorted(arrivals.values())
    gaps = [b-a for a, b in zip(stamps, stamps[1:])]
    # Match Analyze's integer nanosecond median before converting to µs.
    sample_gap = int(statistics.median(gaps)) / 1000
    if sample_gap <= 0:
        raise ValueError(f'{directory}: no positive observation interval')
    prior = [at for at in all_arrivals.values() if at < first_new]
    times = [at for at, _ in sent.values()]
    if max(times) <= min(times):
        raise ValueError(f'{directory}: no positive sender duration')
    schedule = read_json(directory / 'sender-schedule.json')
    rate, start, duration = schedule['rate'], schedule['start_unix_ns'], schedule['duration_ns']
    if any(type(n) is not int or n <= 0 for n in (rate, start, duration)) or rate > 1000000000:
        raise ValueError(f'{directory}: invalid sender schedule')
    step = 1000000000 // rate
    if any(at < start or at >= start + duration for at in times):
        raise ValueError(f'{directory}: sender record outside its schedule')
    lags = [at - (start + seq * step) for seq, (at, _tag) in sent.items()]
    result = {
        'latency_us': (first_new-change) / 1000,
        'lost': len(post - arrivals.keys()),
        'misdelivered': sum(at < first_new for at in old.values()),
        'old_after_first_new': len({seq for seq, at in late_old if at >= first_new}),
        'sent_total': len(sent), 'sent_after_change': len(post),
        'requested_rate': rate,
        'sample_gap_us': sample_gap, 'gap_p99_us': quantile(gaps, .99) / 1000,
        'gap_max_us': max(gaps) / 1000,
        'gap_before_first_new_us': (first_new-max(prior)) / 1000 if prior else None,
        'achieved_pps': (len(sent)-1)*1e9 / (max(times)-min(times)),
        'send_lag_median_us': statistics.median(lags)/1000,
        'send_lag_p99_us': quantile(lags, .99)/1000,
        'send_lag_max_us': max(lags)/1000,
        'sender_start_lateness_us': (start-int(schedule['requested_start_unix_ns']))/1000,
        'unsent_schedule_slots': max(0, (duration+step-1)//step-len(sent)),
        'negative_receive_delays': negatives, 'duplicate_arrivals': duplicates,
    }
    result['loss_percent'] = 100 * result['lost'] / len(post)
    flags = []
    if negatives or min(lags) < 0:
        flags.append('clock_or_schedule_reversal')
    if result['sample_gap_us'] > 1.5e6/rate or result['gap_p99_us'] > 5e6/rate:
        flags.append('coarse_arrival_intervals')
    if result['gap_before_first_new_us'] is None or result['gap_before_first_new_us'] > 5e6/rate:
        flags.append('coarse_transition_observation')
    if not rate*.95 <= result['achieved_pps'] <= rate*1.05:
        flags.append('offered_rate_mismatch')
    if result['unsent_schedule_slots']:
        flags.append('unsent_schedule_slots')
    result['quality_flags'] = ';'.join(flags)
    return result


def forwarding_state(state):
    """Remove allocation/ownership IDs, retaining every reported forwarding field."""
    groups = [{k: v for k, v in group.items() if k not in ('groupId', 'owner')}
              for group in state['groups'].get('groups', [])]
    return {'headend': state['headend'], 'groups': sorted(groups, key=lambda value: json.dumps(value, sort_keys=True))}


def validate_run(work, task, manifest):
    from topo import check

    if not re.fullmatch(r'[0-9]{3,6}-(builtin|builtin-idle|cplane)', task['id']):
        raise ValueError('invalid trial artifact ID')
    directory = work / 'runs' / task['id']
    status = read_json(directory / 'status.json')
    if status != {'exit_code': 0, 'completed_trials': 1, 'requested_trials': 1} or task.get('exit_code') != 0:
        raise ValueError(f"{task['id']}: trial status contradicts completion")
    meta = read_json(directory / 'run.json')
    if meta['mode'] != task['mode'] or meta['rate'] != manifest['rate'] or meta['trials'] != 1:
        raise ValueError(f"{task['id']}: measurement conditions changed")
    if meta['source_commit'] != manifest['source']['commit'] or meta['source_dirty'] != manifest['source']['dirty']:
        raise ValueError(f"{task['id']}: source provenance changed")
    observed = {Path(name).name: sha for name, sha in meta['artifacts'].items() if Path(name).parent.name == 'bin'}
    for name in ('vinberod', 'vinbero', 'rq1probe', 'rq1bgp', 'rq1relay', 'plugin.wasm'):
        if name == 'plugin.wasm' and task['mode'] == 'builtin':
            continue
        source = next(key for key in manifest['sha256'] if Path(key).name == name)
        if observed.get(name) != manifest['sha256'][source]:
            raise ValueError(f"{task['id']}: executable changed: {name}")
    config = read_json(directory / 'affinity.json')['config']
    if config != manifest['affinity']:
        raise ValueError(f"{task['id']}: CPU assignment changed")
    trial = directory / 'trial-1'
    for role in affinity.ROLES:
        record = read_json(trial / f'{role}-affinity.json')
        gomax = config['gomaxprocs'] if role == 'daemon' else len(config['cpus'][role])
        if (record['role'] != role or record['cpus'] != sorted(config['cpus'][role]) or
                record['gomaxprocs'] != gomax or record['pid'] <= 0):
            raise ValueError(f"{task['id']}: incorrect effective CPU assignment for {role}")
    initial, final = read_json(trial / 'initial.json'), read_json(trial / 'final.json')
    check.verify(initial, task['mode'], 'fd00:a::100')
    check.verify(final, task['mode'], 'fd00:b::100', initial)
    metrics = capture_metrics(trial)
    if metrics['requested_rate'] != manifest['rate']:
        raise ValueError(f"{task['id']}: sender rate changed")
    rows = list(csv_rows(directory / 'results.csv', ['trial', 'mode', 'latency_us', 'lost', 'misdelivered', 'sample_gap_us']))
    if len(rows) != 1 or rows[0][:2] != ['1', task['mode']]:
        raise ValueError(f"{task['id']}: expected exactly one result row")
    for key, value in zip(('latency_us', 'lost', 'misdelivered', 'sample_gap_us'), rows[0][2:]):
        reported = float(value)
        if not math.isfinite(reported) or abs(reported - metrics[key]) > 0.0011:
            raise ValueError(f"{task['id']}: {key} disagrees with raw captures")
    return metrics, {stage: forwarding_state(state) for stage, state in (('initial', initial), ('final', final))}


def summarize_rows(rows, manifest, repetitions=2000):
    measured = [r for r in rows if r['phase'] == 'measure']
    summary = {'kind': manifest['kind'], 'state': manifest['state'], 'modes': {},
               'comparisons': {}, 'confidence_method': '95% percentile bootstrap of complete blocks',
               'bootstrap_repetitions': repetitions, 'bootstrap_seed': manifest['seed'],
               'warmup_completed': sum(r['phase'] == 'warmup' and r['state'] == 'complete' for r in rows)}
    for mode in MODES:
        expected = [r for r in measured if r['mode'] == mode]
        complete = [r for r in expected if r['state'] == 'complete']
        item = {'planned': len(expected), 'completed': len(complete),
                'failed': sum(r['state'] == 'failed' for r in expected),
                'not_completed': sum(r['state'] not in ('complete', 'failed') for r in expected)}
        if complete:
            values = [r['latency_us'] for r in complete]
            item.update(latency_median_us=statistics.median(values), latency_min_us=min(values), latency_max_us=max(values),
                        lost=sum(r['lost'] for r in complete), sent_after_change=sum(r['sent_after_change'] for r in complete),
                        misdelivered_median=statistics.median(r['misdelivered'] for r in complete),
                        old_after_first_new=sum(r['old_after_first_new'] for r in complete),
                        sample_gap_median_us=statistics.median(r['sample_gap_us'] for r in complete),
                        quality_flagged=sum(bool(r['quality_flags']) for r in complete))
        summary['modes'][mode] = item
    blocks = {}
    for row in measured:
        group = blocks.setdefault(row['block'], {})
        if row['mode'] in group:
            raise ValueError('a block contains duplicate modes')
        group[row['mode']] = row
    complete = (manifest['state'] == 'complete' and all(r['state'] == 'complete' for r in rows) and
                bool(blocks) and all(set(group) == set(MODES) for group in blocks.values()))
    summary['complete'] = complete
    summary['performance_usable'] = (complete and manifest['kind'] == 'performance' and
                                       manifest.get('calibration', {}).get('enforced') is True and
                                       not manifest['calibration']['quality_errors'] and
                                       not any(r.get('quality_flags') for r in measured))
    # Failed and smoke runs retain descriptive values, but never receive an
    # apparently complete A/B estimate or confidence interval.
    if not summary['performance_usable']:
        return summary
    groups = list(blocks.values())
    rng = random.Random(manifest['seed'])
    samples = {mode: [] for mode in MODES}
    differences = {mode: [] for mode in MODES[1:]}
    for _ in range(repetitions):
        drawn = [rng.choice(groups) for _ in groups]
        for mode in MODES:
            samples[mode].append(statistics.median(g[mode]['latency_us'] for g in drawn))
        for mode in MODES[1:]:
            differences[mode].append(statistics.median(g[mode]['latency_us']-g['builtin']['latency_us'] for g in drawn))
    for mode in MODES:
        summary['modes'][mode]['median_ci95_us'] = [quantile(samples[mode], .025), quantile(samples[mode], .975)]
    for mode in MODES[1:]:
        summary['comparisons'][mode + '-minus-builtin'] = {
            'paired_blocks': len(groups),
            'paired_median_difference_us': statistics.median(g[mode]['latency_us']-g['builtin']['latency_us'] for g in groups),
            'ci95_us': [quantile(differences[mode], .025), quantile(differences[mode], .975)],
        }
    return summary


def summarize(work):
    work = Path(work)
    manifest = read_json(work / 'suite.json')
    if manifest['version'] != 1:
        raise ValueError('unsupported suite schema')
    rows, fingerprints = [], {}
    seen = set()
    for order, task in enumerate(manifest['tasks'], 1):
        if task['id'] in seen or task['mode'] not in MODES or task['phase'] not in ('warmup', 'measure'):
            raise ValueError('invalid or duplicate scheduled trial')
        seen.add(task['id'])
        row = {'order': order, 'id': task['id'], 'phase': task['phase'], 'block': task['block'],
               'mode': task['mode'], 'state': task['state'], 'exit_code': task.get('exit_code', ''),
               'error': task.get('error', '')}
        if task['state'] == 'complete':
            try:
                metrics, state = validate_run(work, task, manifest)
                row.update(metrics)
                if task['phase'] == 'measure':
                    fingerprints.setdefault(task['block'], {})[task['mode']] = state
            except (OSError, ValueError, KeyError) as error:
                row.update(state='failed', error=f'artifact validation: {error}')
        rows.append(row)
    for block, states in fingerprints.items():
        if 'builtin' in states and 'builtin-idle' in states and states['builtin'] != states['builtin-idle']:
            for row in rows:
                if row['phase'] == 'measure' and row['block'] == block and row['mode'] in MODES[:2]:
                    row.update(state='failed', error='builtin and idle plugin used different forwarding state')
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with (work / 'trials.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    summary = summarize_rows(rows, manifest)
    if manifest['state'] == 'complete' and not summary['complete']:
        summary['state'] = 'validation_failed'
    (work / 'summary.json').write_text(json.dumps(summary, indent=2, allow_nan=False) + '\n')
    lines = ['# BGP 更新の反映時間を比較します', '',
             f"実行状態は `{summary['state']}`、用途は `{summary['kind']}` です。", '',
             '| 条件 | 完了 / 予定 | 失敗 | 中央値 µs | 最小〜最大 µs | 損失 / 更新後送信数 |',
             '|---|---:|---:|---:|---:|---:|']
    for mode, result in summary['modes'].items():
        latency = f"{result['latency_median_us']:.3f}" if result['completed'] else '-'
        span = f"{result['latency_min_us']:.3f}〜{result['latency_max_us']:.3f}" if result['completed'] else '-'
        loss = f"{result['lost']} / {result['sent_after_change']}" if result['completed'] else '-'
        lines.append(f"| {mode} | {result['completed']} / {result['planned']} | {result['failed']} | {latency} | {span} | {loss} |")
    lines += ['', '起点は BGP Advertise 呼び出し直前、終点は新経路への最初の既知 probe の到着です。',
              'builtin と builtin-idle は ECMP group、cplane は直接 headend を使うため、cplane との差は制御経路全体の比較です。', '',
              '失敗・未完了・warm-up の行も [全試行の CSV](trials.csv) に残しています。',
              '観測間隔の p99・最大値、切り替え直前の gap、送信予定からの遅れ、旧経路への継続到着も CSV に保存しています。', '']
    if not summary['performance_usable']:
        lines += ['この run は性能比較の区間推定の対象外です。実行状態、用途、校正と CSV の品質情報を確認してください。', '']
    else:
        for comparison, value in summary['comparisons'].items():
            lo, hi = value['ci95_us']
            lines.append(f"{comparison} の block 内差の中央値は {value['paired_median_difference_us']:.3f} µs、95%区間は {lo:.3f}〜{hi:.3f} µs です。")
        lines += ['', '区間推定は同じ block 内の3条件を一緒に再標本化します。異なる session は別々に集計してください。', '']
    lines += ['[集計 JSON](summary.json) と [測定条件](suite.json) に詳細を保存しています。', '']
    (work / 'report.md').write_text('\n'.join(lines))
    return rows, summary


def plot(work, rows):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    measured = [r for r in rows if r['phase'] == 'measure' and r['state'] == 'complete']
    if not measured:
        raise ValueError('no completed measurement trials to plot')
    colors = dict(zip(MODES, ('#2364AA', '#22856B', '#CB6015')))
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4), sharey=True)
    for index, mode in enumerate(MODES):
        group = [r for r in measured if r['mode'] == mode]
        values = [r['latency_us'] for r in group]
        if not values:
            continue
        jitter = [(i-(len(group)-1)/2)*.45/max(1, len(group)-1) for i in range(len(group))]
        axes[0].scatter([index+j for j in jitter], values, s=22, color=colors[mode], alpha=.8)
        median = statistics.median(values)
        axes[0].plot([index-.3, index+.3], [median, median], color=colors[mode], lw=2)
        axes[1].scatter([r['order'] for r in group], values, s=22, color=colors[mode], label=mode)
    axes[0].set_xticks(range(3), MODES)
    axes[0].set_ylabel('BGP advertisement to first new-path arrival (µs)')
    axes[0].set_title('All completed trials; bar = median')
    axes[1].set_xlabel('Execution order including warm-up')
    axes[1].set_title('Recorded execution order')
    axes[1].legend(frameon=False)
    for ax in axes:
        ax.set_ylim(bottom=0)
        ax.grid(axis='y', alpha=.25)
        ax.set_axisbelow(True)
        ax.spines[['top', 'right']].set_visible(False)
    summary = read_json(Path(work) / 'summary.json')
    qualification = 'performance' if summary['performance_usable'] else 'descriptive only'
    fig.suptitle(f"{summary['kind']} / {summary['state']} / {qualification}")
    fig.tight_layout()
    for extension in ('png', 'svg'):
        fig.savefig(Path(work) / f'latency.{extension}', dpi=180)
    plt.close(fig)
    with (Path(work) / 'report.md').open('a') as stream:
        stream.write('\n![各試行の切り替え時間](latency.png)\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work', type=Path)
    parser.add_argument('--plot', action='store_true', help='also write PNG/SVG; requires matplotlib')
    args = parser.parse_args()
    try:
        rows, summary = summarize(args.work)
        if args.plot:
            plot(args.work, rows)
        print(json.dumps(summary, indent=2))
        sys.exit(0 if summary['complete'] else 1)
    except (OSError, ValueError, KeyError, ImportError) as error:
        sys.exit(f'analysis: {error}')

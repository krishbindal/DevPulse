"""Offline comparison of exported DevPulse reports; never infer missing metrics."""
import argparse
import json
from pathlib import Path

MAX_REPORT_BYTES = 2 * 1024 * 1024
METRICS = ('stargazers_count', 'forks_count', 'open_issues_count')
SECTIONS = ('languages', 'inventory', 'ci', 'npm_dependencies',
            'python_dependencies', 'npm_lockfile', 'advisories', 'static_python', 'practices')

def read_report(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError('Report exceeds 2 MiB limit')
    return json.loads(raw)

def compare(left, right):
    for report in (left, right):
        if not isinstance(report, dict) or not isinstance(report.get('full_name'), str) or not report['full_name']:
            raise ValueError('Expected a DevPulse report with full_name')
    def count(report, key):
        value = report.get(key)
        return value if type(value) is int and value >= 0 else None
    def status(report, key):
        section = report.get(key)
        value = section.get('status') if isinstance(section, dict) else None
        return value if value in ('ok', 'partial', 'unavailable', 'not_analyzed', 'not_found', 'not_applicable') else 'unknown'
    metrics = {}
    for key in METRICS:
        a, b = count(left, key), count(right, key)
        metrics[key] = {'left': a, 'right': b, 'right_minus_left': b-a if a is not None and b is not None else None}
    return {'method': 'offline-report-comparison-v1',
            'scope': 'Separate scan snapshots; counts are not quality scores. Open issues include pull requests. No security ranking or inferred missing values.',
            'left': {k: left.get(k) for k in ('full_name', 'scanned_at', 'source')},
            'right': {k: right.get(k) for k in ('full_name', 'scanned_at', 'source')},
            'metrics': metrics,
            'coverage': {key: {'left': status(left,key), 'right': status(right,key)} for key in SECTIONS}}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('left')
    parser.add_argument('right')
    args = parser.parse_args()
    try:
        result = compare(read_report(args.left), read_report(args.right))
    except (OSError, ValueError, RecursionError) as exc:
        parser.exit(2, 'Cannot compare reports: ' + str(exc) + '\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()

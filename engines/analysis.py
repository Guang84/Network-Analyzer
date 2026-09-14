#!/usr/bin/env python3
"""
Analysis helpers for parsed scan results – summary statistics.
"""
import json
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from .vulnerability import assess_networks

def summarize_scan_json(json_file: Path) -> Dict[str, Any]:
    """Load a JSON scan results file and return a summary dictionary."""
    if not json_file.exists():
        return {'error': 'file not found', 'path': str(json_file)}
    try:
        data = json.loads(json_file.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        return {'error': f'unable to read scan JSON: {exc}', 'path': str(json_file)}
    if not isinstance(data, list):
        return {'error': 'scan JSON must contain a network list', 'path': str(json_file)}
    networks = [item for item in data if isinstance(item, dict)]
    summary = {}
    summary['total_networks'] = len(networks)
    channels = [n.get('channel') for n in networks if n.get('channel')]
    summary['top_channels'] = Counter(channels).most_common(10)
    encs = [n.get('encryption_type', 'Unknown') for n in networks]
    summary['encryption_distribution'] = Counter(encs).most_common()
    essids = [n.get('essid') for n in networks if n.get('essid')]
    summary['top_essids'] = Counter(essids).most_common(10)
    # Add risk scores
    risks = [n['risk_level'] for n in assess_networks(networks)]
    summary['risk_distribution'] = Counter(risks).most_common()
    return summary

def load_and_summarize(path: str) -> Dict[str, Any]:
    p = Path(path)
    if p.suffix.lower() == '.json':
        return summarize_scan_json(p)
    else:
        return {'error': 'unsupported file type', 'path': str(p)}


def export_markdown_report(json_file: Path, output_dir: Path) -> Path:
    """Create a portable Markdown report from a saved passive scan."""
    summary = summarize_scan_json(json_file)
    if summary.get('error'):
        raise ValueError(summary['error'])
    output_dir.mkdir(parents=True, exist_ok=True)
    report = output_dir / f"report_{json_file.stem}.md"
    lines = [
        '# Network Analyzer Report', '',
        f'- Generated: {datetime.now(timezone.utc).isoformat()}',
        f'- Source: `{json_file.name}`',
        f"- Networks observed: {summary['total_networks']}", '',
        '## Encryption distribution', '', '| Type | Count |', '| --- | ---: |',
    ]
    def table_value(value: Any) -> str:
        return str(value).replace('\\', '\\\\').replace('|', '\\|').replace('\n', ' ')

    lines.extend(f'| {table_value(name)} | {count} |' for name, count in summary['encryption_distribution'])
    lines.extend(['', '## Top channels', '', '| Channel | Networks |', '| --- | ---: |'])
    lines.extend(f'| {table_value(name)} | {count} |' for name, count in summary['top_channels'])
    lines.extend(['', '## Risk distribution', '', '| Level | Count |', '| --- | ---: |'])
    lines.extend(f'| {table_value(name)} | {count} |' for name, count in summary['risk_distribution'])
    report.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return report

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: analysis.py <scan.json>')
        sys.exit(1)
    print(json.dumps(load_and_summarize(sys.argv[1]), indent=2))

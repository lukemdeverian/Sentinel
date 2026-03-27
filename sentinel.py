"""
Sentinel - Static Security Analysis Tool
Detects vulnerability patterns in C++ and Python source code.
"""

import os
import re
import argparse
from pathlib import Path
from reporter import Reporter
from rules.cpp_rules import CPP_RULES
from rules.python_rules import PYTHON_RULES
from rules.universal_rules import UNIVERSAL_RULES

EXTENSION_MAP = {
    '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
    '.c': 'cpp', '.h': 'cpp', '.hpp': 'cpp',
    '.py': 'python',
}

class Finding:
    def __init__(self, filepath, line_num, line_content, rule):
        self.filepath   = filepath
        self.line_num   = line_num
        self.line_content = line_content.strip()
        self.rule_id    = rule['id']
        self.title      = rule['title']
        self.severity   = rule['severity']   # CRITICAL / HIGH / MEDIUM / LOW
        self.description = rule['description']
        self.cwe        = rule.get('cwe', '')

class Scanner:
    def __init__(self, target_path, verbose=False):
        self.target_path = Path(target_path)
        self.verbose     = verbose
        self.findings    = []

    def _get_rules(self, lang):
        rules = UNIVERSAL_RULES[:]
        if lang == 'cpp':
            rules += CPP_RULES
        elif lang == 'python':
            rules += PYTHON_RULES
        return rules

    def _scan_file(self, filepath, lang):
        rules = self._get_rules(lang)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"  [!] Could not read {filepath}: {e}")
            return

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip full-line comments
            if stripped.startswith('//') or stripped.startswith('#'):
                continue

            # Skip lines that are purely rule metadata dictionaries
            # or string continuations that are part of rule definitions
            metadata_keys = (
                "'id'", '"id"',
                "'title'", '"title"',
                "'description'", '"description"',
                "'cwe'", '"cwe"',
                "'severity'", '"severity"',
                "'pattern'", '"pattern"',
            )
            if any(stripped.startswith(k) for k in metadata_keys):
                continue

            if re.match(r"""^\s*['"]\s*\w""", stripped) and stripped.endswith(("',", '",', "'", '"')):
                continue

            # Run all rules on the raw line
            seen = set()
            for rule in rules:
                if re.search(rule['pattern'], line, re.IGNORECASE):
                    # Duplicate. don't fire the same rule twice on one line
                    key = (rule['id'], line_num)
                    if key not in seen:
                        seen.add(key)
                        self.findings.append(
                            Finding(str(filepath), line_num, line, rule)
                        )

    def run(self):
        if self.target_path.is_file():
            ext  = self.target_path.suffix.lower()
            lang = EXTENSION_MAP.get(ext)
            if lang:
                if self.verbose:
                    print(f"  Scanning: {self.target_path}")
                self._scan_file(self.target_path, lang)
            else:
                print(f"[!] Unsupported file type: {ext}")
        else:
            files = [
                p for p in self.target_path.rglob('*')
                if p.suffix.lower() in EXTENSION_MAP
            ]
            print(f"[*] Found {len(files)} source file(s) to scan...\n")
            for fp in files:
                lang = EXTENSION_MAP[fp.suffix.lower()]
                if self.verbose:
                    print(f"  Scanning: {fp}")
                self._scan_file(fp, lang)

        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description='Sentinel - Static Security Analyzer'
    )
    parser.add_argument('target',
        help='File or directory to scan')
    parser.add_argument('--format', choices=['console', 'json', 'html'],
        default='console', help='Output format (default: console)')
    parser.add_argument('--output', '-o',
        help='Output file path (for json/html)')
    parser.add_argument('--severity',
        choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        help='Minimum severity to report')
    parser.add_argument('--verbose', '-v',
        action='store_true', help='Show each file being scanned')
    parser.add_argument('--stats',
        action='store_true', help='Show per-file finding breakdown after scan')
    args = parser.parse_args()

    print("=" * 55)
    print("  SENTINEL — Static Security Analyzer")
    print("=" * 55)
    print(f"  Target : {args.target}")
    print(f"  Format : {args.format}")
    print("=" * 55 + "\n")

    scanner  = Scanner(args.target, verbose=args.verbose)
    findings = scanner.run()

    # Filter by severity if requested
    severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    if args.severity:
        min_idx  = severity_order.index(args.severity)
        findings = [
            f for f in findings
            if severity_order.index(f.severity) >= min_idx
        ]

    reporter = Reporter(findings, args.target)

    if args.format == 'console':
        reporter.console()
    elif args.format == 'json':
        reporter.json_report(args.output or 'sentinel_report.json')
    elif args.format == 'html':
        reporter.html_report(args.output or 'sentinel_report.html')

    if args.stats:
        reporter.stats()


if __name__ == '__main__':
    main()
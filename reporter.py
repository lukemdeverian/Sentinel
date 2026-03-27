import json
import os
from datetime import datetime

SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

SEVERITY_COLORS = {
    'CRITICAL': '\033[91m',  # bright red
    'HIGH':     '\033[93m',  # yellow
    'MEDIUM':   '\033[94m',  # blue
    'LOW':      '\033[92m',  # green
}
RESET = '\033[0m'
BOLD  = '\033[1m'


class Reporter:
    def __init__(self, findings, target):
        self.findings = findings
        self.target   = target
        self.ts       = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ------------------------------------------------------------------ #
    #  Console                                                             #
    # ------------------------------------------------------------------ #
    def console(self):
        if not self.findings:
            print(f"  {BOLD}No findings. Clean scan.{RESET}\n")
            return

        # Sort: CRITICAL first
        sorted_findings = sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity),
            reverse=True
        )

        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] += 1

        for f in sorted_findings:
            color = SEVERITY_COLORS.get(f.severity, '')
            print(f"{color}{BOLD}[{f.severity}]{RESET} {BOLD}{f.title}{RESET}  ({f.rule_id})")
            print(f"  File : {f.filepath}:{f.line_num}")
            print(f"  Code : {f.line_content[:120]}")
            print(f"  Info : {f.description}")
            if f.cwe:
                print(f"  CWE  : {f.cwe}")
            print()

        # Summary bar
        print("=" * 55)
        print(f"  SUMMARY  —  {len(self.findings)} finding(s)")
        print("=" * 55)
        for sev in reversed(SEVERITY_ORDER):
            if counts[sev]:
                color = SEVERITY_COLORS[sev]
                print(f"  {color}{BOLD}{sev:<10}{RESET}  {counts[sev]}")
        print("=" * 55 + "\n")

    # ------------------------------------------------------------------ #
    #  JSON                                                                #
    # ------------------------------------------------------------------ #
    def json_report(self, outpath):
        data = {
            'tool':      'Sentinel',
            'scanned':   str(self.target),
            'timestamp': self.ts,
            'total':     len(self.findings),
            'findings': [
                {
                    'id':          f.rule_id,
                    'title':       f.title,
                    'severity':    f.severity,
                    'file':        f.filepath,
                    'line':        f.line_num,
                    'code':        f.line_content,
                    'description': f.description,
                    'cwe':         f.cwe,
                }
                for f in sorted(
                    self.findings,
                    key=lambda f: SEVERITY_ORDER.index(f.severity),
                    reverse=True
                )
            ]
        }
        with open(outpath, 'w') as fp:
            json.dump(data, fp, indent=2)
        print(f"  JSON report written to: {outpath}\n")

    # ------------------------------------------------------------------ #
    #  HTML                                                                #
    # ------------------------------------------------------------------ #
    def html_report(self, outpath):
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] += 1

        sorted_findings = sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity),
            reverse=True
        )

        rows = ''
        for f in sorted_findings:
            sev_class = f.severity.lower()
            cwe_link  = (
                f'<a href="https://cwe.mitre.org/data/definitions/'
                f'{f.cwe.replace("CWE-", "")}.html" target="_blank">{f.cwe}</a>'
                if f.cwe else '—'
            )
            rows += f"""
            <tr>
              <td><span class="badge {sev_class}">{f.severity}</span></td>
              <td><strong>{f.rule_id}</strong><br>{f.title}</td>
              <td class="filepath">{f.filepath}<br>Line {f.line_num}</td>
              <td><code>{self._esc(f.line_content[:100])}</code></td>
              <td>{f.description}</td>
              <td>{cwe_link}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sentinel Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e0e0e0; padding: 32px; }}
  h1 {{ font-size: 1.8rem; color: #4fc3f7; margin-bottom: 4px; }}
  .meta {{ color: #888; font-size: 0.85rem; margin-bottom: 28px; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }}
  .card {{ background: #1a1d27; border-radius: 8px; padding: 20px 28px; min-width: 130px; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ font-size: 0.75rem; color: #888; margin-top: 4px; letter-spacing: 1px; }}
  .critical .num {{ color: #ef5350; }}
  .high     .num {{ color: #ffa726; }}
  .medium   .num {{ color: #42a5f5; }}
  .low      .num {{ color: #66bb6a; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1d27; border-radius: 8px; overflow: hidden; }}
  th {{ background: #12151f; color: #4fc3f7; padding: 12px 14px; text-align: left; font-size: 0.8rem; letter-spacing: 1px; }}
  td {{ padding: 12px 14px; border-bottom: 1px solid #252836; vertical-align: top; font-size: 0.875rem; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1f2335; }}
  code {{ background: #12151f; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; color: #80cbc4; word-break: break-all; }}
  .filepath {{ color: #888; font-size: 0.8rem; }}
  .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.5px; }}
  .badge.critical {{ background: #ef5350; color: #fff; }}
  .badge.high     {{ background: #ffa726; color: #000; }}
  .badge.medium   {{ background: #42a5f5; color: #000; }}
  .badge.low      {{ background: #66bb6a; color: #000; }}
  a {{ color: #4fc3f7; }}
  .empty {{ text-align: center; padding: 48px; color: #555; }}
</style>
</head>
<body>
  <h1>🛡 Sentinel — Security Report</h1>
  <div class="meta">Scanned: {self._esc(str(self.target))} &nbsp;|&nbsp; {self.ts} &nbsp;|&nbsp; {len(self.findings)} finding(s)</div>

  <div class="summary">
    <div class="card critical"><div class="num">{counts['CRITICAL']}</div><div class="label">CRITICAL</div></div>
    <div class="card high">   <div class="num">{counts['HIGH']}</div>   <div class="label">HIGH</div></div>
    <div class="card medium"> <div class="num">{counts['MEDIUM']}</div> <div class="label">MEDIUM</div></div>
    <div class="card low">    <div class="num">{counts['LOW']}</div>    <div class="label">LOW</div></div>
  </div>

  {'<table><thead><tr><th>SEVERITY</th><th>RULE</th><th>LOCATION</th><th>CODE</th><th>DESCRIPTION</th><th>CWE</th></tr></thead><tbody>' + rows + '</tbody></table>' if self.findings else '<div class="empty">✓ No findings detected.</div>'}
</body>
</html>"""

        with open(outpath, 'w', encoding='utf-8') as fp:
            fp.write(html)
        print(f"  HTML report written to: {outpath}\n")

    @staticmethod
    def _esc(text):
        return (text.replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;'))
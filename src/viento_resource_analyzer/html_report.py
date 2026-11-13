"""Self-contained, safely escaped HTML report with no remote dependencies."""
from __future__ import annotations
from html import escape

def e(value: object) -> str:
    return escape(str(value), quote=True)

def render_html(report: dict) -> str:
    summary = report['summary']
    cards = ''.join(
        f'<div class="metric"><span>{e(title)}</span><strong class="{css}">{e(value)}</strong></div>'
        for title, value, css in (
            ('Resources', report['resources_scanned'], ''), ('Errors', summary['error'], 'err'),
            ('Warnings', summary['warning'], 'warn'), ('Info', summary['info'], 'inf')))
    findings = ''.join(
        '<tr>'
        f'<td><span class="tag {e(f["severity"])}">{e(f["severity"].upper())}</span></td>'
        f'<td><code>{e(f["code"])}</code></td>'
        f'<td>{e(f["resource"])}</td>'
        f'<td><code>{e(f["file"])}{":" + str(f["line"]) if f["line"] is not None else ""}</code></td>'
        f'<td>{e(f["message"])}</td></tr>' for f in report['findings'])
    edges = ''.join('<tr>'
                    f'<td><code>{e(x["resource"])}</code></td>'
                    f'<td><code>{e(x["dependency"])}</code></td>'
                    f'<td><span class="tag">{e(x["status"])}</span>'
                    f'{" → " + e(x["resolved_to"]) if x.get("resolved_to") and x["resolved_to"] != x["dependency"] else ""}</td></tr>'
                    for x in report.get('dependency_edges', []))
    inventory = ' '.join(f'<code class="name">{e(n)}</code>' for n in report.get('resource_names', []))
    style = '''
:root{color-scheme:dark;--bg:#0b1020;--box:#151e30;--line:#29384f;--txt:#f4f6ff;--muted:#a8b7cc}
*{box-sizing:border-box}body{background:var(--bg);color:var(--txt);font:14px/1.65 system-ui,Segoe UI,Arial;margin:0}
main{max-width:1240px;padding:44px 24px 90px;margin:auto}h1{font-size:clamp(25px,4vw,38px);letter-spacing:-.025em;margin:0 0 3px}h2{margin:35px 0 13px;font-size:20px}
p,.sub,.foot{color:var(--muted)}.brand{color:#b69bff;text-transform:uppercase;font-size:12px;letter-spacing:.12em;font-weight:800}
code{font:12px/1.7 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:26px 0}
.metric{border:1px solid var(--line);border-radius:12px;background:var(--box);padding:17px 20px}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{display:block;font-size:31px;line-height:1.25;margin-top:6px}.metric .err{color:#ff8594}.metric .warn{color:#f4c773}.metric .inf{color:#a7d1ff}
.panel{border:1px solid var(--line);border-radius:12px;background:var(--box);overflow:auto}table{border-collapse:collapse;text-align:left;width:100%}th{background:#1a2840;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}td,th{padding:11px 14px;vertical-align:top;border-bottom:1px solid var(--line)}tr:last-child td{border:0}.tag{background:#2e3b51;border-radius:30px;white-space:nowrap;padding:4px 8px;font-size:10px;font-weight:800;letter-spacing:.05em}.tag.error{background:#51252d;color:#ffb2b9}.tag.warning{background:#544026;color:#f7d18a}.tag.info{background:#273d5e;color:#b7d7ff}
.empty{color:var(--muted);text-align:center;padding:25px}.inventory{padding:16px;line-height:3}.name{background:#202e47;padding:5px 9px;margin-right:6px;border-radius:6px}.foot{font-size:12px;margin-top:25px}
@media(max-width:650px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}main{padding:26px 11px 70px}td,th{padding:8px}}
'''
    if not findings:
        findings = '<tr><td class="empty" colspan="5">No findings from enabled checks</td></tr>'
    if not edges:
        edges = '<tr><td class="empty" colspan="3">No dependencies declared</td></tr>'
    return f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FiveM Resource Analyzer — Report</title><style>{style}</style></head><body><main>
<div class="brand">Static analysis · offline report</div><h1>FiveM Resource Analyzer</h1>
<p>Scan root: <code>{e(report['scan_root'])}</code></p><div class="metrics">{cards}</div>
<h2>Findings</h2><div class="panel"><table><thead><tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Location</th><th>Explanation</th></tr></thead><tbody>{findings}</tbody></table></div>
<h2>Dependencies</h2><div class="panel"><table><thead><tr><th>Resource</th><th>Dependency</th><th>Resolution</th></tr></thead><tbody>{edges}</tbody></table></div>
<h2>Resource inventory</h2><div class="panel inventory">{inventory or '<em>No resources found</em>'}</div>
<p class="foot">Generated locally; no JavaScript or network calls. Static analysis cannot prove that scripts are safe or runtime-correct.</p>
</main></body></html>'''

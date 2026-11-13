"""Self-contained offline HTML dashboard; escape all scanned content.

The only JavaScript is fixed local filter logic, never interpolated from input.
It reads table textContent and writes only textContent/hidden properties.
"""
from __future__ import annotations
from html import escape
from collections import Counter


def e(value: object) -> str:
    return escape(str(value), quote=True)


def render_html(report: dict) -> str:
    summary = report['summary']
    findings_list = report.get('findings', [])
    cards = ''.join(
        f'<div class="metric"><span>{e(title)}</span><strong class="{css}">{e(value)}</strong></div>'
        for title, value, css in (
            ('Resources', report['resources_scanned'], ''), ('Errors', summary['error'], 'err'),
            ('Warnings', summary['warning'], 'warn'), ('Info', summary['info'], 'inf')))
    findings = ''.join(
        '<tr data-finding data-severity="' + e(f['severity']) + '" data-resource="' + e(f['resource']) + '">'
        f'<td><span class="tag {e(f["severity"])}">{e(f["severity"].upper())}</span></td>'
        f'<td><code>{e(f["code"])}</code></td>'
        f'<td>{e(f["resource"])}</td>'
        f'<td><code>{e(f["file"])}{":" + e(f["line"]) if f["line"] is not None else ""}</code></td>'
        f'<td>{e(f["message"])}</td></tr>' for f in findings_list)
    edges = ''.join('<tr>'
                    f'<td><code>{e(x["resource"])}</code></td>'
                    f'<td><code>{e(x["dependency"])}</code></td>'
                    f'<td><span class="tag">{e(x["status"])}</span>'
                    f'{" → " + e(x["resolved_to"]) if x.get("resolved_to") and x["resolved_to"] != x["dependency"] else ""}</td></tr>'
                    for x in report.get('dependency_edges', []))
    startup = ''.join('<tr>'
                      f'<td><code>{e(item["command"])}</code></td>'
                      f'<td><code>{e(item["target"])}</code></td>'
                      f'<td>{e(", ".join(item.get("expanded_resources", [])) or "Not in scan")}</td>'
                      f'<td><code>{e(item["file"])}:{e(item["line"])}</code></td></tr>'
                      for item in report.get('startup_order', []))
    counts_by_resource: dict[str, Counter] = {}
    for item in findings_list:
        counts_by_resource.setdefault(item['resource'], Counter())[item['severity']] += 1
    resource_filter_options = ''.join(
        f'<option value="{e(name)}">{e(name)}</option>'
        for name in sorted(counts_by_resource, key=str.casefold))
    summary_rows = ''.join(
        '<tr><td><code>' + e(name) + '</code></td>'
        + ''.join(f'<td class="number">{counts_by_resource.get(name, {}).get(level, 0)}</td>'
                  for level in ('error', 'warning', 'info')) + '</tr>'
        for name in report.get('resource_names', []))
    if not summary_rows:
        summary_rows = '<tr><td class="empty" colspan="4">No resources found</td></tr>'
    inventory = ' '.join(f'<code class="name">{e(n)}</code>' for n in report.get('resource_names', []))
    if not findings:
        findings = '<tr><td class="empty" colspan="5">No findings from enabled checks</td></tr>'
    if not edges:
        edges = '<tr><td class="empty" colspan="3">No dependencies declared</td></tr>'
    if not startup:
        startup = '<tr><td class="empty" colspan="4">No explicit startup commands in inspected configs</td></tr>'
    style = '''
:root{color-scheme:dark;--bg:#0b0d1d;--panel:#151a2c;--line:#30364d;--txt:#f3f5ff;--muted:#a6b0c5;--accent:#b699ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 10% 0%,#211935 0%,transparent 36%),var(--bg);color:var(--txt);font:14px/1.6 system-ui,Segoe UI,Arial,sans-serif}
main{max-width:1300px;margin:auto;padding:44px 25px 75px}h1{font-size:clamp(28px,4vw,39px);margin:0;letter-spacing:-.025em}h2{font-size:19px;margin:34px 0 12px}p,.muted,.foot{color:var(--muted)}
.brand{color:var(--accent);font-size:11px;letter-spacing:.16em;font-weight:850;text-transform:uppercase}.sub{margin-top:10px}
code{font:12px/1.65 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:25px 0}.metric{border:1px solid var(--line);background:var(--panel);border-radius:10px;padding:16px 20px}.metric span{display:block;font-size:12px;color:var(--muted)}.metric strong{font-size:32px;line-height:1.35}.metric .err{color:#ff8c9b}.metric .warn{color:#ffd08b}.metric .inf{color:#9ecbff}
.panel{border:1px solid var(--line);border-radius:10px;background:var(--panel);overflow:auto}
table{border-collapse:collapse;text-align:left;width:100%}th{background:#1d263d;color:#aebcda;text-transform:uppercase;letter-spacing:.08em;font-size:11px;white-space:nowrap}td,th{padding:10px 13px;border-bottom:1px solid var(--line);vertical-align:top}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#1d253b}
.tag{font-size:11px;border-radius:6px;padding:3px 7px;background:#32415e;color:#dce7ff;white-space:nowrap;font-weight:700}.tag.error{color:#ffb8bf;background:#552833}.tag.warning{color:#ffdca0;background:#55402c}.tag.info{color:#bad9ff;background:#233b5c}.empty{padding:24px;text-align:center;color:var(--muted)}
.tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}.tools input,.tools select{background:#171d30;border:1px solid #424965;color:var(--txt);border-radius:7px;padding:10px 11px;font:inherit}.tools input{min-width:260px;flex:1}.tools select{min-width:140px}.tools label{color:var(--muted)}.tools .count{margin-left:auto;font-size:12px;color:var(--muted)}
.number{text-align:right;font-variant-numeric:tabular-nums}.panel{max-width:100%}#finding-table{table-layout:fixed;min-width:790px}#finding-table th:nth-child(1){width:94px}#finding-table th:nth-child(2){width:190px}#finding-table th:nth-child(3){width:170px}#finding-table th:nth-child(4){width:230px}#finding-table td{overflow-wrap:anywhere}#finding-table td:nth-child(2) code{white-space:nowrap}tr[hidden]{display:none!important}.tools button{background:#2b2350;border:1px solid #62529b;border-radius:7px;color:#f5f0ff;font:inherit;padding:10px 13px;cursor:pointer}.tools button:hover{background:#383063}.inventory{padding:16px;line-height:3}.name{background:#27324e;padding:5px 9px;border-radius:5px;margin-right:5px}.foot{margin-top:20px;font-size:12px}
@media(max-width:700px){main{padding:28px 12px 60px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.tools input{min-width:170px}.tools .count{margin-left:0}td,th{padding:8px}}
'''
    # All JS is authored source; no values from reports are interpolated here.
    js = '''
(function () {
  "use strict";
  const search = document.getElementById("finding-search");
  const severity = document.getElementById("finding-severity");
  const count = document.getElementById("finding-count");
  const resource = document.getElementById("finding-resource");
  const reset = document.getElementById("finding-reset");
  const rows = Array.from(document.querySelectorAll("#finding-table tbody tr[data-finding]"));
  function filter() {
    const needle = search.value.toLocaleLowerCase();
    const chosen = severity.value;
    let visible = 0;
    for (const row of rows) {
      const ok = (chosen === "all" || row.dataset.severity === chosen) &&
        (!resource.value || row.dataset.resource === resource.value) &&
        row.textContent.toLocaleLowerCase().includes(needle);
      row.hidden = !ok;
      if (ok) visible += 1;
    }
    count.textContent = "Showing " + visible + " of " + rows.length + " findings";
  }
  search.addEventListener("input", filter);
  severity.addEventListener("change", filter);
  resource.addEventListener("change", filter);
  reset.addEventListener("click", function () {
    search.value = "";
    severity.value = "all";
    resource.value = "";
    filter();
    search.focus();
  });
  filter();
})();
'''
    cfg_info = f'{e(report.get("cfg_files_scanned", 0))} config files inspected' if report.get('cfg_files_scanned') else 'No server.cfg supplied'
    return f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>FiveM Resource Analyzer — Report</title><style>{style}</style></head><body><main>
<div class="brand">Static analysis · local offline report · v0.4.0</div><h1>FiveM Resource Analyzer</h1>
<p class="sub">Scan root: <code>{e(report['scan_root'])}</code> · {cfg_info}</p>
<div class="metrics">{cards}</div>
<h2>Findings</h2>
<div class="tools"><input id="finding-search" type="search" placeholder="Search resources, rules, file paths…" aria-label="Search findings">
<label for="finding-severity">Severity</label><select id="finding-severity" aria-label="Filter severity"><option value="all">All severities</option><option value="error">Errors</option><option value="warning">Warnings</option><option value="info">Info</option></select>
<label for="finding-resource">Resource</label><select id="finding-resource" aria-label="Filter resource"><option value="">All resources</option>{resource_filter_options}</select>
<button id="finding-reset" type="button">Clear filters</button>
<span class="count" id="finding-count">{len(findings_list)} findings</span></div>
<div class="panel"><table id="finding-table"><thead><tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Location</th><th>Explanation</th></tr></thead><tbody>{findings}</tbody></table></div>
<h2>Resource findings</h2>
<div class="panel"><table><thead><tr><th>Resource</th><th class="number">Errors</th><th class="number">Warnings</th><th class="number">Info</th></tr></thead><tbody>{summary_rows}</tbody></table></div>
<h2>Dependencies</h2><div class="panel"><table><thead><tr><th>Resource</th><th>Dependency</th><th>Resolution</th></tr></thead><tbody>{edges}</tbody></table></div>
<h2>Startup order <span class="muted" style="font-size:12px;font-weight:normal">(static server.cfg interpretation)</span></h2>
<div class="panel"><table><thead><tr><th>Action</th><th>Target</th><th>Resources in scan</th><th>Source</th></tr></thead><tbody>{startup}</tbody></table></div>
<h2>Resource inventory</h2><div class="panel inventory">{inventory or '<em>No resources found</em>'}</div>
<p class="foot">Local offline report. Search/filter runs only in your browser, with no network requests. Config values are never included. Static analysis cannot prove runtime safety, correct boot order, or actual resmon performance. Review reports before sharing.</p>
</main><script type="text/javascript">{js}</script></body></html>'''

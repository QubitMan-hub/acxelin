import json
import tempfile
from pathlib import Path
from collections import Counter
from html import escape as e

from . import __version__, cbom
from .brand import page, tier

MARK = {"critical": "■■■■", "high": "■■■□", "medium": "■■□□", "low": "■□□□", "ok": "□□□□"}

def _code(text):
    """Escapes text and renders `backticked` parts as code."""
    parts = e(text).split("`")
    return "".join(f"<code>{p}</code>" if i % 2 else p for i, p in enumerate(parts))


def _plural(n, word):
    return f"{n} {word}{'s' * (n != 1)}"


def endpoints_html(eps):
    if not eps:
        return ""
    rows = []
    for ep in eps:
        if ep.get("error"):
            rows.append(f"<tr><td>{e(ep['target'])}</td><td colspan=5 class=dim>unreachable: {e(ep['error'])}</td></tr>")
            continue
        pq = ", ".join(ep.get("pq_groups", []))
        others = [g for g in ep.get("groups", []) if g not in ep.get("pq_groups", [])]
        legacy = ", ".join(ep.get("legacy", []))
        extra = ep.get("cert") or ", ".join(ep.get("hostkeys", [])[:4])
        if "observed" in ep:
            extra = f"{_plural(ep['observed'], 'handshake')} captured; {ep.get('clients_offering_pq', 0)} client(s) offered a PQ group"
        rows.append(f"<tr><td>{e(ep['target'])}</td><td>{e(ep.get('version') or '')}</td>"
                    f"<td>{'<span class=yes>yes, ' + e(pq) + '</span>' if pq else 'no'}</td><td>{e(ep.get('preferred_group') or 'unknown')}</td>"
                    f"<td class=w>{e(', '.join(others[:8]))}</td><td class=w>{e(extra)}{'<br>legacy accepted: ' + e(legacy) if legacy else ''}</td></tr>")
    return f"""<h2>Live endpoints</h2><div class="scroll" tabindex="0"><table><thead><tr><th>Endpoint</th><th>Version</th><th>Hybrid PQ key exchange</th>
<th>Preferred group</th><th>Classical groups accepted</th><th>Certificate or host keys</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"""


def policy_html(c):
    if not c:
        return ""
    rows = []
    for v in c["violations"]:
        due = "<span class='tag critical'>overdue</span>" if v["overdue"] else f"<span class=tag>{v['deadline']}</span>"
        rows.append(f"<tr><td>{due}</td><td>{e(v['rule'])}</td><td><b>{e(v['asset']) or 'whole scan'}</b></td><td class=w>{e(v['message'])}</td>"
                    f"<td class='w dim'>{e(', '.join(v['files'][:3]))}</td></tr>")
    verdict = "passes" if c["passed"] else f"fails: {_plural(c['overdue'], 'rule')} already broken"
    return (f"<h2>Policy</h2><p>Checked against {e(', '.join(c['profiles']) or 'own rules')} as of {c['as_of']}: <span class=yes>{verdict}</span>, "
            f"{c['upcoming']} more due later.</p><div class=scroll tabindex=0><table><thead><tr><th>Due</th><th>Rule</th><th>Asset</th><th>Why</th><th>Where</th></tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=5 class=dim>No rule broken.</td></tr>'}</tbody></table></div>")


def html(r):
    st, rd = r.stats, r.readiness
    rows = []
    for index, a in enumerate(r.assets):
        locs = sorted({s.file for s in a.detections})
        new = ("<span class=new>new</span>" if a.new_files else "") + ("<span class=new title='only named in an algorithm list or table, not seen in use'>declared</span>" if a.declared else "")
        rows.append(f"""<tr class="{a.tier}" data-asset="{index}" data-tier="{e(a.tier)}" data-count="{len(a.detections)}" data-confidence="{a.confidence}"><td>{tier(a.tier)}</td><td><a href="#asset-{index}"><b>{e(a.variant)}</b></a>{new}</td>
<td class="w">{e(a.why)}</td><td class="w">{e(a.action) or '<span class="dim">none needed</span>'}</td><td>{e(a.exposure)}</td>
<td>{len(a.detections)} in {_plural(len(locs), 'place')}</td><td>{a.confidence:.2f}</td></tr>""")
    detail = []
    for index, a in enumerate(r.assets):
        occ = "".join(f"<div><code>{e(s.file)}{':' + str(s.line) if s.line else ''}</code> {e(s.evidence)}, {e(s.reason)}<br>{e(s.snippet)}</div>" for s in a.detections[:60])
        fixes = "".join(f"<div><b>{e(w)}</b>: {_code(f)}</div>" for w, f in a.remedies)
        impact = a.params.get("code_impact")
        context = ("<div class='fix'><b>Static migration impact</b><p>Functions: " + e(", ".join(impact["functions"])) +
                   "</p><p>Callers: " + e(", ".join(impact["callers"]) or "none resolved") + "</p><p class=dim>" + e(impact["basis"]) + "</p></div>") if impact else ""
        fixes = context + f"<div class='fix'><span class=tag>How to fix</span>{fixes}</div>" if fixes else context
        detail.append(f"""<details id="asset-{index}"><summary>{tier(a.tier)} <b>{e(a.variant)}</b> <span class='dim'>{e(a.nist)}</span></summary>{fixes}<div class='occ'>{occ}</div></details>""")
    alerts = "".join(f"<div class='alert'><span><span class='tag {e(s)}'>{e(s)}</span></span><div>{e(t)}<br><span class='dim'>{e(w)}{'; ' + e(f) if f else ''}</span></div></div>"
                     for s, t, w, f in r.alerts) or "<p class='dim'>No hygiene alerts.</p>"
    pats = "".join(f"<tr><td><span class='tag {e(p.severity)}'>{e(p.severity)}</span></td><td><b>{e(p.title)}</b><br><span class=dim>{e(p.rule)}, {e(p.cwe)}</span></td>"
                   f"<td><code>{e(p.file)}:{p.line}</code><br><span class=dim>{e(p.snippet)}</span></td><td class=w>{e(p.fix)}</td></tr>" for p in r.patterns)
    libs = "".join(f"<tr><td>{e(l.name)}</td><td>{e(l.ecosystem)}</td><td>{e(l.version) or '<span class=dim>unpinned</span>'}</td>"
                   f"<td>{_plural(len(l.used_in), 'file')}</td><td>{'yes' if l.pq else ''}</td><td class='dim w'>{e(l.manifest)}{'<br>' + e(l.note) if l.note else ''}</td></tr>" for l in r.libraries)
    q = [s for s in r.detections if s.verdict != "accepted"]
    why = Counter(s.reason for s in q)
    quar = "".join(f"<div><code>{e(s.file)}:{s.line}</code> {e(s.algo)}, {e(s.verdict)}: {e(s.reason)}<br>{e(s.snippet)}</div>" for s in q[:300])
    tiers, hz = rd["tiers"], st["horizon"]
    changed = [a for a in r.assets if a.new_files]
    base = ""
    if r.baseline:
        items = "".join(f"<div><b>{e(a.variant)}</b> <span class='dim'>{e(a.tier)}</span><br><span class='dim'>{e(', '.join(a.new_files[:8]))}</span></div>" for a in changed)
        base = f"<h2>New since baseline</h2><div class='occ' style='margin-left:0'>{items or '<p class=dim>Nothing new since the baseline.</p>'}</div>"
    scanned = st['files_code'] + st['files_config'] + st['files_artifacts'] + st['files_binary']
    pol = policy_html(r.compliance)
    body = f"""<div class="stats">
<div><span>Scanned</span><b>{scanned + st['endpoints']}</b><small>{_plural(scanned, 'file')} and {_plural(st['endpoints'], 'endpoint')} checked against the rule base</small></div>
<div><span>Detectors</span><b>{st['raw_detections']}</b><small>raw detections, noisy by design</small></div>
<div><span>Verified</span><b>{st['accepted']}</b><small>verified; {st['quarantined']} held, {st['rejected']} rejected, {st['suppressed']} suppressed</small></div>
<div><span>Act first</span><b>{tiers['critical'] + tiers['high']}</b><small>assets to act on first; {st['promoted_on_second_look']} promoted on second look, {_plural(st['references_followed'], 'key trail')} followed</small></div>
</div>
<div class="ready">
<div>Asymmetric assets that are quantum-safe: {rd['pq_safe']} of {rd['asymmetric']}<div class="bar"><i style="width:{rd['percent']}%"></i></div></div>
<div>Hybrid PQ key exchange seen: {'yes' if rd['hybrid'] else 'no'}</div>
<div class="dim">Assumptions: {hz['shelf_life']:g}y data shelf life, {hz['migration']:g}y migration, CRQC by {hz['crqc_year']} ({hz['years_to_crqc']}y)</div>
</div>
{endpoints_html(r.endpoints)}
{base}
{pol}
<h2>Migration queue</h2>
<p>Priorities are scanner assessments, not proof of runtime protection. Inspect the asset's evidence before changing a system.</p>
<div class="tools" id="queue-tools" hidden><label>Search findings<input id="finding-search" type="search" placeholder="Algorithm, exposure, recommendation"></label>
<label>Priority<select id="finding-tier"><option value="">All priorities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>ok</option></select></label>
<label>Sort by<select id="finding-sort"><option value="priority">Migration priority</option><option value="asset">Asset name</option><option value="count">Most detections</option><option value="confidence">Highest confidence</option></select></label>
<button id="finding-export" type="button">Export filtered CSV</button><button id="finding-reset" type="button">Reset filters</button><span id="finding-count" role="status" aria-live="polite"></span></div>
<div class="scroll" tabindex="0"><table><thead><tr><th>Tier</th><th>Asset</th><th>Why</th><th>Do this</th><th>Exposure</th><th>Seen</th><th>Conf.</th></tr></thead>
<tbody id="migration-rows">{''.join(rows) or '<tr><td colspan=7 class=dim>No cryptography found.</td></tr>'}</tbody></table></div>
<p id="finding-empty" hidden>No findings match. Clear the search or choose All priorities.</p>
<h2>Hygiene alerts</h2>{alerts}
<h2>Security patterns</h2>
<p class="dim">Rules matched one line at a time on code without comments: a starting point for review, not taint tracking. Test code is ranked low.</p>
<div class="scroll" tabindex="0"><table><thead><tr><th>Severity</th><th>Pattern</th><th>Where</th><th>Fix</th></tr></thead>
<tbody>{pats or '<tr><td colspan=4 class=dim>No security patterns matched.</td></tr>'}</tbody></table></div>
<h2>Where each asset lives</h2>{''.join(detail)}
<h2>Crypto libraries</h2>
<div class="scroll" tabindex="0"><table><thead><tr><th>Library</th><th>Source</th><th>Version</th><th>Imported by</th><th>PQ-capable</th><th>Where declared</th></tr></thead>
<tbody>{libs or '<tr><td colspan=6 class=dim>No known crypto libraries declared.</td></tr>'}</tbody></table></div>
<h2>Held back by verification</h2>
<p class="dim">{'; '.join(f'{v} {k}' for k, v in why.most_common())}</p>
<details><summary>Show {len(q)} detections that did not enter the CBOM</summary><div class="occ">{quar}</div></details>
{''.join(f'<p class="dim">{e(n)}</p>' for n in r.notes)}""" + INTERACTIVE
    sub = f"Cryptographic inventory and quantum migration plan, scanned in {st['seconds']}s."
    return page(f"{r.project}: Acxelin Readiness", "Cryptographic inventory", r.project, e(sub), body,
                "CycloneDX 1.6 CBOM in cbom.json, SARIF 2.1.0 in readiness.sarif, full audit trail in findings.json, static code relationships in relationships.json")


def terminal(r):
    st, rd = r.stats, r.readiness
    out = [f"\nacxelin-readiness {__version__}  {r.project}",
           f"detectors {st['raw_detections']} raw  ->  verify {st['accepted']} verified, {st['quarantined']} held, {st['rejected']} rejected, "
           f"{st['suppressed']} suppressed  ->  rank {st['promoted_on_second_look']} promoted, {st['references_followed']} trails  ->  {len(r.assets)} assets",
           f"quantum-safe asymmetric: {rd['pq_safe']}/{rd['asymmetric']} ({rd['percent']}%)   hybrid KEX: {'yes' if rd['hybrid'] else 'no'}"]
    cov = st.get("coverage") or {}
    if cov.get("files"):
        gaps = ", ".join(f"{n} {k}" for k, n in cov["not_read"].items())
        out.append(f"coverage: {cov['read']}/{cov['files']} source and configuration files analysed ({cov['percent']}%)" + (f"; not read: {gaps}" if gaps else ""))
    for ep in r.endpoints:
        if ep.get("error"):
            out.append(f"  endpoint {ep['target']}: unreachable ({ep['error']})")
        else:
            out.append(f"  endpoint {ep['target']}: {ep.get('version')}, PQ groups: {', '.join(ep.get('pq_groups', [])) or 'none'}, preferred {ep.get('preferred_group')}")
    out.append("")
    w = max([len(a.variant) for a in r.assets] + [10])
    for a in r.assets:
        tag = " new" if a.new_files else " decl" if a.declared else "    "
        out.append(f"  {MARK[a.tier]}  {a.tier:<8} {a.variant:<{w}}{tag}  {a.exposure:<28} {len(a.detections):>3}x  {a.action[:60]}")
    if r.alerts:
        out.append("")
        for s, t, where, _ in r.alerts:
            out.append(f"  ! {s:<8} {t}  ({where})")
    if r.patterns:
        out.append("")
        for p in r.patterns[:20]:
            out.append(f"  ! {p.severity:<8} {p.rule} {p.title}  ({p.file}:{p.line})")
        if len(r.patterns) > 20:
            out.append(f"  ! ... {len(r.patterns) - 20} more security patterns in report.html and readiness.sarif")
    if r.compliance:
        c = r.compliance
        out.append(f"\npolicy ({', '.join(c['profiles']) or 'own rules'}, as of {c['as_of']}): "
                   f"{'passes' if c['passed'] else 'FAILS'}, {c['overdue']} overdue, {c['upcoming']} due later")
        for v in c["violations"][:12]:
            out.append(f"  {'overdue ' if v['overdue'] else 'by ' + str(v['deadline']):<8} {v['rule']:<22} {v['asset'] or '(whole scan)'}: {v['message']}")
    for n in r.notes:
        out.append(f"  note: {n}")
    return "\n".join(out)


# Static script: scan content is escaped HTML, never interpolated into JavaScript.
INTERACTIVE = """<script>
(() => {
  const $ = id => document.getElementById(id), body = $("migration-rows");
  const rows = [...body.querySelectorAll("tr[data-asset]")], priorities = {critical:0,high:1,medium:2,low:3,ok:4};
  $("queue-tools").hidden = false;
  const draw = () => {
    const query = $("finding-search").value.toLowerCase(), tier = $("finding-tier").value, sort = $("finding-sort").value;
    const ordered = rows.slice().sort((a,b) => sort === "asset" ? a.cells[1].textContent.localeCompare(b.cells[1].textContent) :
      sort === "count" ? Number(b.dataset.count) - Number(a.dataset.count) : sort === "confidence" ? Number(b.dataset.confidence) - Number(a.dataset.confidence) :
      priorities[a.dataset.tier] - priorities[b.dataset.tier]);
    let visible = 0;
    for (const row of ordered) {
      row.hidden = !!((tier && row.dataset.tier !== tier) || !row.textContent.toLowerCase().includes(query));
      const detail = $("asset-" + row.dataset.asset);
      detail.hidden = row.hidden;
      if (!row.hidden) visible++;
      body.append(row);
    }
    $("finding-count").textContent = `${visible} of ${rows.length} assets`;
    $("finding-empty").hidden = visible !== 0 || rows.length === 0;
  };
  $("finding-search").oninput = draw; $("finding-tier").onchange = draw; $("finding-sort").onchange = draw;
  $("finding-reset").onclick = () => { $("finding-search").value = ""; $("finding-tier").value = ""; $("finding-sort").value = "priority"; draw(); };
  for (const row of rows) row.querySelector("a").onclick = () => { $("asset-" + row.dataset.asset).open = true; };
  $("finding-export").onclick = () => {
    const csv = [["Priority","Asset","Why","Next action","Exposure","Detections","Confidence"],
      ...[...body.querySelectorAll("tr[data-asset]")].filter(r => !r.hidden).map(r => [...r.cells].map(c => c.textContent.trim()))]
      .map(row => row.map(v => '"' + (/^[\\s]*[=+@-]/.test(v) ? "'" : "") + v.replace(/"/g, '""') + '"').join(",")).join("\\r\\n");
    const url = URL.createObjectURL(new Blob([csv], {type:"text/csv;charset=utf-8"})), a = document.createElement("a");
    a.href = url; a.download = "migration.csv"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  draw();
})();
</script>"""

def write_results(out, name, r):
    """Publish complete individual artifacts atomically from private staging."""
    payloads = {
        "cbom.json": json.dumps(cbom.build(name, r.assets, r.artifacts, r.libraries, r.endpoints), indent=2),
        "readiness.sarif": json.dumps(cbom.sarif(r.assets, r.alerts, r.patterns), indent=2),
        "findings.json": json.dumps(cbom.audit(r.detections, r.notes) | {"stats": r.stats, "readiness": r.readiness, "compliance": r.compliance,
                                                                       "patterns": [p.as_dict() for p in r.patterns]}, indent=2, default=str),
        "relationships.json": json.dumps(r.relationships, indent=2),
        "report.html": html(r),
    }
    with tempfile.TemporaryDirectory(prefix=".acxelin_readiness-", dir=out) as staging:
        for filename, value in payloads.items():
            temporary = Path(staging) / filename
            temporary.write_text(value, encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(out / filename)

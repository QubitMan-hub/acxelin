"""Compliance evidence: every certificate, endpoint and CBOM asset mapped to NIST IR 8547 and NSA CNSA 2.0.

NIST IR 8547 (initial public draft, November 2024): quantum-vulnerable public-key algorithms at 112-bit security are deprecated
after 2030 and all of them are disallowed after 2035; ML-KEM and ML-DSA are the replacements.
CNSA 2.0 (NSA, 2022, updated 2024): ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384/512, used exclusively by the category's deadline.
"""
import csv
import datetime as dt
import html
import io
import json
import re
import sys
from pathlib import Path

from acxelin_core.pki import algorithm_of

from .endpoints import key_name
from cryptography import x509

from . import __version__
from .brand import page as _page

CNSA2_DEADLINE = {"tls": 2033, "ssh": 2033, "pki": 2033, "code": 2033}
CNSA2_CATEGORY = {"tls": "web browsers, servers and cloud services", "ssh": "operating systems and services", "pki": "certificates and signing",
                  "code": "custom applications and legacy software"}
CNSA2_ALGORITHMS = ("ML-KEM-1024", "ML-DSA-87", "AES-256", "SHA-384", "SHA-512", "LMS", "XMSS")
LIMIT = 64_000_000
STATUS = {"action": "action needed", "plan": "quantum-vulnerable: plan its migration", "transition": "quantum-safe, classical fallback still allowed",
          "note": "not used for security (declared in code)", "ready": "quantum-safe"}
KINDS = {"tls": "TLS endpoints", "ssh": "SSH endpoints", "pki": "Certificates", "code": "Code and systems"}
DORA_RTS = "Delegated Regulation (EU) 2024/1774 "
CONTROLS = {"tls": ("PR.DS-02", 6), "ssh": ("PR.DS-02", 6), "pki": ("PR.AA-03", 7), "code": ("ID.RA-01", 6)}
FRAMEWORK_NOTE = ("The framework columns name the control each row is evidence for: NIST CSF 2.0 (PR.DS-02 data in transit, PR.AA-03 "
                  "authentication, ID.RA-01 vulnerabilities), DORA's ICT risk management standard (Delegated Regulation (EU) 2024/1774, Art. 6 "
                  "encryption, Art. 7 key management) and NIS2 Art. 21(2)(h) (cryptography). They show what the evidence supports; they are not a "
                  "compliance verdict.")


def _row(kind, name, detail, status, nist, cnsa2, evidence):
    csf, article = CONTROLS[kind]
    return {"kind": kind, "name": name, "detail": detail, "status": status, "nist_ir_8547": nist, "cnsa2": cnsa2,
            "cnsa2_deadline": CNSA2_DEADLINE[kind], "evidence": evidence,
            "frameworks": {"NIST CSF 2.0": csf, "DORA": f"{DORA_RTS}Art. {article}", "NIS2": "Art. 21(2)(h)"}}


def csv_text(header, rows):
    """CSV a spreadsheet opens as text: a cell starting with = + - @ or a control character gets a leading apostrophe."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(header)
    for row in rows:
        w.writerow(["'" + c if isinstance(c, str) and c[:1] in ("=", "+", "-", "@", "\t", "\r") else "" if c is None else c for c in row])
    return out.getvalue()


def to_csv(rep):
    f = lambda r, k: r.get("frameworks", {}).get(k, "")
    return csv_text(["Area", "Asset", "Status", "NIST IR 8547", "CNSA 2.0", "NIST CSF 2.0", "DORA", "NIS2", "Evidence"],
                    [[KINDS[r["kind"]], r["name"], STATUS[r["status"]], r["nist_ir_8547"], r["cnsa2"], f(r, "NIST CSF 2.0"), f(r, "DORA"), f(r, "NIS2"), r["detail"]]
                     for r in rep["items"]])


def certificates(folder):
    """Rows for every certificate in the PEM files of `folder`; files that hold none are skipped."""
    folder, now, out = Path(folder), dt.datetime.now(dt.timezone.utc), []
    for f in sorted(p for p in folder.rglob("*") if p.is_file() and p.stat().st_size <= 1_000_000):
        data = f.read_bytes()
        try:
            certs = x509.load_pem_x509_certificates(data)
        except ValueError:
            try:
                certs = [x509.load_der_x509_certificate(data)]
            except ValueError:
                continue
        for c in certs:
            name = next((str(a.value) for a in c.subject if a.oid == x509.NameOID.COMMON_NAME), f.stem)
            try:
                key = c.public_key()
                algo = algorithm_of(key) or key_name(key)
            except Exception:  # noqa: BLE001 - a key type this library cannot load (GOST, SM2, a new OID) is still a certificate
                algo = c.public_key_algorithm_oid.dotted_string
            expired, when = c.not_valid_after_utc < now, c.not_valid_after_utc.date().isoformat()
            detail = f"certificate, {algo}, {'expired' if expired else 'expires'} {when}"
            evidence = {"serial": format(c.serial_number, "x"), "file": f.name}
            if expired:
                out.append(_row("pki", name, detail, "action", "expired: renew it", "expired", evidence))
            elif algo.startswith("DSA") or algo.startswith("RSA-") and int(algo[4:] or 0) < 2048:
                out.append(_row("pki", name, detail, "action", "disallowed now (NIST SP 800-131A, FIPS 186-5): replace it", "needs ML-DSA-87", evidence))
            elif algo.startswith("ML-DSA"):
                out.append(_row("pki", name, detail, "ready", "approved (FIPS 204)", "compliant" if algo == "ML-DSA-87" else "needs ML-DSA-87", evidence))
            else:
                out.append(_row("pki", name, detail, "plan", "quantum-vulnerable public key: deprecated after 2030 (112-bit), disallowed after 2035", "needs ML-DSA-87", evidence))
    if not out:
        raise ValueError(f"no certificates found in {folder}; give a folder of PEM files")
    return out


def endpoints(results):
    out = []
    for r in results:
        kind = r.get("protocol", "tls")
        if r["grade"] == "F":
            out.append(_row(kind, r["target"], f"unreachable: {r.get('error')}", "action", "unknown", "unknown", {"grade": "F"}))
            continue
        key = (r.get("certificate") or {}).get("key", "")
        classical_key = kind == "tls" and not key.startswith("ML-DSA")
        status = {"A": "ready", "B": "transition", "C": "action"}[r["grade"]]
        if status == "ready" and classical_key:
            status = "transition"
        nist = ("classical key exchange: disallowed after 2035" if r["grade"] == "C" else
                "classical fallback accepted: remove before 2035" if r["grade"] == "B" else "post-quantum key exchange")
        if classical_key and key:
            nist += f"; {key} certificate: deprecated after 2030 (112-bit), disallowed after 2035"
        if r.get("legacy"):
            status, nist = "action", nist + f"; {' and '.join(r['legacy'])} accepted: disallowed now (NIST SP 800-52r2)"
        out.append(_row(kind, r["target"], f"negotiates {r.get('negotiated')}; accepts {', '.join(r['accepts'])}" + (f"; key {key}" if key else ""),
                        status, nist, "compliant" if r.get("cnsa2") else "not compliant", {"grade": r["grade"]}))
    return out


def code(path):
    """Rows from a scan or any other tool's CBOM: an output folder (cbom.json, plus findings.json for security patterns) or a cbom.json file. Each row cites where the asset was seen and, when known, which functions reach it.
    A component without Readiness's priority gets one estimated from its algorithm; a name the catalogue does not know is left out.
    The priority decides `action`; otherwise the NIST status decides between quantum-safe and quantum-vulnerable. Certificate
    components are left out: their key and signature algorithms are rows of their own."""
    path = Path(path)
    folder = path if path.is_dir() else path.parent
    bom, findings = _load(path / "cbom.json" if path.is_dir() else path), folder / "findings.json"
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("components"), list):
        raise ValueError(f"{path} is not a CycloneDX CBOM; give a scan's output folder or its cbom.json")
    project = str(((bom.get("metadata") or {}).get("component") or {}).get("name") or folder.name)
    out, warned = [], False
    for c in bom["components"]:
        if not isinstance(c, dict) or c.get("type") != "cryptographic-asset":
            continue
        props = {p.get("name"): str(p.get("value", "")) for p in c.get("properties") or [] if isinstance(p, dict)}
        old = {"acxelin:" + k.removeprefix("wolfpack:"): v for k, v in props.items() if k.startswith("wolfpack:") and "acxelin:" + k.removeprefix("wolfpack:") not in props}
        if old and not warned:
            warned = print(f"acxelin-readiness: {path}: read through the old wolfpack:* property names; scan again to write acxelin:* names", file=sys.stderr) or True
        props |= old  # old prefix, read through 1.x
        tier, name = props.get("acxelin:tier"), str(c.get("name", "?"))
        estimated = tier is None
        if estimated:  # another tool's CBOM: a priority from the algorithm alone, as merge and the console's import do
            from .catalog import nist_status
            from .inventory import algo_of, estimate
            algo = algo_of(name)
            tier = estimate(algo, name)
            if tier is None:
                continue
            size = re.search(r"(?<![\w.])(\d{3,5})(?![\w.])", name)  # 256 of AES-256-GCM, 2048 of RSA-2048
            props.setdefault("acxelin:nist-status", nist_status(algo, {"key_size": int(size.group(1))} if size else {}))
        nist = props.get("acxelin:nist-status")
        safe = nist.startswith(("Quantum-safe", "Acceptable")) if nist else tier in ("ok", "low")
        status = "note" if "(declared non-security)" in name else "action" if tier in ("critical", "high") else "ready" if safe else "plan"
        nist = nist or "not classified"
        seen = [f"{o.get('location')}:{o.get('line')}" if o.get("line") else str(o.get("location")) for o in (c.get("evidence") or {}).get("occurrences") or []
                if isinstance(o, dict)]
        try:
            callers = json.loads(props.get("acxelin:code-impact") or "{}").get("callers") or []
        except (ValueError, AttributeError):
            callers = []
        where = ", ".join(seen[:3]) + (f" and {len(seen) - 3} more" if len(seen) > 3 else "")
        detail = f"{project}: {props.get('acxelin:usage', 'used')} in {where or 'unknown location'}; {props.get('acxelin:exposure', 'code')}"
        detail += f"; reached from {', '.join(map(str, callers[:3]))}" if callers else ""
        detail += f"; next: {props['acxelin:recommendation']}" if props.get("acxelin:recommendation") else ""
        cnsa = any(name.startswith(a) and not name[len(a):].startswith("/") for a in CNSA2_ALGORITHMS)  # SHA-512/224 is not SHA-512
        out.append(_row("code", name, detail, status, nist, "compliant" if cnsa else "not a CNSA 2.0 algorithm",
                        {"project": project, "tier": tier, "estimated": estimated, "locations": seen[:20], "callers": callers[:20]}))
    report = _load(findings) if findings.is_file() else {}
    for p in report.get("patterns", []) if isinstance(report, dict) else []:
        if isinstance(p, dict) and p.get("severity") in ("critical", "high"):
            out.append(_row("code", f"{p.get('rule')} {p.get('title')}", f"{project}: {p.get('file')}:{p.get('line')} ({p.get('cwe')}); fix: {p.get('fix')}",
                            "action", "undermines the protection of whatever algorithm is chosen", "not compliant",
                            {"project": project, "pattern": p.get("rule"), "locations": [f"{p.get('file')}:{p.get('line')}"]}))
    return out


def _load(path):
    with open(path, "rb") as f:
        raw = f.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError(f"{path} is larger than {LIMIT // 1_000_000} MB")
    try:
        return json.loads(raw)
    except ValueError:
        raise ValueError(f"{path} is not valid JSON") from None


def report(rows):
    counts = {s: sum(r["status"] == s for r in rows) for s in STATUS}
    return {"generated": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(), "assets": len(rows), "status": counts,
            "cnsa2_compliant": sum(r["cnsa2"] == "compliant" for r in rows), "items": rows}


def to_html(rep, title="Post-quantum readiness"):
    """A dashboard over the same rows the JSON holds: what to do first, each area at a glance, then every asset with a filter."""
    e = html.escape
    cls = {"ready": "ok", "transition": "warn", "plan": "warn", "action": "bad", "note": "mute"}
    s, items = rep["status"], rep["items"]
    order = sorted(items, key=lambda r: (list(STATUS).index(r["status"]), r["evidence"].get("tier") != "critical", list(KINDS).index(r["kind"]), r["name"]))
    tiles = "".join(f"<div class=tile><span>{label}</span><b class={tone}>{value}</b></div>" for label, value, tone in (
        ("need action", s["action"], "bad"), ("quantum-vulnerable, plan", s["plan"], "warn"), ("classical fallback allowed", s["transition"], "warn"),
        ("quantum-safe", s["ready"], "ok"), ("meet CNSA 2.0", rep["cnsa2_compliant"], "")) if value or tone in ("bad", "ok"))
    first = [r for r in order if r["status"] == "action"][:8]
    todo = "".join(f"<li><span class='pill bad'>{e(KINDS[r['kind']])}</span> <b>{e(r['name'])}</b>: {e(r['nist_ir_8547'])}<br><small>{e(r['detail'])}</small></li>"
                   for r in first) or "<li class=ok>Nothing needs action now.</li>"
    more = s["action"] - len(first)
    areas = "".join(f"<tr><td>{e(KINDS[k])}</td><td>{len(rows)}</td>" + "".join(f"<td class={cls[st] if n else 'mute'}>{n}</td>" for st in STATUS for n in [sum(r['status'] == st for r in rows)])
                    + f"<td>{CNSA2_DEADLINE[k]}<br><small>{e(CNSA2_CATEGORY[k])}</small></td></tr>"
                    for k in KINDS for rows in [[r for r in items if r["kind"] == k]] if rows)
    rows = "".join(
        f"<tr data-status={r['status']}><td>{e(KINDS[r['kind']])}</td><td><b>{e(r['name'])}</b></td><td><span class='pill {cls[r['status']]}'>{e(STATUS[r['status']])}</span></td>"
        f"<td>{e(r['nist_ir_8547'])}</td><td class={'ok' if r['cnsa2'] == 'compliant' else 'mute'}>{e(r['cnsa2'])}</td>"
        f"<td><small>{e(' · '.join(f'{k} {v.removeprefix(DORA_RTS)}' for k, v in r.get('frameworks', {}).items()))}</small></td>"
        f"<td><small>{e(r['detail'])}</small></td></tr>"
        for r in order)
    options = "".join(f"<option value={k}>{e(v)}</option>" for k, v in STATUS.items() if s[k])
    sub = ("Every certificate, endpoint and CBOM asset you included, mapped to NIST IR 8547 (draft: quantum-vulnerable public-key "
           "algorithms deprecated after 2030 at 112-bit strength, disallowed after 2035) and NSA CNSA 2.0 (ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512 by "
           "each category's deadline). Code and system rows are static evidence from a scan or another tool's CBOM, not proof of runtime use.")
    body = (f"<div class=tiles>{tiles}</div>"
            f"<section class=panel><h2>Do these first</h2><ul class=todo>{todo}</ul>{f'<p><small>{more} more below.</small></p>' if more > 0 else ''}</section>"
            f"<section class=panel><h2>By area</h2><div class=scroll tabindex=0 role=region aria-label='Assets by area'><table><thead><tr><th>Area</th><th>Assets</th>"
            + "".join(f"<th>{e(v)}</th>" for v in STATUS.values()) + f"<th>CNSA 2.0 deadline</th></tr></thead><tbody>{areas}</tbody></table></div></section>"
            f"<section class=panel><h2>Every asset</h2><div class=filters hidden><label>Search<input id=q type=search placeholder='name, file, algorithm'></label>"
            f"<label>Status<select id=st><option value=''>All</option>{options}</select></label><span id=n role=status></span></div>"
            f"<div class=scroll tabindex=0 role=region aria-label='Every asset'><table><thead><tr><th>Area</th><th>Asset</th><th>Status</th><th>NIST IR 8547</th><th>CNSA 2.0</th><th>Frameworks</th><th>Evidence</th></tr></thead>"
            f"<tbody id=rows>{rows}</tbody></table></div><p><small>{e(FRAMEWORK_NOTE)}</small></p></section>" + DASHBOARD)
    return _page(title, "Readiness assessment", title, e(sub), body, f"Acxelin Readiness {__version__}")


DASHBOARD = """<style>.todo{list-style:none;display:grid;gap:10px}.todo small{color:var(--mute)}.filters{display:flex;flex-wrap:wrap;gap:12px;padding:12px 18px;border-bottom:1px solid var(--line)}
.filters label{display:grid;gap:4px;font-size:12px;color:var(--mute)}.filters input,.filters select{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink)}
#n{align-self:end;font-size:12px;color:var(--mute)}td small{display:block;max-width:60ch}</style>
<script>(() => { const f = document.querySelector('.filters'), q = document.getElementById('q'), st = document.getElementById('st'), n = document.getElementById('n');
const rows = [...document.querySelectorAll('#rows tr')]; f.hidden = false;
const draw = () => { let shown = 0; for (const r of rows) { r.hidden = (st.value && r.dataset.status !== st.value) || !r.textContent.toLowerCase().includes(q.value.toLowerCase()); shown += !r.hidden; } n.textContent = shown + ' of ' + rows.length; };
q.oninput = draw; st.onchange = draw; draw(); })();</script>"""


def to_json(rep):
    return json.dumps(rep, indent=1, default=str)

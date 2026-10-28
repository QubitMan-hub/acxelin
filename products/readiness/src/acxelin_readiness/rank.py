import posixpath
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .catalog import CATALOG, SHOR, LEGACY, GROVER, SAFE, HYBRIDS, classical_bits, nist_status
from .detectors import config, iter_files, read, rel, DENY
from .detectors.lexer import LANGS

TIERS = ["critical", "high", "medium", "low", "ok"]
WEIGHT = {t: 40 - 10 * i for i, t in enumerate(TIERS)}
EXPOSURE = [("live", "live network endpoint", 5), ("config", "deployed configuration", 4), ("artifact", "key or certificate material", 3.5), ("binary", "compiled artifact", 3),
            ("call", "application code", 3), ("constant", "application code", 3), ("identifier", "application code", 2.5),
            ("import", "application code", 2), ("string", "application code", 2)]
CONFIDENTIALITY = {"pke", "key-agree", "kem", "protocol", "other"}


LOOKS = ("flow", "registries", "siblings")
NOISE = re.compile(r"\b(print\w*|log\w*|debug|info|warn\w*|error|trace|format|printf|append|equals\w*|contains|includes|startsWith|endsWith|assert\w*|expect"
                   r"|flag\.\w+|add_argument|add_option|getenv|JsonProperty\w*|SerializedName|DataMember|bench\w*|perf\w*|PerfCase|describe|it|test\w*|do_table)\s*\(", re.I)




def siblings(detections):
    """A literal like "RS256" yields RSA and SHA-256; if one half is accepted, so is the other."""
    key = lambda s: (s.file, s.line, s.params.get("literal"))
    ok = {}
    for s in detections:
        if s.verdict == "accepted" and s.evidence == "string":
            ok[key(s)] = ok.get(key(s), True) and "declared" in s.context
    n = 0
    for s in detections:
        if s.verdict == "quarantined" and s.evidence == "string" and key(s) in ok:
            s.verdict, s.confidence, s.reason = "accepted", 0.7, "same literal as an accepted detection"
            if ok[key(s)]:
                s.context.add("declared")
            n += 1
    return n


def list_name(ls, first):
    """Name of the variable a list is assigned to, read from the nearest code line at or above its first entry."""
    for k in range(first, max(0, first - 8), -1):
        if k > len(ls):
            continue
        line = ls[k - 1].split("#")[0].split("//")[0]
        m = re.search(r"([A-Za-z_][\w.]*)['\"]?\s*(?::[^=\n]{1,40})?(?::=|=|:)\s*[\[({]", line)
        if m:
            return m.group(1)
    return ""


def sniffs(ls, name, after):
    """True when every later use of the list searches for its entries inside other data: format recognition, not declared support."""
    n = re.escape(name.split(".")[-1])
    needle = re.compile(rf"(?i)\.(?:startswith|endswith|find|index|search|match)\(\s*(?:tuple\(\s*)?{n}\b"
                        rf"|\b(\w+)\s+in\s+[\w.\[\]()]+\s+for\s+\1\s+in\s+{n}\b")
    loop = re.compile(rf"\bfor\s*\(?\s*(?:[\w<>\[\]]+\s+)?(?:_\s*,\s*)?(\w+)\s*(?:in|:|:=\s*range)\s+{n}\b")
    uses = [k for k in range(after, len(ls)) if re.search(rf"\b{n}\b", ls[k])]
    for k in uses:
        m = loop.search(ls[k])
        body = "\n".join([ls[k][m.end():]] + ls[k + 1:k + 4]) if m else ""
        if not (needle.search(ls[k]) or m and re.search(rf"(?i)(?:startswith|endswith|hasprefix|hassuffix|contains|includes|indexof)\(\s*(?:[\w.]+\s*,\s*)?{m.group(1)}\b"
                                                          rf"|\b{m.group(1)}\s+in\s+\w", body)):
            return False
    return bool(uses)


def clusters(detections, lines, size=3, gap=2):
    """Runs of three or more string literals on nearby lines: the entries of one list or table, with its variable name."""
    by_file = defaultdict(list)
    for s in detections:
        if s.evidence == "string" and s.verdict in ("quarantined", "accepted") and s.line:
            by_file[s.file].append(s)
    for f, group in by_file.items():
        group.sort(key=lambda s: s.line)
        cluster = [group[0]]
        for s in group[1:] + [None]:
            if s is not None and s.line - cluster[-1].line <= gap:
                cluster.append(s)
                continue
            if len({c.line for c in cluster}) >= size:
                yield f, cluster, list_name(lines(f), cluster[0].line)
            cluster = [s] if s is not None else []


def registries(detections, lines):
    """An algorithm list or table is declared support, unless it is a deny-list or a format sniffer."""
    n = 0
    for f, cluster, name in clusters(detections, lines):
        if DENY.search(name) or name and sniffs(lines(f), name, cluster[-1].line):
            continue
        for c in cluster:
            if c.verdict == "quarantined":
                c.verdict, c.confidence, c.reason = "accepted", 0.65, f"part of an algorithm list of {len(cluster)} entries (lines {cluster[0].line}-{cluster[-1].line})"
                n += 1
            if c.verdict == "accepted" and not c.reason.startswith("second look"):
                c.context.add("declared")
    return n


def recognise(detections, lines):
    """The ranking's last word on lists: entries of a list used only to sniff formats are held, however they got in."""
    n = 0
    for f, cluster, name in clusters(detections, lines):
        if name and sniffs(lines(f), name, cluster[-1].line):
            for c in cluster:
                if c.verdict == "accepted":
                    c.verdict, c.confidence, c.reason = "quarantined", 0.35, f"entry of {name}, a list used only to recognise formats"
                    n += 1
    return n


def flows(detections, lines, threshold=0.6):
    """Held string literals are accepted only if the literal visibly flows into a call."""
    promoted = 0
    for s in detections:
        if s.verdict != "quarantined" or s.evidence != "string":
            continue
        if "flows" in s.context:
            s.verdict, s.confidence, s.reason = "accepted", max(threshold, 0.7), "second look: the constant reaches a crypto call (followed through the syntax tree)"
            promoted += 1
            continue
        ls = lines(s.file)
        if not (0 < s.line <= len(ls)):
            continue
        line = ls[s.line - 1]
        lits = re.findall(r"""(['"`])(.*?)\1""", line)
        hit = None
        for _, lit in lits:
            e = re.escape(lit)
            m = re.match(r"\s*(?:(?:const|let|var|final|static|private|public|protected|readonly|val)\s+)*(?:[\w<>\[\]]+\s+)?([A-Za-z_]\w*)\s*[:=]\s*(?:[rbuRBU]{1,2})?['\"`]" + e, line)
            if m:
                var = re.escape(m.group(1))
                for k in range(s.line, min(len(ls), s.line + 40)):
                    if (re.search(r"\w\s*\([^)]*\b" + var + r"\b", ls[k]) and not NOISE.search(ls[k])) or re.search(r"\b\w+\s*=\s*" + var + r"\b\s*[,)]", ls[k]):
                        hit = f"constant {m.group(1)} flows into a call on line {k + 1}"
                        break
            elif re.search(r"\w\s*\([^)]*['\"`]" + e + r"['\"`]", line) and not NOISE.search(line) or re.search(
                    r"(alg\w*|cipher\w*|hash\w*|digest\w*|curve\w*|kex\w*|sig\w*|scheme\w*|transformation\w*|protocol\w*|padding\w*)['\"]?\s*(?::[^=\n]{1,40})?[:=]\s*[\[(]?\s*['\"`]" + e, line, re.I):
                hit = "literal is passed directly into a call or algorithm setting"
            elif re.search(r"^\s*case\s+['\"`]" + e + r"['\"`]\s*:", line) or re.search(
                    r"(alg\w*|cipher\w*|hash\w*|digest\w*|curve\w*|kex\w*|sig\w*|scheme\w*|mode\w*)\s*===?\s*['\"`]" + e + r"['\"`]", line, re.I):
                hit = "code branches on the literal"
            if hit:
                break
        if hit:
            s.verdict, s.confidence, s.reason = "accepted", max(threshold, 0.7), f"second look: {hit}"
            promoted += 1
    return promoted


def second_look(detections, lines, threshold=0.6):
    """The rank sends the pipeline back over what the verify held. Returns how many detections each look promoted."""
    run = {"flow": lambda: flows(detections, lines, threshold), "registries": lambda: registries(detections, lines),
           "siblings": lambda: siblings(detections)}
    return {k: run[k]() for k in LOOKS}


def follow_references(root, arts, detections, scope=False):
    """Ranking's scan: find where keys and certificates are referenced, so deployed material is weighted as deployed."""
    local = [a for a in arts if "://" not in a.file]
    if not local or not Path(root).is_dir():
        return 0
    names = defaultdict(list)
    for a in local:
        names[Path(a.file).name].append(a)
    rx = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(n) for n in names) + r")(?![\w-])")
    found = 0
    for p in iter_files(root, scope):
        if p.suffix.lower() not in LANGS and not config.is_config(p):
            continue
        text = read(p)
        if not text:
            continue
        r = rel(root, p)
        for m in rx.finditer(text):
            start = m.start()
            while start and (text[start - 1].isalnum() or text[start - 1] in "._-/\\"):
                start -= 1
            for a in referenced(names[m.group(1)], r, text[start:m.end()]):
                line = text.count("\n", 0, m.start()) + 1
                a.details.setdefault("referenced_by", []).append(f"{r}:{line}")
                found += 1
                if config.is_config(p):
                    for s in detections:
                        if s.file == a.file:
                            s.context.add("deployed")
    return found


def referenced(candidates, by, written):
    """Which of the files sharing a name a reference means: the path as written from the referring file's folder, else the
    files whose path ends with the most of what was written (a bare name shared by several files names them all)."""
    ref = written.replace("\\", "/")
    own = posixpath.normpath(posixpath.join(posixpath.dirname(by), ref)) if not ref.startswith("/") else None
    exact = [a for a in candidates if a.file == own and a.file != by]
    if exact:
        return exact
    want = [x for x in ref.split("/") if x not in ("", ".", "..")]
    tail = lambda f: next((n for n in range(len(want), 0, -1) if f.split("/")[-n:] == want[-n:]), 0)
    scored = [(tail(a.file), a) for a in candidates if a.file != by]
    best = max((n for n, _ in scored), default=0)
    return [a for n, a in scored if n == best and n]


@dataclass
class Horizon:
    shelf_life: float = 10
    migration: float = 5
    crqc_year: int = 2035

    @property
    def z(self):
        return self.crqc_year - datetime.now(timezone.utc).year


def exposure(a):
    if any("deployed" in s.context for s in a.detections):
        return "deployed key or certificate", 4.5
    evs = {s.evidence for s in a.detections}
    for ev, label, w in EXPOSURE:
        if ev in evs:
            return label, w
    return "application code", 2


def declared_non_security(a):
    """Every use of this asset was declared not for security (Python's usedforsecurity=False): a checksum or cache key."""
    return all(s.params.get("purpose") == "non-security" for s in a.detections)


def trust_stores(arts, least=5):
    """Files of five or more certificates, every one self-signed, and nothing else: roots the project trusts, not keys it holds."""
    by = defaultdict(list)
    for a in arts:
        by[a.file].append(a)
    return {f: g for f, g in by.items() if "://" not in f and len(g) >= least and all(a.kind == "certificate" and a.details.get("self_signed") for a in g)}


def assess(a, h, hybrid_files):
    c = CATALOG[a.algo]
    bits = classical_bits(a.algo, a.params)
    label, w = exposure(a)
    a.exposure = label
    a.nist = nist_status(a.algo, a.params)
    a.action = c.replace
    weak_hash = a.params.get("hash") in ("MD5", "SHA-1") and c.primitive in ("signature", "pke")
    if c.threat == LEGACY or (bits is not None and bits < 112) or a.params.get("mode") == "ECB" or weak_hash:
        tier = "critical" if w >= 3 else "high"
        if a.params.get("mode") == "ECB":
            a.why = "ECB mode leaks plaintext structure; broken today regardless of quantum"
            a.action = "Switch to AES-256-GCM (authenticated, randomized)"
        elif weak_hash:
            a.why = f"Signature over {a.params['hash']}, which has practical collision attacks"
            a.action = "Re-sign with SHA-256 or stronger now; plan ML-DSA migration"
        elif bits is not None and bits < 112 and c.threat != LEGACY:
            a.why = f"About {bits}-bit classical security, below NIST's 112-bit floor"
            a.action = "Rotate to at least 3072-bit now, then migrate to " + c.replace
        else:
            a.why = "Broken or disallowed today, independent of any quantum computer"
    elif c.threat == SHOR:
        conf = c.primitive in CONFIDENTIALITY or a.params.get("padding") == "oaep"
        z = h.z
        if conf and h.shelf_life + h.migration > z:
            tier = "high"
            a.why = (f"Harvest now, decrypt later: data needs {h.shelf_life:g}y secrecy + {h.migration:g}y migration "
                     f"= {h.shelf_life + h.migration:g}y, but a CRQC is assumed in {z}y (Mosca)")
        elif not conf and h.migration > z:
            tier = "high"
            a.why = f"Signature migration ({h.migration:g}y) exceeds assumed time to a CRQC ({z}y)"
        else:
            tier = "medium"
            a.why = "Breakable by Shor's algorithm on a future quantum computer" + ("" if conf else "; no harvest-now risk for signatures, but forgery risk once a CRQC exists")
        if a.algo == "ECC":
            a.why += ". Key use (signing or key agreement) not determined, so confidentiality is assumed"
        if a.algo in ("TLS 1.3", "X25519", "X448", "ECDH", "DH") and {s.file for s in a.detections} <= hybrid_files:
            if a.algo == "TLS 1.3":
                tier, a.why, a.action = "ok", "TLS 1.3 with a hybrid ML-KEM group configured alongside it", ""
            else:
                tier = "medium"
                a.why = "Classical fallback next to a configured hybrid PQ group; keep only while peers lack hybrid support"
                a.action = "Remove once clients support X25519MLKEM768"
    elif c.threat == GROVER and (bits or 0) >= 192:
        tier = "ok"
        a.why = "At least 96-bit security even against Grover"
        a.action = ""
    elif c.threat == GROVER:
        tier = "low"
        a.why = "Grover halves effective strength; fine for most data, prefer 256-bit for long-lived secrets"
        if a.algo == "AES" and not a.params.get("key_size"):
            a.why = "Key size not visible statically; AES-128 is acceptable, AES-256 preferred for long-lived data"
    else:
        tier = "ok"
        a.why = "Quantum-safe" if c.primitive in ("kem", "signature") else "No known quantum break at this strength"
        a.action = ""
    if a.params.get("purpose") == "password":
        a.why = "Weak fast hash in a password-hasher implementation; confirm whether this hasher is enabled"
        a.action = "Use Argon2id or scrypt with an appropriate work factor and migrate stored password hashes; a plain SHA-256 replacement is not sufficient"
    for s in a.detections:
        if s.params.get("purpose") == "non-security":
            s.context.add("non-security")
    if tier in ("critical", "high", "medium") and declared_non_security(a):
        tier = "low"
        a.why = "Declared not for security (usedforsecurity=False), so a checksum or cache key; this is the developer's statement, not verified"
        a.action = "Keep it out of passwords, signatures and integrity checks"
    if tier in ("critical", "high", "medium") and all("trust-store" in s.context for s in a.detections):
        tier = "low"
        a.why = "Root certificates in a trust store: keys the project trusts, not keys it holds"
        a.action = "Update the bundle; post-quantum roots arrive with CA updates"
    if a.test_only and tier in ("critical", "high", "medium"):
        tier = TIERS[TIERS.index(tier) + 1]
        a.why += " (test code only)"
    a.tier = tier
    a.score = round(WEIGHT[tier] + w + a.confidence, 2)
    return a


def alerts(arts, libs, detections, stores=None):
    out, stores = [], stores or {}
    now = datetime.now(timezone.utc)
    for f, g in stores.items():
        out.append(("info", f"Trust store of {len(g)} root certificates ({summary(g)}); ranked low", f"{f}:1", "Keep the bundle up to date"))
    for art in arts:
        if art.file in stores:
            continue
        test = any("test" in s.context for s in detections if s.file == art.file)
        if art.kind == "private-key" and not art.file.startswith("tls://"):
            sev = "high" if test else "critical"
            enc = " (encrypted)" if art.details.get("encrypted") else ""
            refs = art.details.get("referenced_by", [])
            used = f"; loaded by {', '.join(refs[:3])}" if refs else ""
            out.append((sev, f"Private key{enc} stored in repository{used}", f"{art.file}:{art.line}", "Move to a secrets manager or HSM and rotate the key"))
        if art.kind == "certificate":
            na = datetime.fromisoformat(art.details["not_after"])
            if na < now:
                out.append(("high", f"Expired certificate ({art.details['subject'][:60]})", f"{art.file}:{art.line}", "Reissue"))
            elif art.algo in CATALOG and CATALOG[art.algo].threat == SHOR and na.year > 2030:
                out.append(("medium", f"Certificate valid past 2030 with quantum-vulnerable {art.algo} key", f"{art.file}:{art.line}",
                            "Shorten validity or reissue under an ML-DSA or hybrid hierarchy"))
    for lib in libs:
        if lib.note:
            out.append(("high" if "CVE" in lib.note or "Unmaintained" in lib.note else "low", f"{lib.name}: {lib.note}", f"{lib.manifest}:{lib.line}", ""))
        if not lib.used_in:
            out.append(("info", f"{lib.name} is declared but no import was found", f"{lib.manifest}:{lib.line}", "Remove it or confirm indirect use"))
    return sorted(out, key=lambda x: (TIERS + ["info"]).index(x[0]))


def summary(g):
    n = defaultdict(int)
    for a in g:
        n[a.algo] += 1
    return ", ".join(f"{v} {k}" for k, v in sorted(n.items(), key=lambda x: -x[1]))


def readiness(assets):
    asym = [a for a in assets if CATALOG[a.algo].primitive in ("pke", "signature", "key-agree", "kem", "other")]
    safe = [a for a in asym if CATALOG[a.algo].threat == SAFE]
    return {"asymmetric": len(asym), "pq_safe": len(safe), "percent": round(100 * len(safe) / len(asym)) if asym else 0,
            "hybrid": any(a.algo in HYBRIDS for a in assets),
            "tiers": {t: sum(1 for a in assets if a.tier == t) for t in TIERS}}


def lead(assets, h):
    hybrid = {s.file for a in assets if a.algo in HYBRIDS for s in a.detections}
    for a in assets:
        assess(a, h, hybrid)
    return sorted(assets, key=lambda a: (-a.score, a.variant))

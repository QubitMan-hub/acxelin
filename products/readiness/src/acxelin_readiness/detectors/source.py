import ast
import re
from collections import defaultdict
from pathlib import Path

from ..catalog import lookup, pq_from_text, parse_transformation, parse_symmetric_name, named_hash, AMBIGUOUS, MODES
from ..model import Detection
from . import iter_files, rel, is_test, read, names as named, pyflow
from .lexer import LANGS, split, line_of
from .pysrc import scan_python
from .rules import RULES
from .suites import sig_scheme, ssh_token, noise_name, jose_alg, kms_spec

WORD = re.compile(r"\b(?:TLS ?v?1\.[0-3]|SSL ?v?[23]|SHA-?(?:1|224|256|384|512)|SHA3-\d+|MD[45]|[A-Z][A-Za-z0-9-]{1,20})\b")
SSH_LIKE = re.compile(r"^(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|ecdh-sha2-nistp\d+|rsa-sha2-(?:256|512)|hmac-(?:sha|md5)[\w-]*|diffie-hellman-[\w-]+|curve25519-sha256|sntrup761x25519-sha512|mlkem768x25519-sha256|(?:aes\d+|3des|chacha20-poly1305)[\w-]*@openssh\.com|(?:aes\d+|3des)-(?:ctr|cbc|gcm))(?:@[\w.]+)?$")
SIG_LIKE = re.compile(r"^(?:\w+with\w+|(?:RS|PS|ES|HS)(?:256|384|512)|(?:RSA|ECDSA)-SHA\d+|EdDSA)$")


class Ctx:
    def __init__(self, path, text, lang, sink, comment=False):
        self.path, self.text, self.lang, self.sink, self.comment = path, text, lang, sink, comment
        self.lines = text.splitlines()
        self.line = 0

    def window_text(self, n):
        return "\n".join(self.lines[self.line - 1:self.line - 1 + n])

    def attach(self, params, algos, window=15):
        if self.comment:
            return
        for s in reversed(self.sink):
            if s.file == self.path and s.algo in algos and 0 <= self.line - s.line <= window and "comment" not in s.context:
                for k, v in params.items():
                    if v is not None and not s.params.get(k):
                        s.params[k] = v
                return


def _emit(sink, path, lang, line, lines, algo, params, evidence, detector, ctx):
    if not algo:
        return
    snip = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
    sink.append(Detection(algo=algo, file=path, line=line, evidence=evidence, detector=detector, snippet=snip, lang=lang,
                         params={k: v for k, v in params.items() if v is not None}, context=set(ctx)))


DECL = re.compile(r"""(?m)^[ \t]*(?:(?:export|public|private|protected|internal|static|final|const|readonly|let|var|val|pub)\s+)*"""
                  r"""(?:[A-Za-z_][\w<>\[\]]*\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w&']+\s*)?:?=\s*(["'`])([^"'`\n]{1,80})\2\s*[;,]?[ \t]*$""")


CONST_DECL = re.compile(r"""(?m)^[ \t]*(?:(?:export|public|private|protected|internal|static|pub)\s+)*(?:final|const|readonly)\s+"""
                        r"""(?:(?:static|final|readonly|const|val)\s+)*(?:[A-Za-z_][\w<>\[\]]*\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w&']+\s*)?=\s*"""
                        r"""(?:(["'`])([^"'`\n]{1,80})\2|(\d{2,5}))\s*[;,]?[ \t]*$""")
DEFINE = re.compile(r'(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+(?:"([^"\n]{1,80})"|\(?(\d{2,5})\)?)[ \t]*$')
INCLUDE = re.compile(r'(?m)^[ \t]*#[ \t]*include[ \t]*"([^"]+)"')


def constants(code, fixed_only=False):
    """Constants a file declares, as {name: (source text to inline, end offset)}. Numbers only from declarations that cannot change."""
    out = {}
    if not fixed_only:
        for m in DECL.finditer(code):
            out.setdefault(m.group(1), (f'"{m.group(3)}"', m.end()))
    for m in CONST_DECL.finditer(code):
        out.setdefault(m.group(1), (f'"{m.group(3)}"' if m.group(2) else m.group(4), m.end()))
    for m in DEFINE.finditer(code):
        out.setdefault(m.group(1), (f'"{m.group(2)}"' if m.group(2) else m.group(3), m.end()))
    return out


CHAIN = re.compile(r"(?<![\w.$])[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")
ASSIGNED = re.compile(r"\s*:?=[^=]")


def propagate(code, shared=None):
    """Inlines constants into later uses, keeping line structure intact. `shared` holds constants reachable from other files."""
    consts = constants(code)
    for k, v in (shared or {}).items():
        consts.setdefault(k, (v, -1))
    consts = {k: v for k, v in consts.items() if len(k) > 1}
    if not consts:
        return code

    def sub(m):
        parts = m.group(0).split(".")
        for n in range(len(parts), 0, -1):
            name = ".".join(parts[:n])
            if name in consts:
                val, end = consts[name]
                stop = m.start() + len(name)
                if m.start() > end and not ASSIGNED.match(code, stop):
                    return val + m.group(0)[len(name):]
                break
        return m.group(0)
    return CHAIN.sub(sub, code)


def shared_constants(root, scope=False):
    """Constants other files can reach: Owner.NAME in Java, Kotlin and C# (Owner is the declaring file), pkg.Name in Go,
    and #define macros per C header. A name declared with two different values is dropped rather than guessed."""
    qualified, headers = defaultdict(set), defaultdict(lambda: defaultdict(set))
    for p in iter_files(root, scope):
        lang = LANGS.get(p.suffix.lower())
        if lang not in ("java", "csharp", "go", "c"):
            continue
        text = read(p)
        if not text:
            continue
        code = split(text, lang)[0]
        consts = constants(code, fixed_only=True)
        if lang == "c":
            if p.suffix.lower() in (".h", ".hpp"):
                for k, (v, _) in consts.items():
                    headers[p.name][k].add(v)
            continue
        owner = p.stem
        if lang == "go":
            m = re.search(r"(?m)^package\s+(\w+)", code)
            if not m:
                continue
            owner = m.group(1)
            consts = {k: v for k, v in consts.items() if k[0].isupper()}
        for k, (v, _) in consts.items():
            qualified[f"{owner}.{k}"].add(v)
    settle = lambda table: {k: next(iter(v)) for k, v in table.items() if len(v) == 1}
    return settle(qualified), {h: settle(t) for h, t in headers.items()}


JS_IMPORT = re.compile(r"""(?:import\s*\{([^}]*)\}\s*from|(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\()\s*['"](\.{1,2}/[^'"]+)['"]""")
JS_EXPORT = re.compile(r"""(?m)^[ \t]*export\s+const\s+([A-Za-z_$][\w$]*)\s*(?::\s*\w+\s*)?=\s*(["'`])([^"'`\n]{1,80})\2""")


def js_imports(root, p, code):
    """Constants a JavaScript or TypeScript module imports by name from a relative module that exports them as `export const`."""
    out = {}
    for m in JS_IMPORT.finditer(code):
        base = (p.parent / m.group(3)).resolve()
        target = next((c for c in (base, *(base.with_name(base.name + e) for e in (".js", ".ts", ".mjs", ".cjs")), base / "index.js", base / "index.ts")
                       if c.is_file()), None)
        if target is None or root not in target.parents:
            continue
        exported = {e.group(1): f'"{e.group(3)}"' for e in JS_EXPORT.finditer(split(read(target) or "", "js")[0])}
        for name in re.split(r"\s*,\s*", (m.group(1) or m.group(2)).strip()):
            src, _, alias = name.partition(" as ") if " as " in name else name.partition(":")
            if src.strip() in exported:
                out[(alias or src).strip()] = exported[src.strip()]
    return out


def run_rules(path, text, lang, sink, base_ctx, comment=False):
    ctx = Ctx(path, text, lang, sink, comment)
    for rx, fn in RULES.get(lang, []):
        for m in rx.finditer(text):
            ctx.line = line_of(text, m.start())
            res = fn(m, ctx) or []
            for r in res:
                algo, params = r[0], r[1]
                ev = r[2] if len(r) > 2 else "call"
                c = set(base_ctx) | ({"comment"} if comment else set())
                _emit(sink, path, lang, ctx.line, ctx.lines, algo, params, ev, "source", c)


def classify_literal(v):
    v = v.strip()
    if not v or len(v) > 200 or v.startswith(("http://", "https://", "/", "./")):
        return [], False
    if len(v) > 40 or v.count(" ") >= 2:
        hits = []
        for w in WORD.findall(v):
            if w.upper() in AMBIGUOUS or len(w) < 3:
                continue
            a = lookup(w) or pq_from_text(w)
            if a:
                hits.append((a, {}))
        return hits, True
    if SSH_LIKE.match(v):
        hits = [(a, p) for a, p in ssh_token(v) if a]
        if v.lower().startswith(("ssh-rsa", "ssh-dss")):
            return [(a, {k: x for k, x in p.items() if k != "hash"}) for a, p in hits[:1]], False
        return hits, False
    if SIG_LIKE.match(v):
        return sig_scheme(v), False
    for parse in (noise_name, jose_alg, kms_spec):
        hits = parse(v)
        if hits:
            return hits, False
    if "/" in v:
        a, p = parse_transformation(v)
        return ([(a, p)] if a else []), False
    if re.sub(r"[-_\s/.]", "", v).upper() in AMBIGUOUS:
        return [], False
    a = lookup(v) or pq_from_text(v)
    if a:
        return [(a, {"hash": named_hash(v)} if a in ("HMAC", "PBKDF2") and named_hash(v) else {})], False
    if re.match(r"(?i)^(aes|des|3des|chacha20|rc4|bf)[-_]", v) and all(
            t.isdigit() or t.upper() in MODES or t.upper() in ("EDE", "EDE3", "POLY1305") for t in re.split(r"[-_]", v)[1:]):
        a, p = parse_symmetric_name(v)
        return ([(a, p)] if a else []), False
    return [], False


def glued(text, lit):
    i = text.find(lit)
    while i >= 0:
        if text[i + len(lit):].lstrip().startswith("+") or text[:i].rstrip().endswith("+"):
            return True
        i = text.find(lit, i + 1)
    return False


def concatenated(val, text):
    """A literal glued to a runtime value ("RSA-SHA" + bits, "PBKDF2WithHmac" + name): only its complete parts are known.
    A fragment the value may finish ("SHA-" + bits) is ambiguous and never guessed."""
    if not val.strip() or "+" not in text or not any(glued(text, q + val + q) for q in "'\"`"):
        return None
    parts = [p for p in re.split(r"[-_/\s.]+|(?<=[a-z0-9])(?=[A-Z])", val) if p]
    return [(a, {}) for a in dict.fromkeys(lookup(p) for p in parts if p.upper() not in AMBIGUOUS and len(p) > 2) if a]


SWITCHED_OFF = re.compile(r"(?i)(?<![a-z0-9])NO_(?:SSL|TLS)v?\d|![ \t]*(?:SSL|TLS)v\d|\bdisabled?_?(?:protocols?|versions?)\b")


def string_scout(path, lang, strings, lines, sink, base_ctx, docs):
    off = {}
    for line, val in strings:
        text = lines[line - 1] if 0 < line <= len(lines) else ""
        glued = concatenated(val, text) if text else None
        hits, prose = (glued, False) if glued is not None else classify_literal(val)
        if line not in off:
            off[line] = bool(SWITCHED_OFF.search(text))
        if off[line]:  # SSL_FLAG_TBL_INV("TLSv1", SSL_OP_NO_TLSv1): the name of what is being turned off
            hits = [(a, p) for a, p in hits if not re.match(r"(?:TLS|SSL) \d", a or "")]
        for a, p in hits:
            c = set(base_ctx)
            if prose:
                c.add("prose")
            if line in docs:
                c.add("doc")
            _emit(sink, path, lang, line, lines, a, dict(p, literal=val), "string", "strings", c)


def scan_file(root, p, sink, shared=((), {}), unparsed=None, on_python=None, on_source=None, parse_python=None, flow=None, on_code=None):
    lang = LANGS.get(p.suffix.lower())
    if not lang:
        return False
    text = read(p)
    if text is None:
        return False
    path = rel(root, p)
    aliases = on_source(path, text, lang) if on_source else None
    base = {"test"} if is_test(path) else set()
    lines = text.splitlines()
    code, comments, strings, docs = split(text, lang)
    if on_code:
        on_code(path, text, lang, (code, comments, strings, docs))
    if lang == "python":
        found = scan_python(path, text, on_tree=on_python, **({"parse": parse_python} if parse_python else {}), flow=flow.view(path) if flow else None)
        if found is None and unparsed is not None:
            unparsed.append(path)
        for algo, ln, ev, snip, params in found or []:
            _emit(sink, path, lang, ln, lines, algo, params, ev, "source", base | ({"doc"} if ln in docs else set()))
    else:
        qualified, headers = shared
        reach = {k: v for h in INCLUDE.findall(code) for k, v in headers.get(Path(h).name, {}).items()} if lang == "c" else dict(qualified)
        if lang == "js":
            reach.update(js_imports(Path(root).resolve(), p.resolve(), code))
        run_rules(path, propagate(code, reach), lang, sink, base)
        run_rules(path, comments, lang, sink, base, comment=True)
    if lang != "hash":
        for ln, a in named.scan(code, lang, path, aliases or ()):
            _emit(sink, path, lang, ln, lines, a, {}, "identifier", "names", base | ({"doc"} if ln in docs else set()))
    if lang != "hash":
        for ln, a in named.symbols(code, lang, path):
            _emit(sink, path, lang, ln, lines, a, {}, "identifier", "symbols", base | ({"doc"} if ln in docs else set()))
    string_scout(path, lang, strings, lines, sink, base, docs)
    for m in re.finditer(r"[^\n]+", comments):
        for a, p in classify_literal(m.group(0))[0] if len(m.group(0).strip()) > 3 else []:
            _emit(sink, path, lang, line_of(comments, m.start()), lines, a, p, "string", "strings", base | {"comment"})
    return True


def scan(root, scope=False, unparsed=None, on_python=None, on_source=None, parse_python=None, parse_index=None, on_code=None, notes=None):
    """`unparsed` collects Python files this interpreter cannot parse (newer syntax); only their strings and comments are read."""
    sink, n = [], 0
    shared = shared_constants(root, scope)
    flow = pyflow.Index(root, scope, parse_index or ast.parse)
    if flow.limited and notes is not None:
        notes.append(f"Over {pyflow.LARGE} Python files: values are followed one import away from crypto code, not across the whole project, "
                     "to keep memory bounded; a value passed through more modules is not seen.")
    for p in iter_files(root, scope):
        n += scan_file(root, p, sink, shared, unparsed, on_python, on_source, parse_python, flow, on_code)
    for s in sink:
        if s.evidence == "string" and flow.used.get((s.file, s.line)) == s.params.get("literal"):
            s.context.add("flows")
    return sink, n

"""Values passed through parameters: `digest(data, "SHA-512")` reaching `MessageDigest.getInstance(alg)` inside `digest`.

A crypto API called with a parameter is resolved from the literal arguments at the function's call sites. Python is
handled by the syntax tree instead (pyflow), which also follows constants and caller parameters. The rebuilt call
(`MessageDigest.getInstance("SHA-512")`) goes through the ordinary language rules, so this module holds no algorithm knowledge.
"""
import re
from collections import defaultdict

from ..model import Detection
from . import iter_files, rel, is_test, read
from .lexer import LANGS, split, line_of
from .rules import RULES

IDENT = r"[A-Za-z_$][\w$]*"
SINKS = {
    "java": rf"\b((?:Cipher|MessageDigest|Mac|Signature|KeyPairGenerator|KeyGenerator|KeyAgreement|SecretKeyFactory|KeyFactory)\.getInstance)\(\s*({IDENT})\s*[,)]",
    "js": rf"\b((?:crypto\.)?create(?:Hash|Hmac|Cipheriv|Decipheriv|Sign|Verify))\(\s*({IDENT})\s*[,)]",
}
DEFS = {
    "java": re.compile(rf"\b({IDENT})\s*\(([^()]*)\)\s*(?:throws\s+[\w.,\s]+)?\{{"),
    "js": re.compile(rf"(?:\bfunction\s+({IDENT})\s*\(([^()]*)\)|\b({IDENT})\s*[:=]\s*(?:async\s*)?(?:function\s*)?\(([^()]*)\)\s*(?:=>)?|^\s*(?:async\s+)?({IDENT})\s*\(([^()]*)\)\s*\{{)", re.M),
}
KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "new", "synchronized", "using", "lock", "foreach"}
LITERAL = re.compile(r"""^\s*(["'`])([^"'`\\\n]{1,80})\1\s*$""")


def params_of(text):
    """Parameter names in order, from Java/C#/JS parameter lists (types, defaults and annotations stripped)."""
    names = []
    for p in split_args(text):
        p = re.sub(r"=.*$|:.*$", "", p.strip()).replace("...", "")
        m = re.search(rf"({IDENT})\s*$", p)
        if m:
            names.append(m.group(1))
    return names


def split_args(text):
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    return out + [cur] if cur.strip() else out


def enclosing(code, pos, lang, name):
    """(function name, index of `name` among its parameters) for the nearest function above `pos` that takes `name`."""
    best = None
    for m in DEFS[lang].finditer(code, 0, pos):
        fn = next(g for g in m.groups()[0::2] if g)
        args = next(g for g in m.groups()[1::2] if g is not None)
        if fn in KEYWORDS:
            continue
        ps = params_of(args)
        if name in ps:
            best = (fn, ps.index(name))
    return best if best and best[1] >= 0 else None


NAME = re.compile(r"[A-Za-z_$][\w$]*")


def call_args(code, fn):
    """Argument lists of every call to `fn` in `code` (not its definition)."""
    for m in re.finditer(rf"(?<![\w$])(?<!def ){re.escape(fn)}\s*\(", code):
        before = code[max(0, m.start() - 20):m.start()]
        if re.search(r"(?:function|def|void|public|private|protected|static)\s+$", before):
            continue
        depth, j = 1, m.end()
        while j < len(code) and depth and j - m.end() < 2000:
            depth += {"(": 1, ")": -1}.get(code[j], 0)
            j += 1
        yield split_args(code[m.end():j - 1])


def scan(root, scope=False):
    files = defaultdict(list)
    for p in iter_files(root, scope):
        lang = LANGS.get(p.suffix.lower())
        if lang in SINKS:
            text = read(p)
            if text:
                files[lang].append((rel(root, p), text, split(text, lang)[0]))
    sink = []
    for lang, group in files.items():
        rx, seen, mentions = re.compile(SINKS[lang]), {}, defaultdict(list)
        for _, _, code in group:  # which files mention each name, so a function's callers are looked for only where it appears
            for name in set(NAME.findall(code)):
                mentions[name].append(code)
        for path, text, code in group:
            for m in rx.finditer(code):
                where = enclosing(code, m.start(), lang, m.group(2))
                if not where:
                    continue
                fn, idx = where
                if (fn, idx) not in seen:  # each function's callers are read once, however many sinks it holds
                    values = set()
                    for other in mentions.get(fn, ()):
                        for args in call_args(other, fn):
                            lit = LITERAL.match(args[idx]) if idx < len(args) else None
                            if lit:
                                values.add(lit.group(2))
                    seen[fn, idx] = values
                values = seen[fn, idx]
                line = line_of(code, m.start())
                snippet = text.splitlines()[line - 1].strip()[:160]
                for v in sorted(values):
                    for algo, params in resolve(lang, f'{m.group(1)}("{v}")'):
                        sink.append(Detection(algo=algo, file=path, line=line, evidence="call", detector="parameters", snippet=snippet, lang=lang,
                                             params={k: x for k, x in dict(params, literal=v, via=fn).items() if x},
                                             context={"test"} if is_test(path) else set()))
    return sink


def resolve(lang, rebuilt):
    """What the ordinary detectors make of the rebuilt call."""
    out = []
    for rx, fn in RULES.get(lang, []):
        for m in rx.finditer(rebuilt):
            out += [(r[0], r[1]) for r in fn(m, _Ctx(rebuilt)) or [] if r[0]]
    return out


class _Ctx:
    """The minimal context a rule needs when it reads a rebuilt one-line call."""
    comment, path, line = False, "", 1
    sink: list[Detection] = []

    def __init__(self, text):
        self.text, self.lines = text, [text]

    def window_text(self, n):
        return self.text

    def attach(self, params, algos, window=15):
        pass

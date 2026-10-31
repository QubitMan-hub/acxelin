import io
import re
import tokenize

LANGS = {
    ".py": "python", ".java": "java", ".kt": "java", ".kts": "java", ".scala": "java", ".groovy": "java",
    ".go": "go", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c", ".cs": "csharp", ".rs": "rust",
    ".swift": "c", ".php": "c", ".rb": "hash", ".sh": "hash", ".ps1": "hash",
}
C_LIKE = {"java", "go", "js", "c", "csharp", "rust"}


def _blank(s):
    return "\n".join(" " * len(p) for p in s.split("\n"))


SPECIAL = {q: re.compile("//|/\\*|[" + re.escape(q) + "]") for q in ("\"'`", "\"'", "\"")}


def split_c(text, lang):
    code, com, strings = [], [], []
    i, n, line = 0, len(text), 1
    quotes = "\"'`" if lang in ("js", "go") else "\"" if lang == "rust" else "\"'"
    special = SPECIAL[quotes]
    while i < n:
        ch = text[i]
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j == -1 else j
            seg = text[i:j]
            code.append(_blank(seg)); com.append(seg); i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            seg = text[i:j]
            code.append(_blank(seg)); com.append(seg); line += seg.count("\n"); i = j
        elif ch in quotes:
            j, start_line = i + 1, line
            while j < n and text[j] != ch:
                if text[j] == "\\" and ch != "`":
                    j += 1
                elif text[j] == "\n" and ch != "`":
                    break
                j += 1
            seg = text[i:j + 1]
            code.append(seg); com.append(_blank(seg)); strings.append((start_line, seg[1:-1] if len(seg) > 1 else ""))
            line += seg.count("\n"); i = j + 1
        else:
            m = special.search(text, i + 1)
            j = m.start() if m else n
            seg = text[i:j]
            code.append(seg); com.append(_blank(seg))
            line += seg.count("\n"); i = j
    return "".join(code), "".join(com), strings


def split_hash(text):
    code, com, strings = [], [], []
    for n, raw in enumerate(text.splitlines(keepends=True), 1):
        q, cut, start = None, None, 0
        for k, ch in enumerate(raw):
            if q:
                if ch == q:
                    q = None
                    strings.append((n, raw[start:k]))
            elif ch in "\"'":
                q, start = ch, k + 1
            elif ch == "#" or (ch == ";" and raw.lstrip().startswith(";")):
                cut = k
                break
        if cut is None:
            code.append(raw); com.append(_blank(raw))
        else:
            code.append(raw[:cut] + _blank(raw[cut:])); com.append(_blank(raw[:cut]) + raw[cut:])
    return "".join(code), "".join(com), strings


MAX_TOKENIZED_LINE = 5000  # characters


def split_python(text):
    lines = text.splitlines(keepends=True)
    if max(map(len, lines), default=0) > MAX_TOKENIZED_LINE:
        # Python 3.11's tokenizer matches the rest of a line again for every character after an unterminated quote: one 40,000-character
        # line took 20 seconds. Minified or hostile lines get the line-based split every other language gets; the rest of the file is read.
        c, m, s = split_hash(text)
        return c, m, s, set()
    code = [list(l) for l in lines]
    com = [[c if c == "\n" else " " for c in l] for l in lines]
    strings, docs = [], set()
    prev = None
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return text, _blank(text), [], docs
    for idx, t in enumerate(toks):
        if t.type == tokenize.COMMENT:
            r, c = t.start
            for k in range(len(t.string)):
                if c + k < len(code[r - 1]):
                    com[r - 1][c + k] = code[r - 1][c + k]
                    code[r - 1][c + k] = " "
        elif t.type == tokenize.STRING:
            nxt = toks[idx + 1].type if idx + 1 < len(toks) else None
            is_doc = prev in (None, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.NL) and nxt in (tokenize.NEWLINE, tokenize.ENDMARKER)
            body = t.string.lstrip("rbuRBUfF")
            q = body[:3] if body[:3] in ('"""', "'''") else body[:1]
            val = body[len(q):-len(q)] if len(body) >= 2 * len(q) else body
            strings.append((t.start[0], val))
            if is_doc:
                docs.update(range(t.start[0], t.end[0] + 1))
        if t.type not in (tokenize.NL, tokenize.COMMENT):
            prev = t.type
    return "".join("".join(l) for l in code), "".join("".join(l) for l in com), strings, docs


def split(text, lang):
    if lang == "python":
        return split_python(text)
    if lang in C_LIKE:
        c, m, s = split_c(text, lang)
        return c, m, s, set()
    c, m, s = split_hash(text)
    return c, m, s, set()


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1

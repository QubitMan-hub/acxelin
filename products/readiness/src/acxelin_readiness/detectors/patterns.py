"""Security patterns around cryptography, by rule: certificate checks switched off, secrets written into code, weak randomness
for keys, unsigned tokens and fixed IVs. This is pattern detection on comment-free code, one line at a time; it is not taint
tracking, so a value that reaches the risky call through other variables is not followed."""
import re
from dataclasses import dataclass

from . import iter_files, rel, is_test, read
from .lexer import LANGS, split
from .names import blank_strings

RULES = {
    "WPC001": ("Certificate verification switched off", "CWE-295", "high",
               "Verify the peer: keep certificate and host-name checks on and trust a private CA explicitly instead"),
    "WPC002": ("Secret written into source code", "CWE-798", "high",
               "Load it from a secrets manager or the environment, and rotate the exposed value"),
    "WPC003": ("Predictable random numbers used for key material", "CWE-338", "medium",
               "Use a cryptographic generator: secrets / os.urandom, crypto.randomBytes, SecureRandom, crypto/rand"),
    "WPC004": ("Token accepted without checking its signature", "CWE-347", "high",
               "Verify the signature and pin the expected algorithms; never accept alg none"),
    "WPC005": ("Fixed or all-zero IV or nonce", "CWE-329", "medium",
               "Generate a fresh random IV or nonce for every message"),
}

P = {
    "WPC001": {
        "python": r"\bverify\s*=\s*False\b|\bssl\._create_unverified_context\s*\(|\.check_hostname\s*=\s*False\b|\b(?:verify_mode|cert_reqs)\s*=\s*(?:ssl\.)?CERT_NONE\b",
        "js": r"\brejectUnauthorized\s*:\s*false\b|\bstrictSSL\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\b[\]'\"]*\s*=\s*['\"]?0",
        "go": r"\bInsecureSkipVerify\s*:\s*true\b",
        "java": r"\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bNoopHostnameVerifier\b|\bsetHostnameVerifier\s*\(\s*\(?[\w\s,]*\)?\s*->\s*true\b"
                r"|\bcheckServerTrusted\s*\([^)]*\)\s*(?:throws\s+[\w.]+\s*)?\{\s*\}",
        "csharp": r"\w*ValidationCallback\s*\+?=\s*\(?[\w\s,]*\)?\s*=>\s*true\b|\bDangerousAcceptAnyServerCertificateValidator\b",
        "c": r"\bSSL_CTX_set_verify\s*\([^,]+,\s*SSL_VERIFY_NONE\b|\bCURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0L?|false)\b",
        "rust": r"\bdanger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)",
        "hash": r"\bVERIFY_NONE\b|--insecure\b|\bverify_mode\s*[:=]>?\s*OpenSSL::SSL::VERIFY_NONE",
    },
    "WPC003": {
        "python": r"\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample|randbytes)\s*\(",
        "js": r"\bMath\.random\s*\(",
        "java": r"\bnew\s+Random\s*\(|\bThreadLocalRandom\.current\s*\(",
        "csharp": r"\bnew\s+Random\s*\(",
        "go": r"\b(?:mrand|rand)\.(?:Int|Intn|Int31|Int63|Uint32|Uint64)\s*\(",
        "c": r"(?<![\w.])(?:rand|random|mt_rand)\s*\(\s*\)|\bmt_rand\s*\(",
        "hash": r"(?<![\w.])rand\s*\(",
    },
    "WPC004": {
        "python": r"[\"']verify_signature[\"']\s*:\s*False\b|\bjwt\.decode\s*\([^)]*\bverify\s*=\s*False|\balgorithms\s*=\s*\[\s*[\"']none[\"']",
        "js": r"\balgorithms\s*:\s*\[\s*['\"]none['\"]",
        "java": r"\.parseUnsecuredClaims\s*\(|\.unsecured\s*\(\s*\)",
        "go": r"\bjwt\.UnsafeAllowNoneSignatureType\b",
    },
    "WPC005": {
        "python": r"\b(?:iv|nonce)\s*=\s*(?:b[\"'][^\"']+[\"']|bytes\s*\(\s*\d+\s*\)|b[\"']\\x00[\"']\s*\*\s*\d+)",
        "js": r"\b(?:iv|nonce)\s*=\s*Buffer\.(?:alloc\s*\(\s*\d+\s*(?:,\s*0\s*)?\)|from\s*\(\s*['\"])",
        "java": r"\bnew\s+(?:IvParameterSpec|GCMParameterSpec)\s*\((?:\s*\d+\s*,)?\s*new\s+byte\s*\[\s*\d+\s*\]\s*\)",
        "csharp": r"\.IV\s*=\s*new\s+byte\s*\[\s*\d+\s*\]",
    },
}
RX = {rule: {lang: re.compile(rx) for lang, rx in by.items()} for rule, by in P.items()}
GO_MATH_RAND = re.compile(r"\"math/rand(?:/v2)?\"")
KEYISH = re.compile(r"(?i)(?:key|token|secret|salt|nonce|(?<![a-z])iv(?![a-z])|passw|otp|session_?id|csrf)")
SECRET = re.compile(r"""(?<![\w.])([\w.]*?(?i:password|passwd|pwd|secret|api_?key|private_?key|access_?token|auth_?token|client_?secret|signing_?key|encryption_?key)(?![a-z])\w*)["']?\s*(?:(?<![=!<>])=(?!=)|:(?!:)|:=|=>)\s*[rbuRBU]?(["'`])([^"'`\n]{8,200})\2""")
NOT_SECRET_NAME = re.compile(r"(?i)(?:field|label|prompt|message|msg|error|name|length|len|policy|pattern|regex|url|uri|path|file|dir|env|header|param|type|hash|_id$|placeholder|hint|title|key_?size|key_?length)$")
PLACEHOLDER = re.compile(r"(?i)\$\{|\{\{|%\(|<[^>]*>|\byour[_ -]|example|changeme|change_me|xxx|\*\*\*|dummy|placeholder|redacted|todo|replace|sample|(?-i:^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$|^[a-z]+(?:[ _-][a-z]+)+$)")


@dataclass
class Pattern:
    rule: str
    file: str
    line: int
    snippet: str
    test: bool

    @property
    def title(self):
        return RULES[self.rule][0]

    @property
    def cwe(self):
        return RULES[self.rule][1]

    @property
    def severity(self):
        return "low" if self.test else RULES[self.rule][2]

    @property
    def fix(self):
        return RULES[self.rule][3]

    def as_dict(self):
        return {"rule": self.rule, "title": self.title, "cwe": self.cwe, "severity": self.severity, "file": self.file, "line": self.line,
                "fix": self.fix, "test": self.test, "snippet": self.snippet}


def blank(code):
    """String contents become spaces (quotes and line breaks kept), so a pattern never matches text inside a string."""
    return blank_strings(code, lambda t: t[0] + "".join("\n" if c == "\n" else " " for c in t[1:-1]) + t[-1])


def secret(value):
    v = value.strip()
    return len(v) >= 8 and not v.isdigit() and not re.search(r"(?i)pass|secret|token|key", v) and " " not in v and "/" not in v and "\\" not in v and not PLACEHOLDER.search(v) and len(set(v)) > 3 \
        and not v.lower().endswith((".pem", ".key", ".crt", ".json", ".txt"))


def scan_text(path, text, lang, parts=None):
    code, _, _, docs = parts or split(text, lang)
    bare, lines, out = blank(code), text.splitlines(), []
    test = is_test(path) or path.rsplit("/", 1)[-1] in ("test.py", "tests.py", "conftest.py")
    go_rand = lang != "go" or GO_MATH_RAND.search(code)
    code_lines, bare_lines = code.split("\n"), bare.split("\n")

    def add(rule, ln, hide=None):
        snippet = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
        out.append(Pattern(rule, path, ln, (snippet.replace(hide, "<redacted>") if hide else snippet)[:160], test))
    for ln, b in enumerate(bare_lines, 1):
        if ln in docs:
            continue
        for rule in ("WPC001", "WPC004", "WPC005"):
            rx = RX[rule].get(lang)
            if rx and any(b[m.start()] == m.group(0)[0] for m in rx.finditer(code_lines[ln - 1])):
                add(rule, ln)
        rx = RX["WPC003"].get(lang)
        if rx and go_rand and (m := rx.search(b)) and KEYISH.search(b[:m.start()]):
            add("WPC003", ln)
        for m in SECRET.finditer(code_lines[ln - 1]):
            if b[m.start(1):m.end(1)] == m.group(1) and not NOT_SECRET_NAME.search(m.group(1)) and secret(m.group(3)):
                add("WPC002", ln, m.group(3))
                break
    return out


def scan(root, scope=False):
    out = []
    for p in iter_files(root, scope):
        lang = LANGS.get(p.suffix.lower())
        if lang is None:
            continue
        text = read(p)
        if text:
            out += scan_text(rel(root, p), text, lang)
    return ordered(out)


def ordered(found):
    order = ["critical", "high", "medium", "low"]
    return sorted(found, key=lambda p: (order.index(p.severity), p.file, p.line))

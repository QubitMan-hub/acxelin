"""Policy: the organisation's own rules and published transition standards, checked against what the pipeline found.

NIST IR 8547 (initial public draft, November 2024): quantum-vulnerable public-key algorithms are deprecated after 2030 at 112-bit
strength and disallowed after 2035; anything already disallowed by SP 800-131A is disallowed now.
CNSA 2.0 (NSA, 2022): AES-256, SHA-384/512, ML-KEM-1024 and ML-DSA-87 (plus LMS/XMSS for firmware signing). The deadline is
configurable because NSA's dates differ by product category; 2033 is the default.
"""
from dataclasses import dataclass, asdict, field
from datetime import date

from .catalog import CATALOG, HYBRIDS, LEGACY, SHOR, classical_bits

PROFILES = ("nist-ir-8547", "cnsa-2.0", "india-dst")
KEYS = {"profiles": list, "as_of": int, "cnsa_deadline": int, "india_deadline": int, "forbid": list, "min_bits": dict, "require_hybrid": bool, "fail": bool}
CNSA = {"SHA-384", "SHA-512", "ML-KEM-1024", "ML-DSA-87"}
CNSA_SCOPE = {"pke", "signature", "key-agree", "kem", "other", "block-cipher", "stream-cipher", "ae", "hash"}


@dataclass
class Violation:
    rule: str
    asset: str
    message: str
    deadline: int | None
    overdue: bool
    files: list = field(default_factory=list)


def check(policy):
    """Problems with a [policy] table, as messages; an empty list means it is valid."""
    out = [f"unknown policy key {k!r} (known: {', '.join(KEYS)})" for k in policy if k not in KEYS]
    out += [f"policy {k} has the wrong type" for k, t in KEYS.items() if k in policy and not isinstance(policy[k], t)]
    if out:
        return out
    out += [f"unknown profile {p!r} (known: {', '.join(PROFILES)})" for p in policy.get("profiles", []) if p not in PROFILES]
    out += ["policy forbid must list names" for f in policy.get("forbid", []) if not isinstance(f, str)][:1]
    out += [f"policy min_bits {k} must be a whole number" for k, v in policy.get("min_bits", {}).items() if not isinstance(v, int) or isinstance(v, bool)]
    return out


def exempt(a):
    """Test-only code, hashes declared non-security (usedforsecurity=False) and trust-store roots are reported, but break no rule."""
    return a.test_only or all(s.params.get("purpose") == "non-security" or "trust-store" in s.context for s in a.detections)


def evaluate(assets, endpoints, policy, today=None):
    """Every rule each asset breaks. A rule whose deadline has passed (or that has none) is overdue; the rest are upcoming."""
    as_of = policy.get("as_of") or (today or date.today()).year
    profiles, out = policy.get("profiles", []), []
    forbid = {f.upper() for f in policy.get("forbid", [])}
    min_bits = {k.upper(): v for k, v in policy.get("min_bits", {}).items()}

    def add(a, rule, message, deadline=None):
        v = Violation(rule, a.variant if a else "", message, deadline, deadline is None or (as_of > deadline if rule in ("NIST IR 8547", "India DST roadmap") else as_of >= deadline),
                      sorted({s.file for s in a.detections})[:10] if a else [])
        out.append(v)
        if a:
            a.policy = sorted(set(getattr(a, "policy", []) + [rule]))

    for a in assets:
        if exempt(a):
            continue
        c, bits = CATALOG[a.algo], classical_bits(a.algo, a.params)
        if "nist-ir-8547" in profiles:
            if c.threat == LEGACY or bits is not None and bits < 112:
                add(a, "NIST SP 800-131A", "disallowed now")
            elif c.threat == SHOR:
                deadline = 2030 if bits == 112 else 2035
                add(a, "NIST IR 8547", f"quantum-vulnerable: {'deprecated after 2030, ' if deadline == 2030 else ''}disallowed after 2035", deadline)
        if "cnsa-2.0" in profiles and c.primitive in CNSA_SCOPE:
            size = a.params.get("key_size")
            if a.algo == "AES" and size is None:
                add(a, "CNSA 2.0", "AES key size not observed: CNSA 2.0 compliance unverified (it needs AES-256)")
            elif not (a.algo in CNSA or a.algo == "AES" and size == 256):
                add(a, "CNSA 2.0", "not in the CNSA 2.0 suite (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87)", policy.get("cnsa_deadline", 2033))
        if "india-dst" in profiles and (c.threat in (LEGACY, SHOR) or bits is not None and bits < 112):
            # DST National Quantum Mission task force roadmap (2026): critical information infrastructure fully post-quantum by
            # December 2029, other enterprises by 2033 (india_deadline = 2033)
            add(a, "India DST roadmap", "disallowed now" if c.threat == LEGACY or bits is not None and bits < 112 else "quantum-vulnerable: replace by the end of "
                + str(policy.get("india_deadline", 2029)), None if c.threat == LEGACY or bits is not None and bits < 112 else policy.get("india_deadline", 2029))
        names = {a.algo.upper(), c.family.upper(), a.variant.upper()}
        if names & forbid:
            add(a, "policy: forbid", f"{a.variant} is forbidden by policy")
        floor = min_bits.get(a.algo.upper()) or min_bits.get(c.family.upper())
        if floor and a.params.get("key_size") and a.params["key_size"] < floor:
            add(a, "policy: min_bits", f"{a.params['key_size']}-bit key, policy minimum {floor}")
    if policy.get("require_hybrid"):
        kex = [a for a in assets if CATALOG[a.algo].primitive in ("key-agree", "protocol") and not exempt(a)]
        hybrid = any(a.algo in HYBRIDS for a in assets) or any(ep.get("pq_groups") for ep in endpoints)
        if kex and not hybrid:
            add(None, "policy: require_hybrid", "key exchange found, but no hybrid post-quantum key exchange anywhere in this scan")
    out.sort(key=lambda v: (not v.overdue, v.deadline or 0, v.rule, v.asset))
    overdue = sum(v.overdue for v in out)
    return {"profiles": profiles, "as_of": as_of, "overdue": overdue, "upcoming": len(out) - overdue, "passed": overdue == 0,
            "violations": [asdict(v) for v in out]}

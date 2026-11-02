"""`cnsa2` follows the NSA's CNSA 2.0 FAQ (ver. 2.2, October 2026, p. 28): a hybrid counts as CNSA 2.0 only where NSA named it, and
it names no TLS hybrid. So the edge offers and accepts pure ML-KEM-1024 only, and shadow mode says a hybrid-only client would be refused."""
from acxelin_tls import policies, shadow


def test_cnsa2_offers_pure_ml_kem_1024_only():
    p = policies.policy("cnsa2")
    assert p.groups == "MLKEM1024" and (p.sigalgs, p.ciphersuites) == ("mldsa87", "TLS_AES_256_GCM_SHA384")


def test_shadow_says_a_client_offering_only_the_p_384_hybrid_would_be_refused():
    hybrid = {"groups": ["SecP384r1MLKEM1024"], "sigalgs": ["mldsa87"], "suites": ["TLS_AES_256_GCM_SHA384"]}
    assert any("ML-KEM-1024" in r for r in shadow.reasons("cnsa2", hybrid))
    assert shadow.reasons("cnsa2", hybrid | {"groups": ["SecP384r1MLKEM1024", "MLKEM1024"]}) == []

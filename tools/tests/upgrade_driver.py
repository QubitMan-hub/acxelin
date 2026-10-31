"""Runs one step on a CA folder with whichever acxelin_core is first on PYTHONPATH and prints what it sees as JSON.
Used by test_upgrade_rollback.py for both the released code and the code in this tree; it must work unchanged on every baseline."""
import json
import sys
from pathlib import Path

from acxelin_core import pki

op, root = sys.argv[1], Path(sys.argv[2])


def state(ca):
    crl = (ca.root / "crl.pem").read_bytes()
    verdicts = {}
    for r in ca.records():
        if r.kind == "ca":
            continue
        try:
            pki.check_revocation(int(r.serial, 16), crl, ca.cert)
            verdicts[r.common_name] = "accepted"
        except pki.CAError as e:
            verdicts[r.common_name] = "refused: revoked" if "revoked" in str(e) else f"refused: {e}"
    parsed = pki.x509.load_pem_x509_crl(crl)
    return {"records": [{k: v for k, v in vars(r).items() if v or k != "replaces"} for r in ca.records()], "verdicts": verdicts, "crl_number": pki.crl_number(parsed)}


def revoked(ca, name):
    _, rec = ca.issue(name, "client", out=root / name)
    ca.revoke(rec.serial, "keyCompromise")


if op == "create":
    ca = pki.CA.init(root / "ca", "Upgrade Root", algorithm="ML-DSA-65")
    ca.issue("good", "server", names=["good.example"], out=root / "good")
    revoked(ca, "bad")
else:
    ca = pki.CA(root / "ca")
    if op == "extend":
        revoked(ca, "later")
    elif op == "extend2":
        revoked(ca, "later2")
print(json.dumps(state(ca)))

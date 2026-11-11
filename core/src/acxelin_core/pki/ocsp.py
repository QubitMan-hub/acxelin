"""OCSP answers for the CA's certificates, signed by the CA's own key, and the check a client makes of one.

A server staples an answer to its handshake so that a client learns "this certificate is still good" without asking the CA
(RFC 6066, RFC 6960). The answer is only as fresh as its `next_update`: a stale one is never sent. Stapling does not replace
revocation checking at the server: the edge still checks its clients' certificates against the CRL.
"""
import datetime as dt
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from . import REASONS, CAError, now
from .signers import KeySigner

SKEW = dt.timedelta(minutes=5)


def respond(ca, cert, hours=24):
    """The DER answer for `cert`, valid for `hours` (1 to 168): good, or revoked with the time and reason."""
    if not 1 <= hours <= 168:
        raise CAError("an OCSP answer should be valid for between 1 and 168 hours")
    try:
        cert.verify_directly_issued_by(ca.cert)
    except (ValueError, TypeError, InvalidSignature):
        raise CAError(f"{cert.subject.rfc4514_string()} was not issued by this CA") from None
    signer = ca.signer
    if not isinstance(signer, KeySigner):
        raise CAError("OCSP answers are signed with the CA key held in a file; CAs with a KMS or signing-command key are not supported yet")
    rec = next((r for r in ca.records() if r.serial == format(cert.serial_number, "x")), None)
    if rec is None:
        raise CAError(f"serial {cert.serial_number:x} is not in this CA's records")
    start = now()
    revoked = rec.status == "revoked"
    reason = REASONS.get(rec.reason) if revoked else None
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=cert, issuer=ca.cert, algorithm=hashes.SHA256(),
        cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
        this_update=start, next_update=start + dt.timedelta(hours=hours),
        revocation_time=dt.datetime.fromisoformat(rec.revoked_at) if revoked else None, revocation_reason=reason)
    return builder.responder_id(ocsp.OCSPResponderEncoding.HASH, ca.cert).sign(signer.key, None).public_bytes(
        Encoding.DER)


def _verified(der, issuer, cert=None):
    try:
        r = ocsp.load_der_ocsp_response(der)
    except ValueError:
        raise CAError("that is not an OCSP response") from None
    if r.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise CAError(f"the OCSP response is an error ({r.response_status.name.lower()}), not an answer")
    try:
        issuer.public_key().verify(r.signature, r.tbs_response_bytes)
    except (InvalidSignature, TypeError, ValueError):
        raise CAError("the OCSP response's signature does not verify against the CA that issued the certificate") from None
    if cert is not None:
        want = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, r.hash_algorithm).build()
        if (r.serial_number, r.issuer_key_hash, r.issuer_name_hash) != (want.serial_number, want.issuer_key_hash, want.issuer_name_hash):
            raise CAError("the OCSP response answers for another certificate")
    return r


def _fresh(r, at):
    if r.next_update_utc is None:
        raise CAError("the OCSP response has no end of validity")
    if at < r.this_update_utc - SKEW:
        raise CAError("the OCSP response is not valid yet: check this machine's clock")
    if at > r.next_update_utc:
        raise CAError(f"the OCSP response is out of date (it ended {r.next_update_utc:%Y-%m-%d %H:%M} UTC)")


def check(der, cert, issuer, now=None):
    """The status (good, revoked, unknown) an OCSP response gives `cert`, once it is shown to be signed by `issuer`, for this
    certificate and current; CAError saying what is wrong otherwise."""
    r = _verified(der, issuer, cert)
    _fresh(r, now or dt.datetime.now(dt.timezone.utc))
    return r.certificate_status


class StapleFile:
    """A provider for `Context.set_staple` that follows a file an operator refreshes: re-read when it changes, checked once for
    signature (and certificate, when given), and withheld as soon as it is out of date. `problem` says why nothing is sent."""

    def __init__(self, path, issuer, cert=None):
        self.path, self.issuer, self.cert = Path(path), issuer, cert
        self.stamp, self.kept, self.problem = None, None, "no OCSP file yet"
        self.clock = lambda: dt.datetime.now(dt.timezone.utc)

    def __call__(self):
        try:
            st = self.path.stat()
            stamp = (st.st_mtime_ns, st.st_size)
            if stamp != self.stamp:
                self.stamp, self.kept, self.problem = stamp, None, ""
                der = self.path.read_bytes()
                self.kept = (der, _verified(der, self.issuer, self.cert))
        except OSError as e:
            self.stamp, self.kept, self.problem = None, None, f"cannot read {self.path}: {e.strerror or e}"
        except CAError as e:
            self.kept, self.problem = None, f"{self.path} is not used: {e}"
        if self.kept is None:
            return None
        try:
            _fresh(self.kept[1], self.clock())
        except CAError as e:
            self.problem = f"{self.path} is not used: {e}"
            return None
        self.problem = ""
        return self.kept[0]

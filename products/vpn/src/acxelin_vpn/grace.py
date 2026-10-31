"""The outage grace: a peer that has not re-agreed keys within its normal limit may stay on its last keys for up to the
customer's `outage_grace_minutes`, but only while the CRL shows its certificate is not revoked. The cap is absolute, and a
revoked peer is never kept: revocation is checked first, on every pass."""
import threading

from acxelin_core.pki import CAError

MAX_MINUTES = 1440


def check_minutes(who, value, crl):
    if not 0 <= value <= MAX_MINUTES:
        raise ValueError(f"{who}outage_grace_minutes must be between 0 and {MAX_MINUTES} (24 hours), not {value:g}")
    if value and not crl:
        raise ValueError(f"{who}outage_grace_minutes needs crl: without a revocation list nothing shows a silent peer is not revoked")


def crl_verdict(revocation, serial, issuer):
    """('ok', '') when the CRL is readable, signed, current and lacks the certificate; ('revoked', why) when it lists it;
    ('unusable', why) when it cannot be used, which never clears anyone."""
    if not revocation or serial is None:
        return "unusable", "no revocation list to check against"
    try:
        revocation.check(serial, (), issuer)
    except CAError as e:
        return ("revoked" if "revoked" in str(e) else "unusable"), str(e)
    except OSError as e:
        return "unusable", f"the CRL cannot be read: {e}"
    return "ok", ""


class Grace:
    """Which peers are running on their last keys, logged once when each enters and once when it leaves, and counted."""

    def __init__(self, log, counts):
        self.log, self.counts, self.active, self.lock = log, counts, set(), threading.Lock()
        counts["grace_used"] = 0

    def begin(self, who, cap_s, silent_s):
        with self.lock:
            if who in self.active:
                return
            self.active.add(who)
            self.counts["grace_used"] += 1
        self.log.warning("%s: no key agreement for %d minutes; running on its last keys under the outage grace, which ends at the latest "
                         "%d minutes from the normal limit", who, silent_s // 60, cap_s // 60)

    def end(self, who, why=None):
        """Leave the grace; True if `who` was in it. With `why`, logs the end (the caller that removes `who` logs its own line)."""
        with self.lock:
            if who not in self.active:
                return False
            self.active.discard(who)
        if why:
            self.log.warning("%s: outage grace ended: %s", who, why)
        return True

    def state(self, who, silent_s, limit_s, cap_s):
        """What status and metrics show: whether `who` is in grace, and how far into the cap it is."""
        if who not in self.active:
            return {"in_grace": False}
        elapsed = max(0, int(silent_s - limit_s))
        return {"in_grace": True, "grace_elapsed_s": elapsed, "grace_remaining_s": max(0, int(cap_s) - elapsed), "grace_cap_s": int(cap_s)}

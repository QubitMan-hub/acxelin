"""Enrolment with an OIDC ID token: a person signs in to the company's identity provider and its signed token is the credential
for one client certificate in their own name.

What is checked, in this order: the token is RS256 or ES256 (never `none` or a shared-secret algorithm), its signature verifies
under a key in the provider's key set, the issuer and audience are this configuration's, it has not expired, the name claim is
present (a verified email when that is the claim), the domain and group are allowed, and the token has not been used before.
The certificate's common name must then be exactly that name. Only a hash of a used token is kept.
"""
import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from . import CAError, write

ALGORITHMS = ("RS256", "ES256")
MAX_TOKEN = 16384
LEEWAY = 60  # seconds of clock difference tolerated with the provider
KEYS_KEPT = 300  # seconds a fetched key set is reused


def _decode(part):
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except ValueError:
        raise CAError("the token is not a signed ID token") from None


def _json(part):
    try:
        out = json.loads(_decode(part))
    except ValueError:
        raise CAError("the token is not a signed ID token") from None
    if not isinstance(out, dict):
        raise CAError("the token is not a signed ID token")
    return out


def _int(value):
    return int.from_bytes(_decode(value), "big")


def _fetch(url):
    import http.client
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.read(1 << 20)
    except (OSError, ValueError, http.client.HTTPException) as e:
        raise CAError(f"cannot fetch the identity provider's keys from {url}: {e}") from None


@dataclass
class Policy:
    issuer: str
    audience: str
    name_claim: str = "email"
    domains: list = field(default_factory=list)
    groups_claim: str = "groups"
    groups: list = field(default_factory=list)
    jwks_file: str = ""
    jwks_url: str = ""
    jwks: dict = None  # a key set given directly (tests)
    fetch: object = _fetch
    _kept: tuple = (0.0, None)

    def keys(self):
        if self.jwks is not None:
            return self.jwks
        if self.jwks_file:
            try:
                data = Path(self.jwks_file).read_bytes()
            except OSError as e:
                raise CAError(f"cannot read the identity provider's key set {self.jwks_file}: {e}") from None
        else:
            when, kept = self._kept
            if kept is not None and time.monotonic() - when < KEYS_KEPT:
                return kept
            try:
                data = self.fetch(self.jwks_url)
            except OSError as e:
                raise CAError(f"cannot fetch the identity provider's keys from {self.jwks_url}: {e}") from None
        try:
            keys = json.loads(data)
        except ValueError:
            raise CAError("the identity provider's key set is not JSON: check jwks_file or jwks_url in oidc.json") from None
        if not isinstance(keys, dict) or not isinstance(keys.get("keys"), list):
            raise CAError("the identity provider's key set must be a JSON object with a 'keys' list")
        if self.jwks_url:
            self._kept = (time.monotonic(), keys)
        return keys


def configure(ca, issuer, audience, jwks_file=None, jwks_url=None, name_claim="email", domains=(), groups_claim="groups", groups=()):
    """Write the folder's OIDC enrolment settings (`oidc.json`)."""
    if not issuer.startswith("https://"):
        raise CAError(f"the issuer is the provider's https address, not {issuer!r}")
    if bool(jwks_file) == bool(jwks_url):
        raise CAError("give exactly one of --jwks-file (keys you copy from the provider) and --jwks-url (fetched at enrolment)")
    if jwks_url and not jwks_url.startswith("https://"):
        raise CAError(f"the key set address must be https, not {jwks_url!r}")
    if domains and name_claim != "email":
        raise CAError("domains limit the part of an email after '@'; they need --name-claim email")
    settings = {"issuer": issuer, "audience": audience, "name_claim": name_claim, "domains": [d.lower() for d in domains],
                "groups_claim": groups_claim, "groups": list(groups), "jwks_file": str(Path(jwks_file).resolve()) if jwks_file else "",
                "jwks_url": jwks_url or ""}
    write(Path(ca.root) / "oidc.json", json.dumps(settings, indent=1).encode())
    return settings


def load(root):
    """The folder's settings, or None when OIDC enrolment is not set up."""
    path = Path(root) / "oidc.json"
    if not path.exists():
        return None
    try:
        return Policy(**json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, TypeError) as e:
        raise CAError(f"{path} is not valid: {e}. Write it again with `ca oidc`") from None


def _public_key(jwk, alg):
    if alg == "RS256" and jwk.get("kty") == "RSA":
        key = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
        if key.key_size < 2048:
            raise CAError("the provider's signing key is smaller than 2048 bits and is not accepted")
        return key
    if alg == "ES256" and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1()).public_key()
    raise CAError("the provider's key does not fit the token's algorithm")


def _check_signature(alg, key, signing, signature):
    try:
        if alg == "RS256":
            key.verify(signature, signing, padding.PKCS1v15(), hashes.SHA256())
        else:
            if len(signature) != 64:
                raise InvalidSignature
            key.verify(utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
                       signing, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise CAError("the token's signature does not verify against the provider's keys") from None


def verify(token, policy, now=None):
    """The (name, expiry) a valid token vouches for; CAError saying what is wrong otherwise."""
    if len(token) > MAX_TOKEN:
        raise CAError("the token is too long to be an ID token")
    parts = token.split(".")
    if len(parts) != 3:
        raise CAError("the token is not a signed ID token (three parts separated by dots)")
    header, claims = _json(parts[0]), _json(parts[1])
    alg = header.get("alg")
    if alg not in ALGORITHMS:
        raise CAError(f"the token's algorithm {alg!r} is not accepted; RS256 and ES256 are")
    try:
        keys = [k for k in policy.keys()["keys"] if isinstance(k, dict) and k.get("kid") == header.get("kid")] if header.get("kid") \
            else policy.keys()["keys"]
        if len(keys) != 1:
            raise CAError("the token names no key in the provider's key set" if not keys else "the token names no key, and the set has several")
        key = _public_key(keys[0], alg)
    except (KeyError, ValueError, TypeError):
        raise CAError("the provider's key set has a key that cannot be read") from None
    _check_signature(alg, key, f"{parts[0]}.{parts[1]}".encode(), _decode(parts[2]))

    now = time.time() if now is None else now
    if claims.get("iss") != policy.issuer:
        raise CAError(f"the token's issuer is not {policy.issuer}")
    aud = claims.get("aud")
    if policy.audience not in (aud if isinstance(aud, list) else [aud]):
        raise CAError(f"the token is not for this service (audience {policy.audience})")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        raise CAError("the token has no expiry")
    if exp < now - LEEWAY:
        raise CAError("the token has expired: sign in again")
    for claim in ("nbf", "iat"):
        if isinstance(claims.get(claim), (int, float)) and claims[claim] > now + LEEWAY:
            raise CAError("the token is not valid yet: check this machine's clock")
    name = claims.get(policy.name_claim)
    if not isinstance(name, str) or not name:
        raise CAError(f"the token has no {policy.name_claim} claim")
    if len(name) > 64:
        raise CAError(f"the {policy.name_claim} claim is longer than the 64 characters a certificate name allows")
    if policy.name_claim == "email" and claims.get("email_verified") is not True:
        raise CAError("the provider has not verified this email address")
    if policy.domains and name.rpartition("@")[2].lower() not in policy.domains:
        raise CAError(f"{name} is not in an allowed domain ({', '.join(policy.domains)})")
    if policy.groups:
        member = claims.get(policy.groups_claim)
        if not isinstance(member, list) or not set(policy.groups) & set(member):
            raise CAError(f"the token is not in an allowed group ({', '.join(policy.groups)})")
    return name, exp


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def spent(root):
    """The used tokens (hash -> expiry); entries past their expiry are dropped, as the token could not be replayed anyway."""
    path = Path(root) / "oidc-used.json"
    try:
        used = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError:
        raise CAError(f"{path} is damaged; a used identity token could be replayed until you restore it") from None
    cutoff = time.time() - 2 * LEEWAY
    return {h: e for h, e in used.items() if e >= cutoff}


def spend(root, used, token_hash, expires):
    """Record the token as used until it expires, or with `expires` None take it back (the certificate could not be made)."""
    if expires is None:
        used.pop(token_hash, None)
    else:
        used[token_hash] = expires
    write(Path(root) / "oidc-used.json", json.dumps(used).encode(), secret=True)

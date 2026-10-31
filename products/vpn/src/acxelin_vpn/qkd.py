"""Keys from a quantum key distribution (QKD) network, through the key server's ETSI GS QKD 014 REST API, mixed into a site's
IPsec keys. QKD links run between sites, so this is for site-to-site tunnels only.

The initiating site asks its key server for a new key for the peer's secure application entity (SAE) and sends the key's ID in
the post-quantum key agreement; the peer asks its own key server for the key with that ID. Both mix it into the 64 bytes they
already derived from the post-quantum mutual TLS session, with HKDF-SHA384. The QKD key adds to the post-quantum keys and never
replaces them: an unauthenticated or compromised QKD link alone cannot set the tunnel's keys. The key servers are reached over
mutual TLS 1.3 with the SAE's certificate.
"""
import base64
import json
import re
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from acxelin_core import https, tls

SAE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
KEY_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
KEY_BITS = 256
# Key servers are rarely post-quantum yet: hybrid groups first, classical accepted; any signature algorithm.
KME_POLICY = tls.Policy("qkd-kme", "X25519MLKEM768:SecP384r1MLKEM1024:X25519:secp384r1:secp256r1", None,
                        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")


class QKDError(Exception):
    pass


class KME:
    """One site's key management entity (KME) and this site's SAE ID on it."""

    def __init__(self, url, sae_id, ca, cert, key, passphrase=lambda: None):
        u = urlsplit(url)
        if u.scheme != "https" or not u.hostname:
            raise ValueError(f"qkd_kme must be an https:// address, not {url!r}")
        if not SAE.match(sae_id):
            raise ValueError(f"qkd_sae_id {sae_id!r} must be letters, digits, '.', '_' or '-'")
        self.host, self.port, self.base = u.hostname, u.port or 443, u.path.rstrip("/")
        self.sae_id, self.ca, self.cert, self.keyfile, self.passphrase = sae_id, ca, cert, key, passphrase

    def _post(self, path, body):
        try:
            ctx = tls.client_context(KME_POLICY, self.ca, self.cert, self.keyfile, self.passphrase())
            with tls.connect(self.host, self.port, ctx, server_name=self.host, timeout=10) as conn:
                status, _, raw = https.request(conn, "POST", self.base + path, self.host, json.dumps(body).encode(),
                                               {"Content-Type": "application/json", "Accept": "application/json"})
        except (OSError, tls.TLSError, https.HTTPError) as e:
            raise QKDError(f"key server {self.host}:{self.port} unreachable or refused ({e})") from None
        if status != 200:
            raise QKDError(f"key server {self.host}:{self.port} answered {status}")
        try:
            keys = json.loads(raw)["keys"]
            (entry,) = keys
            key_id, key = str(entry["key_ID"]), base64.b64decode(entry["key"], validate=True)
        except (ValueError, KeyError, TypeError):
            raise QKDError(f"key server {self.host}:{self.port} did not return exactly one well-formed key") from None
        if len(key) != KEY_BITS // 8 or not KEY_ID.match(key_id):
            raise QKDError(f"key server {self.host}:{self.port} returned a key of {len(key) * 8} bits or a malformed key ID")
        return key_id, key

    def new_key(self, peer_sae):
        """(key ID, 32-byte key): a fresh key shared with `peer_sae` (ETSI GS QKD 014, Get key)."""
        return self._post(f"/api/v1/keys/{peer_sae}/enc_keys", {"number": 1, "size": KEY_BITS})

    def key(self, peer_sae, key_id):
        """The key `peer_sae` was handed under `key_id` (ETSI GS QKD 014, Get key with key IDs)."""
        if not KEY_ID.match(str(key_id)):
            raise QKDError("malformed QKD key ID")
        got_id, key = self._post(f"/api/v1/keys/{peer_sae}/dec_keys", {"key_IDs": [{"key_ID": key_id}]})
        if got_id != key_id:
            raise QKDError("the key server returned a different key than the one asked for")
        return key


def mix(material, qkd_key, context):
    """The post-quantum key material with the QKD key mixed in: secret as long as either input is."""
    return HKDF(hashes.SHA384(), len(material), None, b"acxelin-vpn-qkd-v1|" + context).derive(material + qkd_key)

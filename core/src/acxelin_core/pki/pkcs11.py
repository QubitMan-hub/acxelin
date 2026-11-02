"""The CA key in a PKCS#11 token (a hardware security module, a smart card, SoftHSM): the token signs, the key never leaves it.

Talks to the vendor's PKCS#11 library through ctypes (nothing to install) and uses CKM_ML_DSA from PKCS#11 3.2, so the token must offer it.
The PIN is read from an environment variable named in the configuration, never from the file, a command line or a log.
"""
import ctypes
import os
import secrets
import threading
import weakref

from . import signers
from .signers import SignerError, algorithm_identifier, encode

CKR = {0x00: "ok", 0x05: "general error", 0x07: "bad arguments", 0x30: "device error", 0x31: "device memory", 0x32: "device removed", 0x54: "function not supported",
       0x60: "key function not permitted", 0x62: "key size out of range", 0x63: "key type inconsistent", 0x70: "mechanism invalid", 0x71: "mechanism parameter invalid",
       0x82: "object handle invalid", 0xA0: "PIN incorrect", 0xA1: "PIN invalid", 0xA2: "PIN length out of range", 0xA3: "PIN expired", 0xA4: "PIN locked",
       0xB3: "session handle invalid", 0x100: "user already logged in", 0x101: "user not logged in", 0x191: "already initialized", 0x15: "attribute sensitive"}
CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL, CKA_VALUE, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_VERIFY, CKA_SIGN, CKA_EXTRACTABLE, CKA_PARAMETER_SET = (
    0x0, 0x1, 0x2, 0x3, 0x11, 0x100, 0x103, 0x10A, 0x108, 0x162, 0x61D)
CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKK_ML_DSA = 2, 3, 0x4A
CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA = 0x1C, 0x1D
CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER = 2, 4, 1
PARAMETER_SETS = {1: "ML-DSA-44", 2: "ML-DSA-65", 3: "ML-DSA-87"}
ULONG = ctypes.c_ulong  # CK_ULONG is the C unsigned long: 8 bytes on Linux and macOS, 4 on Windows



def algorithm_of(parameter_set):
    if parameter_set not in PARAMETER_SETS:
        raise SignerError(f"the token's key has ML-DSA parameter set {parameter_set}, which is not one of ML-DSA-44, ML-DSA-65 or ML-DSA-87")
    return PARAMETER_SETS[parameter_set]


def spki(algorithm, raw_public_key):
    """The standard SubjectPublicKeyInfo for a raw ML-DSA public key as a token reports it (CKA_VALUE)."""
    return encode(0x30, algorithm_identifier(signers.OIDS[algorithm]) + encode(0x03, b"\x00" + bytes(raw_public_key)))


class Attribute(ctypes.Structure):
    if os.name == "nt":
        _pack_ = 1  # PKCS#11 packs its structures on Windows; Python 3.14 rejects `_pack_` on the gcc layout, so it is not set elsewhere
    _fields_ = [("type", ULONG), ("value", ctypes.c_void_p), ("length", ULONG)]


class Mechanism(ctypes.Structure):
    if os.name == "nt":
        _pack_ = 1  # PKCS#11 packs its structures on Windows; Python 3.14 rejects `_pack_` on the gcc layout, so it is not set elsewhere
    _fields_ = [("mechanism", ULONG), ("parameter", ctypes.c_void_p), ("length", ULONG)]


def template(items):
    """A CK_ATTRIBUTE array for (type, bytes-or-int-or-bool) pairs, and the buffers that must stay alive while it is used."""
    keep, attrs = [], (Attribute * len(items))()
    for i, (t, v) in enumerate(items):
        if isinstance(v, bool):
            buf = ctypes.create_string_buffer(bytes([v]), 1)
        elif isinstance(v, int):
            buf = ctypes.create_string_buffer(ULONG(v).value.to_bytes(ctypes.sizeof(ULONG), "little"), ctypes.sizeof(ULONG))
        else:
            buf = ctypes.create_string_buffer(bytes(v), len(v))
        keep.append(buf)
        attrs[i] = Attribute(t, ctypes.cast(buf, ctypes.c_void_p), len(v) if not isinstance(v, (bool, int)) else ctypes.sizeof(buf))
    return attrs, keep


_loaded = {}
_lock = threading.Lock()


def load(path):
    """The module at `path`, initialised once per process (PKCS#11 forbids initialising it twice)."""
    with _lock:
        if path not in _loaded:
            try:
                lib = ctypes.CDLL(str(path))
            except OSError as e:
                raise SignerError(f"cannot load the PKCS#11 module {path}: {e}") from None
            for name in ("C_Initialize", "C_GetSlotList", "C_GetTokenInfo", "C_OpenSession", "C_Login", "C_FindObjectsInit", "C_FindObjects",
                         "C_FindObjectsFinal", "C_GetAttributeValue", "C_SignInit", "C_Sign", "C_GenerateKeyPair", "C_CloseSession"):
                if not hasattr(lib, name):
                    raise SignerError(f"{path} is not a PKCS#11 module: it has no {name}")
                getattr(lib, name).restype = ULONG
            rv = lib.C_Initialize(None)
            if rv not in (0, 0x191):
                raise SignerError(f"the PKCS#11 module {path} did not start: {CKR.get(rv, hex(rv))}")
            _loaded[path] = lib
        return _loaded[path]


def check(rv, what):
    if rv:
        raise SignerError(f"{what}: {CKR.get(rv, 'error 0x%x' % rv)}")


class Token:
    """One logged-in session on the token with this label."""

    def __init__(self, module, token_label, pin):
        self.lib, self.lock = load(module), threading.Lock()
        count = ULONG(0)
        check(self.lib.C_GetSlotList(1, None, ctypes.byref(count)), "listing the PKCS#11 slots")
        slots = (ULONG * max(count.value, 1))()
        check(self.lib.C_GetSlotList(1, slots, ctypes.byref(count)), "listing the PKCS#11 slots")
        self.slot = None
        for slot in list(slots)[:count.value]:
            info = ctypes.create_string_buffer(1024)  # CK_TOKEN_INFO starts with the 32-byte label
            if self.lib.C_GetTokenInfo(ULONG(slot), info) == 0 and info.raw[:32].decode("utf-8", "replace").strip() == token_label:
                self.slot = slot
                break
        if self.slot is None:
            raise SignerError(f"no token labelled '{token_label}' in the PKCS#11 module (is it plugged in and initialised?)")
        self.session = ULONG(0)
        check(self.lib.C_OpenSession(ULONG(self.slot), CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(self.session)), "opening a session on the token")
        weakref.finalize(self, self.lib.C_CloseSession, self.session)
        rv = self.lib.C_Login(self.session, CKU_USER, pin.encode(), len(pin.encode()))
        if rv == 0xA0 or rv == 0xA1 or rv == 0xA2:
            raise SignerError("the token refused the PIN (check the variable that holds it)")
        if rv == 0xA4:
            raise SignerError("the token's PIN is locked: unlock it with the security officer PIN before the CA can sign")
        if rv != 0x100:
            check(rv, "logging in to the token")

    def find(self, cls, label):
        attrs, keep = template([(CKA_CLASS, cls), (CKA_KEY_TYPE, CKK_ML_DSA), (CKA_LABEL, label.encode())])
        check(self.lib.C_FindObjectsInit(self.session, attrs, 3), "searching the token")
        found, n = (ULONG * 2)(), ULONG(0)
        try:
            check(self.lib.C_FindObjects(self.session, found, 2, ctypes.byref(n)), "searching the token")
        finally:
            self.lib.C_FindObjectsFinal(self.session)
        del keep
        if n.value == 0:
            raise SignerError(f"no ML-DSA key labelled '{label}' on the token")
        if n.value > 1:
            raise SignerError(f"more than one ML-DSA key is labelled '{label}' on the token: give them different labels")
        return found[0]

    def attribute(self, handle, attr_type):
        query = (Attribute * 1)(Attribute(attr_type, None, 0))
        check(self.lib.C_GetAttributeValue(self.session, ULONG(handle), query, 1), "reading a key attribute")
        if query[0].length in (ULONG(-1).value, 0):
            raise SignerError("cannot read that key attribute: the token does not release it")
        buf = ctypes.create_string_buffer(query[0].length)
        query[0].value = ctypes.cast(buf, ctypes.c_void_p)
        check(self.lib.C_GetAttributeValue(self.session, ULONG(handle), query, 1), "reading a key attribute")
        return buf.raw[:query[0].length]

    def read_private_value(self, label):
        """Ask the token for the private key's bytes. A correctly made CA key refuses (that is the point); this exists so tests can show it."""
        try:
            return self.attribute(self.find(CKO_PRIVATE_KEY, label), CKA_VALUE)
        except SignerError as e:
            raise SignerError(f"not extractable: cannot read the private key ({e})") from None

    def sign(self, handle, data):
        mech = Mechanism(CKM_ML_DSA, None, 0)
        with self.lock:
            check(self.lib.C_SignInit(self.session, ctypes.byref(mech), ULONG(handle)), "starting a signature on the token")
            size = ULONG(0)
            buf = ctypes.create_string_buffer(bytes(data), len(data))
            check(self.lib.C_Sign(self.session, buf, len(data), None, ctypes.byref(size)), "signing on the token")
            out = ctypes.create_string_buffer(size.value)
            check(self.lib.C_Sign(self.session, buf, len(data), out, ctypes.byref(size)), "signing on the token")
        return out.raw[:size.value]


class PKCS11Signer(signers.Signer):
    def __init__(self, module, token, key, pin):
        self.token = Token(module, token, pin)
        self.private = self.token.find(CKO_PRIVATE_KEY, key)
        public = self.token.find(CKO_PUBLIC_KEY, key)
        self.algorithm = algorithm_of(int.from_bytes(self.token.attribute(public, CKA_PARAMETER_SET), "little"))
        self.spki = spki(self.algorithm, self.token.attribute(public, CKA_VALUE))

    def sign(self, data):
        return self.token.sign(self.private, data)


def pin_from_env(var):
    pin = os.environ.get(var)
    if not pin:
        raise SignerError(f"the token's PIN is read from the environment variable {var}, which is not set")
    return pin


def from_config(cfg):
    if "pin" in cfg:
        raise SignerError("a PKCS#11 PIN does not belong in the configuration file: name the environment variable that holds it in \"pin_env\"")
    pin = pin_from_env(cfg.get("pin_env", "ACXELIN_PKCS11_PIN"))
    for needed in ("module", "token", "key"):
        if not cfg.get(needed):
            raise SignerError(f"the pkcs11 signer needs \"{needed}\"")
    load(cfg["module"])  # a missing module is reported before the PIN is used
    return PKCS11Signer(cfg["module"], cfg["token"], cfg["key"], pin)


def generate(module, token, pin, key_label, algorithm="ML-DSA-87"):
    """Make an ML-DSA key pair inside the token: sensitive and not extractable, so the private key can never be read out."""
    sets = {v: k for k, v in PARAMETER_SETS.items()}
    if algorithm not in sets:
        raise SignerError(f"{algorithm} is not an ML-DSA algorithm")
    t = Token(module, token, pin)
    ident = secrets.token_bytes(16)
    pub, keep1 = template([(CKA_TOKEN, True), (CKA_VERIFY, True), (CKA_LABEL, key_label.encode()), (CKA_PARAMETER_SET, sets[algorithm])])
    priv, keep2 = template([(CKA_TOKEN, True), (CKA_PRIVATE, True), (CKA_SENSITIVE, True), (CKA_EXTRACTABLE, False), (CKA_SIGN, True), (CKA_LABEL, key_label.encode())])
    mech, h_pub, h_priv = Mechanism(CKM_ML_DSA_KEY_PAIR_GEN, None, 0), ULONG(0), ULONG(0)
    check(t.lib.C_GenerateKeyPair(t.session, ctypes.byref(mech), pub, len(pub), priv, len(priv), ctypes.byref(h_pub), ctypes.byref(h_priv)), "generating the key pair on the token")
    del keep1, keep2, ident
    return key_label

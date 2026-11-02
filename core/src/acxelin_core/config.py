"""Settings from TOML files, with clear errors, and passphrases from the environment."""
import math
import os
import tomllib
from dataclasses import MISSING
from pathlib import Path


def build(cls, d, where, **extra):
    """A settings dataclass from a TOML table, with clear errors for unknown, missing and mistyped settings."""
    fields = cls.__dataclass_fields__
    unknown = set(d) - set(fields)
    if unknown:
        import difflib
        hints = [f"{u} (did you mean {m[0]}?)" if (m := difflib.get_close_matches(u, fields, 1, 0.8)) else u for u in sorted(unknown)]
        raise ValueError(f"{where}: unknown settings {', '.join(hints)}")
    missing = [n for n, f in fields.items() if n not in d and n not in extra and f.default is MISSING and f.default_factory is MISSING]
    if missing:
        raise ValueError(f"{where}: missing {', '.join(missing)}")
    for k, v in d.items():
        t = fields[k].type
        t = {"str": str, "int": int, "float": float, "bool": bool, "list": list, "dict": dict}.get(t, t)
        ok = isinstance(v, (int, float)) and not isinstance(v, bool) if t is float else isinstance(v, t) if isinstance(t, type) else True
        if t is int and isinstance(v, bool):
            ok = False
        if not ok:
            kind = {str: "text in quotes", int: "a whole number", float: "a number", bool: "true or false", list: "a list", dict: "a table"}
            raise ValueError(f"{where}: {k} must be {kind.get(t, t.__name__)}, not {v!r}")
        if t is float:
            try:
                finite = math.isfinite(v)
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError(f"{where}: {k} must be a finite number, not {v!r}")
    return cls(**d, **extra)


def read_text(path):
    """A text file as Windows tools save it too: UTF-8 with or without a byte-order mark, or UTF-16 (PowerShell 5 redirection)."""
    data = Path(path).read_bytes()
    for bom, codec in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if data.startswith(bom):
            return data.decode(codec)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"{path} is not UTF-8 text; save it as UTF-8") from None


def read_toml(path):
    try:
        return tomllib.loads(read_text(path))
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"{path}: {e}") from None


def env_passphrase(var):
    """The passphrase in environment variable `var`, None when no variable is named."""
    if not var:
        return None
    if var not in os.environ:
        raise ValueError(f"environment variable {var} is not set")
    return os.environ[var].encode()


"""Container images: a `docker save` or OCI archive is unpacked layer by layer, whiteouts applied, and scanned as a filesystem."""
import json
import shutil
import tarfile
import zlib
from pathlib import Path, PurePosixPath

MAX_FILE = 64_000_000
MAX_BYTES, MAX_FILES, MAX_LAYERS = 512_000_000, 50_000, 256  # for the whole image, as for a downloaded repository


def is_image(p):
    p = Path(p)
    if not p.is_file() or not tarfile.is_tarfile(p):
        return False
    with tarfile.open(p) as t:
        names = set(t.getnames())
        if "index.json" in names and "oci-layout" in names:
            return True
        if "manifest.json" not in names:
            return False
        try:  # docker save writes a list of images, each with its layers; other archives also carry a manifest.json
            man = _json(t, "manifest.json")
        except (ValueError, KeyError, tarfile.TarError):
            return False
    return isinstance(man, list) and bool(man) and isinstance(man[0], dict) and isinstance(man[0].get("Layers"), list)


def _json(outer, name):
    return json.load(outer.extractfile(name))


def layers(outer):
    """Layer member names, bottom first, each once. ValueError for a manifest that is not one: names that are not text, an
    index that leads back to itself or nests too deep, or more than MAX_LAYERS layers."""
    names = set(outer.getnames())
    blob = lambda d: "blobs/" + d.replace(":", "/") if isinstance(d, str) else None
    if "manifest.json" in names:
        found = _json(outer, "manifest.json")[0]["Layers"]
    else:
        man, seen = _json(outer, "index.json"), set()
        while isinstance(man, dict) and "manifests" in man:
            digest = man["manifests"][0]["digest"]
            if digest in seen or len(seen) >= 8:
                raise ValueError("the image's manifests lead back to themselves or nest too deep")
            seen.add(digest)
            man = _json(outer, blob(digest))
        found = [blob(x["digest"]) for x in man["layers"]]
    if not isinstance(found, list) or not all(isinstance(n, str) for n in found):
        raise ValueError("the image's manifest lists layers that are not names")
    found = list(dict.fromkeys(found))
    if len(found) > MAX_LAYERS:
        raise ValueError(f"the image has more than {MAX_LAYERS} layers")
    return found


def _parts(name):
    """The path's parts, or None for anything that could leave the folder: parent parts, and on Windows backslashes and drives."""
    parts = [p for p in PurePosixPath(name).parts if p not in ("/", ".")]
    return None if not parts or any(p == ".." or "\\" in p or ":" in p for p in parts) else parts


def _remove(p):
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p, ignore_errors=True)
    elif p.exists():
        p.unlink()


class Full(Exception):
    pass


def apply(layer, dest, budget=None):
    """Regular files and folders only: links, devices and oversized files are left out, so nothing can point outside `dest`.
    `budget` is [bytes, files] left for the whole image; Full is raised when a file would go over it."""
    root, budget = dest.resolve(), budget if budget is not None else [MAX_BYTES, MAX_FILES]
    for m in layer:
        parts = _parts(m.name)
        if not parts:
            continue
        where, base = dest.joinpath(*parts[:-1]), parts[-1]
        if not where.resolve().is_relative_to(root):
            continue
        try:
            if base == ".wh..wh..opq":
                for c in where.iterdir() if where.is_dir() else ():
                    _remove(c)
            elif base.startswith(".wh."):
                gone = base[4:]
                if gone not in ("", ".", "..") and (where / gone).resolve().parent.is_relative_to(root):
                    _remove(where / gone)
            elif m.isdir():
                (where / base).mkdir(parents=True, exist_ok=True)
            elif m.isreg() and m.size <= MAX_FILE:
                if m.size > budget[0] or budget[1] <= 0:
                    raise Full
                budget[0] -= m.size
                budget[1] -= 1
                where.mkdir(parents=True, exist_ok=True)
                with layer.extractfile(m) as src, open(where / base, "wb") as out:
                    shutil.copyfileobj(src, out)
        except OSError:
            continue


def unpack(archive, dest):
    """Returns notes on layers that could not be read (zstd compression, for one)."""
    notes, dest, budget = [], Path(dest), [MAX_BYTES, MAX_FILES]
    with tarfile.open(archive) as outer:
        names = layers(outer)
        for name in names:
            try:
                with tarfile.open(fileobj=outer.extractfile(name), mode="r:*") as layer:
                    apply(layer, dest, budget)
            except Full:
                notes.append(f"stopped at layer {name}: the image unpacks to more than the limit of {MAX_BYTES // 1_000_000} MB "
                             f"or {MAX_FILES} files, so later files were not scanned")
                break
            except (tarfile.TarError, KeyError, OSError, EOFError, zlib.error) as e:
                notes.append(f"layer {name} not read: {e}")
    return [f"container image {Path(archive).name}: {len(names)} layer(s) unpacked and scanned as one filesystem"] + notes

"""A CycloneDX 1.6 software bill of materials for one release folder: every wheel in it, with the SHA-256 of its bytes.

    python tools/sbom.py PRODUCT VERSION WHEELHOUSE OUT.cdx.json

Standard library only. Licences are copied from each wheel's own metadata and left out when it gives none. The same folder always
gives the same bytes: nothing here reads the clock.
"""
import hashlib
import json
import re
import sys
import uuid
import zipfile
from email.parser import Parser
from pathlib import Path


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def metadata(wheel):
    with zipfile.ZipFile(wheel) as z:
        found = [n for n in z.namelist() if n.count("/") == 1 and n.endswith(".dist-info/METADATA")]
        if len(found) != 1:
            raise ValueError(f"{wheel.name} has no single .dist-info/METADATA, so it cannot be listed")
        return Parser().parsestr(z.read(found[0]).decode("utf-8"))


def requirement_name(line):
    return canonical(re.split(r"[\s;<>=!~(\[@]", line.strip(), maxsplit=1)[0])


def generate(folder, product, version):
    folder = Path(folder)
    wheels = sorted(folder.glob("*.whl"))
    if not wheels:
        raise ValueError(f"{folder} holds no wheels")
    components, requires = [], {}
    for w in wheels:
        meta = metadata(w)
        name, ver = canonical(meta["Name"] or ""), meta["Version"] or ""
        if not name or not ver:
            raise ValueError(f"{w.name}: its metadata gives no name or version")
        c = {"type": "library", "bom-ref": w.name, "name": name, "version": ver, "purl": f"pkg:pypi/{name}@{ver}",
             "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(w.read_bytes()).hexdigest()}],
             "properties": [{"name": "acxelin:wheel", "value": w.name}]}
        licence = (meta["License-Expression"] or "").strip() or (meta["License"] or "").strip()
        if licence and "\n" not in licence and len(licence) <= 200:
            c["licenses"] = [{"expression": licence}]
        components.append(c)
        requires[w.name] = [requirement_name(r) for r in meta.get_all("Requires-Dist") or []]
    refs = {}
    for c in components:
        refs.setdefault(c["name"], []).append(c["bom-ref"])
    subject = f"acxelin-{product}"
    root = {"type": "application", "bom-ref": f"product:{subject}", "name": subject, "version": version, "purl": f"pkg:pypi/{subject}@{version}"}
    own = [w for w in refs.get(subject, [])]
    if not own:
        raise ValueError(f"{folder} holds no wheel of {subject}")
    wanted = {r for w in own for r in requires[w]} - {subject}
    edges = [{"ref": root["bom-ref"], "dependsOn": sorted(r for n in wanted for r in refs.get(n, []))}]
    for c in components:
        edges.append({"ref": c["bom-ref"], "dependsOn": sorted(r for n in set(requires[c["bom-ref"]]) for r in refs.get(n, []) if r != c["bom-ref"])})
    digest = hashlib.sha256("\n".join(f"{c['bom-ref']} {c['hashes'][0]['content']}" for c in components).encode()).hexdigest()
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'{subject}-{version}:{digest}')}", "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": "acxelin-sbom"}]}, "component": root},
            "components": components, "dependencies": edges}


def dumps(bom):
    return json.dumps(bom, indent=1) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    try:
        text = dumps(generate(sys.argv[3], sys.argv[1], sys.argv[2]))
    except (ValueError, OSError, zipfile.BadZipFile) as e:
        sys.exit(f"sbom: {e}")
    Path(sys.argv[4]).write_text(text, encoding="utf-8")
    print(f"wrote {sys.argv[4]}")

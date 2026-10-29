import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

SCHEMAS = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "cyclonedx"


def main(path):
    if not Path(path).is_file():
        print(f"{path} not found: run `acxelin-readiness scan PATH` first, or give the CBOM to check")
        return 1
    s = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in SCHEMAS.glob("*.json")}
    reg = Registry()
    for n, doc in s.items():
        r = Resource.from_contents(doc, default_specification=DRAFT7)
        reg = reg.with_resource(n, r)
        if "$id" in doc:
            reg = reg.with_resource(doc["$id"], r)
    bom = json.loads(Path(path).read_text(encoding="utf-8"))
    errs = list(Draft7Validator(s["bom-1.6.schema.json"], registry=reg).iter_errors(bom))
    for e in errs[:20]:
        print(list(e.path), e.message[:200])
    print(f"{path}: {len(errs)} schema errors")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "readiness-out/cbom.json"))

"""Build what a customer receives for one product: its wheel, acxelin-core's and every third-party wheel they need, with the
product's installers, README, manual and other docs, licence, example settings and service units. Nothing of another product.

    python tools/wheelhouse.py readiness OUT
    sh OUT/install.sh            (or install.ps1 on Windows)
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


# Where the folder installs offline: compiled wheels are fetched again for each. Intel Macs are left out because cffi 2.x
# publishes no wheel for them.
PLATFORMS = ("manylinux2014_x86_64", "manylinux2014_aarch64", "win_amd64", "macosx_11_0_arm64")
PYTHONS = ("3.11", "3.12", "3.13", "3.14")


def pip(*args):
    subprocess.run([sys.executable, "-m", "pip", *args], check=True)


def build(product, out, extras=""):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    pip("wheel", "--quiet", "--wheel-dir", str(out), str(ROOT / "core"), f"{ROOT / 'products' / product}{extras}")
    pins = sorted({"==".join(w.name.split("-")[:2]) for w in out.glob("*.whl") if not w.name.endswith("-none-any.whl")})
    for plat in PLATFORMS:
        for py in PYTHONS:
            target = ("--only-binary=:all:", "--platform", plat, "--python-version", py, "--implementation", "cp")
            if pins:
                pip("download", "--quiet", "--no-deps", *target, "--dest", str(out), *pins)
            with tempfile.TemporaryDirectory() as t:  # the whole product must resolve from the folder alone, for each one
                pip("install", "--quiet", "--dry-run", "--ignore-installed", "--no-index", "--find-links", str(out), *target,
                    "--target", t, f"acxelin-{product}{extras}")
    return out


EXTRAS = {"vpn": "[vpn]", "readiness": "[crawler,aws]"}
CUSTOMER = ["install.sh", "install.ps1", "README.md", "LICENSE", "CHANGELOG.md", "docs", "config", "deploy/systemd"]


def package(product, out):
    out = build(product, out, EXTRAS.get(product, ""))
    if EXTRAS.get(product):
        (out / "extras").write_text(EXTRAS[product])  # what install.sh and install.ps1 add when it resolves
    src = ROOT / "products" / product
    for name in CUSTOMER:
        if (src / name).is_dir():
            shutil.copytree(src / name, out / name, dirs_exist_ok=True)
        elif (src / name).exists():
            shutil.copy2(src / name, out / name)
    return out


if __name__ == "__main__":
    print(package(sys.argv[1], sys.argv[2]))

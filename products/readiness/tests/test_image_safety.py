"""Container images are untrusted archives: no layer may write, delete or link outside the folder it is unpacked into."""
import gzip
import io
import json
import tarfile

import pytest

from acxelin_readiness import cli, image


def tarbytes(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return b.getvalue()


def archive(path, *layers, manifest=None):
    names = [f"l{i}.tar" for i in range(len(layers))]
    path.write_bytes(tarbytes([("manifest.json", json.dumps(manifest if manifest is not None else [{"Layers": names}]).encode()),
                               *zip(names, layers)]))
    return path


@pytest.mark.parametrize("name", [".wh...", "a/.wh...", ".wh..", "a/.wh.", "x/../.wh.victim", "..\\.wh.victim"])
def test_a_whiteout_never_removes_anything_outside_the_image(tmp_path, name):
    victim = tmp_path / "victim"
    dest = victim / "dest"
    dest.mkdir(parents=True)
    (victim / "precious.txt").write_text("keep me")
    image.unpack(archive(tmp_path / "img.tar", tarbytes([("a/file.py", b"x"), (name, b"")])), dest)
    assert (victim / "precious.txt").read_text() == "keep me" and (dest / "a/file.py").exists()


@pytest.mark.parametrize("name", ["..\\..\\evil.txt", "C:\\evil.txt", "C:/evil.txt", "\\\\srv\\share\\evil.txt", "a/b\\..\\..\\evil.txt"])
def test_windows_style_names_are_left_out(tmp_path, name):
    dest = tmp_path / "dest"
    dest.mkdir()
    image.unpack(archive(tmp_path / "img.tar", tarbytes([(name, b"evil"), ("ok.py", b"x")])), dest)
    assert sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*")) == ["dest", "dest/ok.py", "img.tar"]


def test_a_truncated_layer_is_a_note_and_the_rest_is_scanned(tmp_path):
    good = tarbytes([("keys.py", b"import hashlib\nhashlib.md5(b'x')\n")])
    cut = gzip.compress(tarbytes([("big.bin", bytes(range(256)) * 800)]))[:300]
    dest = tmp_path / "dest"
    dest.mkdir()
    notes = image.unpack(archive(tmp_path / "img.tar", good, cut), dest)
    assert (dest / "keys.py").exists() and any("not read" in n for n in notes)


def test_a_tar_with_some_other_manifest_is_scanned_as_a_plain_archive_not_an_image(tmp_path):
    arc = tmp_path / "extension.tar"
    arc.write_bytes(tarbytes([("manifest.json", b'{"name": "a browser extension", "version": "1"}'), ("x.js", b"1")]))
    assert not image.is_image(arc)
    assert cli.main(["scan", str(arc), "--out", str(tmp_path / "out"), "--quiet"]) == 0

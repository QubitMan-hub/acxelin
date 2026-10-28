"""GitHub repositories by link: only github.com, the token only to the API host, and an archive that cannot write outside its folder."""
import http.server
import io
import tarfile
import threading

import pytest

from acxelin_readiness import remote


@pytest.mark.parametrize("url,want", [
    ("https://github.com/acme/shop", ("acme", "shop", None)),
    ("https://github.com/acme/shop.git", ("acme", "shop", None)),
    ("https://github.com/acme/shop/", ("acme", "shop", None)),
    ("https://github.com/acme/shop/tree/release/2.0", ("acme", "shop", "release/2.0")),
    ("github.com/acme/my_repo.js", ("acme", "my_repo.js", None)),
])
def test_links_as_people_paste_them(url, want):
    assert remote.parse(url) == want


@pytest.mark.parametrize("url", [
    "http://github.com/acme/shop", "https://gitlab.com/acme/shop", "https://github.com.evil.example/acme/shop",
    "https://token@github.com/acme/shop", "https://user:pw@github.com/acme/shop", "https://github.com/acme",
    "https://github.com/acme/shop/tree/../../x", "https://github.com/acme/../shop", "https://github.com/acme/shop?x=1",
    "https://github.com:8443/acme/shop", "https://github.com/ac me/shop", "https://github.com/acme/shop/blob/main/a.py",
])
def test_anything_else_is_refused(url):
    with pytest.raises(ValueError):
        remote.parse(url)


def tarball(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, kind, data in members:
            m = tarfile.TarInfo(name)
            if kind == "file":
                m.size = len(data)
                t.addfile(m, io.BytesIO(data))
            elif kind == "dir":
                m.type = tarfile.DIRTYPE
                t.addfile(m)
            else:
                m.type, m.linkname = (tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE), data
                t.addfile(m)
    return buf.getvalue()


GOOD = tarball([("acme-shop-1a2b/", "dir", b""), ("acme-shop-1a2b/keys.py", "file", b"import hashlib\nhashlib.md5(b'x')\n"),
                ("acme-shop-1a2b/src/app.py", "file", b"print('hi')\n")])


class Server:
    """An API host that redirects to a separate download host, recording what each one received."""
    def __init__(self, body=GOOD, status=200):
        self.seen, self.body, self.status = [], body, status
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.seen.append((self.headers["Host"].split(":")[0], self.path, self.headers.get("Authorization")))
                if self.path.startswith("/repos/"):
                    if outer.status != 200:
                        self.send_response(outer.status)
                        self.end_headers()
                        return
                    self.send_response(302)
                    self.send_header("Location", f"http://localhost:{self.server.server_address[1]}/download.tar.gz")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(outer.body)))
                    self.end_headers()
                    self.wfile.write(outer.body)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def server():
    s = Server()
    yield s
    s.close()


def test_a_repository_is_downloaded_without_its_top_folder(server, tmp_path):
    dest = tmp_path / "shop"
    remote.fetch("https://github.com/acme/shop", dest, api=server.api)
    assert (dest / "keys.py").read_bytes().startswith(b"import hashlib") and (dest / "src/app.py").exists()
    assert server.seen[0][1] == "/repos/acme/shop/tarball"


def test_a_branch_is_asked_for_by_name(server, tmp_path):
    remote.fetch("https://github.com/acme/shop/tree/release/2.0", tmp_path / "shop", api=server.api)
    assert server.seen[0][1] == "/repos/acme/shop/tarball/release/2.0"


def test_the_token_goes_to_the_api_host_only_never_to_where_it_redirects(server, tmp_path):
    remote.fetch("https://github.com/acme/shop", tmp_path / "shop", token="ghp_secretvalue", api=server.api)
    (api_host, _, sent), (download_host, _, forwarded) = server.seen
    assert api_host != download_host and sent == "Bearer ghp_secretvalue" and forwarded is None


@pytest.mark.parametrize("status,words", [(404, "not found"), (401, "token"), (403, "refused")])
def test_errors_say_what_to_do_and_never_echo_the_token(tmp_path, status, words):
    s = Server(status=status)
    try:
        with pytest.raises(ValueError) as e:
            remote.fetch("https://github.com/acme/shop", tmp_path / "shop", token="ghp_secretvalue", api=s.api)
    finally:
        s.close()
    assert words in str(e.value).lower() and "ghp_secretvalue" not in str(e.value)


def test_a_rescan_replaces_the_previous_download(server, tmp_path):
    dest = tmp_path / "shop"
    remote.fetch("https://github.com/acme/shop", dest, api=server.api)
    (dest / "removed-upstream.py").write_text("x")
    remote.fetch("https://github.com/acme/shop", dest, api=server.api)
    assert not (dest / "removed-upstream.py").exists() and (dest / "keys.py").exists()


@pytest.mark.parametrize("name,kind,data", [
    ("top/../../escape.py", "file", b"x"), ("/etc/escape.py", "file", b"x"), ("top/link", "symlink", "/etc/passwd"),
    ("top/hard", "hardlink", "top/keys.py"), ("top/..\\..\\escape.py", "file", b"x"), ("top/C:/escape.py", "file", b"x"),
])
def test_nothing_in_the_archive_lands_outside_its_folder_or_links_out(tmp_path, name, kind, data):
    s = Server(body=tarball([("top/", "dir", b""), ("top/keys.py", "file", b"ok"), (name, kind, data)]))
    try:
        remote.fetch("https://github.com/acme/shop", tmp_path / "r" / "shop", api=s.api)
    finally:
        s.close()
    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    assert written == ["r", "r/shop", "r/shop/keys.py"], written
    assert not any(p.is_symlink() for p in tmp_path.rglob("*"))


def test_size_limits_stop_a_download_and_an_unpacking(tmp_path, monkeypatch):
    big = tarball([("top/", "dir", b"")] + [(f"top/{i}.py", "file", b"x" * 1000) for i in range(20)])
    s = Server(body=big)
    try:
        monkeypatch.setattr(remote, "MAX_DOWNLOAD", len(big) - 1)
        with pytest.raises(ValueError, match="larger"):
            remote.fetch("https://github.com/acme/shop", tmp_path / "a", api=s.api)
        monkeypatch.setattr(remote, "MAX_DOWNLOAD", 10 * len(big))
        monkeypatch.setattr(remote, "MAX_FILES", 5)
        with pytest.raises(ValueError, match="files"):
            remote.fetch("https://github.com/acme/shop", tmp_path / "b", api=s.api)
        monkeypatch.setattr(remote, "MAX_FILES", 1000)
        monkeypatch.setattr(remote, "MAX_BYTES", 5000)
        with pytest.raises(ValueError, match="larger"):
            remote.fetch("https://github.com/acme/shop", tmp_path / "c", api=s.api)
    finally:
        s.close()
    assert not any((tmp_path / d).exists() for d in "abc"), "a refused download leaves nothing behind"


def test_a_download_that_switches_from_https_to_http_is_refused():
    opener = remote.opener()
    handler = next(h for h in opener.handlers if isinstance(h, remote.Redirects))
    import urllib.request
    req = urllib.request.Request("https://api.github.com/repos/a/b/tarball")
    with pytest.raises(ValueError, match="HTTPS"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://codeload.github.com/a/b")


def test_the_command_line_scans_a_link_with_the_token_from_the_environment_only(tmp_path, monkeypatch):
    from unittest.mock import patch
    from acxelin_readiness import cli
    seen = {}

    def fetch(url, dest, token=None):
        seen.update(url=url, token=token)
        seen["dest"] = dest
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
        (dest / ".acxelin-readiness.toml").write_text('tls = ["internal.example:443"]\n')
        return dest
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fromtheenvironment")
    with patch("acxelin_readiness.cli.remote.fetch", side_effect=fetch), patch("acxelin_readiness.pipeline.run", wraps=__import__("acxelin_readiness.pipeline").pipeline.run) as run:
        assert cli.main(["scan", "https://github.com/acme/shop", "--out", str(tmp_path / "out"), "--quiet"]) == 0
    assert (seen["url"], seen["token"]) == ("https://github.com/acme/shop", "ghp_fromtheenvironment")
    cbom = (tmp_path / "out/cbom.json").read_text()
    assert "MD5" in cbom and "acme/shop" in cbom
    assert run.call_args.args[2] == [], "a downloaded repository's own settings never choose which hosts this computer probes"
    assert not seen["dest"].exists(), "the downloaded copy is deleted after the scan"


def test_a_connection_that_drops_mid_download_is_a_refusal_with_advice(tmp_path, monkeypatch):
    class Dropping:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            raise TimeoutError("timed out")
    monkeypatch.setattr(remote, "opener", lambda: type("O", (), {"open": lambda self, req, timeout: Dropping()})())
    with pytest.raises(remote.Refused, match="reach GitHub"):
        remote.fetch("https://github.com/acme/shop", tmp_path / "shop")


def test_a_local_folder_named_like_a_github_path_is_scanned_where_it_is(tmp_path, monkeypatch):
    from unittest.mock import patch
    from acxelin_readiness import cli
    (tmp_path / "github.com/acme/app").mkdir(parents=True)
    (tmp_path / "github.com/acme/app/a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    monkeypatch.chdir(tmp_path)
    with patch("acxelin_readiness.cli.remote.fetch", side_effect=AssertionError("downloaded")):
        assert cli.main(["scan", "github.com/acme/app", "--out", str(tmp_path / "out"), "--quiet"]) == 0
    assert "MD5" in (tmp_path / "out/cbom.json").read_text()

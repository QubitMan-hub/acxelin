"""GitHub repositories by link: download the archive through the API and unpack it for scanning. Nothing in it is run."""
import re
import secrets
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlsplit

API = "https://api.github.com"
MAX_DOWNLOAD = 256_000_000
MAX_BYTES = 512_000_000
MAX_FILES = 50000
MAX_FILE = 32_000_000
OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
NAME = re.compile(r"[A-Za-z0-9._-]{1,100}")


class Refused(ValueError):
    """A download GitHub or the limits refused; the message is safe to show."""


def parse(url):
    """(owner, repo, ref or None) of https://github.com/OWNER/REPO[.git][/tree/REF]; anything else is refused."""
    text = url.strip() if isinstance(url, str) else ""
    if text.startswith("github.com/"):
        text = "https://" + text
    u = urlsplit(text)
    parts = [p for p in u.path.split("/") if p]
    if u.scheme != "https" or u.netloc != "github.com" or u.query or u.fragment or len(parts) < 2:
        raise ValueError("Enter a GitHub repository link such as https://github.com/owner/repository")
    owner, repo, rest = parts[0], parts[1].removesuffix(".git"), parts[2:]
    ref = "/".join(rest[1:]) if rest[:1] == ["tree"] and len(rest) > 1 else None
    ok = lambda p: NAME.fullmatch(p) and p not in (".", "..")
    if not OWNER.fullmatch(owner) or not ok(repo) or (rest and ref is None) or ref and not all(ok(p) for p in ref.split("/")):
        raise ValueError("Enter a GitHub repository link such as https://github.com/owner/repository, or a branch as …/tree/branch")
    return owner, repo, ref


def label(url):
    owner, repo, ref = parse(url)
    return f"{owner}/{repo}" + (f"@{ref}" if ref else "")


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != urlsplit(req.full_url).scheme:
            raise Refused("GitHub's download was refused: it redirected away from HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def opener():
    return urllib.request.build_opener(Redirects)


def _download(owner, repo, ref, token, api, into):
    req = urllib.request.Request(f"{api}/repos/{owner}/{repo}/tarball" + (f"/{quote(ref, safe='/')}" if ref else ""),
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "acxelin-readiness", "X-GitHub-Api-Version": "2022-11-28"})
    if token:
        req.add_unredirected_header("Authorization", f"Bearer {token}")  # never forwarded: only the API host sees it
    try:
        with opener().open(req, timeout=60) as r:
            total = 0
            while chunk := r.read(1 << 20):
                total += len(chunk)
                if total > MAX_DOWNLOAD:
                    raise Refused(f"The repository archive is larger than {MAX_DOWNLOAD // 1_000_000} MB; scan a local copy instead")
                into.write(chunk)
    except urllib.error.HTTPError as e:
        raise Refused({404: "Repository not found on GitHub. For a private repository, save a read-only access token first.",
                          401: "GitHub refused the access token: check that it has not expired and can read this repository."}.get(
            e.code, "GitHub refused the download: the rate limit is reached, or the token cannot read this repository." if e.code in (403, 429)
            else f"GitHub answered {e.code}; try again later.")) from None
    except urllib.error.URLError as e:
        raise Refused(f"Could not reach GitHub ({e.reason}); check the network or proxy") from None


def _unpack(archive, dest):
    """Regular files and folders under the archive's top folder only: links, devices, absolute and parent paths are left out."""
    files = size = 0
    with tarfile.open(fileobj=archive, mode="r:*") as t:
        for m in t:
            if m.name.startswith(("/", "\\")):
                continue
            parts = PurePosixPath(m.name).parts[1:]
            if not parts or any(p in (".", "..") or "\\" in p or ":" in p for p in parts) or not (m.isdir() or m.isreg()):
                continue
            target = dest.joinpath(*parts)
            if not target.resolve().is_relative_to(dest.resolve()):
                continue
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            files, size = files + 1, size + m.size
            if files > MAX_FILES:
                raise Refused(f"The repository has more than {MAX_FILES} files; scan a local copy instead")
            if size > MAX_BYTES:
                raise Refused(f"The repository is larger than {MAX_BYTES // 1_000_000} MB unpacked; scan a local copy instead")
            if m.size > MAX_FILE:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with t.extractfile(m) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def fetch(url, dest, token=None, api=API):
    """Replace `dest` with the repository's current files. On any failure `dest` is left as it was."""
    owner, repo, ref = parse(url)
    dest = Path(dest)
    dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = dest.parent / f".{dest.name}.{secrets.token_hex(6)}.tmp"
    try:
        with tempfile.TemporaryFile() as archive:
            _download(owner, repo, ref, token, api, archive)
            archive.seek(0)
            work.mkdir(mode=0o700)
            try:
                _unpack(archive, work)
            except (tarfile.TarError, EOFError, OSError) as e:
                raise Refused("GitHub sent an archive that could not be unpacked; try again") from e
        if dest.exists():
            shutil.rmtree(dest)
        work.rename(dest)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return dest

"""Inputs an adversarial review built to hang, crash or take over a scan, each now refused or bounded: a repository whose git
settings run a command, archives and images that unpack to gigabytes or loop, damaged keystores and captures, settings in a
scanned folder that choose hosts to probe, servers that never finish a handshake, and a line that makes a pattern backtrack."""
import io
import json
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock
import zipfile
from pathlib import Path


def git(d, *a):
    return subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True)


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class GitTest(unittest.TestCase):
    def test_a_scanned_repositorys_git_settings_run_nothing(self):
        from acxelin_readiness.cli import changed_files
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            git(d, "init", "-q")
            (d / "a.py").write_text("x = 1\n")
            (d / "b.py").write_text("y = 1\n")
            git(d, "add", ".")
            git(d, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "one")
            pwned = d.parent / f"{d.name}-pwned"
            git(d, "config", "core.fsmonitor", f"touch {pwned}-fsmonitor; false")
            git(d, "config", "filter.evil.clean", f"touch {pwned}-filter; cat")
            git(d, "config", "diff.external", f"touch {pwned}-diff")
            (d / ".git" / "info" / "attributes").write_text("*.py filter=evil diff=evil\n")
            time.sleep(1.1)  # past the index's timestamp, so git would have to look inside the file
            (d / "a.py").write_text("x = 2\n")
            (d / "c.py").write_text("z = 1\n")
            (d / "b.py").write_text("y = 2\n")
            git(d, "-c", "core.fsmonitor=false", "-c", "filter.evil.clean=cat", "add", "b.py")
            try:
                self.assertEqual(changed_files(d, "HEAD"), {"a.py", "b.py", "c.py"}, "changed, staged and new files")
            finally:
                ran = [p.name for p in d.parent.glob(f"{d.name}-pwned*")]
                for p in d.parent.glob(f"{d.name}-pwned*"):
                    p.unlink()
            self.assertEqual(ran, [], "git ran a command the scanned repository chose")


def jar(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


class ArchiveTest(unittest.TestCase):
    def test_a_small_jar_that_repeats_a_constant_millions_of_times_stays_small(self):
        from acxelin_readiness.detectors import binary
        data = jar([("A.class", b"javax/crypto" + b"MD5\0" * 1_000_000)])
        self.assertLess(len(data), 50_000)
        start = time.monotonic()
        found = binary.scan_archive(data, "a.jar", set())
        self.assertEqual([d.algo for d in found], ["MD5"], "one finding per distinct constant")
        self.assertLess(time.monotonic() - start, 5)

    def test_an_archive_has_a_total_budget(self):
        from acxelin_readiness.detectors import binary
        cls = b"javax/crypto" + b"\0" * (3 << 20) + b"MD5\0"
        data = jar([(f"C{i}.class", cls) for i in range(binary.ARCHIVE_BUDGET // len(cls) + 20)])
        with unittest.mock.patch.object(binary, "scan_class", wraps=binary.scan_class) as seen:
            binary.scan_archive(data, "a.jar", set())
        self.assertLessEqual(seen.call_count * len(cls), binary.ARCHIVE_BUDGET)

    def test_a_scan_can_be_stopped_inside_an_archive(self):
        from acxelin_readiness.detectors import Scope, binary

        class Stop(Exception):
            pass
        calls = []

        def checkpoint():
            calls.append(1)
            if len(calls) > 3:
                raise Stop
        with tempfile.TemporaryDirectory() as d:
            Path(d, "a.jar").write_bytes(jar([(f"C{i}.class", b"javax/crypto MD5\0") for i in range(50)]))
            with self.assertRaises(Stop):
                binary.scan(d, Scope(checkpoint=checkpoint))


# keystores a fuzzer found: one raises InvalidVersion while reading a certificate, the other TypeError while naming it
DAMAGED = ["zs7OzgAAAAIAAAABAAAAAgABYQAAAAAAAAAAAAVYLjUwOQAAAQcwggEDMIGroAMCAW8CAQEwCgYIKoZIzj0EAwIwDDEKMAgGA1UEAwwBYTAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMAwxCjAIBgNVBAMMAWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS0Nw7q4D9zEKezrrO0vX8bYgxw6QQfLgO7vXoJMH2P2TXCNyutyVAF3n/9/pfpzA+uzQo03+T+bgJ0qrOqwoubMAoGCCqGSM49BAMCA0cAMEQCIALdibHy8h5scvNgtQp1B/o3hEHBWXz7incFVIAn+I1kAiAQQ7K1bB6wzi8MBsq7TICJMVpyDaXKwxNAojMl50QKZAAAAAAAAAAAAAAAAAAAAAAAAAAA",
           "zs7OzgAAAAIAAAABAAAAAgABYQAAAAAAAAAAAAVYLjUwzQAAAQcwggEDMIGroAMCAQICAQEwCgYIKoZIzj0EAwIwDDEKMAgGA1UEAwwBYTAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMAwxCjAIBgNVBAMDAWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS0Nw7q4D9zEKezrrO0vX8bYgxw6QQfLgO7vXoJMH2P2TXCNyutyVAF3n/9/pfpzA+uzQo03+T+bgJ0qrOqwoubMAoGCCqGSM49BAMCA0cAMEQCIALdibHy8h5scvNgtQp1B/o3hEHBWXz7incFVIAn+I1kAiAQQ7K1bB6wzi8MBsq7TICJMVpyDaXKwxNAojMl50QKZAAAAAAAAAAAAAAAAAAAAAAAAAAA"]


class KeystoreTest(unittest.TestCase):
    def test_a_damaged_keystore_is_skipped_and_the_scan_goes_on(self):
        import base64
        from acxelin_readiness.detectors import keystores
        for i, data in enumerate(DAMAGED):
            with self.subTest(i):
                keystores.read(base64.b64decode(data), "store.jks")


class SettingsTest(unittest.TestCase):
    def test_a_scanned_folders_settings_cannot_choose_what_this_machine_connects_to(self):
        import contextlib
        from acxelin_readiness import cli
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / ".acxelin-readiness.toml"
            f.write_text('tls = ["10.0.0.5:443"]\nssh = ["10.0.0.6"]\naws = ["eu-west-1"]\nexclude = ["gen"]\n')
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                cfg = cli.settings(None, Path(d))
            self.assertEqual(cfg, {"exclude": ["gen"]})
            self.assertIn("--config", err.getvalue())
            self.assertEqual(cli.settings(str(f), Path(d))["tls"], ["10.0.0.5:443"], "named with --config, it is trusted")


def serve_once(send):
    import socket
    import threading
    srv = socket.create_server(("127.0.0.1", 0))

    def run():
        conn, _ = srv.accept()
        try:
            send(conn)
        except OSError:
            pass
        finally:
            conn.close()
            srv.close()
    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


class ProbeTest(unittest.TestCase):
    def drip(self, first):
        def send(conn):
            conn.settimeout(20)
            conn.recv(65536)
            conn.sendall(first)
            for _ in range(200):
                conn.sendall(b"x")
                time.sleep(0.1)
        return send

    def test_a_server_sending_a_byte_at_a_time_cannot_hold_a_tls_probe(self):
        from acxelin_readiness.detectors import probe
        port = serve_once(self.drip(b"\x16\x03\x03\xff\xff"))
        start = time.monotonic()
        kind, _ = probe.server_hello("127.0.0.1", port, [0x11EC], timeout=1.0)
        self.assertEqual(kind, "error")
        self.assertLess(time.monotonic() - start, 5)

    def test_an_endless_ssh_banner_is_cut_off_in_time_and_size(self):
        from acxelin_readiness.detectors import probe

        def flood(conn):
            conn.settimeout(20)
            for _ in range(100_000):
                conn.sendall(b"x" * 4096)
        for send in (flood, self.drip(b"SSH-2.0-x\r\n\xff\xff\xff\xff")):
            port = serve_once(send)
            start = time.monotonic()
            with self.assertRaises(OSError):
                probe.ssh_kexinit("127.0.0.1", port, timeout=1.0)
            self.assertLess(time.monotonic() - start, 5)


class PatternTest(unittest.TestCase):
    def test_one_long_identifier_cannot_make_a_rule_backtrack_for_hours(self):
        from acxelin_readiness.detectors import patterns
        text = "class A { void f() { var " + "a" * 200_000 + " = 1; } }\n"
        start = time.monotonic()
        patterns.scan_text("a.cs", text, "csharp")
        self.assertLess(time.monotonic() - start, 3)
        found = patterns.scan_text("b.cs", "h.ServerCertificateCustomValidationCallback = (a, b, c, d) => true;\n", "csharp")
        self.assertTrue(found, "the rule still finds what it is for")


class CaptureTest(unittest.TestCase):
    def test_a_capture_with_an_empty_interface_block_is_read_not_fatal(self):
        import struct
        from acxelin_readiness.detectors import capture
        shb = struct.pack("<II", 0x0A0D0D0A, 28) + b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1) + struct.pack("<I", 28)
        idb = struct.pack("<III", 1, 12, 12)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.pcapng"
            p.write_bytes(shb + idb)
            try:
                capture.scan(p)
            except ValueError:
                pass  # refused in words is fine; a crash is not


class MergeTest(unittest.TestCase):
    def test_wrongly_typed_cbom_fields_are_ignored_not_fatal(self):
        from acxelin_readiness import inventory
        base = {"type": "cryptographic-asset", "name": "RSA-1024", "cryptoProperties": {"assetType": "algorithm"}}
        odd = [{"cryptoProperties": {"assetType": "algorithm", "algorithmProperties": "x"}}, {"evidence": [1]},
               {"evidence": {"occurrences": "abc"}}, {"evidence": {"occurrences": [{"location": ["a"]}, 5]}},
               {"properties": [{"name": "acxelin:policy", "value": 5}]}, {"properties": [{"name": "acxelin:recommendation", "value": {"a": 1}}]},
               {"properties": [{"name": "acxelin:tier", "value": [1]}]}, {"properties": "x"}]
        for extra in odd:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as d:
                p = Path(d) / "a" / "cbom.json"
                p.parent.mkdir()
                p.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [base | extra]}))
                inventory.run([str(p)], "Org", Path(d) / "out")


class CSVTest(unittest.TestCase):
    def test_part_of_a_cell_after_a_semicolon_cannot_become_a_formula(self):
        import csv
        from acxelin_readiness import evidence
        text = evidence.csv_text(["Place"], [["x;=HYPERLINK(\"http://evil\")"], ["=1+1"]])
        for row in csv.reader(io.StringIO(text), delimiter=";"):
            self.assertFalse(any(c.lstrip('"').startswith("=") for c in row[1:]), row)
        self.assertEqual(list(csv.reader(io.StringIO(text)))[2], ["'=1+1"])

"""The VPN window's server: only its own page, on its own host name and origin, with the key from its address."""
import contextlib
import http.client
import html
import io
import json
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from acxelin_vpn import cli
from acxelin_vpn import app


class WindowServerTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.d = Path(tmp.name)
        self.window = app.App(folder=self.d, apply=False)
        self.httpd = app.serve(self.window)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.port = self.httpd.server_address[1]

    def call(self, path="/api/state", token=None, **headers):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", path, headers={"Host": f"127.0.0.1:{self.port}", "Authorization": f"Bearer {token or self.window.token}"} | headers)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def test_strangers_are_refused_and_cannot_lock_the_owner_out(self):
        self.assertEqual(self.call(), 200)
        self.assertEqual(self.call(Host=f"rebound.example:{self.port}"), 421)
        self.assertEqual(self.call(token="guess"), 401)
        for _ in range(20):
            self.assertEqual(self.call(token="guess", Origin="https://evil.example"), 403)
        self.assertEqual(self.call(), 200, "refused origins do not count towards the wrong-key lockout")
        self.assertEqual(self.call(Origin=f"http://localhost:{self.port}"), 200)

    def test_the_page_allows_only_its_own_script_and_no_framing(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", "/", headers={"Host": f"localhost:{self.port}"})
        r = c.getresponse()
        page = r.read()
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("script-src 'sha256-", csp)
        self.assertEqual(page.count(b"<script>"), 1)
        self.assertNotIn(self.window.token.encode(), page)

    def test_a_file_that_is_not_an_invitation_is_refused_and_not_kept(self):
        status, body = self.window.handle("POST", "/api/invitation", {"name": "x.acxinvite", "text": "{\"acxelin_invite\": 1}"})
        self.assertEqual(status, 400)
        self.assertIn("not an Acxelin VPN invitation", body["error"])
        self.assertEqual(list(self.d.glob("*.acxinvite")), [])
        self.assertEqual(self.window.handle("POST", "/api/connect", {"passphrase": "x"})[1]["error"][:24], "open the invitation file")


    def test_a_one_time_address_opens_one_window_and_expires(self):
        def exchange(ticket):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            c.request("POST", "/api/session", json.dumps({"ticket": ticket}), {"Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json"})
            r = c.getresponse()
            body = json.loads(r.read())
            c.close()
            return r.status, body
        ticket = self.window.ticket()
        self.assertEqual(exchange(ticket), (200, {"token": self.window.token}))
        self.assertEqual(exchange(ticket)[0], 401, "a used address does not open a second window")
        self.assertEqual(exchange(self.window.ticket(ttl=-1))[0], 401, "an expired address is refused")
        self.assertEqual(exchange(None)[0], 401)

    def test_quit_disconnects_and_stops_the_service(self):
        stopped = threading.Event()
        self.window.on_quit = stopped.set
        self.assertEqual(app.request(self.port, self.window.token, "POST", "/api/quit"), {"stopping": True})
        self.assertTrue(stopped.wait(5), "the service stops after its answer has gone out")
        with self.assertRaises(ValueError):
            app.request(self.port, "wrong", "GET", "/api/state")


class SingleWindowTest(unittest.TestCase):
    def test_a_second_launch_opens_the_running_window_with_a_new_one_time_address(self):
        with TemporaryDirectory() as d:
            window = app.App(folder=d, apply=False)
            httpd = app.serve(window)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            self.addCleanup(httpd.server_close)
            self.addCleanup(httpd.shutdown)
            port = httpd.server_address[1]
            held, running = app.claim(d, "wg0.app")
            with held:
                self.assertIsNone(running)
                self.assertEqual(app.claim(d, "wg0.app"), (None, None))
                (Path(d) / "wg0.app.json").write_text(json.dumps({"port": port, "token": window.token}))
                out = io.StringIO()
                with mock.patch("webbrowser.open") as browser, contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
                    cli.main(["app", "--folder", d])
                self.assertEqual(e.exception.code, 0)
                page = browser.call_args.args[0]
                self.assertNotIn("#", page, "the launch ticket is not on the browser's command line")
                url = html.unescape((Path(d) / "console-launch.html").read_text().split("url=", 1)[1].split('"', 1)[0])
                self.assertTrue(url.startswith(f"http://127.0.0.1:{port}/#"))
                self.assertNotIn(window.token, url + out.getvalue(), "the session key never goes to a browser's command line")
                self.assertTrue(window.redeem(url.split("#")[1]))
                with app.claim(d, "wg1.app")[0]:
                    pass

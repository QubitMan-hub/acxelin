"""ACME dns-01 through a command the operator provides: the CA runs it to look up the TXT records of _acme-challenge.NAME.

The client is certbot's own `acme` library, so a certificate is obtained by the protocol and not by a test double."""
import datetime as dt
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from acxelin_core.pki import CA
from acxelin_tls.acme import Service, make_csr, serve

try:
    import josepy as jose
    from acme import challenges, client, errors, messages
    REASON = None
except ImportError:
    REASON = "needs the acme package (pip install -e .[integration])"

LOOKUP = """import json, os, sys
records = json.load(open(sys.argv[1]))
open(sys.argv[1] + ".env", "w").write(json.dumps(sorted(os.environ)))
open(sys.argv[1] + ".args", "w").write(json.dumps(sys.argv[2:]))
for value in records.get(sys.argv[-1], []):
    print('"' + value + '"')  # dig +short prints TXT records in quotes
"""


def start(httpd, test):
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    test.addCleanup(httpd.server_close)
    test.addCleanup(httpd.shutdown)


@unittest.skipIf(REASON, REASON)
class DNS01Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        (self.d / "lookup.py").write_text(LOOKUP, encoding="utf-8")
        self.dns = self.d / "dns.json"
        self.dns.write_text("{}", encoding="utf-8")
        self.ca = CA.init(self.d / "pki", "ACME Root")
        self.serve(dns=[sys.executable, str(self.d / "lookup.py"), str(self.dns)])

    def serve(self, dns):
        self.httpd = serve(Service(self.ca, "http://placeholder", allow=["*.test", "*.corp.test"], http_port=1, allow_local=True, dns_command=dns), "127.0.0.1:0")
        self.svc = self.httpd.service
        self.url = self.svc.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        start(self.httpd, self)

    def acme(self):
        key = jose.JWKEC(key=ec.generate_private_key(ec.SECP256R1()))
        net = client.ClientNetwork(key, alg=jose.ES256, user_agent="acxelin-tls-test")
        c = client.ClientV2(client.ClientV2.get_directory(self.url + "/directory", net), net)
        c.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
        return c, key

    def publish(self, domain, value):
        records = json.loads(self.dns.read_text(encoding="utf-8"))
        records.setdefault(f"_acme-challenge.{domain}", []).append(value)
        self.dns.write_text(json.dumps(records), encoding="utf-8")

    def order(self, c, names):
        return c.new_order((make_csr(names, self.d / f"k{len(list(self.d.glob('k*')))}") / "csr.pem").read_bytes())

    def dns_challenge(self, authz):
        return next(ch for ch in authz.body.challenges if isinstance(ch.chall, challenges.DNS01))

    def prove(self, c, key, order, publish=True):
        for authz in order.authorizations:
            ch = self.dns_challenge(authz)
            response, validation = ch.response_and_validation(key)
            if publish:
                self.publish(authz.body.identifier.value, validation)
            c.answer_challenge(ch, response)
        return c.poll_and_finalize(order, dt.datetime.now() + dt.timedelta(seconds=20))

    def test_a_name_that_no_web_server_answers_for_gets_a_certificate_by_dns_01(self):
        c, key = self.acme()
        order = self.prove(c, key, self.order(c, ["intranet.corp.test"]))
        leaf = x509.load_pem_x509_certificates(order.fullchain_pem.encode())[0]
        leaf.verify_directly_issued_by(self.ca.cert)
        self.assertEqual(leaf.signature_algorithm_oid.dotted_string, "2.16.840.1.101.3.4.3.19")

    def test_a_wildcard_can_only_be_proved_by_dns_01_and_the_certificate_says_so(self):
        c, key = self.acme()
        order = self.order(c, ["*.corp.test"])
        types = {type(ch.chall) for ch in order.authorizations[0].body.challenges}
        self.assertEqual(types, {challenges.DNS01}, "RFC 8555: a wildcard cannot be proved over HTTP")
        done = self.prove(c, key, order)
        san = x509.load_pem_x509_certificates(done.fullchain_pem.encode())[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), ["*.corp.test"])
        self.assertEqual(json.loads((self.dns.parent / "dns.json.args").read_text()), ["_acme-challenge.corp.test"], "the base name is looked up, not the wildcard")

    def test_the_wrong_record_leaves_the_order_unissued_and_says_where_to_look(self):
        c, key = self.acme()
        order = self.order(c, ["intranet.corp.test"])
        self.publish("intranet.corp.test", "not-the-right-value")
        ch = self.dns_challenge(order.authorizations[0])
        c.answer_challenge(ch, ch.response(key))
        with self.assertRaises(errors.ValidationError) as caught:
            c.poll_and_finalize(order, dt.datetime.now() + dt.timedelta(seconds=15))
        self.assertIn("_acme-challenge.intranet.corp.test", str(caught.exception))
        self.assertEqual(self.ca.records(), [])

    def test_no_record_at_all_is_a_clear_failure(self):
        c, key = self.acme()
        with self.assertRaises(errors.ValidationError) as caught:
            self.prove(c, key, self.order(c, ["intranet.corp.test"]), publish=False)
        self.assertIn("no TXT record", str(caught.exception))

    def test_a_command_that_fails_does_not_leak_its_error_to_the_client(self):
        self.serve([sys.executable, "-c", "import sys; sys.stderr.write('resolver at 10.9.8.7 refused'); sys.exit(3)"])
        c, key = self.acme()
        with self.assertRaises(errors.ValidationError) as caught:
            self.prove(c, key, self.order(c, ["intranet.corp.test"]), publish=False)
        self.assertNotIn("10.9.8.7", str(caught.exception))
        self.assertIn("see the CA's log", str(caught.exception))

    def test_the_command_gets_no_secrets_and_no_shell(self):
        os.environ["ACXELIN_TLS_CA_PASSPHRASE"] = "hunter2-do-not-leak"
        self.addCleanup(os.environ.pop, "ACXELIN_TLS_CA_PASSPHRASE", None)
        c, key = self.acme()
        self.prove(c, key, self.order(c, ["intranet.corp.test"]))
        seen = json.loads((self.dns.parent / "dns.json.env").read_text())
        self.assertNotIn("ACXELIN_TLS_CA_PASSPHRASE", seen)
        self.assertIn("PATH", seen)

    def test_a_name_that_could_be_an_option_or_a_shell_trick_never_reaches_the_command(self):
        c, key = self.acme()
        for bad in ("-x.corp.test", "a b.corp.test", "x;id.corp.test", "x$(id).corp.test", "x`id`.corp.test", "x\nid.corp.test"):
            with self.subTest(name=bad), self.assertRaises(messages.Error):
                c.new_order(self.csr_for(bad))
        self.assertFalse((self.dns.parent / "dns.json.args").exists())

    def csr_for(self, name):
        from cryptography.hazmat.primitives import hashes, serialization
        k = ec.generate_private_key(ec.SECP256R1())
        return (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False).sign(k, hashes.SHA256())).public_bytes(serialization.Encoding.PEM)

    def test_a_command_that_hangs_is_cut_off(self):
        self.serve([sys.executable, "-c", "import time; time.sleep(60)"])
        self.svc.dns_timeout = 1
        c, key = self.acme()
        started = time.monotonic()
        with self.assertRaises(errors.ValidationError):
            self.prove(c, key, self.order(c, ["intranet.corp.test"]), publish=False)
        self.assertLess(time.monotonic() - started, 15)

    def test_a_flood_of_output_is_capped_and_not_believed(self):
        self.serve([sys.executable, "-c", "import sys\nfor i in range(400000): print('x' * 60)"])
        c, key = self.acme()
        with self.assertRaises(errors.ValidationError):
            self.prove(c, key, self.order(c, ["intranet.corp.test"]), publish=False)

    def test_without_a_command_there_is_no_dns_01_and_a_wildcard_says_why(self):
        self.serve(None)
        c, key = self.acme()
        order = self.order(c, ["intranet.corp.test"])
        self.assertEqual({type(ch.chall) for ch in order.authorizations[0].body.challenges}, {challenges.HTTP01})
        with self.assertRaisesRegex(messages.Error, "--dns-command"):
            c.new_order((make_csr(["*.corp.test"], self.d / "w") / "csr.pem").read_bytes())

    def test_an_authorization_made_before_dns_01_existed_still_works_and_gets_a_token(self):
        c, key = self.acme()
        self.order(c, ["old.corp.test"])
        aid, authz = next(iter(self.svc.state["authz"].items()))
        for field in ("dns_token", "dns_status", "dns_error", "dns_validated", "wildcard"):
            authz.pop(field, None)  # what a state file written by 1.0.x holds
        views = self.svc.challenge_views(aid)
        self.assertEqual([v["type"] for v in views], ["http-01", "dns-01"])
        self.assertTrue(authz["dns_token"] and authz["dns_status"] == "pending")

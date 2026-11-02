"""Problems found by using the products as a first-time customer would; each test shows the problem fixed."""
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from acxelin_core.config import build
from acxelin_core.pki import CA, CAError


class SecretsTest(unittest.TestCase):
    def test_a_passphrase_pasted_where_a_serial_goes_is_never_repeated(self):
        with tempfile.TemporaryDirectory() as d:
            ca = CA.init(Path(d) / "pki", "Root")
            for pasted in ("correct horse 9!", "hunter2-hunter2", "s3cr3t"):
                with self.assertRaises(CAError) as caught:
                    ca.find(pasted)
                self.assertNotIn(pasted, str(caught.exception))
                self.assertIn("hex", str(caught.exception))


@dataclass
class Sample:
    name: str
    require_client_cert: bool = False
    crl_every: float = 60.0


class SettingsTest(unittest.TestCase):
    def test_a_misspelled_setting_names_the_one_that_was_meant(self):
        with self.assertRaisesRegex(ValueError, "require_client_certs.*did you mean require_client_cert"):
            build(Sample, {"name": "x", "require_client_certs": True}, "edge #1")
        with self.assertRaises(ValueError) as caught:
            build(Sample, {"name": "x", "colour": "amber"}, "edge #1")
        self.assertNotIn("did you mean", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

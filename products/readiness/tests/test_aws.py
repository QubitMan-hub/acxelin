"""AWS KMS keys and ACM certificates read directly: list and describe calls only, never key material, and a refused region is a note, not a crash."""
import datetime as dt

import pytest

from acxelin_readiness import pipeline
from acxelin_readiness.detectors import aws

CALLS = []
NEVER = {"get_public_key", "export_certificate", "get_certificate", "encrypt", "decrypt", "sign", "generate_data_key"}


class Pager:
    def __init__(self, name, pages):
        self.name, self.pages = name, pages

    def paginate(self, **kw):
        CALLS.append((self.name, kw))
        return self.pages


class Client:
    def __init__(self, service, region):
        self.service, self.region = service, region

    def __getattr__(self, name):
        CALLS.append((name, None))
        if name in NEVER:
            raise AssertionError(f"{name} must never be called")
        raise AttributeError(name)

    def get_paginator(self, name):
        if self.region == "us-east-9":
            raise PermissionError("AccessDenied")
        if self.service == "kms":
            return Pager(name, [{"Keys": [{"KeyId": "k1"}]}, {"Keys": [{"KeyId": "k2"}, {"KeyId": "k3"}]}])
        return Pager(name, [{"CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:eu-west-1:1:certificate/abc"}]}])

    def describe_key(self, KeyId):
        spec = {"k1": "RSA_2048", "k2": "ML_DSA_65", "k3": "SYMMETRIC_DEFAULT"}[KeyId]
        return {"KeyMetadata": {"KeyId": KeyId, "KeySpec": spec, "KeyUsage": "SIGN_VERIFY", "KeyState": "Enabled", "KeyManager": "CUSTOMER"}}

    def describe_certificate(self, CertificateArn):
        return {"Certificate": {"CertificateArn": CertificateArn, "DomainName": "shop.example.com", "KeyAlgorithm": "EC_prime256v1",
                                "NotAfter": dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc), "Status": "ISSUED"}}


class Session:
    def client(self, service, region_name):
        return Client(service, region_name)


@pytest.fixture(autouse=True)
def clean():
    CALLS.clear()


def test_keys_and_certificates_become_findings_at_their_aws_location():
    found, notes = aws.scan(["eu-west-1"], Session())
    got = {(d.algo, d.file, d.params.get("key_size"), d.params.get("curve")) for d in found}
    assert ("RSA", "aws://kms/eu-west-1/k1", 2048, None) in got and ("ML-DSA-65", "aws://kms/eu-west-1/k2", None, None) in got
    assert ("AES", "aws://kms/eu-west-1/k3", 256, None) in got and ("ECC", "aws://acm/eu-west-1/abc", None, "P-256") in got
    assert any("shop.example.com" in n and "expired" in n for n in notes)


def test_every_certificate_key_type_is_listed_and_nothing_but_list_and_describe_is_called():
    aws.scan(["eu-west-1"], Session())
    acm = next(kw for name, kw in CALLS if name == "list_certificates")
    assert {"RSA_1024", "RSA_4096", "EC_prime256v1", "EC_secp521r1"} <= set(acm["Includes"]["keyTypes"])
    assert not {name for name, _ in CALLS} & NEVER


def test_a_refused_region_is_a_note_and_the_others_are_still_read():
    found, notes = aws.scan(["us-east-9", "eu-west-1"], Session())
    assert found and any("us-east-9" in n and "not read" in n for n in notes)


def test_kms_findings_are_ranked_like_any_other(tmp_path):
    r = pipeline.run(tmp_path, "cloud", aws=["eu-west-1"], aws_session=Session())
    rsa = next(a for a in r.assets if a.variant == "RSA-2048")
    assert rsa.tier in ("critical", "high", "medium") and {s.file for s in rsa.detections} == {"aws://kms/eu-west-1/k1"}

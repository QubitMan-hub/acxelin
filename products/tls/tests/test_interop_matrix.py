"""The interop matrix: its predictions are right on their own terms, and (in the interop CI job) every real peer behaves as predicted."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "interop"))
import matrix  # noqa: E402

PQ_ML_DSA = {"pq": True, "mldsa": True}
PQ_ONLY = {"pq": True, "mldsa": False}
CLASSICAL = {"pq": False, "mldsa": False}


@pytest.mark.parametrize("caps,mode,offers_1024,expected", [
    (PQ_ML_DSA, "strict", False, (True, True)),
    (PQ_ONLY, "strict", False, (False, False)),     # a Go client has ML-KEM but cannot verify ML-DSA certificates
    (CLASSICAL, "strict", False, (False, False)),
    (CLASSICAL, "transition", False, (True, False)),  # served, but not post-quantum: the matrix must say so
    (PQ_ONLY, "transition", False, (True, True)),
    (PQ_ML_DSA, "cnsa2", False, (False, False)),    # no default client offers an ML-KEM-1024 group
    (PQ_ML_DSA, "cnsa2", True, (True, True)),
    (PQ_ONLY, "cnsa2", True, (False, False)),
])
def test_what_a_client_should_get_from_each_edge_policy(caps, mode, offers_1024, expected):
    assert matrix.client_expectation(caps, mode, offers_1024) == expected


@pytest.mark.parametrize("caps,mode,cert_is_mldsa,expected", [
    (PQ_ML_DSA, "strict", True, (True, True)),
    (PQ_ONLY, "strict", False, (False, False)),      # Acxelin's strict client refuses a classical certificate even over ML-KEM
    (PQ_ONLY, "transition", False, (True, True)),
    (CLASSICAL, "transition", False, (True, False)),
    (PQ_ONLY, "cnsa2", False, (False, False)),
])
def test_what_the_acxelin_client_should_get_from_each_server(caps, mode, cert_is_mldsa, expected):
    assert matrix.server_expectation(caps, mode, cert_is_mldsa) == expected


def test_version_parsing_reads_the_library_not_the_program():
    assert matrix.version_tuple("OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9)") == (3, 5, 9)
    assert matrix.version_tuple("go version go1.24.7 linux/amd64") == (1, 24, 7)
    assert matrix.version_tuple("nothing here") == (0, 0, 0)


@pytest.mark.skipif(os.environ.get("ACXELIN_INTEROP") != "1", reason="the interop CI job sets ACXELIN_INTEROP=1; it needs go, node, curl, nginx and OpenSSL 3.5")
def test_every_real_peer_behaves_as_predicted(capsys):
    assert matrix.main([]) == 0, capsys.readouterr().err

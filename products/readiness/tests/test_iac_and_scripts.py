"""Keys made by infrastructure code and shell scripts: Terraform's tls_private_key and ACM certificates, and openssl and
ssh-keygen command lines, the way real provisioning scripts write them."""
from acxelin_readiness import workspace

TF = """resource "tls_private_key" "node" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}
resource "aws_acm_certificate" "web" {
  domain_name   = "example.com"
  key_algorithm = "EC_prime256v1"
}
"""

SH = """#!/bin/sh
openssl genrsa -out ca.key 4096
openssl req -x509 -new -sha512 -key ca.key -out ca.crt
openssl ecparam -name secp384r1 -genkey -noout -out ec.key
openssl genpkey -algorithm ed25519 -out ed.key
openssl req -new -newkey rsa:1024 -nodes -keyout old.key -out old.csr
openssl enc -des3 -in secrets.txt -out secrets.enc
ssh-keygen -t rsa -b 3072 -f id_rsa
ssh-keygen -t ecdsa -b 521 -f id_ecdsa
# openssl genrsa -out unused.key 512 in a comment is not run
"""


def names(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return {a["name"] for a in workspace.scan(tmp_path)["assets"]}


def test_terraform_keys_carry_their_curve(tmp_path):
    assert {"ECDSA-P-384", "ECC-P-256"} <= names(tmp_path, "main.tf", TF)


def test_openssl_and_ssh_keygen_command_lines_in_scripts(tmp_path):
    found = names(tmp_path, "pki.sh", SH)
    assert {"RSA-4096", "SHA-512", "ECC-P-384", "Ed25519", "RSA-1024", "3DES", "RSA-3072", "ECDSA-P-521"} <= found
    assert "RSA-512" not in found, "a comment is not a command"

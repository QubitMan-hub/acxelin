"""Ruby's OpenSSL and Digest APIs and PHP's openssl_* and hash functions, written the way real projects call them."""
from acxelin_readiness import workspace

RUBY = """require 'openssl'
key = OpenSSL::PKey::RSA.generate(2048)
ec = OpenSSL::PKey::EC.generate('prime256v1')
ed = OpenSSL::PKey.generate_key('ED25519')
mac = OpenSSL::HMAC.hexdigest('SHA256', secret, data)
old = Digest::MD5.hexdigest(data)
c = OpenSSL::Cipher.new('aes-128-cbc')
ctx.min_version = OpenSSL::SSL::TLS1_VERSION
ALGORITHMS = %w[RS256 ES384].freeze  # comment mentioning SHA1 is not code
"""

PHP = """<?php
$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
openssl_sign($data, $sig, $key, OPENSSL_ALGO_SHA1);
$c = openssl_encrypt($data, 'des-ede3-cbc', $k);
$h = hash_hmac('sha256', $data, $secret);
$p = hash_pbkdf2('sha512', $pw, $salt, 100000);
$d = hash('md5', $data);
"""


def found(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return {a["name"] for a in workspace.scan(tmp_path)["assets"]}


def test_ruby_crypto_calls_are_found(tmp_path):
    names = found(tmp_path, "sign.rb", RUBY)
    assert {"RSA-2048", "ECC-P-256", "Ed25519", "HMAC-SHA-256", "MD5", "AES-128-CBC", "TLS 1.0"} <= names
    assert "SHA-1" not in names, "a comment is not code"


def test_php_crypto_calls_are_found(tmp_path):
    names = found(tmp_path, "sign.php", PHP)
    assert {"ECC-P-384", "SHA-1", "3DES", "HMAC-SHA-256", "PBKDF2-SHA-512", "MD5"} <= names

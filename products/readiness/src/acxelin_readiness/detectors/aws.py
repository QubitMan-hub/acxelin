"""AWS KMS keys and ACM certificates, read with the caller's own AWS credentials. Only list and describe calls: no key material, no
certificate bodies. Needs boto3 (`pip install "acxelin-readiness[aws]"`)."""
import datetime as dt

from ..model import Detection
from .suites import kms_spec

ACM_KEYS = ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]


def session():
    try:
        import boto3
    except ImportError:
        raise ValueError('reading AWS needs boto3: pip install "acxelin-readiness[aws]"') from None
    return boto3.Session()


def scan(regions, aws=None):
    """[Detection] for each KMS key and ACM certificate in `regions`, and notes for regions not read and certificates expired or expiring."""
    aws, found, notes = aws or session(), [], []
    now = dt.datetime.now(dt.timezone.utc)

    def add(spec, loc, snippet, role):
        for algo, params in kms_spec(spec or ""):
            found.append(Detection(algo=algo, file=loc, line=0, evidence="config", detector="aws", snippet=snippet, lang="aws",
                                   params={k: v for k, v in dict(params, role=role).items() if v is not None}))
    for region in regions:
        try:
            kms = aws.client("kms", region_name=region)
            for page in kms.get_paginator("list_keys").paginate():
                for key in page.get("Keys", []):
                    m = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    add(m.get("KeySpec"), f"aws://kms/{region}/{m['KeyId']}",
                        f"KMS key {m.get('KeySpec')}, {m.get('KeyUsage')}, {m.get('KeyState')}, {m.get('KeyManager', '').lower()}-managed", "kms-key")
            acm = aws.client("acm", region_name=region)
            for page in acm.get_paginator("list_certificates").paginate(Includes={"keyTypes": ACM_KEYS}):
                for c in page.get("CertificateSummaryList", []):
                    d = acm.describe_certificate(CertificateArn=c["CertificateArn"])["Certificate"]
                    name, ends = d.get("DomainName", "certificate"), d.get("NotAfter")
                    add(d.get("KeyAlgorithm"), f"aws://acm/{region}/{d['CertificateArn'].rsplit('/', 1)[-1]}", f"ACM certificate {name}, {d.get('KeyAlgorithm')}",
                        "subject-public-key")
                    if ends and ends < now + dt.timedelta(days=30):
                        notes.append(f"aws {region}: ACM certificate {name} {'expired' if ends < now else 'expires'} {ends.date().isoformat()}")
        except Exception as e:  # noqa: BLE001 - a region or service the credentials cannot read: the rest is still read
            notes.append(f"aws {region}: not read ({type(e).__name__}); check the credentials' kms:List*, kms:Describe*, acm:List* and acm:Describe* permissions")
    return found, notes

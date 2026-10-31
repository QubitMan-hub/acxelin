"""From nothing to a remote-access gateway in one command: the certificate authority (or the one already there), the
gateway's ML-DSA certificate, a revocation list, and a checked gateway.toml with absolute paths, then the three commands
that start enrollment, start the gateway and invite the first person."""
import ipaddress
import re
from pathlib import Path

from acxelin_core.files import write
from acxelin_core.pki import CA

NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$")


def gateway(folder, name, address=None, pool="10.99.0.0/24", routes=(), dns=(), full_tunnel=False, passphrase=None, force=False):
    """Set up a gateway called `name` in `folder`; returns the configuration file's path."""
    from .wireguard import load_gateway
    if not NAME.match(name) or len(name) > 253:
        raise ValueError(f"{name!r} is not a host name: use the name laptops reach the gateway by, such as vpn.acme.example")
    if address:
        ipaddress.ip_address(address)
    folder = Path(folder).resolve()
    conf = folder / "gateway.toml"
    if conf.exists() and not force:
        raise ValueError(f"{conf} already exists; use --force to replace it (the certificate authority is kept either way)")
    pki = folder / "pki"
    ca = CA(pki, passphrase) if (pki / "ca.crt").exists() else CA.init(pki, f"{name} VPN Root", passphrase=passphrase)
    ca.issue(name, "server", [name] + ([address] if address else []), out=folder / "gateway", replace=force)
    ca.crl()
    q = lambda p: '"' + str(p).replace("\\", "\\\\") + '"'
    lines = ["# written by `acxelin-vpn setup`; every setting is explained in config/gateway.toml", "[wireguard]",
             f"name = {q(name)}", f"endpoint = {q(f'{address or name}:51820')}", 'keyring_listen = "0.0.0.0:7443"', f"pool = {q(pool)}",
             f"routes = [{', '.join(q(r) for r in routes)}]", f"dns = [{', '.join(q(d) for d in dns)}]", f"full_tunnel = {'true' if full_tunnel else 'false'}",
             f"cert = {q(folder / 'gateway' / 'chain.pem')}", f"key = {q(folder / 'gateway' / 'key.pem')}", f"ca = {q(pki / 'ca.crt')}",
             f"crl = {q(pki / 'crl.pem')}", f"private_key = {q(folder / 'wireguard.key')}", f"state = {q(folder / 'state' / 'leases.json')}",
             'metrics = "127.0.0.1:9101"']
    (folder / "state").mkdir(parents=True, exist_ok=True)
    write(conf, ("\n".join(lines) + "\n").encode())
    load_gateway(conf)  # the file it wrote must load as it stands
    return conf


def next_steps(conf, name):
    d = conf.parent
    return (f"Gateway {name} is set up in {d}:\n"
            f"  pki/          the certificate authority; keep pki/ca.key safe\n"
            f"  gateway/      the gateway's ML-DSA certificate and key\n"
            f"  gateway.toml  its settings, checked\n\n"
            f"Next, on this machine:\n"
            f"  1. Enrollment, where invitations are redeemed (port 9443):\n"
            f"     acxelin-vpn ca serve --dir {d / 'pki'} --cert {d / 'gateway' / 'chain.pem'} --key {d / 'gateway' / 'key.pem'}\n"
            f"  2. The gateway (as root, with WireGuard installed):\n"
            f"     acxelin-vpn gateway --config {conf}\n"
            f"  3. Invite someone, and send them the file:\n"
            f"     acxelin-vpn invite alice --dir {d / 'pki'} --enroll https://{name}:9443 --gateway {name}:7443\n"
            f"Laptops need to reach UDP 51820 and TCP 7443 and 9443. `acxelin-vpn console --ca {d / 'pki'}` shows who is connected once\n"
            f"you add the gateway's status address, http://127.0.0.1:9101.")

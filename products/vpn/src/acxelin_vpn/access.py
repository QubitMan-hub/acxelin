"""Per-user route sets: which networks each person may reach through the gateway, and the packet filter that makes it true.

The key agreement tells a restricted person only their networks. That alone is advice: anyone can add a route by hand. The filter is the
enforcement: for each restricted address (the one the gateway leased to them) every packet from the tunnel that is not going to one of their
networks is dropped, whether it is forwarded to the office (forward) or aimed at the gateway itself (input). WireGuard already drops packets
whose source is not the peer's own address, so the source cannot be faked. Linux only (nftables).
"""
import ipaddress
import re
import shutil
import subprocess

TABLE = "acxelin_vpn_access"
INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}")


class AccessError(Exception):
    pass


def label(name):
    return re.sub(r"[^A-Za-z0-9._@-]", "_", str(name))[:64]


def ruleset(interface, restricted):
    """nftables text that replaces the table in one step. `restricted` is {name: (leased address, [networks])}."""
    if not isinstance(interface, str) or not INTERFACE.fullmatch(interface):
        raise ValueError(f"{interface!r} is not an interface name")
    rules = []
    for name, (address, networks) in sorted(restricted.items(), key=lambda kv: ipaddress.IPv4Address(kv[1][0])):
        source = str(ipaddress.IPv4Address(address))
        allowed = ", ".join(str(n) for n in sorted({ipaddress.IPv4Network(n, strict=True) for n in networks}))
        if not allowed:
            raise ValueError(f"{name}: no networks")
        rules.append(f'    iifname "{interface}" ip saddr {source} ip daddr != {{ {allowed} }} drop comment "{label(name)}"')
    lines = [f"table inet {TABLE}", f"delete table inet {TABLE}", f"table inet {TABLE} {{"]
    for chain, hook in (("forward", "forward"), ("input", "input")):
        lines += [f"  chain {chain} {{", f"    type filter hook {hook} priority -10; policy accept;", *rules, "  }"]
    return "\n".join(lines + ["}", ""])


class Nft:
    def apply(self, text):
        try:
            r = subprocess.run(["nft", "-f", "-"], input=text, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise AccessError(f"could not run nft: {e}") from None
        if r.returncode:
            raise AccessError(f"nft refused the access rules: {r.stderr.strip()[:300]}")

    def clear(self):
        subprocess.run(["nft", "delete", "table", "inet", TABLE], capture_output=True, text=True, timeout=15)


def require(cfg, which=shutil.which):
    """A gateway that manages its interface and restricts people must be able to enforce it; refuse to start otherwise."""
    if cfg.access and cfg.manage_interface and not which("nft"):
        raise RuntimeError("per-user access needs the nft command (install nftables) to enforce it. Without it people would only be advised of their routes, "
                           "which anyone can bypass. To enforce the rules another way, set manage_interface = false and load `acxelin-vpn access rules` yourself")


def validate(cfg):
    """Raise ValueError, in words, for an access table that cannot be enforced."""
    if cfg.access and cfg.full_tunnel:
        raise ValueError("access cannot be combined with full_tunnel = true: a person who gets all traffic cannot also be limited to some networks; use routes instead")
    if not isinstance(cfg.access, dict):
        raise ValueError("[wireguard.access] must be a table of name = [networks]")
    union = [ipaddress.ip_network(r) for r in cfg.routes]
    for name, nets in cfg.access.items():
        if cfg.users and name not in cfg.users:
            raise ValueError(f"{name!r} is in access but not in users: add it to users, or remove it from access")
        if not isinstance(nets, list):
            raise ValueError(f"access for {name!r} must be a list of networks, for example [\"10.20.0.0/24\"]")
        if not nets:
            raise ValueError(f"access for {name!r} needs at least one network; to give a person nothing, remove them from users")
        if len(nets) > 256:
            raise ValueError(f"access for {name!r} lists {len(nets)} networks; at most 256")
        for n in nets:
            try:
                net = ipaddress.ip_network(n, strict=True)
            except (ValueError, TypeError):
                raise ValueError(f"{n!r} (access for {name!r}) is not a network: write it like 10.20.0.0/24") from None
            if net.version != 4:
                raise ValueError(f"{n} (access for {name!r}): per-user access supports IPv4 networks only")
            if net.prefixlen == 0:
                raise ValueError(f"{n} (access for {name!r}) is everything: list the networks this person may reach, not all of them")
            if not any(net.subnet_of(r) for r in union if r.version == 4):
                raise ValueError(f"{n} (access for {name!r}) is not inside any of the routes: list the network in routes first")

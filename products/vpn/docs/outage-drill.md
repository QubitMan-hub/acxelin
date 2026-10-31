# Outage drill: what happens to the tunnel when key agreement stops

**Status: not run.** The script `tools/outage_drill.sh` and this procedure were written without a second machine. The script's
syntax was checked with `bash -n` and shellcheck, its refusals and its rule clean-up were exercised on one machine, and the
`block` and `slow` outages themselves have never been run against a real tunnel. Treat the "expect" lines below as predictions
from reading the code, and correct them with what you see.

The unit tests prove the grace's logic with stand-ins for `wg` and charon. Network namespaces cannot reproduce a real partition,
so this drill is how you learn, on two real Linux machines, what your own gateway and computers do. You need two Linux
virtual machines with root, WireGuard (kernel module or wireguard-go), iptables, iproute2 and curl, that reach each
other. Below, `GW` is the gateway machine and `CL` the client. The script is `products/vpn/tools/outage_drill.sh` in the source repository; it is not in the release folder, so copy it to both machines (the commands below call it as `tools/outage_drill.sh`). Use machines you can lose network access to; the script never
touches anything but TCP port 7443 between the two machines, but a mistake in a firewall is a mistake.

## 1. Set up the gateway and one client

On `GW`, as root. Install Acxelin VPN as in section 3 of the manual, then:

```
acxelin-vpn setup vpn.drill.example --address GW_IP --dir /root/drill
```

It prints the three commands to run next. Start enrollment and the gateway, each in its own terminal (or under `systemd`, section 8):

```
acxelin-vpn ca serve --dir /root/drill/pki --cert /root/drill/gateway/chain.pem --key /root/drill/gateway/key.pem
acxelin-vpn gateway --config /root/drill/gateway.toml
```

Replace `GW_IP` with the gateway's address. On `CL`, add the line `GW_IP vpn.drill.example` to `/etc/hosts`, so the invitation's names resolve there. Invite one person on `GW` and copy the file to `CL`:

```
acxelin-vpn invite alice --dir /root/drill/pki --enroll https://vpn.drill.example:9443 --gateway vpn.drill.example:7443
```

On `CL`, in an administrator terminal:

```
acxelin-vpn join alice.acxinvite
```

Leave it running. In another terminal check that it is protected and that traffic crosses the tunnel (`10.99.0.1` is the gateway's tunnel address with the default pool):

```
acxelin-vpn status --interface wg0
```

```
ping -c3 10.99.0.1
```

## 2. The runs

For every run, open the timeline in a terminal on each machine and keep the output:

```
sudo tools/outage_drill.sh watch --role gateway --wg-interface wg0
```

```
sudo tools/outage_drill.sh watch --role client --wg-interface wg0 --target 10.99.0.1
```

The gateway line shows each person's WireGuard handshake age and the gateway's own view (`keys=` seconds since the last key agreement; `IN GRACE n s left` when the outage grace is keeping them on their last keys). The client line shows its WireGuard handshake age, whether a ping through the tunnel works, and the first line of `acxelin-vpn status`.

Run A uses the default, `outage_grace_minutes` unset (0). Run B sets `outage_grace_minutes = 30` in `/root/drill/gateway.toml`; a running gateway applies it within seconds (no restart: a restart forgets every connected computer). Do each run from a protected tunnel, and leave the tunnel to settle for a minute between runs.

### Run 1: the key agreement port is partitioned for 12 minutes (longer than the normal limit of 6.5 minutes)

On `GW` (`GW_NIC` is the network card that carries the traffic, such as `eth0`; `CL_IP` is the client's real address):

```
sudo tools/outage_drill.sh block --role gateway --wg-interface wg0 --interface GW_NIC --peer-ip CL_IP --minutes 12
```

It prints what it will change and waits for `yes`. It drops TCP 7443 both ways for 12 minutes, prints the timeline for a minute before, during and five minutes after, and removes its rules when it ends or on Ctrl-C. The client can be partitioned instead by running the same command on `CL` with `--role client --target 10.99.0.1 --peer-ip GW_IP`.

Expect with grace 0: the gateway removes `alice` about 6.5 minutes into the outage (it checks every 15 seconds), after which WireGuard handshakes stop and the ping fails; `acxelin-vpn status` on `CL` says the computer is not protected. Expect with grace 30: the gateway shows `IN GRACE` from about 6.5 minutes on and keeps the peer. The client's behaviour is the thing to watch: reading the code, the client software takes its own tunnel down after its next failed key agreement (within about two minutes) and retries every second, so with grace the ping may still fail even though the gateway kept the peer. If it does, the gateway-side grace does not yet keep laptops connected through an outage of the key agreement port, and that is a finding to report, not a configuration error.

### Run 2: a revocation during the outage

Find the client's serial on `GW` with `acxelin-vpn ca list --dir /root/drill/pki`, then:

```
sudo tools/outage_drill.sh block --role gateway --wg-interface wg0 --interface GW_NIC --peer-ip CL_IP --minutes 12 --revoke-serial SERIAL --ca-dir /root/drill/pki --revoke-at-min 8
```

It revokes the certificate 8 minutes in (set `ACXELIN_VPN_CA_PASSPHRASE` if the CA key is encrypted). Expect with grace 30: `alice` is inside the grace at minute 8 and is removed within 15 seconds of the revocation, not at the end of the grace. The gateway here has the CA on the same machine, so it reads the new CRL at once; with `crl_url` pointing at another machine that is also partitioned, the CRL would arrive late, and so would the removal (see the manual, section 8).

### Run 3: the key agreement is slow, not gone

```
sudo tools/outage_drill.sh slow --role gateway --wg-interface wg0 --interface GW_NIC --peer-ip CL_IP --minutes 12 --delay-ms 4000 --loss 40
```

This delays and drops the gateway's replies on port 7443 only. Expect key agreements to take longer or fail some of the time, `keys=` to climb past the 2-minute rotation, and the tunnel to drop only once the limit passes (or not at all if enough agreements get through).

### Run 4: the gateway restarts

```
sudo tools/outage_drill.sh restart --role gateway --wg-interface wg0 --restart-cmd 'systemctl restart acxelin-vpn-wireguard'
```

The gateway forgets every connected computer when it starts, so this is not covered by the grace: expect the tunnel to drop, and the client to bring it back by itself at its next key agreement. Use your own restart command if you run the gateway another way.

## 3. What to send back

The two timelines for each run, `acxelin-vpn doctor` on both machines, the gateway's `outage_grace_minutes`, and the gateway log (`journalctl -u acxelin-vpn-wireguard`, or its terminal) covering the run. The log has one warning line when a person enters the grace and one when they leave it or are removed.

If a run leaves the machine in a strange state, `sudo iptables -S | grep acxelin-drill` and `sudo tc qdisc show dev GW_NIC` show anything the script did not remove; `sudo iptables -w -D` with the printed rule removes a rule, and `sudo tc qdisc del dev GW_NIC root` restores the default queue.

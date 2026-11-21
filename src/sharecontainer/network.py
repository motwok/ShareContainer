"""Interfaces and the DHCP mode on macvlan."""

import ipaddress
import os
import time

from . import paths, sysops


class NetworkError(Exception):
    pass


def check_interfaces(cfg, exists=os.path.isdir, attempts=10, sleep=time.sleep):
    """Waits briefly for the interfaces; a missing interface stops the start."""
    for _ in range(attempts):
        missing = [i.name for i in cfg.interfaces if not exists(f"/sys/class/net/{i.name}")]
        if not missing:
            return
        sleep(1)
    raise NetworkError(f"interface(s) not found in the container: {', '.join(missing)}")


def ipv4(iface):
    out = sysops.run(["ip", "-4", "-o", "addr", "show", "dev", iface])
    return [line.split()[3] for line in out.splitlines() if " inet " in line]


def dhcp_interfaces(cfg):
    return [i.name for i in cfg.interfaces if i.dhcp]


def dhcp_command(cfg, iface):
    """udhcpc in the foreground; it renews the lease and sends the server name to the DHCP server."""
    return ["udhcpc", "-f", "-R", "-i", iface, "-x", f"hostname:{cfg.name}", "-F", cfg.name, "-s", paths.DHCP_EVENT]


def lease_file(iface):
    return f"{paths.RUN}/dhcp-{iface}.lease"


def dhcp_event(event, env, run=None, current=None):
    """Called by udhcpc: sets the leased address and the default route; nothing in /proc/sys.

    Docker's address goes before the lease is added: with promote_secondaries off, deleting a primary
    address deletes the secondary addresses of its subnet too.
    """
    run = run or sysops.run
    current = current or ipv4
    iface = env.get("interface", "")
    if event in ("bound", "renew"):
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{env['subnet']}").prefixlen
        lease = f"{env['ip']}/{prefix}"
        if current(iface) != [lease]:
            run(["ip", "-4", "addr", "flush", "dev", iface])
            run(["ip", "addr", "add", lease, "dev", iface])
        router = (env.get("router") or "").split()
        if router:
            run(["ip", "route", "replace", "default", "via", router[0], "dev", iface])
        sysops.write_file(lease_file(iface), lease + "\n")
        sysops.log(f"{iface}: DHCP {event} {lease}")
    elif event in ("leasefail", "nak"):
        sysops.log(f"{iface}: DHCP {event} {env.get('message', '')}".rstrip())
    return 0


def global_addresses(iface):
    """Stable global addresses of iface; temporary, deprecated and tentative ones are left out."""
    out = sysops.run(["ip", "-o", "addr", "show", "dev", iface, "scope", "global"])
    addrs = []
    for line in out.splitlines():
        f = line.split()
        if len(f) > 3 and not {"temporary", "deprecated", "tentative"} & set(f):
            addrs.append(f[3])
    return sorted(addrs)


def ipv6_active(iface, read=sysops.read_file):
    conf = f"/proc/sys/net/ipv6/conf/{iface}"
    disabled = (read(f"{conf}/disable_ipv6", "1") or "1").strip()
    accept_ra = (read(f"{conf}/accept_ra", "0") or "0").strip()
    return disabled == "0" and accept_ra != "0"


def wait_for_ipv6(iface, timeout=15, sleep=time.sleep, clock=time.monotonic, read=sysops.read_file):
    """DHCP mode: waits for SLAAC addresses, so Samba finds them at start; then drops Docker's default
    route when the router sent one (Docker's IPv6 gateway usually does not exist)."""
    if not ipv6_active(iface, read):
        return []
    end = clock() + timeout
    while clock() < end:
        out = sysops.run(["ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "global", "dynamic"])
        # An address in duplicate address detection is not usable yet.
        if any("tentative" not in line for line in out.splitlines()):
            break
        sleep(1)
    else:
        sysops.log(f"{iface}: no IPv6 router advertisement within {timeout} s")
        return []
    routes = [r.split() for r in sysops.run(["ip", "-6", "route", "show", "default", "dev", iface]).splitlines()]
    if any("ra" in r for r in routes):
        for r in routes:
            if "ra" not in r and "via" in r:
                via = r[r.index("via") + 1]
                sysops.run(["ip", "-6", "route", "del", "default", "via", via, "dev", iface], check=False)
                sysops.log(f"{iface}: dropped Docker's IPv6 default route via {via}")
    addrs = global_addresses(iface)
    sysops.log(f"{iface}: addresses {' '.join(addrs)}")
    return addrs


def watch(ifaces, interval=15, sleep=time.sleep, addresses=None):
    """Service: ends when the global addresses of the interfaces change, so the container restarts;
    Samba listens only on the addresses it found at start."""
    addresses = addresses or global_addresses
    first = {i: addresses(i) for i in ifaces}
    while True:
        sleep(interval)
        for i in ifaces:
            now = addresses(i)
            if now != first[i]:
                sysops.log(f"{i}: addresses changed from {' '.join(first[i]) or '-'} to {' '.join(now) or '-'}, "
                           "restarting the container")
                return 1


def clear_leases(cfg):
    """A restarted container keeps /run; an old lease must not count as the new one."""
    for iface in dhcp_interfaces(cfg):
        try:
            os.unlink(lease_file(iface))
        except FileNotFoundError:
            pass


def wait_for_lease(iface, timeout=60, sleep=time.sleep, clock=time.monotonic):
    """Waits until udhcpc reported a lease through dhcp_event."""
    end = clock() + timeout
    while clock() < end:
        lease = (sysops.read_file(lease_file(iface), "") or "").strip()
        if lease:
            sysops.log(f"{iface}: DHCP address {lease}")
            return lease
        sleep(1)
    raise NetworkError(f"{iface}: no DHCP answer within {timeout} s")

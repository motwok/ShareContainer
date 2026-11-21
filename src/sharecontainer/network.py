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

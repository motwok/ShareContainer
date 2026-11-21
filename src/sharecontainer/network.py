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


def dhcp_event(event, env, run=None):
    """Called by udhcpc: sets the leased address and the default route; nothing in /proc/sys."""
    run = run or sysops.run
    iface = env.get("interface", "")
    if event in ("bound", "renew"):
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{env['subnet']}").prefixlen
        run(["ip", "addr", "replace", f"{env['ip']}/{prefix}", "dev", iface])
        router = (env.get("router") or "").split()
        if router:
            run(["ip", "route", "replace", "default", "via", router[0], "dev", iface])
        sysops.log(f"{iface}: DHCP {event} {env['ip']}/{prefix}")
    elif event in ("leasefail", "nak"):
        sysops.log(f"{iface}: DHCP {event} {env.get('message', '')}".rstrip())
    return 0


def wait_for_lease(iface, before, timeout=60, sleep=time.sleep, clock=time.monotonic):
    """Waits for a leased IPv4 address, then drops the address Docker assigned."""
    end = clock() + timeout
    while clock() < end:
        new = [a for a in ipv4(iface) if a not in before]
        if new:
            for a in before:
                sysops.run(["ip", "addr", "del", a, "dev", iface], check=False)
            sysops.log(f"{iface}: DHCP address {new[0]}")
            return new[0]
        sleep(1)
    raise NetworkError(f"{iface}: no DHCP answer within {timeout} s")

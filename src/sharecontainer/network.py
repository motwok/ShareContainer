"""Interfaces and the DHCP mode on macvlan."""

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


def dhcpcd_conf(cfg):
    return "\n".join([
        f"hostname {cfg.name}",
        "clientid",
        "option rapid_commit",
        "require dhcp_server_identifier",
        "noipv4ll",
        "nohook resolv.conf, hostname",
        "",
    ])


def dhcpcd_command(cfg):
    sysops.write_file(paths.DHCPCD_CONF, dhcpcd_conf(cfg))
    return ["dhcpcd", "-B", "-f", paths.DHCPCD_CONF] + dhcp_interfaces(cfg)


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

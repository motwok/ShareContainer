"""Name services: NetBIOS (nmbd), WS-Discovery (wsdd2), mDNS (Avahi)."""

import os

from . import paths, sysops


def avahi_conf(cfg):
    return "\n".join([
        "[server]",
        f"host-name={cfg.name.lower()}",
        "use-ipv4=yes",
        "use-ipv6=yes",
        f"allow-interfaces={','.join(i.name for i in cfg.interfaces)}",
        "enable-dbus=no",
        "ratelimit-interval-usec=1000000",
        "ratelimit-burst=1000",
        "[wide-area]",
        "enable-wide-area=no",
        "[publish]",
        "publish-hinfo=no",
        "publish-workstation=no",
        "[rlimits]",
        "",
    ])


def avahi_service(cfg):
    lines = [
        '<?xml version="1.0" standalone="no"?>',
        '<!DOCTYPE service-group SYSTEM "avahi-service.dtd">',
        "<service-group>",
        '  <name replace-wildcards="yes">%h</name>',
        "  <service>",
        "    <type>_smb._tcp</type>",
        "    <port>445</port>",
        "  </service>",
    ]
    if cfg.smb.macos or any(s.macos for s in cfg.shares):
        lines += ["  <service>", "    <type>_device-info._tcp</type>", "    <port>0</port>",
                  "    <txt-record>model=MacSamba</txt-record>", "  </service>"]
    lines.append("</service-group>")
    return "\n".join(lines) + "\n"


def wsdd_command(cfg):
    cmd = ["wsdd2", "-w"]
    for i in cfg.interfaces:
        cmd += ["-i", i.name]
    cmd += ["-H", cfg.name]
    if cfg.workgroup:
        cmd += ["-G", cfg.workgroup]
    return cmd


def apply(cfg):
    if cfg.smb.mdns:
        sysops.make_dir(paths.RUN, 0o711)
        sysops.write_file(paths.AVAHI_CONF, avahi_conf(cfg))
        sysops.make_dir(paths.AVAHI_SERVICES, 0o755)
        for f in os.listdir(paths.AVAHI_SERVICES):
            os.unlink(os.path.join(paths.AVAHI_SERVICES, f))
        sysops.write_file(f"{paths.AVAHI_SERVICES}/smb.service", avahi_service(cfg))
        sysops.make_dir(paths.AVAHI_RUN, 0o755)

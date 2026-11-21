"""Container start: validate, prepare, then hand over to the supervisor."""

import os

from . import acls, accounts, config, discovery, network, paths, smbconf, ssh, supervisor, sysops, webdav
from .supervisor import Service

CMD = "/usr/local/bin/sharecontainer"


def prepare(cfg):
    sysops.make_dir(paths.RUN, 0o711)
    if os.path.isdir(paths.CONFIG_DIR):
        os.chmod(paths.CONFIG_DIR, 0o700)
    sysops.make_dir(paths.STATE, 0o711)
    sysops.make_dir(paths.OWN_STATE, 0o700)
    accounts.apply(cfg)
    if any(cfg.has_home(u) for u in cfg.users):
        sysops.make_dir(paths.HOMES, 0o711)
    for u in cfg.users:
        if cfg.has_home(u):
            home = f"{paths.HOMES}/{u.name}"
            if not os.path.isdir(home):
                sysops.make_dir(home, 0o700, u.uid, u.uid)
    acls.apply(cfg)
    ssh.apply_views(cfg)
    # smb.conf is also needed for the password database when SMB is off.
    sysops.write_file(paths.SMB_CONF, smbconf.generate(cfg))
    sysops.run(["testparm", "-s", paths.SMB_CONF])
    if cfg.ssh.enabled:
        ssh.apply(cfg)
    if cfg.webdav.enabled:
        webdav.apply(cfg)
    discovery.apply(cfg)


def services(cfg):
    out = []
    if cfg.smb.enabled:
        out.append(Service("smbd", ["smbd", "--foreground", "--no-process-group", "--debug-stdout",
                                    f"--configfile={paths.SMB_CONF}"], [445]))
        if cfg.smb.netbios:
            out.append(Service("nmbd", ["nmbd", "--foreground", "--no-process-group", "--debug-stdout",
                                        f"--configfile={paths.SMB_CONF}"]))
        if cfg.smb.wsd:
            out.append(Service("wsdd2", discovery.wsdd_command(cfg)))
        if cfg.smb.mdns:
            out.append(Service("avahi", ["avahi-daemon", "--no-chroot", "-f", paths.AVAHI_CONF]))
    if cfg.ssh.enabled:
        out.append(Service("sshd", ["/usr/sbin/sshd", "-D", "-e", "-f", paths.SSHD_CONF], [cfg.ssh.port]))
    if cfg.webdav.enabled:
        out.append(Service("apache", ["/usr/sbin/apache2", "-DFOREGROUND", "-f", paths.APACHE_CONF],
                           [cfg.webdav.port], umask=0o007))
    if cfg.metrics.enabled:
        out.append(Service("metrics", [CMD, "metrics"], [cfg.metrics.port]))
    return out


def main(path=paths.CONFIG_FILE, run=supervisor.run):
    try:
        cfg = config.load(path)
    except config.ConfigError as e:
        sysops.log("invalid configuration, not starting:")
        for err in e.errors:
            sysops.log(f"  {err}")
        return 2
    try:
        network.check_interfaces(cfg)
        first = []
        dhcp = network.dhcp_interfaces(cfg)
        network.check_sysctls(cfg)
        before = {i: network.ipv4(i) for i in dhcp}
        prepare(cfg)
        if dhcp:
            first.append(Service("dhcpcd", network.dhcpcd_command(cfg)))
    except (network.NetworkError, accounts.AccountError, acls.AclError, sysops.CommandError, OSError) as e:
        sysops.log(f"cannot start: {e}")
        return 1
    return run(first + services(cfg), dhcp_wait=(lambda: [network.wait_for_lease(i, before[i]) for i in dhcp])
               if dhcp else None)

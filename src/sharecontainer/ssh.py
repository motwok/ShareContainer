"""sshd configuration, host keys, per-user views and policies."""

import json
import os

from . import paths, sysops
from .config import SSH_PROTOCOLS

HOST_KEY_TYPES = ("ed25519", "ecdsa", "rsa")


def host_keys():
    """Creates missing host keys in the volume, so clients keep trusting the server after a rebuild."""
    sysops.make_dir(paths.SSH_STATE, 0o711)
    sysops.make_dir(paths.SSH_HOST_KEYS, 0o700)
    out = []
    for t in HOST_KEY_TYPES:
        f = f"{paths.SSH_HOST_KEYS}/ssh_host_{t}_key"
        if not os.path.exists(f):
            sysops.log(f"creating SSH host key {t}")
            sysops.run(["ssh-keygen", "-q", "-t", t, "-N", "", "-C", "", "-f", f])
        out.append(f)
    return out


def generate(cfg, keys):
    users = cfg.ssh_users()
    lines = [
        f"Port {cfg.ssh.port}",
        *[f"HostKey {k}" for k in keys],
        f"AuthorizedKeysFile {paths.SSH_KEYS}/%u",
        "UsePAM no",
        "PermitRootLogin no",
        "PasswordAuthentication no",
        "PermitEmptyPasswords no",
        "KbdInteractiveAuthentication no",
        "PubkeyAuthentication yes",
        "DisableForwarding yes",
        "PermitTTY no",
        "PermitUserRC no",
        "PermitUserEnvironment no",
        "PrintMotd no",
        "LogLevel INFO",
        "PidFile none",
        f"Subsystem sftp {paths.SFTP_SERVER}",
        f"ForceCommand {paths.SSH_COMMAND}",
        f"AllowUsers {' '.join(u.name for u in users) if users else 'nobody-allowed'}",
    ]
    for u in users:
        if cfg.password_login(u):
            lines += [f"Match User {u.name}", "    PasswordAuthentication yes"]
            if u.name == "anonymous":
                lines.append("    PermitEmptyPasswords yes")
    return "\n".join(lines) + "\n"


def policy(cfg, user):
    """What the SSH command of a user may do: allowed protocols and real roots."""
    roots = {"home": None}
    read, write = [], []
    for s in cfg.shares:
        r = set()
        for p in SSH_PROTOCOLS:
            r.update(cfg.share_users(s, p))
        if user.name in r:
            roots[s.name] = s.path
            read.append(s.path)
            if user.name in cfg.expand(s.write):
                write.append(s.path)
    home = f"{paths.HOMES}/{user.name}" if cfg.has_home(user) else None
    if home:
        roots["home"] = home
        read.append(home)
        write.append(home)
    else:
        del roots["home"]
    protos = {}
    for p in SSH_PROTOCOLS:
        if cfg.may(user, p):
            shares = [s.path for s in cfg.shares if user.name in cfg.share_users(s, p)]
            protos[p] = {"read": sorted(set(x for x in read if x in shares or x == home)),
                         "write": sorted(set(x for x in write if x in shares or x == home))}
    return {"view": f"{paths.VIEWS}/{user.name}", "links": roots, "protocols": protos}


def apply_views(cfg):
    """One view per SSH user: symlinks to the shares and the home; readable by the user only."""
    sysops.make_dir(paths.RUN, 0o711)
    sysops.make_dir(paths.VIEWS, 0o711)
    sysops.make_dir(paths.POLICIES, 0o711)
    for u in cfg.ssh_users():
        pol = policy(cfg, u)
        view = pol["view"]
        sysops.make_dir(view, 0o750, 0, u.uid)
        for entry in os.listdir(view):
            os.unlink(os.path.join(view, entry))
        for name, target in sorted(pol["links"].items()):
            os.symlink(target, os.path.join(view, name))
        sysops.write_file(f"{paths.POLICIES}/{u.name}.json", json.dumps(pol, sort_keys=True) + "\n", 0o640, 0, u.uid)
    # Users without SSH still need a home path that exists for useradd's -d.
    for u in cfg.users:
        if not cfg.has_home(u) and u not in cfg.ssh_users():
            sysops.make_dir(f"{paths.VIEWS}/{u.name}", 0o750, 0, u.uid)


def apply(cfg):
    sysops.make_dir(paths.SSHD_RUN, 0o755)
    sysops.make_dir(paths.RUN, 0o711)
    sysops.make_dir(paths.SSH_KEYS, 0o711)
    keys = host_keys()
    sysops.write_file(paths.SSHD_CONF, generate(cfg, keys), 0o600)
    sysops.run(["/usr/sbin/sshd", "-t", "-f", paths.SSHD_CONF])

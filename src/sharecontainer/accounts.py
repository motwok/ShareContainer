"""Unix users and groups, recreated at every start from the configuration."""

import grp
import pwd

from . import paths, sysops
from .config import DAV_GROUP, DAV_GROUP_GID, GUEST


class AccountError(Exception):
    pass


def _group(name, gid):
    try:
        cur = grp.getgrnam(name)
    except KeyError:
        try:
            other = grp.getgrgid(gid)
        except KeyError:
            sysops.run(["groupadd", "-g", str(gid), name])
            return
        raise AccountError(f"gid {gid} of group {name} belongs to the image's group {other.gr_name}")
    if cur.gr_gid != gid:
        raise AccountError(f"group {name} exists with gid {cur.gr_gid}, not {gid}")


def _user(name, uid, home, groups):
    try:
        cur = pwd.getpwnam(name)
    except KeyError:
        try:
            other = pwd.getpwuid(uid)
        except KeyError:
            sysops.run(["useradd", "-M", "-N", "-u", str(uid), "-g", str(uid), "-d", home, "-s", "/bin/sh",
                        "-G", ",".join(groups), name] if groups else
                       ["useradd", "-M", "-N", "-u", str(uid), "-g", str(uid), "-d", home, "-s", "/bin/sh", name])
            return
        raise AccountError(f"uid {uid} of user {name} belongs to the image's user {other.pw_name}")
    if cur.pw_uid != uid:
        raise AccountError(f"user {name} exists with uid {cur.pw_uid}, not {uid}")
    sysops.run(["usermod", "-d", home, "-s", "/bin/sh", "-G", ",".join(groups), name])


def home_of(cfg, user):
    return f"{paths.HOMES}/{user.name}" if cfg.has_home(user) else f"{paths.VIEWS}/{user.name}"


def apply(cfg):
    """Creates groups and users; every user gets a private group named like the user."""
    if cfg.webdav.enabled:
        _group(DAV_GROUP, DAV_GROUP_GID)
    for g in cfg.groups:
        _group(g.name, g.gid)
    for u in cfg.users:
        _group(u.name, u.uid)
        groups = list(u.groups)
        if cfg.may(u, "webdav"):
            groups.append(DAV_GROUP)
        _user(u.name, u.uid, home_of(cfg, u), groups)
    apply_passwords(cfg)


def read_shadow():
    """Stored Unix password hashes: {user: hash}."""
    out = {}
    for line in (sysops.read_file(paths.SSH_SHADOW, "") or "").splitlines():
        name, _, h = line.partition(":")
        if name and h:
            out[name] = h
    return out


def write_shadow(hashes):
    text = "".join(f"{n}:{h}\n" for n, h in sorted(hashes.items()))
    sysops.write_file(paths.SSH_SHADOW, text, 0o600)


def apply_passwords(cfg):
    """Sets the Unix password fields: stored hash, '*' (no password, not locked) or empty for the guest."""
    hashes = read_shadow()
    lines = []
    for u in cfg.users:
        h = "" if u.name == GUEST else hashes.get(u.name, "*")
        lines.append(f"{u.name}:{h}")
    if lines:
        sysops.run(["chpasswd", "-e"], data="\n".join(lines) + "\n")


def shadow_hash(name):
    """Reads the current hash of a user from /etc/shadow."""
    for line in sysops.read_file(paths.ETC_SHADOW, "").splitlines():
        f = line.split(":")
        if f[0] == name:
            return f[1]
    raise AccountError(f"user {name} not found in /etc/shadow")

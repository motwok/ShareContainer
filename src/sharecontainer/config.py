"""Reads and validates the configuration file."""

import os
import posixpath
import re
from dataclasses import dataclass, field

import yaml

PROTOCOLS = ("smb", "webdav", "sftp", "rsync", "borg")
SSH_PROTOCOLS = ("sftp", "rsync", "borg")
GUEST = "anonymous"
DAV_GROUP = "sharecontainer-dav"
DAV_GROUP_GID = 65533
NOBODY_ID = 65534
MIN_PROTOCOLS = ("SMB2_02", "SMB2_10", "SMB3", "SMB3_00", "SMB3_02", "SMB3_11")
ENCRYPTION = ("default", "off", "if_required", "desired", "required")
SIGNING = ("default", "auto", "mandatory", "disabled")
RESERVED_SHARES = ("home", "homes", "global", "printers", "print$", "ipc$")
SYSTEM_PATHS = ("/bin", "/boot", "/config", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run",
                "/sbin", "/sys", "/tmp", "/user", "/usr", "/var")
NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SHARE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,14}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}$")
PARAM_RE = re.compile(r"^[A-Za-z0-9 :_.-]+$")
# No control characters and no backslash: smb.conf continues a line ending in a backslash.
VALUE_RE = re.compile(r"[^\x00-\x1f\x7f\\]*")
PATH_RE = re.compile(r'/[^\x00-\x1f\x7f"\\]*')


class ConfigError(Exception):
    def __init__(self, errors):
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass
class Interface:
    name: str
    speed: int
    dhcp: bool


@dataclass
class Group:
    name: str
    gid: int


@dataclass
class User:
    name: str
    uid: int
    groups: list
    protocols: tuple
    password_login: object
    home: object


@dataclass
class Share:
    name: str
    path: str
    read: list
    write: list
    protocols: tuple
    macos: object
    recycle: object
    guest: object
    encryption: object
    extra: dict


@dataclass
class Smb:
    enabled: bool = False
    multichannel: bool = False
    min_protocol: str = "SMB3"
    encryption: str = "default"
    signing: str = "default"
    windows_acls: bool = False
    macos: bool = False
    recycle: bool = False
    guest: bool = False
    netbios: bool = False
    wsd: bool = False
    mdns: bool = False
    extra: dict = field(default_factory=dict)


@dataclass
class Ssh:
    enabled: bool = False
    port: int = 2022
    password_login_disabled: bool = True
    password_login: bool = False


@dataclass
class WebDav:
    enabled: bool = False
    https: bool = False
    port: int = 8080


@dataclass
class Metrics:
    enabled: bool = True
    port: int = 9482


@dataclass
class Config:
    name: str
    workgroup: object
    log_level: int
    interfaces: list
    smb: Smb
    ssh: Ssh
    webdav: WebDav
    metrics: Metrics
    homes: bool
    groups: list
    users: list
    shares: list

    def user(self, name):
        return next((u for u in self.users if u.name == name), None)

    def enabled(self, proto):
        if proto == "smb":
            return self.smb.enabled
        if proto == "webdav":
            return self.webdav.enabled
        return self.ssh.enabled

    def may(self, user, proto):
        return self.enabled(proto) and proto in user.protocols

    def expand(self, entries):
        """Turns list entries (user or @group) into user names."""
        names = set()
        for e in entries:
            if e.startswith("@"):
                names.update(u.name for u in self.users if e[1:] in u.groups)
            else:
                names.add(e)
        return names

    def share_users(self, share, proto, write=False):
        """Users that may use share over proto, for writing or at all."""
        if proto not in share.protocols or not self.enabled(proto):
            return []
        names = self.expand(share.write) if write else self.expand(share.read) | self.expand(share.write)
        return sorted(n for n in names if self.may(self.user(n), proto))

    def has_home(self, user):
        if user.name == GUEST:
            return False
        return self.homes if user.home is None else user.home

    def password_login(self, user):
        if user.name == GUEST:
            return True
        if self.ssh.password_login_disabled:
            return False
        return self.ssh.password_login if user.password_login is None else user.password_login

    def share_flag(self, share, flag):
        value = getattr(share, flag)
        return getattr(self.smb, flag) if value is None else value

    def guest_share(self, share):
        return self.smb.enabled and "smb" in share.protocols and self.share_flag(share, "guest")

    def ssh_users(self):
        return [u for u in self.users if any(self.may(u, p) for p in SSH_PROTOCOLS)]


class _Reader:
    def __init__(self):
        self.errors = []

    def err(self, where, msg):
        self.errors.append(f"{where}: {msg}")

    def mapping(self, value, where, keys):
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.err(where, "must be a mapping")
            return {}
        for k in value:
            if k not in keys:
                self.err(f"{where}.{k}", "unknown key")
        return value

    def items(self, value, where):
        if value is None:
            return []
        if not isinstance(value, list):
            self.err(where, "must be a list")
            return []
        return value

    @staticmethod
    def _get(m, key, default):
        """An explicit null means the default, like a missing key."""
        v = m.get(key)
        return default if v is None else v

    def boolean(self, m, key, where, default):
        v = self._get(m, key, default)
        if v is not None and not isinstance(v, bool):
            self.err(f"{where}.{key}", "must be true or false")
            return default
        return v

    def integer(self, m, key, where, default, lo, hi):
        v = self._get(m, key, default)
        if v is None:
            self.err(f"{where}.{key}", "is required")
            return v
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            self.err(f"{where}.{key}", f"must be a whole number from {lo} to {hi}")
            return default
        return v

    def string(self, m, key, where, default, pattern=None, choices=None, required=False):
        v = self._get(m, key, default)
        if v is None:
            if required:
                self.err(f"{where}.{key}", "is required")
            return v
        if not isinstance(v, str):
            self.err(f"{where}.{key}", "must be text")
            return default
        if pattern and not pattern.fullmatch(v):
            self.err(f"{where}.{key}", f"invalid value {v!r}")
            return default
        if choices and v not in choices:
            self.err(f"{where}.{key}", f"must be one of {', '.join(choices)}")
            return default
        return v

    def names(self, m, key, where, pattern):
        out = []
        for i, v in enumerate(self.items(m.get(key), f"{where}.{key}")):
            if not isinstance(v, str) or not pattern.fullmatch(v):
                self.err(f"{where}.{key}[{i}]", f"invalid entry {v!r}")
            else:
                out.append(v)
        return out

    def protocols(self, m, where):
        if m.get("protocols") is None:
            return PROTOCOLS
        out = []
        for i, v in enumerate(self.items(m["protocols"], f"{where}.protocols")):
            if v not in PROTOCOLS:
                self.err(f"{where}.protocols[{i}]", f"must be one of {', '.join(PROTOCOLS)}")
            else:
                out.append(v)
        return tuple(out)

    def extra(self, m, where):
        v = self.mapping(m.get("extra"), f"{where}.extra", m.get("extra") or {})
        out = {}
        for k, val in v.items():
            if not isinstance(k, str) or not PARAM_RE.fullmatch(k):
                self.err(f"{where}.extra", f"invalid parameter name {k!r}")
            elif isinstance(val, (dict, list)) or val is None or not VALUE_RE.fullmatch(str(val)):
                self.err(f"{where}.extra.{k}", "must be a single value")
            else:
                out[k] = "yes" if val is True else "no" if val is False else str(val)
        return out


def parse(data):
    """Builds a Config from the parsed YAML document or raises ConfigError."""
    r = _Reader()
    top = r.mapping(data, "share.yaml", ("server", "network", "smb", "ssh", "webdav", "metrics", "homes",
                                         "groups", "users", "shares"))
    if data is None:
        r.err("share.yaml", "is empty")

    srv = r.mapping(top.get("server"), "server", ("name", "workgroup", "log_level"))
    name = r.string(srv, "name", "server", None, HOST_RE, required=True)
    workgroup = r.string(srv, "workgroup", "server", None, HOST_RE)
    log_level = r.integer(srv, "log_level", "server", 1, 0, 10)

    net = r.mapping(top.get("network"), "network", ("interfaces",))
    interfaces = []
    for i, it in enumerate(r.items(net.get("interfaces"), "network.interfaces")):
        w = f"network.interfaces[{i}]"
        it = r.mapping(it, w, ("name", "speed", "dhcp"))
        iname = r.string(it, "name", w, None, IFACE_RE, required=True)
        speed = r.integer(it, "speed", w, None, 1000000, 10 ** 13)
        interfaces.append(Interface(iname, speed, r.boolean(it, "dhcp", w, False)))
    if not interfaces:
        r.err("network.interfaces", "at least one interface is required")
    if len({i.name for i in interfaces}) != len(interfaces):
        r.err("network.interfaces", "names must be unique")

    s = r.mapping(top.get("smb"), "smb", tuple(Smb.__dataclass_fields__))
    smb = Smb(
        enabled=r.boolean(s, "enabled", "smb", False),
        multichannel=r.boolean(s, "multichannel", "smb", False),
        min_protocol=r.string(s, "min_protocol", "smb", "SMB3", choices=MIN_PROTOCOLS),
        encryption=r.string(s, "encryption", "smb", "default", choices=ENCRYPTION),
        signing=r.string(s, "signing", "smb", "default", choices=SIGNING),
        windows_acls=r.boolean(s, "windows_acls", "smb", False),
        macos=r.boolean(s, "macos", "smb", False),
        recycle=r.boolean(s, "recycle", "smb", False),
        guest=r.boolean(s, "guest", "smb", False),
        netbios=r.boolean(s, "netbios", "smb", False),
        wsd=r.boolean(s, "wsd", "smb", False),
        mdns=r.boolean(s, "mdns", "smb", False),
        extra=r.extra(s, "smb"),
    )

    h = r.mapping(top.get("ssh"), "ssh", ("enabled", "port", "password_login_disabled", "password_login"))
    ssh = Ssh(r.boolean(h, "enabled", "ssh", False), r.integer(h, "port", "ssh", 2022, 1, 65535),
              r.boolean(h, "password_login_disabled", "ssh", True), r.boolean(h, "password_login", "ssh", False))

    d = r.mapping(top.get("webdav"), "webdav", ("enabled", "https", "port"))
    https = r.boolean(d, "https", "webdav", False)
    dav = WebDav(r.boolean(d, "enabled", "webdav", False), https,
                 r.integer(d, "port", "webdav", 8443 if https else 8080, 1, 65535))

    mt = r.mapping(top.get("metrics"), "metrics", ("enabled", "port"))
    metrics = Metrics(r.boolean(mt, "enabled", "metrics", True), r.integer(mt, "port", "metrics", 9482, 1, 65535))

    hm = r.mapping(top.get("homes"), "homes", ("enabled",))
    homes = r.boolean(hm, "enabled", "homes", False)

    groups = []
    for i, g in enumerate(r.items(top.get("groups"), "groups")):
        w = f"groups[{i}]"
        g = r.mapping(g, w, ("name", "gid"))
        groups.append(Group(r.string(g, "name", w, None, NAME_RE, required=True),
                            r.integer(g, "gid", w, None, 1, 65532)))

    users = []
    for i, u in enumerate(r.items(top.get("users"), "users")):
        w = f"users[{i}]"
        u = r.mapping(u, w, ("name", "uid", "groups", "protocols", "password_login", "home"))
        users.append(User(r.string(u, "name", w, None, NAME_RE, required=True), r.integer(u, "uid", w, None, 1, 65532),
                          r.names(u, "groups", w, NAME_RE), r.protocols(u, w),
                          r.boolean(u, "password_login", w, None), r.boolean(u, "home", w, None)))

    shares = []
    for i, sh in enumerate(r.items(top.get("shares"), "shares")):
        w = f"shares[{i}]"
        sh = r.mapping(sh, w, ("name", "path", "read", "write", "protocols", "macos", "recycle", "guest",
                               "encryption", "extra"))
        sname = r.string(sh, "name", w, None, SHARE_RE, required=True)
        path = r.string(sh, "path", w, f"/shares/{sname}" if sname else "")
        entry = re.compile(r"^@?[a-z_][a-z0-9_-]{0,31}$")
        shares.append(Share(sname, path, r.names(sh, "read", w, entry), r.names(sh, "write", w, entry),
                            r.protocols(sh, w), r.boolean(sh, "macos", w, None), r.boolean(sh, "recycle", w, None),
                            r.boolean(sh, "guest", w, None),
                            r.string(sh, "encryption", w, None, choices=ENCRYPTION), r.extra(sh, w)))

    cfg = Config(name, workgroup, log_level, interfaces, smb, ssh, dav, metrics, homes, groups, users, shares)
    if not r.errors:
        _check(cfg, r)
    if r.errors:
        raise ConfigError(r.errors)
    return cfg


def _dupes(values):
    seen, dup = set(), set()
    for v in values:
        (dup if v in seen else seen).add(v)
    return sorted(dup, key=str)


def _check(cfg, r):
    """Rules across sections."""
    if not any(cfg.enabled(p) for p in ("smb", "webdav", "sftp")):
        r.err("share.yaml", "no protocol is switched on (smb, webdav or ssh)")
    group_names = {g.name for g in cfg.groups}
    user_names = {u.name for u in cfg.users}
    for d in _dupes([g.name for g in cfg.groups]):
        r.err("groups", f"group {d} is defined twice")
    for d in _dupes([u.name for u in cfg.users]):
        r.err("users", f"user {d} is defined twice")
    for d in _dupes([s.name.lower() for s in cfg.shares]):
        r.err("shares", f"share {d} is defined twice")
    for d in _dupes([u.uid for u in cfg.users]):
        r.err("users", f"uid {d} is used twice")
    # Every user gets a private group with gid = uid.
    for d in _dupes([g.gid for g in cfg.groups] + [u.uid for u in cfg.users]):
        r.err("groups", f"gid {d} is used twice (a user's private group has the gid of its uid)")
    for n in sorted(group_names & user_names):
        r.err("groups", f"group {n} has the name of a user (users get a private group of their name)")
    for n in sorted(group_names | user_names):
        if n == DAV_GROUP:
            r.err("groups", f"{n} is reserved")
    ports = [("smb", 445, cfg.smb.enabled), ("ssh", cfg.ssh.port, cfg.ssh.enabled),
             ("webdav", cfg.webdav.port, cfg.webdav.enabled), ("metrics", cfg.metrics.port, cfg.metrics.enabled)]
    for d in _dupes([p for _, p, on in ports if on]):
        r.err("share.yaml", f"port {d} is used twice")
    for u in cfg.users:
        for g in u.groups:
            if g not in group_names:
                r.err(f"users.{u.name}.groups", f"unknown group {g}")
    homes = {u.name.lower() for u in cfg.users if cfg.has_home(u)}
    paths = {}
    for s in cfg.shares:
        w = f"shares.{s.name}"
        if s.name.lower() in RESERVED_SHARES:
            r.err(w, "this name is reserved")
        if s.name.lower() in homes:
            r.err(w, "a share must not have the name of a user with a home directory")
        p = s.path
        if not PATH_RE.fullmatch(p) or posixpath.normpath(p) != p or p == "/" or any(
                p == x or p.startswith(x + "/") for x in SYSTEM_PATHS):
            r.err(f"{w}.path", f"{p!r} must be an absolute, normalized path outside the system folders")
        if p in paths:
            r.err(f"{w}.path", f"same path as share {paths[p]}")
        paths[p] = s.name
        for e in s.read + s.write:
            if e.startswith("@") and e[1:] not in group_names:
                r.err(w, f"unknown group {e[1:]}")
            elif not e.startswith("@") and e not in user_names:
                r.err(w, f"unknown user {e}")
        if cfg.guest_share(s):
            g = cfg.user(GUEST)
            if g is None or GUEST not in cfg.expand(s.read + s.write) or not cfg.may(g, "smb"):
                r.err(w, f"guest access needs the user {GUEST} with protocol smb on the read or write list")
        # SFTP has no per-share restriction (no chroot), so it cannot be excluded for its users.
        if cfg.ssh.enabled and "sftp" not in s.protocols:
            for n in sorted(cfg.expand(s.read + s.write)):
                if cfg.may(cfg.user(n), "sftp"):
                    r.err(w, f"excludes sftp, but user {n} may use sftp; SFTP cannot be restricted per share")
    if cfg.webdav.enabled and cfg.webdav.https:
        for f in ("/config/tls/cert.pem", "/config/tls/key.pem"):
            if not os.path.isfile(f):
                r.err("webdav.https", f"{f} is missing")


def load(path):
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        raise ConfigError([f"{path}: not found"]) from None
    except yaml.YAMLError as e:
        raise ConfigError([f"{path}: {e}"]) from None
    return parse(data)

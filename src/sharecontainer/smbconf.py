"""Generates smb.conf."""

from . import paths
from .config import GUEST


def _vfs(cfg, share):
    mods = []
    if cfg.smb.windows_acls:
        mods.append("acl_xattr")
    if cfg.share_flag(share, "macos"):
        mods += ["catia", "fruit", "streams_xattr"]
    if cfg.share_flag(share, "recycle"):
        mods.append("recycle")
    return mods


def _section(name, params):
    lines = [f"[{name}]"]
    lines += [f"   {k} = {v}" for k, v in params]
    return "\n".join(lines)


def generate(cfg):
    smb = cfg.smb
    ifaces = []
    for i in cfg.interfaces:
        cap = "capability=RSS," if smb.multichannel else ""
        ifaces.append(f'"{i.name};{cap}speed={i.speed}"')
    smb_users = {u.name for u in cfg.users if cfg.may(u, "smb")}
    invalid = ["root"] + sorted(u.name for u in cfg.users if u.name not in smb_users)
    guests = any(cfg.guest_share(s) for s in cfg.shares)
    g = [
        ("server role", "standalone server"),
        ("netbios name", cfg.name),
        ("server string", "ShareContainer"),
        ("interfaces", " ".join(ifaces)),
        ("bind interfaces only", "yes"),
        ("server multi channel support", "yes" if smb.multichannel else "no"),
        ("server min protocol", smb.min_protocol),
        ("smb ports", "445"),
        ("disable netbios", "no" if smb.netbios else "yes"),
        ("passdb backend", "tdbsam"),
        ("map to guest", "Bad User" if guests else "Never"),
        ("guest account", GUEST if guests else "nobody"),
        ("invalid users", " ".join(invalid)),
        ("log level", str(cfg.log_level)),
        ("load printers", "no"),
        ("printing", "bsd"),
        ("printcap name", "/dev/null"),
        ("disable spoolss", "yes"),
        ("kernel oplocks", "yes"),
        ("unix extensions", "no"),
    ]
    if cfg.workgroup:
        g.insert(1, ("workgroup", cfg.workgroup))
    if smb.encryption != "default":
        g.append(("server smb encrypt", smb.encryption))
    if smb.signing != "default":
        g.append(("server signing", smb.signing))
    if smb.windows_acls:
        g += [("map acl inherit", "yes"), ("acl_xattr:ignore system acls", "no")]
    if smb.macos or any(s.macos for s in cfg.shares):
        g += [("fruit:metadata", "stream"), ("fruit:model", "MacSamba"), ("fruit:nfs_aces", "no"),
              ("fruit:delete_empty_adfiles", "yes")]
    if cfg.metrics.enabled:
        g.append(("smbd profiling level", "count"))
    g += sorted(smb.extra.items())
    out = [_section("global", g)]

    for s in cfg.shares:
        if "smb" not in s.protocols:
            continue
        users = cfg.share_users(s, "smb")
        writers = cfg.share_users(s, "smb", write=True)
        p = [
            ("path", s.path),
            ("valid users", " ".join(users) if users else "nobody"),
            ("read only", "yes"),
            ("write list", " ".join(writers)),
            ("guest ok", "yes" if cfg.guest_share(s) else "no"),
            ("inherit acls", "yes"),
        ]
        mods = _vfs(cfg, s)
        if mods:
            p.append(("vfs objects", " ".join(mods)))
        if cfg.share_flag(s, "recycle"):
            p += [("recycle:repository", ".recycle/%U"), ("recycle:keeptree", "yes"),
                  ("recycle:versions", "yes"), ("recycle:touch", "yes")]
        if s.encryption:
            p.append(("smb encrypt", s.encryption))
        p += sorted(s.extra.items())
        out.append(_section(s.name, p))

    if any(cfg.has_home(u) and cfg.may(u, "smb") for u in cfg.users):
        p = [("path", f"{paths.HOMES}/%S"), ("valid users", "%S"), ("browseable", "no"), ("read only", "no")]
        mods = _vfs(cfg, _HOME)
        if mods:
            p.append(("vfs objects", " ".join(mods)))
        out.append(_section("homes", p))
    return "\n\n".join(out) + "\n"


class _Home:
    macos = None
    recycle = None


_HOME = _Home()

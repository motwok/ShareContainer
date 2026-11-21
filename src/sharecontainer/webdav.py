"""Apache configuration for WebDAV with mpm-itk: every request runs as the logged-in user."""

import grp
import pwd

from . import paths, sysops
from .config import DAV_GROUP_GID, NOBODY_ID

READ_METHODS = "GET HEAD OPTIONS PROPFIND"
MODULES = ("mpm_prefork", "mpm_itk", "authz_core", "alias", "rewrite", "headers", "dav", "dav_fs", "mime")


def _list(names):
    return ", ".join(f"'{n}'" for n in names)


def _require(names):
    return f'Require expr "%{{reqenv:SC_USER}} in {{ {_list(names)} }}"' if names else "Require all denied"


def generate(cfg):
    users = [u for u in cfg.users if cfg.may(u, "webdav")]
    uids = [u.uid for u in users] + [NOBODY_ID]
    gids = [u.uid for u in users] + [g.gid for g in cfg.groups] + [DAV_GROUP_GID, NOBODY_ID]
    mods = list(MODULES) + (["ssl", "socache_shmcb"] if cfg.webdav.https else [])
    lines = [f"LoadModule {m}_module {paths.APACHE_MODULES}/{'' if m == 'mpm_itk' else 'mod_'}{m}.so" for m in mods]
    lines += [
        "ServerRoot /etc/apache2",
        f"ServerName {cfg.name}",
        f"PidFile {paths.RUN}/apache2.pid",
        f"Mutex file:{paths.RUN} default",
        "User www-data",
        "Group www-data",
        f"Listen {cfg.webdav.port}",
        "ServerTokens Prod",
        "ServerSignature Off",
        "TraceEnable Off",
        "ErrorLog /proc/self/fd/2",
        f"LogLevel {'info' if cfg.log_level >= 2 else 'warn'}",
        'LogFormat "%h %{SC_USER}e \\"%r\\" %>s %b" sc',
        "CustomLog /proc/self/fd/1 sc",
        "TypesConfig /etc/mime.types",
        f"LimitUIDRange {min(uids)} {max(uids)}",
        f"LimitGIDRange {min(gids)} {max(gids)}",
        f"DavLockDB {paths.DAV_LOCKS}/DAVLock",
        f"DocumentRoot {paths.DAV_ROOT}",
        "<Directory />",
        "    Options None",
        "    AllowOverride None",
        "    Require all denied",
        "</Directory>",
        f"<Directory {paths.DAV_ROOT}>",
        "    Require all granted",
        "</Directory>",
    ]
    if cfg.webdav.https:
        lines += ["SSLEngine on", f"SSLCertificateFile {paths.TLS_CERT}", f"SSLCertificateKeyFile {paths.TLS_KEY}",
                  "SSLProtocol -all +TLSv1.2 +TLSv1.3", "SSLSessionCache none"]
    lines += [
        # mpm-itk switches the uid before authentication, so the user comes from our map program.
        "RewriteEngine on",
        f'RewriteMap auth "prg:{paths.DAV_AUTH}"',
        "RewriteRule ^ - [E=SC_USER:nobody,E=SC_GROUP:nogroup]",
        "RewriteCond %{HTTP:Authorization} ^Basic",
        "RewriteRule ^ - [E=SC_USER:${auth:%{HTTP:Authorization}|nobody}]",
        "RewriteCond %{ENV:SC_USER} !=nobody",
        "RewriteRule ^ - [E=SC_GROUP:%{ENV:SC_USER}]",
        "RewriteCond %{ENV:SC_USER} =nobody",
        "RewriteRule ^ - [R=401,L]",
        'Header always set WWW-Authenticate "Basic realm=\\"ShareContainer\\", charset=\\"UTF-8\\"" '
        '"expr=%{REQUEST_STATUS} == 401"',
        "AssignUserIDExpr %{reqenv:SC_USER}",
        "AssignGroupIDExpr %{reqenv:SC_GROUP}",
    ]
    homes = [u.name for u in users if cfg.has_home(u)]
    if homes:
        lines += [f"RewriteRule ^/home(/.*)?$ {paths.HOMES}/%{{ENV:SC_USER}}$1 [L]",
                  f"<Directory {paths.HOMES}>", "    DAV On", "    Options None", "    AllowOverride None",
                  f"    {_require(homes)}", "</Directory>"]
    for s in cfg.shares:
        if "webdav" not in s.protocols:
            continue
        lines += [
            f"Alias /{s.name} {s.path}",
            f"<Directory {s.path}>",
            "    DAV On",
            "    Options None",
            "    AllowOverride None",
            f"    <Limit {READ_METHODS}>",
            f"        {_require(cfg.share_users(s, 'webdav'))}",
            "    </Limit>",
            f"    <LimitExcept {READ_METHODS}>",
            f"        {_require(cfg.share_users(s, 'webdav', write=True))}",
            "    </LimitExcept>",
            "</Directory>",
        ]
    return "\n".join(lines) + "\n"


def apply(cfg):
    www = pwd.getpwnam("www-data")
    sysops.make_dir(paths.RUN, 0o711)
    sysops.make_dir(paths.DAV_ROOT, 0o755)
    sysops.make_dir(paths.DAV_LOCKS, 0o2770, 0, grp.getgrnam("sharecontainer-dav").gr_gid)
    sysops.make_dir(paths.DAV_STATE, 0o750, 0, www.pw_gid)
    if sysops.read_file(paths.DAV_PASSWORDS) is None:
        sysops.write_file(paths.DAV_PASSWORDS, "", 0o640, 0, www.pw_gid)
    users = sorted(u.name for u in cfg.users if cfg.may(u, "webdav"))
    sysops.write_file(paths.DAV_USERS, "".join(f"{n}\n" for n in users), 0o640, 0, www.pw_gid)
    sysops.write_file(paths.APACHE_CONF, generate(cfg), 0o644)
    sysops.run(["/usr/sbin/apache2", "-t", "-f", paths.APACHE_CONF])

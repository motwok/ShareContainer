"""The container commands passwd and keys."""

import getpass
import grp
import os
import pwd
import sys

from . import accounts, config, paths, sysops
from .config import GUEST


class UsageError(Exception):
    pass


def _user(cfg, name):
    if cfg.user(name) is None:
        raise UsageError(f"{name} is not a user of the configuration")
    if name == GUEST:
        raise UsageError(f"{GUEST} is the guest; its password is always empty and it has no keys")
    try:
        pwd.getpwnam(name)
    except KeyError:
        raise UsageError(f"{name} does not exist yet; restart the container after changing the configuration") from None


def set_password(name, password):
    import bcrypt

    sysops.run(["smbpasswd", "-c", paths.SMB_CONF, "-s", "-a", name], data=f"{password}\n{password}\n")
    sysops.run(["chpasswd"], data=f"{name}:{password}\n")
    hashes = accounts.read_shadow()
    hashes[name] = accounts.shadow_hash(name)
    accounts.write_shadow(hashes)
    entries = {}
    for line in (sysops.read_file(paths.DAV_PASSWORDS, "") or "").splitlines():
        n, _, h = line.partition(":")
        if n:
            entries[n] = h
    entries[name] = bcrypt.hashpw(password.encode(), bcrypt.gensalt(10)).decode()
    os.makedirs(paths.DAV_STATE, exist_ok=True)
    gid = grp.getgrnam("www-data").gr_gid
    sysops.write_file(paths.DAV_PASSWORDS, "".join(f"{n}:{h}\n" for n, h in sorted(entries.items())), 0o640, 0, gid)


def passwd(args, cfg=None, ask=getpass.getpass, stdin=sys.stdin):
    """passwd [--stdin] USER: sets the password for SMB, SSH and WebDAV at once."""
    from_stdin = "--stdin" in args
    names = [a for a in args if a != "--stdin"]
    if len(names) != 1:
        raise UsageError("usage: passwd [--stdin] USER")
    name = names[0]
    cfg = cfg or config.load(paths.CONFIG_FILE)
    _user(cfg, name)
    if from_stdin:
        password = stdin.readline().rstrip("\n")
    else:
        password = ask(f"New password for {name}: ")
        if ask("Repeat: ") != password:
            raise UsageError("the passwords differ")
    if not password or "\n" in password or "\r" in password:
        raise UsageError("the password must not be empty")
    set_password(name, password)
    print(f"password of {name} set for SMB, SSH and WebDAV")


def _keyfile(name):
    return f"{paths.SSH_KEYS}/{name}"


def _keys(name):
    return [x for x in (sysops.read_file(_keyfile(name), "") or "").splitlines() if x.strip()]


def _write_keys(name, keys):
    sysops.make_dir(paths.SSH_KEYS, 0o711)
    sysops.write_file(_keyfile(name), "".join(k + "\n" for k in keys), 0o644)


def keys(args, cfg=None, stdin=sys.stdin):
    """keys add USER [FILE|-] | keys list USER | keys remove USER NUMBER"""
    usage = "usage: keys add USER [FILE|-] | keys list USER | keys remove USER NUMBER"
    if len(args) < 2 or args[0] not in ("add", "list", "remove"):
        raise UsageError(usage)
    action, name = args[0], args[1]
    cfg = cfg or config.load(paths.CONFIG_FILE)
    _user(cfg, name)
    current = _keys(name)
    if action == "list":
        if len(args) != 2:
            raise UsageError(usage)
        for i, k in enumerate(current, 1):
            print(f"{i} {sysops.run(['ssh-keygen', '-l', '-f', '-'], data=k + chr(10)).strip()}")
        return
    if action == "remove":
        if len(args) != 3 or not args[2].isdigit() or not 1 <= int(args[2]) <= len(current):
            raise UsageError(f"{usage}; NUMBER from 'keys list {name}'")
        del current[int(args[2]) - 1]
        _write_keys(name, current)
        print(f"key {args[2]} of {name} removed")
        return
    if len(args) > 3:
        raise UsageError(usage)
    src = args[2] if len(args) == 3 else "-"
    text = stdin.read() if src == "-" else sysops.read_file(src)
    if text is None:
        raise UsageError(f"{src}: not found")
    added = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            sysops.run(["ssh-keygen", "-l", "-f", "-"], data=line + "\n")
        except sysops.CommandError:
            raise UsageError(f"not a public key: {line[:40]}") from None
        if line not in current:
            current.append(line)
            added += 1
    _write_keys(name, current)
    print(f"{added} key(s) added for {name}")

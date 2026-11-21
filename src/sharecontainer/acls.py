"""Read and write lists as POSIX ACLs on the share folders."""

import json
import os

from . import paths, sysops


class AclError(Exception):
    pass


def _entries(cfg, share):
    """ACL entries of the lists; groups stay groups so that new members get access at once."""
    write = {e for e in share.write}
    read = {e for e in share.read if e not in write}
    out = []
    for e in sorted(write):
        out.append(f"{'g:' + e[1:] if e.startswith('@') else 'u:' + e}:rwx")
    for e in sorted(read):
        out.append(f"{'g:' + e[1:] if e.startswith('@') else 'u:' + e}:r-x")
    return out


def spec(cfg, share):
    return ",".join(["u::rwx", "g::---", "o::---", "m::rwx"] + _entries(cfg, share))


def _load_state():
    try:
        return json.loads(sysops.read_file(paths.ACL_STATE, "{}"))
    except ValueError:
        return {}


def apply(cfg):
    """Sets access and default ACLs; existing content only when a share's lists changed."""
    sysops.make_dir(paths.OWN_STATE, 0o700)
    state = _load_state()
    new = {}
    for s in cfg.shares:
        acl = spec(cfg, s)
        new[s.path] = acl
        if not os.path.isdir(s.path):
            sysops.log(f"share {s.name}: creating {s.path}")
            sysops.make_dir(s.path, 0o770)
        os.chown(s.path, 0, 0)
        try:
            sysops.run(["setfacl", "--set", acl, s.path])
            sysops.run(["setfacl", "-d", "--set", acl, s.path])
        except sysops.CommandError as e:
            raise AclError(f"share {s.name}: cannot set POSIX ACLs on {s.path} "
                           f"(file system without ACL support?): {e}") from None
        if state.get(s.path) != acl:
            sysops.log(f"share {s.name}: lists changed, setting ACLs on existing content")
            files = acl.replace("rwx", "rwX").replace("r-x", "r-X")
            sysops.run(["find", s.path, "-mindepth", "1", "-xdev", "!", "-type", "l", "-exec", "setfacl", "--set", files, "{}", "+"])
            sysops.run(["find", s.path, "-mindepth", "1", "-xdev", "-type", "d", "-exec", "setfacl", "-d", "--set",
                        acl, "{}", "+"])
    sysops.write_file(paths.ACL_STATE, json.dumps(new, indent=1, sort_keys=True) + "\n", 0o600)

"""ForceCommand of sshd: allows only SFTP, rsync and Borg, inside the user's view."""

import json
import os
import pwd
import shlex
import sys

from . import paths

RSYNC_DENIED = ("--log-file", "--write-batch", "--read-batch", "--temp-dir", "-T", "--partial-dir",
                "--backup-dir", "--compare-dest", "--copy-dest", "--link-dest", "--files-from", "--config",
                "--daemon", "--rsync-path", "--remove-source-files", "--only-write-batch")
BORG_OPTIONS = ("--debug", "--info", "--warning", "--error", "--critical", "--log-json", "--show-rc")
BORG_VALUE_OPTIONS = ("--umask", "--lock-wait", "--debug-topic")
BORG1 = ("borg", "borg1", "borgbackup")
BORG2 = ("borg2", "borgbackup2")


class Denied(Exception):
    pass


def _inside(path, roots, base):
    real = os.path.realpath(os.path.join(base, path))
    return any(real == r or real.startswith(r.rstrip("/") + "/") for r in roots)


def _rsync(args, rules, view):
    if len(args) < 3 or args[1] != "--server" or "." not in args:
        raise Denied("not an rsync server command")
    dot = args.index(".")
    opts, targets = args[2:dot], args[dot + 1:]
    for o in opts:
        if o.split("=", 1)[0] in RSYNC_DENIED:
            raise Denied(f"rsync option {o} is not allowed")
    sender = "--sender" in opts
    roots = rules["read"] if sender else rules["write"]
    if not targets:
        raise Denied("rsync without a path")
    for t in targets:
        if not _inside(t, roots, view):
            raise Denied(f"{t}: outside the allowed folders")
    return ["rsync"] + args[1:]


def _borg(args, rules, binary):
    if len(args) < 2 or args[1] != "serve":
        raise Denied("only 'serve' is allowed")
    cmd = [binary, "serve"]
    i = 2
    while i < len(args):
        a = args[i]
        key = a.split("=", 1)[0]
        if a in BORG_OPTIONS:
            cmd.append(a)
        elif key in BORG_VALUE_OPTIONS:
            if "=" in a:
                cmd.append(a)
            elif i + 1 < len(args):
                cmd += [a, args[i + 1]]
                i += 1
        i += 1
    if not rules["write"]:
        raise Denied("no folder for Borg repositories")
    for r in rules["write"]:
        cmd += ["--restrict-to-path", r]
    return cmd


def command(original, policy):
    """Translates SSH_ORIGINAL_COMMAND into the command to run, or raises Denied."""
    if not original:
        raise Denied("interactive login is not available; use SFTP, scp, rsync or Borg")
    args = shlex.split(original)
    name = os.path.basename(args[0])
    protos = policy["protocols"]
    if args[0] in (paths.SFTP_SERVER, "internal-sftp") or name == "sftp-server":
        if "sftp" not in protos:
            raise Denied("SFTP is not allowed for this user")
        return [paths.SFTP_SERVER, "-d", policy["view"]]
    if name == "scp":
        raise Denied("the legacy scp protocol is not supported; use a current scp (SFTP mode) or sftp")
    if name == "rsync":
        if "rsync" not in protos:
            raise Denied("rsync is not allowed for this user")
        return _rsync(args, protos["rsync"], policy["view"])
    if name in BORG1 + BORG2:
        if "borg" not in protos:
            raise Denied("Borg is not allowed for this user")
        return _borg(args, protos["borg"], "borg2" if name in BORG2 else "borg")
    raise Denied(f"command {name} is not allowed")


def main(env=None, execvp=os.execvp, chdir=os.chdir):
    env = os.environ if env is None else env
    user = pwd.getpwuid(os.getuid()).pw_name
    try:
        with open(f"{paths.POLICIES}/{user}.json") as f:
            policy = json.load(f)
        cmd = command(env.get("SSH_ORIGINAL_COMMAND", ""), policy)
    except (OSError, ValueError, Denied) as e:
        print(f"sharecontainer: {e}", file=sys.stderr)
        return 1
    chdir(policy["view"])
    execvp(cmd[0], cmd)
    return 1  # only reached if execvp is replaced

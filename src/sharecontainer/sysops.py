"""Thin wrappers around the system, replaced in tests."""

import os
import subprocess
import sys


class CommandError(Exception):
    pass


def run(cmd, data=None, check=True):
    """Runs cmd and returns its stdout as text."""
    proc = subprocess.run(cmd, input=data, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise CommandError(f"{' '.join(cmd)}: exit {proc.returncode}: {proc.stderr.strip()}")
    return proc.stdout


def write_file(path, text, mode=0o644, uid=0, gid=0):
    """Writes text atomically with the given mode and owner."""
    tmp = f"{path}.tmp{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chown(tmp, uid, gid)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_file(path, default=None):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return default


def make_dir(path, mode=0o755, uid=0, gid=0):
    os.makedirs(path, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def log(msg):
    print(f"sharecontainer: {msg}", file=sys.stderr, flush=True)

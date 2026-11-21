"""RewriteMap program for Apache: maps a Basic Authorization header to the user name, or nobody."""

import base64
import hashlib
import os
import sys
import time

from . import paths
from .config import GUEST

CACHE_SECONDS = 300


class Checker:
    """Verifies passwords against the bcrypt file; results are cached, bcrypt is slow by design."""

    def __init__(self, passwords=paths.DAV_PASSWORDS, users=paths.DAV_USERS, clock=time.monotonic):
        self.passwords = passwords
        self.users = users
        self.clock = clock
        self.stamp = None
        self.hashes = {}
        self.allowed = set()
        self.cache = {}

    def _reload(self):
        stamp = tuple(_mtime(p) for p in (self.passwords, self.users))
        if stamp == self.stamp:
            return
        self.stamp = stamp
        self.cache = {}
        self.hashes = {}
        for line in _lines(self.passwords):
            name, _, h = line.partition(":")
            self.hashes[name] = h
        self.allowed = set(_lines(self.users))

    def user(self, header):
        import bcrypt

        self._reload()
        key = hashlib.sha256(header.encode()).digest()
        hit = self.cache.get(key)
        if hit and hit[1] > self.clock():
            return hit[0]
        try:
            scheme, value = header.split(" ", 1)
            name, _, password = base64.b64decode(value.strip(), validate=True).decode().partition(":")
        except ValueError:
            return "nobody"
        result = "nobody"
        h = self.hashes.get(name)
        if scheme != "Basic" or name not in self.allowed:
            pass
        elif name == GUEST:
            result = name if password == "" else "nobody"
        elif h and bcrypt.checkpw(password.encode(), h.encode()):
            result = name
        self.cache[key] = (result, self.clock() + CACHE_SECONDS)
        return result


def _mtime(path):
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def _lines(path):
    try:
        with open(path) as f:
            return [x.strip() for x in f if x.strip()]
    except OSError:
        return []


def main(stdin=sys.stdin, stdout=sys.stdout, checker=None):
    checker = checker or Checker()
    for line in stdin:
        stdout.write(checker.user(line.strip()) + "\n")
        stdout.flush()
    return 0

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from sharecontainer import config, paths, sysops  # noqa: E402

BASE = {
    "server": {"name": "FS", "workgroup": "WG"},
    "network": {"interfaces": [{"name": "eth0", "speed": 1000000000}]},
    "smb": {"enabled": True},
    "ssh": {"enabled": True},
    "webdav": {"enabled": True},
    "groups": [{"name": "team", "gid": 2000}],
    "users": [
        {"name": "alice", "uid": 2001, "groups": ["team"]},
        {"name": "bob", "uid": 2002, "protocols": ["smb"]},
        {"name": "anonymous", "uid": 2009},
    ],
    "shares": [
        {"name": "data", "read": ["@team", "bob"], "write": ["alice"]},
        {"name": "pub", "guest": True, "read": ["anonymous"], "write": ["alice"]},
    ],
}


@pytest.fixture
def raw():
    return copy.deepcopy(BASE)


@pytest.fixture
def cfg(raw):
    return config.parse(raw)


class Recorder:
    def __init__(self):
        self.calls = []
        self.results = {}
        self.fail = set()

    def __call__(self, cmd, data=None, check=True):
        self.calls.append((list(cmd), data))
        key = cmd[0]
        if key in self.fail and check:
            raise sysops.CommandError(f"{key} failed")
        return self.results.get(key, "")

    def names(self):
        return [c[0][0] for c in self.calls]


@pytest.fixture
def rec(monkeypatch):
    r = Recorder()
    monkeypatch.setattr(sysops, "run", r)
    return r


@pytest.fixture
def fs(tmp_path, monkeypatch):
    """Redirects every path of paths.py into tmp_path; owners are not changed."""
    for name in dir(paths):
        v = getattr(paths, name)
        if name.isupper() and isinstance(v, str) and v.startswith("/"):
            monkeypatch.setattr(paths, name, str(tmp_path) + v)
    monkeypatch.setattr(os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(sysops, "log", lambda msg: None)
    return tmp_path

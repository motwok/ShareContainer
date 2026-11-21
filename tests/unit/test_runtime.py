import json
import os
import types

import pytest

from sharecontainer import accounts, acls, config, discovery, network, paths, ssh, sysops, webdav


class FakeDb:
    """Stands in for pwd/grp: a dict name -> id."""

    def __init__(self, by_name):
        self.by_name = dict(by_name)

    def getpwnam(self, n):
        if n not in self.by_name:
            raise KeyError(n)
        return types.SimpleNamespace(pw_uid=self.by_name[n], pw_name=n, pw_gid=self.by_name[n])

    def getpwuid(self, i):
        for n, v in self.by_name.items():
            if v == i:
                return types.SimpleNamespace(pw_uid=i, pw_name=n)
        raise KeyError(i)

    def getgrnam(self, n):
        if n not in self.by_name:
            raise KeyError(n)
        return types.SimpleNamespace(gr_gid=self.by_name[n], gr_name=n)

    def getgrgid(self, i):
        for n, v in self.by_name.items():
            if v == i:
                return types.SimpleNamespace(gr_gid=i, gr_name=n)
        raise KeyError(i)


def test_sysops(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "chown", lambda *a: None)
    f = tmp_path / "a" / "f"
    sysops.make_dir(str(f.parent), 0o700)
    sysops.write_file(str(f), "x", 0o600)
    assert sysops.read_file(str(f)) == "x" and sysops.read_file(str(tmp_path / "no"), "d") == "d"
    assert oct(f.stat().st_mode & 0o777) == "0o600"
    assert sysops.run(["sh", "-c", "echo hi"]) == "hi\n"
    assert sysops.run(["sh", "-c", "exit 3"], check=False) == ""
    with pytest.raises(sysops.CommandError, match="exit 3"):
        sysops.run(["sh", "-c", "echo e >&2; exit 3"])
    sysops.log("hello")


def test_accounts_create(cfg, rec, fs, monkeypatch):
    db = FakeDb({"www-data": 33})
    monkeypatch.setattr(accounts, "pwd", db)
    monkeypatch.setattr(accounts, "grp", db)
    (fs / "var/lib/samba/ssh").mkdir(parents=True)
    (fs / "var/lib/samba/ssh/shadow").write_text("alice:$6$x\n\nbad\n")
    accounts.apply(cfg)
    cmds = [c[0] for c in rec.calls]
    assert ["groupadd", "-g", "65533", "sharecontainer-dav"] in cmds
    assert ["groupadd", "-g", "2000", "team"] in cmds
    add = next(c for c in cmds if c[0] == "useradd" and c[-1] == "alice")
    assert "-G" in add and "team,sharecontainer-dav" in add and f"{paths.VIEWS}/alice" in add
    assert next(c for c in cmds if c[0] == "useradd" and c[-1] == "bob")[-2] == "/bin/sh"
    assert rec.calls[-1] == (["chpasswd", "-e"], "alice:$6$x\nbob:*\nanonymous:\n")


def test_accounts_existing(cfg, rec, fs, monkeypatch):
    db = FakeDb({"team": 2000, "alice": 2001, "bob": 2002, "anonymous": 2009, "sharecontainer-dav": 65533})
    monkeypatch.setattr(accounts, "pwd", db)
    monkeypatch.setattr(accounts, "grp", db)
    cfg.webdav.enabled = False
    accounts.apply(cfg)
    assert [c[0][0] for c in rec.calls].count("usermod") == 3


@pytest.mark.parametrize("db,msg", [
    ({"team": 50}, "group team exists with gid 50"),
    ({"other": 2000}, "belongs to the image's group other"),
    ({"team": 2000, "alice": 2001, "x": 2001}, "exists with uid"),
])
def test_accounts_conflicts(cfg, rec, fs, monkeypatch, db, msg):
    cfg.webdav.enabled = False
    fake = FakeDb(db)
    monkeypatch.setattr(accounts, "grp", fake)
    if "x" in db:
        pw = FakeDb({"alice": 1})
        monkeypatch.setattr(accounts, "pwd", pw)
        fake.by_name.pop("x")
    with pytest.raises(accounts.AccountError, match=msg):
        accounts.apply(cfg)


def test_accounts_uid_taken(cfg, rec, fs, monkeypatch):
    cfg.webdav.enabled = False
    monkeypatch.setattr(accounts, "grp", FakeDb({"team": 2000, "alice": 2001}))
    monkeypatch.setattr(accounts, "pwd", FakeDb({"daemon": 2001}))
    with pytest.raises(accounts.AccountError, match="image's user daemon"):
        accounts.apply(cfg)


def test_accounts_no_users(cfg, rec, fs):
    cfg.users = []
    cfg.groups = []
    cfg.webdav.enabled = False
    accounts.apply(cfg)
    assert rec.calls == []


def test_shadow(fs):
    (fs / "etc").mkdir()
    (fs / "etc/shadow").write_text("root:*:1\nalice:$6$y:2\n")
    assert accounts.shadow_hash("alice") == "$6$y"
    with pytest.raises(accounts.AccountError):
        accounts.shadow_hash("bob")
    os.makedirs(os.path.dirname(paths.SSH_SHADOW))
    accounts.write_shadow({"b": "2", "a": "1"})
    assert open(paths.SSH_SHADOW).read() == "a:1\nb:2\n"
    assert accounts.read_shadow() == {"a": "1", "b": "2"}


def test_acls(cfg, rec, fs):
    for s in cfg.shares:
        s.path = str(fs) + s.path
    os.makedirs(cfg.shares[0].path)
    acls.apply(cfg)
    cmds = [c[0] for c in rec.calls]
    spec = "u::rwx,g::---,o::---,m::rwx,u:alice:rwx,g:team:r-x,u:bob:r-x"
    assert ["setfacl", "--set", spec, cfg.shares[0].path] in cmds
    assert any(c[0] == "find" for c in cmds)
    state = json.load(open(paths.ACL_STATE))
    assert state[cfg.shares[0].path] == spec
    rec.calls.clear()
    acls.apply(cfg)
    assert not any(c[0][0] == "find" for c in rec.calls)


def test_acls_broken_state_and_no_acl(cfg, rec, fs):
    for s in cfg.shares:
        s.path = str(fs) + s.path
    os.makedirs(os.path.dirname(paths.ACL_STATE))
    open(paths.ACL_STATE, "w").write("{bad")
    assert acls._load_state() == {}
    rec.fail.add("setfacl")
    with pytest.raises(acls.AclError, match="without ACL support"):
        acls.apply(cfg)


def test_ssh_apply(cfg, rec, fs):
    for s in cfg.shares:
        s.path = str(fs) + s.path
    os.makedirs(paths.SSH_HOST_KEYS)
    open(f"{paths.SSH_HOST_KEYS}/ssh_host_rsa_key", "w").close()
    ssh.apply(cfg)
    assert [c[0][0] for c in rec.calls] == ["ssh-keygen", "ssh-keygen", "/usr/sbin/sshd"]
    assert "ForceCommand" in open(paths.SSHD_CONF).read()


def test_views(cfg, fs):
    cfg.user("bob").protocols = ("smb",)
    os.makedirs(f"{paths.VIEWS}/alice")
    os.symlink("/old", f"{paths.VIEWS}/alice/old")
    ssh.apply_views(cfg)
    assert sorted(os.listdir(f"{paths.VIEWS}/alice")) == ["data", "pub"]
    assert os.readlink(f"{paths.VIEWS}/alice/data") == "/shares/data"
    assert json.load(open(f"{paths.POLICIES}/alice.json"))["view"] == f"{paths.VIEWS}/alice"
    assert os.path.isdir(f"{paths.VIEWS}/bob")


def test_webdav_apply(cfg, rec, fs, monkeypatch):
    db = FakeDb({"www-data": 33, "sharecontainer-dav": 65533})
    monkeypatch.setattr(webdav, "pwd", db)
    monkeypatch.setattr(webdav, "grp", db)
    webdav.apply(cfg)
    assert open(paths.DAV_USERS).read() == "alice\nanonymous\n"
    assert open(paths.DAV_PASSWORDS).read() == ""
    assert os.stat(paths.DAV_PASSWORDS).st_mode & 0o777 == 0o640
    assert os.stat(paths.DAV_STATE).st_mode & 0o777 == 0o750
    assert rec.calls[-1][0][0] == "/usr/sbin/apache2"
    open(paths.DAV_PASSWORDS, "w").write("alice:x\n")
    webdav.apply(cfg)
    assert open(paths.DAV_PASSWORDS).read() == "alice:x\n"


def test_discovery_apply(cfg, fs):
    discovery.apply(cfg)
    assert not os.path.exists(paths.AVAHI_CONF)
    cfg.smb.mdns = True
    os.makedirs(paths.AVAHI_SERVICES)
    open(f"{paths.AVAHI_SERVICES}/old.service", "w").close()
    discovery.apply(cfg)
    assert os.listdir(paths.AVAHI_SERVICES) == ["smb.service"]


def test_network(cfg, rec, fs):
    network.check_interfaces(cfg, exists=lambda p: True)
    with pytest.raises(network.NetworkError, match="eth0"):
        network.check_interfaces(cfg, exists=lambda p: False, attempts=2, sleep=lambda s: None)
    rec.results["ip"] = "2: eth0    inet 10.0.0.5/24 brd x\n2: eth0    inet6 fe80::1/64\n"
    assert network.ipv4("eth0") == ["10.0.0.5/24"]
    cfg.interfaces[0].dhcp = True
    assert network.dhcp_interfaces(cfg) == ["eth0"]
    os.makedirs(paths.RUN)
    assert network.dhcpcd_command(cfg)[-1] == "eth0"
    assert "hostname FS" in open(paths.DHCPCD_CONF).read()
    assert network.wait_for_lease("eth0", ["10.0.0.9/24"]) == "10.0.0.5/24"
    assert (["ip", "addr", "del", "10.0.0.9/24", "dev", "eth0"], None) in rec.calls
    t = iter(range(100))
    with pytest.raises(network.NetworkError, match="no DHCP answer"):
        network.wait_for_lease("eth0", ["10.0.0.5/24"], timeout=3, sleep=lambda s: None, clock=lambda: next(t))

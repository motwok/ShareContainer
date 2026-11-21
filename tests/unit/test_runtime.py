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
    os.makedirs(paths.STATE)
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
    assert network.dhcp_command(cfg, "eth0")[:5] == ["udhcpc", "-f", "-R", "-i", "eth0"]
    assert "hostname:FS" in network.dhcp_command(cfg, "eth0")
    os.makedirs(paths.RUN)
    open(network.lease_file("eth0"), "w").write("10.0.0.5/24\n")
    assert network.wait_for_lease("eth0") == "10.0.0.5/24"
    os.unlink(network.lease_file("eth0"))
    t = iter(range(100))
    with pytest.raises(network.NetworkError, match="no DHCP answer"):
        network.wait_for_lease("eth0", timeout=3, sleep=lambda s: None, clock=lambda: next(t))


def test_dhcp_event(monkeypatch, fs):
    os.makedirs(paths.RUN)
    calls = []
    monkeypatch.setattr(sysops, "log", lambda m: calls.append(m))

    def run(cmd, check=True):
        calls.append(cmd)
    env = {"interface": "eth0", "ip": "10.1.2.3", "subnet": "255.255.255.0", "router": "10.1.2.1 10.1.2.254"}
    assert network.dhcp_event("bound", env, run, current=lambda i: ["172.17.0.2/16"]) == 0
    assert calls[:2] == [["ip", "-4", "addr", "flush", "dev", "eth0"], ["ip", "addr", "add", "10.1.2.3/24", "dev", "eth0"]]
    assert ["ip", "route", "replace", "default", "via", "10.1.2.1", "dev", "eth0"] in calls
    assert open(network.lease_file("eth0")).read() == "10.1.2.3/24\n"
    calls.clear()
    network.dhcp_event("renew", dict(env, router=""), run, current=lambda i: ["10.1.2.3/24"])
    assert not any(isinstance(c, list) for c in calls)
    network.dhcp_event("nak", {"interface": "eth0", "message": "no"}, run)
    network.dhcp_event("leasefail", {}, run)
    network.dhcp_event("deconfig", env, run)
    assert calls[-2:] == ["eth0: DHCP nak no", ": DHCP leasefail"]
    monkeypatch.setattr(sysops, "run", lambda cmd, check=True: calls.append(("default", cmd)) or "")
    network.dhcp_event("bound", env)
    assert ("default", ["ip", "addr", "add", "10.1.2.3/24", "dev", "eth0"]) in calls


ADDR = """\
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\\       valid_lft forever
2: eth0    inet6 2001:db8::5/64 scope global dynamic mngtmpaddr \\       valid_lft 7000sec
2: eth0    inet6 2001:db8::99/64 scope global temporary dynamic \\       valid_lft 7000sec
2: eth0    inet6 2001:db8::77/64 scope global deprecated dynamic \\       valid_lft 0sec
"""


def test_global_addresses(rec):
    rec.results["ip"] = ADDR
    assert network.global_addresses("eth0") == ["10.0.0.5/24", "2001:db8::5/64"]


def test_ipv6_active():
    conf = {"disable_ipv6": "0\n", "accept_ra": "1\n"}
    assert network.ipv6_active("eth0", read=lambda p, d: conf.get(p.rsplit("/", 1)[1]))
    conf["accept_ra"] = "0\n"
    assert not network.ipv6_active("eth0", read=lambda p, d: conf.get(p.rsplit("/", 1)[1]))
    assert not network.ipv6_active("eth0", read=lambda p, d: None)


def test_wait_for_ipv6(monkeypatch):
    on = lambda p, d: "0" if p.endswith("disable_ipv6") else "2"  # noqa: E731
    assert network.wait_for_ipv6("eth0", read=lambda p, d: None) == []
    calls = []
    answers = {
        ("ip", "-6", "-o"): iter(["", "2: eth0 inet6 2001:db8::5/64 scope global tentative dynamic\n",
                                  "2: eth0 inet6 2001:db8::5/64 scope global dynamic\n"
                                  "2: eth0 inet6 fd00::5/64 scope global tentative dynamic\n",
                                  "2: eth0 inet6 2001:db8::5/64 scope global dynamic\n"
                                  "2: eth0 inet6 fd00::5/64 scope global dynamic\n"]),
    }
    routes = "default via 2001:db8:5c00:: dev eth0 metric 1024 pref medium\n" \
             "default via fe80::1 dev eth0 proto ra metric 1024 expires 1800sec\n"

    def run(cmd, data=None, check=True):
        calls.append(cmd)
        if cmd[:3] == ["ip", "-6", "-o"]:
            return next(answers[("ip", "-6", "-o")])
        if cmd[:4] == ["ip", "-6", "route", "show"]:
            return routes
        if cmd[:3] == ["ip", "-o", "addr"]:
            return ADDR
        return ""
    monkeypatch.setattr(sysops, "run", run)
    monkeypatch.setattr(sysops, "log", lambda m: None)
    assert network.wait_for_ipv6("eth0", sleep=lambda s: None, read=on) == ["10.0.0.5/24", "2001:db8::5/64"]
    assert ["ip", "-6", "route", "del", "default", "via", "2001:db8:5c00::", "dev", "eth0"] in calls
    # No router route: Docker's route stays.
    calls.clear()
    answers[("ip", "-6", "-o")] = iter(["x\n"])
    routes = "default via 2001:db8:5c00:: dev eth0 metric 1024\n"
    network.wait_for_ipv6("eth0", sleep=lambda s: None, read=on)
    assert not any(c[:4] == ["ip", "-6", "route", "del"] for c in calls)
    # No router advertisement at all.
    answers[("ip", "-6", "-o")] = iter([""] * 10)
    t = iter(range(100))
    assert network.wait_for_ipv6("eth0", timeout=3, sleep=lambda s: None, clock=lambda: next(t), read=on) == []


def test_watch(monkeypatch):
    monkeypatch.setattr(sysops, "log", lambda m: None)
    seq = iter([["a"], ["b"], ["a"], ["b"], ["a"], ["c"]])
    assert network.watch(["eth0", "eth1"], sleep=lambda s: None, addresses=lambda i: next(seq)) == 1
    seq2 = iter([[], ["x"]])
    assert network.watch(["eth0"], sleep=lambda s: None, addresses=lambda i: next(seq2)) == 1
    monkeypatch.setattr(network, "global_addresses", lambda i: [])
    calls = iter([None, RuntimeError("stop")])

    def sleep(s):
        r = next(calls)
        if r:
            raise r
    with pytest.raises(RuntimeError):
        network.watch(["eth0"], sleep=sleep)


def test_clear_leases(cfg, fs):
    os.makedirs(paths.RUN)
    cfg.interfaces[0].dhcp = True
    open(network.lease_file("eth0"), "w").write("10.0.0.1/24\n")
    network.clear_leases(cfg)
    assert not os.path.exists(network.lease_file("eth0"))
    network.clear_leases(cfg)

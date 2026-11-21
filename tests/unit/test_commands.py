import io
import os
import types

import pytest

from sharecontainer import __main__ as cli
from sharecontainer import accounts, config, credentials, network, paths, start, supervisor, sysops
from sharecontainer.credentials import UsageError


@pytest.fixture
def known(monkeypatch):
    monkeypatch.setattr(credentials.pwd, "getpwnam", lambda n: types.SimpleNamespace(pw_name=n))
    monkeypatch.setattr(credentials.grp, "getgrnam", lambda n: types.SimpleNamespace(gr_gid=33))


def test_passwd(cfg, rec, fs, known, monkeypatch):
    monkeypatch.setattr(accounts, "shadow_hash", lambda n: "$6$h")
    os.makedirs(os.path.dirname(paths.SSH_SHADOW))
    os.makedirs(paths.DAV_STATE)
    open(paths.DAV_PASSWORDS, "w").write("bob:old\n\n")
    credentials.passwd(["--stdin", "alice"], cfg=cfg, stdin=io.StringIO("pw1\n"))
    assert rec.calls[0] == (["smbpasswd", "-c", paths.SMB_CONF, "-s", "-a", "alice"], "pw1\npw1\n")
    assert rec.calls[1] == (["chpasswd"], "alice:pw1\n")
    assert accounts.read_shadow() == {"alice": "$6$h"}
    lines = open(paths.DAV_PASSWORDS).read().splitlines()
    assert lines[0].startswith("alice:$2") and lines[1] == "bob:old"
    answers = iter(["pw2", "pw2"])
    credentials.passwd(["alice"], cfg=cfg, ask=lambda prompt: next(answers))


@pytest.mark.parametrize("args,stdin,msg", [
    ([], "", "usage"),
    (["carl"], "", "not a user"),
    (["anonymous"], "", "guest"),
    (["--stdin", "alice"], "\n", "must not be empty"),
])
def test_passwd_errors(cfg, known, args, stdin, msg):
    with pytest.raises(UsageError, match=msg):
        credentials.passwd(args, cfg=cfg, stdin=io.StringIO(stdin))


def test_passwd_mismatch_and_unknown(cfg, monkeypatch):
    monkeypatch.setattr(credentials.pwd, "getpwnam", lambda n: types.SimpleNamespace())
    answers = iter(["a", "b"])
    with pytest.raises(UsageError, match="differ"):
        credentials.passwd(["alice"], cfg=cfg, ask=lambda p: next(answers))

    def missing(n):
        raise KeyError(n)
    monkeypatch.setattr(credentials.pwd, "getpwnam", missing)
    with pytest.raises(UsageError, match="restart the container"):
        credentials.passwd(["alice"], cfg=cfg)


def test_passwd_loads_config(fs, monkeypatch, known):
    monkeypatch.setattr(config, "load", lambda p: (_ for _ in ()).throw(config.ConfigError(["bad"])))
    with pytest.raises(config.ConfigError):
        credentials.passwd(["alice"])


def test_keys(cfg, rec, fs, known, capsys):
    rec.results["ssh-keygen"] = "256 SHA256:abc alice (ED25519)\n"
    credentials.keys(["add", "alice", "-"], cfg=cfg, stdin=io.StringIO("# c\n\nssh-ed25519 AAAA a\nssh-ed25519 AAAA a\n"))
    assert open(f"{paths.SSH_KEYS}/alice").read() == "ssh-ed25519 AAAA a\n"
    f = fs / "k.pub"
    f.write_text("ssh-rsa BBBB b\n")
    credentials.keys(["add", "alice", str(f)], cfg=cfg)
    credentials.keys(["list", "alice"], cfg=cfg)
    assert "2 256 SHA256:abc" in capsys.readouterr().out
    credentials.keys(["remove", "alice", "1"], cfg=cfg)
    assert open(f"{paths.SSH_KEYS}/alice").read() == "ssh-rsa BBBB b\n"


@pytest.mark.parametrize("args,msg", [
    (["add"], "usage"),
    (["copy", "alice"], "usage"),
    (["list", "alice", "x"], "usage"),
    (["remove", "alice", "9"], "NUMBER"),
    (["add", "alice", "a", "b"], "usage"),
    (["add", "alice", "/nonexistent"], "not found"),
])
def test_keys_errors(cfg, rec, fs, known, args, msg):
    with pytest.raises(UsageError, match=msg):
        credentials.keys(args, cfg=cfg)


def test_keys_invalid(cfg, rec, fs, known):
    rec.fail.add("ssh-keygen")
    with pytest.raises(UsageError, match="not a public key"):
        credentials.keys(["add", "alice"], cfg=cfg, stdin=io.StringIO("garbage\n"))


def test_keys_loads_config(monkeypatch):
    monkeypatch.setattr(config, "load", lambda p: (_ for _ in ()).throw(config.ConfigError(["bad"])))
    with pytest.raises(config.ConfigError):
        credentials.keys(["list", "alice"])


def test_services(cfg):
    names = [s.name for s in start.services(cfg)]
    assert names == ["smbd", "sshd", "apache", "metrics"]
    cfg.smb.netbios = cfg.smb.wsd = cfg.smb.mdns = True
    cfg.metrics.enabled = False
    assert [s.name for s in start.services(cfg)] == ["smbd", "nmbd", "wsdd2", "avahi", "sshd", "apache"]
    cfg.smb.enabled = cfg.ssh.enabled = cfg.webdav.enabled = False
    assert start.services(cfg) == []


def test_prepare(cfg, rec, fs, monkeypatch):
    calls = []
    for mod, fn in [(accounts, "apply"), (start.acls, "apply"), (start.ssh, "apply_views"), (start.ssh, "apply"),
                    (start.webdav, "apply"), (start.discovery, "apply")]:
        monkeypatch.setattr(mod, fn, lambda c, n=f"{mod.__name__}.{fn}": calls.append(n))
    os.makedirs(paths.CONFIG_DIR)
    os.makedirs(os.path.dirname(paths.SMB_CONF))
    cfg.homes = True
    cfg.user("alice").home = True
    os.makedirs(f"{paths.HOMES}/bob")
    start.prepare(cfg)
    assert os.path.isdir(f"{paths.HOMES}/alice") and rec.calls[0][0][0] == "testparm"
    assert len(calls) == 6
    cfg.ssh.enabled = cfg.webdav.enabled = False
    cfg.homes = False
    cfg.user("alice").home = None
    os.rmdir(paths.CONFIG_DIR)
    start.prepare(cfg)
    assert len(calls) == 10


def test_main(cfg, monkeypatch, fs):
    monkeypatch.setattr(config, "load", lambda p: (_ for _ in ()).throw(config.ConfigError(["x: bad"])))
    assert start.main() == 2
    monkeypatch.setattr(config, "load", lambda p: cfg)
    monkeypatch.setattr(network, "check_interfaces", lambda c: None)
    monkeypatch.setattr(start, "prepare", lambda c: None)
    got = {}
    assert start.main(run=lambda s, dhcp_wait: got.update(s=s, w=dhcp_wait) or 0) == 0
    assert got["w"] is None and got["s"][0].name == "smbd"
    cfg.interfaces[0].dhcp = True
    monkeypatch.setattr(network, "ipv4", lambda i: ["1.2.3.4/24"])
    monkeypatch.setattr(network, "check_sysctls", lambda c: None)
    monkeypatch.setattr(network, "dhcpcd_command", lambda c: ["dhcpcd"])
    monkeypatch.setattr(network, "wait_for_lease", lambda i, b: f"{i}:{b}")
    assert start.main(run=lambda s, dhcp_wait: got.update(s=s, w=dhcp_wait) or 0) == 0
    assert got["s"][0].name == "dhcpcd" and got["w"]() == ["eth0:['1.2.3.4/24']"]

    def broken(c):
        raise network.NetworkError("no eth0")
    monkeypatch.setattr(network, "check_interfaces", broken)
    assert start.main() == 1


def test_cli(monkeypatch, capsys, cfg):
    monkeypatch.setattr(start, "main", lambda: 5)
    assert cli.main([]) == 5 and cli.main(["run"]) == 5
    monkeypatch.setattr(config, "load", lambda p: cfg)
    assert cli.main(["check"]) == 0 and cli.main(["check", "/x"]) == 0
    monkeypatch.setattr(credentials, "passwd", lambda a: None)
    monkeypatch.setattr(credentials, "keys", lambda a: None)
    assert cli.main(["passwd", "alice"]) == 0 and cli.main(["keys", "list", "alice"]) == 0
    monkeypatch.setattr(supervisor, "health", lambda: 0)
    assert cli.main(["health"]) == 0
    monkeypatch.setattr(cli.metrics, "serve", lambda c: None)
    assert cli.main(["metrics"]) == 0
    monkeypatch.setattr(cli.sshcmd, "main", lambda: 1)
    monkeypatch.setattr(cli.davauth, "main", lambda: 0)
    assert cli.main(["ssh-command"]) == 1 and cli.main(["davauth"]) == 0
    assert cli.main(["nonsense"]) == 2
    monkeypatch.setattr(credentials, "passwd", lambda a: (_ for _ in ()).throw(UsageError("u")))
    assert cli.main(["passwd"]) == 2
    monkeypatch.setattr(config, "load", lambda p: (_ for _ in ()).throw(config.ConfigError(["e1"])))
    assert cli.main(["check"]) == 2
    assert "e1" in capsys.readouterr().err
    monkeypatch.setattr(cli.sys, "argv", ["x", "nonsense"])
    assert cli.main() == 2
    assert sysops is not None

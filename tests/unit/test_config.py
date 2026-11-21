import pytest

from sharecontainer import config
from sharecontainer.config import ConfigError, parse


def errors(data):
    with pytest.raises(ConfigError) as e:
        parse(data)
    return "\n".join(e.value.errors)


def test_defaults(cfg):
    assert cfg.name == "FS" and cfg.workgroup == "WG" and cfg.log_level == 1
    assert cfg.ssh.port == 2022 and cfg.ssh.password_login_disabled and not cfg.ssh.password_login
    assert cfg.webdav.port == 8080 and not cfg.webdav.https
    assert cfg.metrics.enabled and cfg.metrics.port == 9482
    assert not cfg.homes and cfg.smb.min_protocol == "SMB3"
    assert cfg.shares[0].path == "/shares/data"
    assert cfg.user("alice").protocols == config.PROTOCOLS
    assert cfg.user("nobody") is None


def test_https_default_port(raw, tmp_path, monkeypatch):
    monkeypatch.setattr(config.os.path, "isfile", lambda p: True)
    raw["webdav"]["https"] = True
    assert parse(raw).webdav.port == 8443


def test_https_needs_files(raw, monkeypatch):
    monkeypatch.setattr(config.os.path, "isfile", lambda p: False)
    raw["webdav"]["https"] = True
    assert "cert.pem is missing" in errors(raw)


def test_helpers(cfg, raw):
    alice, bob, guest = cfg.users
    assert cfg.expand(["@team", "bob"]) == {"alice", "bob"}
    assert cfg.may(alice, "webdav") and not cfg.may(bob, "webdav")
    assert cfg.enabled("rsync")
    data, pub = cfg.shares
    assert cfg.share_users(data, "smb") == ["alice", "bob"]
    assert cfg.share_users(data, "smb", write=True) == ["alice"]
    assert cfg.share_users(data, "webdav") == ["alice"]
    data.protocols = ("smb",)
    assert cfg.share_users(data, "webdav") == []
    assert not cfg.has_home(guest) and not cfg.has_home(alice)
    alice.home = True
    assert cfg.has_home(alice)
    assert cfg.password_login(guest) and not cfg.password_login(alice)
    cfg.ssh.password_login_disabled = False
    assert not cfg.password_login(alice)
    cfg.ssh.password_login = True
    assert cfg.password_login(alice)
    alice.password_login = False
    assert not cfg.password_login(alice)
    assert cfg.share_flag(pub, "guest") and cfg.guest_share(pub)
    assert [u.name for u in cfg.ssh_users()] == ["alice", "anonymous"]


def test_full_values(raw):
    raw["server"]["log_level"] = 3
    raw["network"]["interfaces"][0]["dhcp"] = True
    raw["smb"].update({"multichannel": True, "min_protocol": "SMB2_02", "encryption": "required",
                       "signing": "mandatory", "extra": {"socket options": "TCP_NODELAY", "x y": True, "z": False,
                                                          "n": 3}})
    raw["ssh"].update({"port": 22, "password_login_disabled": False, "password_login": True})
    raw["metrics"] = {"enabled": False, "port": 9000}
    raw["homes"] = {"enabled": True}
    raw["users"][0].update({"password_login": False, "home": False, "protocols": ["smb", "sftp"]})
    raw["shares"][0].update({"path": "/srv/data", "macos": True, "recycle": True, "encryption": "off",
                             "protocols": ["smb", "sftp"], "extra": {"comment": "Data"}})
    c = parse(raw)
    assert c.smb.extra == {"socket options": "TCP_NODELAY", "x y": "yes", "z": "no", "n": "3"}
    assert c.interfaces[0].dhcp and c.shares[0].extra == {"comment": "Data"}
    assert c.shares[0].path == "/srv/data" and c.homes


@pytest.mark.parametrize("change,message", [
    (lambda r: r.update(bogus=1), "share.yaml.bogus: unknown key"),
    (lambda r: r.update(server="x"), "server: must be a mapping"),
    (lambda r: r.update(groups="x"), "groups: must be a list"),
    (lambda r: r["server"].pop("name"), "server.name: is required"),
    (lambda r: r["server"].update(name="bad name"), "invalid value"),
    (lambda r: r["server"].update(name=5), "must be text"),
    (lambda r: r["server"].update(log_level=11), "from 0 to 10"),
    (lambda r: r["server"].update(log_level=True), "from 0 to 10"),
    (lambda r: r["network"].update(interfaces=[]), "at least one interface"),
    (lambda r: r["network"]["interfaces"].append({"name": "eth0", "speed": 1000000000}), "names must be unique"),
    (lambda r: r["network"]["interfaces"][0].pop("speed"), "speed: is required"),
    (lambda r: r["smb"].update(enabled="yes"), "must be true or false"),
    (lambda r: r["smb"].update(min_protocol="NT1"), "must be one of"),
    (lambda r: r["smb"].update(extra={"bad\n": 1}), "invalid parameter name"),
    (lambda r: r["smb"].update(extra={"a": [1]}), "must be a single value"),
    (lambda r: r["smb"].update(extra={"a": "x\\"}), "must be a single value"),
    (lambda r: r["smb"].update(extra={"a": "x\ny = z"}), "must be a single value"),
    (lambda r: r["smb"].update(extra={"a\n": "x"}), "invalid parameter name"),
    (lambda r: r["shares"].append({"name": "x", "path": "/srv/a\nb"}), "outside the system folders"),
    (lambda r: r["shares"].append({"name": "x", "path": '/srv/a"b'}), "outside the system folders"),
    (lambda r: r["shares"].append({"name": "x", "path": "/srv/../etc"}), "outside the system folders"),
    (lambda r: r["server"].update(name="FS\n"), "invalid value"),
    (lambda r: r["users"][0].update(protocols=["ftp"]), "must be one of smb"),
    (lambda r: r["users"][0].update(groups=["Bad"]), "invalid entry"),
    (lambda r: r["users"][0].update(groups=["missing"]), "unknown group missing"),
    (lambda r: r["users"].append({"name": "alice", "uid": 3000}), "user alice is defined twice"),
    (lambda r: r["users"].append({"name": "carl", "uid": 2001}), "uid 2001 is used twice"),
    (lambda r: r["groups"].append({"name": "team", "gid": 2100}), "group team is defined twice"),
    (lambda r: r["groups"].append({"name": "other", "gid": 2001}), "gid 2001 is used twice"),
    (lambda r: r["groups"].append({"name": "alice", "gid": 2500}), "has the name of a user"),
    (lambda r: r["groups"].append({"name": "sharecontainer-dav", "gid": 2500}), "is reserved"),
    (lambda r: r["ssh"].update(port=445), "port 445 is used twice"),
    (lambda r: r["shares"].append({"name": "DATA", "path": "/x"}), "share data is defined twice"),
    (lambda r: r["shares"].append({"name": "home"}), "this name is reserved"),
    (lambda r: r["shares"].append({"name": "x", "path": "/etc/x"}), "outside the system folders"),
    (lambda r: r["shares"].append({"name": "x", "path": "/shares/data"}), "same path as share data"),
    (lambda r: r["shares"][0]["read"].append("@nogroup"), "unknown group nogroup"),
    (lambda r: r["shares"][0]["read"].append("carl"), "unknown user carl"),
    (lambda r: r["shares"][1].update(read=["bob"]), "guest access needs the user anonymous"),
    (lambda r: r["shares"][0].update(protocols=["smb"]), "SFTP cannot be restricted per share"),
    (lambda r: (r["smb"].update(enabled=False), r["ssh"].update(enabled=False), r["webdav"].update(enabled=False)),
     "no protocol is switched on"),
])
def test_errors(raw, change, message):
    change(raw)
    assert message in errors(raw)


def test_share_named_like_home_user(raw):
    raw["homes"] = {"enabled": True}
    raw["shares"].append({"name": "Alice", "path": "/srv/a"})
    assert "name of a user with a home directory" in errors(raw)


def test_null_means_default(raw):
    raw["ssh"].update(password_login_disabled=None, port=None)
    raw["server"]["log_level"] = None
    c = parse(raw)
    assert c.ssh.password_login_disabled and c.ssh.port == 2022 and c.log_level == 1


def test_empty_document():
    assert "is empty" in errors(None)


def test_list_entry_types(raw):
    raw["shares"][0]["read"] = [5]
    assert "invalid entry 5" in errors(raw)


def test_load(tmp_path):
    p = tmp_path / "share.yaml"
    with pytest.raises(ConfigError, match="not found"):
        config.load(str(p))
    p.write_text("a: [")
    with pytest.raises(ConfigError, match="share.yaml"):
        config.load(str(p))
    p.write_text("server:\n  name: X\nnetwork:\n  interfaces:\n    - name: eth0\n      speed: 1000000000\n"
                 "smb:\n  enabled: true\n")
    assert config.load(str(p)).name == "X"

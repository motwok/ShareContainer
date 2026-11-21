from sharecontainer import config, discovery, smbconf, ssh, webdav


def test_smbconf_basic(cfg):
    out = smbconf.generate(cfg)
    assert 'interfaces = "eth0;speed=1000000000"' in out
    assert "server multi channel support = no" in out
    assert "workgroup = WG" in out
    assert "map to guest = Bad User" in out and "guest account = anonymous" in out
    assert "invalid users = root" in out
    assert "[data]" in out and "valid users = alice bob" in out and "write list = alice" in out
    assert "kernel oplocks = yes" in out and "smbd profiling level = count" in out
    assert "[homes]" not in out and "vfs objects" not in out


def test_smbconf_features(raw):
    raw["server"].pop("workgroup")
    raw["smb"].update({"multichannel": True, "encryption": "required", "signing": "mandatory", "windows_acls": True,
                       "macos": True, "recycle": True, "extra": {"socket options": "TCP_NODELAY"}})
    raw["metrics"] = {"enabled": False}
    raw["homes"] = {"enabled": True}
    raw["users"][1]["protocols"] = ["sftp"]
    raw["shares"][0].update({"encryption": "desired", "extra": {"comment": "x"}})
    raw["shares"][1].update({"guest": False, "macos": False, "recycle": False})
    raw["shares"].append({"name": "nosmb", "path": "/srv/n", "write": ["alice"],
                          "protocols": ["webdav", "sftp", "rsync", "borg"]})
    raw["shares"].append({"name": "empty", "path": "/srv/e"})
    out = smbconf.generate(config.parse(raw))
    assert 'interfaces = "eth0;capability=RSS,speed=1000000000"' in out
    assert "server multi channel support = yes" in out and "workgroup" not in out
    assert "server smb encrypt = required" in out and "server signing = mandatory" in out
    assert "map acl inherit = yes" in out and "fruit:metadata = stream" in out
    assert "invalid users = root bob" in out and "map to guest = Never" in out
    assert "vfs objects = acl_xattr catia fruit streams_xattr recycle" in out
    assert "smb encrypt = desired" in out and "comment = x" in out and "socket options = TCP_NODELAY" in out
    assert "[nosmb]" not in out and "valid users = nobody" in out
    assert "[homes]" in out and "path = /user/%S" in out
    assert "profiling" not in out


def test_smbconf_homes_without_vfs(raw):
    raw["homes"] = {"enabled": True}
    out = smbconf.generate(config.parse(raw))
    home = out.split("[homes]")[1]
    assert "vfs objects" not in home


def test_sshd(cfg):
    out = ssh.generate(cfg, ["/k1"])
    assert "Port 2022" in out and "HostKey /k1" in out and "AllowUsers alice anonymous" in out
    assert "Match User anonymous" in out and "PermitEmptyPasswords yes" in out
    assert "Match User alice" not in out
    cfg.ssh.password_login_disabled = False
    cfg.user("alice").password_login = True
    assert "Match User alice\n    PasswordAuthentication yes\nMatch" in ssh.generate(cfg, [])
    cfg.users = []
    assert "AllowUsers nobody-allowed" in ssh.generate(cfg, [])


def test_policy(raw):
    raw["homes"] = {"enabled": True}
    raw["users"][0]["protocols"] = ["smb", "sftp", "rsync"]
    raw["shares"].append({"name": "smbonly", "path": "/srv/s", "read": ["bob"], "protocols": ["smb"]})
    cfg = config.parse(raw)
    p = ssh.policy(cfg, cfg.user("alice"))
    assert p["links"] == {"home": "/user/alice", "data": "/shares/data", "pub": "/shares/pub"}
    assert set(p["protocols"]) == {"sftp", "rsync"}
    assert p["protocols"]["rsync"]["write"] == ["/shares/data", "/shares/pub", "/user/alice"]
    g = ssh.policy(cfg, cfg.user("anonymous"))
    assert "home" not in g["links"] and g["protocols"]["borg"]["write"] == []
    assert g["protocols"]["sftp"]["read"] == ["/shares/pub"]


def test_webdav(raw):
    raw["homes"] = {"enabled": True}
    raw["shares"].append({"name": "nodav", "path": "/srv/n", "read": ["alice"], "protocols": ["smb", "sftp"]})
    raw["shares"].append({"name": "empty", "path": "/srv/e"})
    out = webdav.generate(config.parse(raw))
    assert "mpm_itk.so" in out and "mod_dav.so" in out and "mod_ssl" not in out
    assert "LimitUIDRange 2001 65534" in out and "LimitGIDRange 2000 65534" in out
    assert "Alias /data /shares/data" in out and "Alias /nodav" not in out
    assert "in { 'alice' }" in out and "Require all denied" in out
    assert "RewriteRule ^/home(/.*)?$ /user/%{ENV:SC_USER}$1 [L]" in out
    assert "ServerName FS" in out and "LogLevel warn" in out


def test_webdav_https(raw, monkeypatch):
    monkeypatch.setattr(config.os.path, "isfile", lambda p: True)
    raw["webdav"]["https"] = True
    raw["server"]["log_level"] = 3
    out = webdav.generate(config.parse(raw))
    assert "SSLEngine on" in out and "Listen 8443" in out and "mod_ssl.so" in out and "LogLevel info" in out
    assert "RewriteRule ^/home" not in out


def test_avahi(raw):
    cfg = config.parse(raw)
    assert "enable-dbus=no" in discovery.avahi_conf(cfg) and "allow-interfaces=eth0" in discovery.avahi_conf(cfg)
    assert "_device-info" not in discovery.avahi_service(cfg)
    raw["shares"][0]["macos"] = True
    assert "_device-info" in discovery.avahi_service(config.parse(raw))


def test_wsdd(cfg):
    assert discovery.wsdd_command(cfg) == ["wsdd2", "-w", "-i", "eth0", "-H", "FS", "-G", "WG"]
    cfg.workgroup = None
    assert discovery.wsdd_command(cfg) == ["wsdd2", "-w", "-i", "eth0", "-H", "FS"]

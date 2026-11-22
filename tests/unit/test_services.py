import base64
import io
import json
import os
import signal
import types

import pytest

from sharecontainer import davauth, metrics, paths, sshcmd, supervisor, sysops

POLICY = {
    "view": "/run/v/alice",
    "links": {"data": "/shares/data"},
    "protocols": {
        "sftp": {"read": ["/shares/data"], "write": ["/shares/data"]},
        "rsync": {"read": ["/shares/data", "/shares/ro"], "write": ["/shares/data"]},
        "borg": {"read": ["/shares/data"], "write": ["/shares/data", "/user/alice"]},
    },
}


@pytest.fixture
def real(monkeypatch):
    monkeypatch.setattr(sshcmd.os.path, "realpath", lambda p: p.replace("/run/v/alice/", "/shares/"))


def test_sftp():
    assert sshcmd.command("/usr/lib/openssh/sftp-server", POLICY) == [paths.SFTP_SERVER, "-d", "/run/v/alice"]
    assert sshcmd.command("internal-sftp", POLICY)[0] == paths.SFTP_SERVER


@pytest.mark.parametrize("cmd,msg", [
    ("", "interactive login"),
    ("scp -t x", "legacy scp"),
    ("bash -i", "command bash is not allowed"),
    ("rsync --daemon", "not an rsync server command"),
    ("rsync --server --log-file=/x . data/", "option --log-file"),
    ("rsync --server -logDtprXe.iLsfxCIvu . data/", "option -logDtprXe"),
    ("rsync --server --xattrs . data/", "option --xattrs"),
    ("rsync --server -logDtpre.iLsfxCIvu .", "without a path"),
    ("rsync --server -e.LsfxCIvu . ro/x", "outside the allowed folders"),
    ("borg list", "only 'serve'"),
])
def test_denied(cmd, msg, real):
    with pytest.raises(sshcmd.Denied, match=msg):
        sshcmd.command(cmd, POLICY)


def test_not_allowed():
    pol = dict(POLICY, protocols={})
    for cmd, msg in [("sftp-server", "SFTP"), ("rsync --server . x", "rsync is not"), ("borg serve", "Borg is not")]:
        with pytest.raises(sshcmd.Denied, match=msg):
            sshcmd.command(cmd, pol)
    pol = dict(POLICY, protocols={"borg": {"read": [], "write": []}})
    with pytest.raises(sshcmd.Denied, match="no folder"):
        sshcmd.command("borg serve", pol)


def test_rsync(real):
    assert sshcmd.command("rsync --server -logDtpre.iLsfxCIvu . data/x", POLICY) == \
        ["rsync", "--server", "-logDtpre.iLsfxCIvu", ".", "data/x"]
    assert sshcmd.command("rsync --server --sender -e.LsfxCIvu . ro/x", POLICY)[2] == "--sender"


def test_borg():
    out = sshcmd.command("borg serve --umask=077 --debug --lock-wait 5 --evil --restrict-to-path / --debug-topic",
                         POLICY)
    assert out == ["borg", "serve", "--umask=077", "--debug", "--lock-wait", "5",
                   "--restrict-to-path", "/shares/data", "--restrict-to-path", "/user/alice"]
    assert sshcmd.command("borg2 serve", POLICY)[0] == "borg2"


def test_main(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(paths, "POLICIES", str(tmp_path))
    monkeypatch.setattr(sshcmd.pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_name="alice"))
    assert sshcmd.main(env={}) == 1
    assert "No such file" in capsys.readouterr().err
    (tmp_path / "alice.json").write_text(json.dumps(POLICY))
    assert sshcmd.main(env={"SSH_ORIGINAL_COMMAND": "id"}) == 1
    ran = []
    assert sshcmd.main(env={"SSH_ORIGINAL_COMMAND": "sftp-server"}, execvp=lambda a, b: ran.append(b),
                       chdir=lambda d: ran.append(d)) == 1
    assert ran == ["/run/v/alice", [paths.SFTP_SERVER, "-d", "/run/v/alice"]]


def _hdr(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def test_davauth(tmp_path):
    import bcrypt

    pw = tmp_path / "pw"
    users = tmp_path / "users"
    pw.write_text("alice:" + bcrypt.hashpw(b"secret", bcrypt.gensalt(4)).decode() + "\n\n")
    users.write_text("alice\nanonymous\n")
    now = [0]
    c = davauth.Checker(str(pw), str(users), clock=lambda: now[0])
    assert c.user(_hdr("alice", "secret")) == "alice"
    assert c.user(_hdr("alice", "secret")) == "alice"  # cached
    assert c.user(_hdr("alice", "wrong")) == "nobody"
    assert c.user(_hdr("anonymous", "")) == "anonymous"
    assert c.user(_hdr("anonymous", "x")) == "nobody"
    assert c.user(_hdr("bob", "x")) == "nobody"
    assert c.user("Basic !!!") == "nobody"
    assert c.user("Bearer " + base64.b64encode(b"alice:secret").decode()) == "nobody"
    now[0] = 1000
    users.write_text("anonymous\n")
    os.utime(users, (1, 1))
    assert c.user(_hdr("alice", "secret")) == "nobody"
    c2 = davauth.Checker(str(tmp_path / "none"), str(tmp_path / "none2"))
    assert c2.user(_hdr("alice", "secret")) == "nobody"
    out = io.StringIO()
    assert davauth.main(io.StringIO(_hdr("anonymous", "") + "\n"), out, c) == 0
    assert out.getvalue() == "anonymous\n"


def test_metrics(cfg):
    status = {"sessions": {"1": {"channels": {"a": {}, "b": {}}}, "2": {}},
              "tcons": {"x": {"service": "data"}, "y": {"service": "other"}},
              "open_files": {"/shares/data/f": {"service_path": "/shares/data"}}}
    locks = {"byte_range_locks": {"f": {"service_path": "/shares/data", "locks": [1, 2]},
                                  "g": {"service_path": "/shares/pub"}}}
    prof = {"SMB2 Calls": {"smb2_read": {"count": 3, "outbytes": 30}, "smb2_write": {"count": 4, "inbytes": 40}}}
    out = "\n".join(metrics.collect(cfg, status, locks, prof))
    assert "sharecontainer_up 1" in out and "sharecontainer_smb_sessions 2" in out
    assert "sharecontainer_smb_channels 2" in out
    assert 'sharecontainer_smb_share_connections{share="data"} 1' in out
    assert 'sharecontainer_smb_open_files{share="data"} 1' in out
    assert 'sharecontainer_smb_locks{share="data"} 2' in out and 'sharecontainer_smb_locks{share="pub"} 1' in out
    assert "sharecontainer_smb_read_bytes_total 30" in out and "sharecontainer_smb_write_requests_total 4" in out


def test_metrics_sources(cfg, monkeypatch):
    monkeypatch.setattr(sysops, "run", lambda cmd: "{}" if cmd == ["smbstatus", "--json"] else "bad")
    out = "\n".join(metrics.collect(cfg))
    assert "sharecontainer_smb_sessions 0" in out and "sharecontainer_smb_read_bytes_total 0" in out

    def boom(cmd):
        raise sysops.CommandError("x")
    monkeypatch.setattr(sysops, "run", boom)
    assert "sharecontainer_up 0" in "\n".join(metrics.collect(cfg))


def test_metrics_server(cfg, monkeypatch):
    import threading
    import urllib.error
    import urllib.request

    monkeypatch.setattr(metrics, "collect", lambda c: ["sharecontainer_up 1"])
    servers = []
    real = metrics._Server4

    class Capture(real):
        def __init__(self, *a):
            super().__init__(*a)
            servers.append(self)

    monkeypatch.setattr(metrics, "_Server4", Capture)

    def no_v6(*a):
        raise OSError("no IPv6")
    monkeypatch.setattr(metrics, "_Server", no_v6)
    t = threading.Thread(target=metrics.serve, args=(cfg, 0), daemon=True)
    cfg.metrics.port = 0
    t.start()
    while not servers:
        pass
    port = servers[0].server_address[1]
    assert urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics").read() == b"sharecontainer_up 1\n"
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(f"http://127.0.0.1:{port}/")
    servers[0].shutdown()


def test_metrics_server_v6(monkeypatch):
    s = metrics._Server(("::1", 0), metrics.BaseHTTPRequestHandler)
    s.server_close()


class FakeProc:
    def __init__(self, pid):
        self.pid = pid


def test_supervisor_service_dies(fs, monkeypatch):
    os.makedirs(paths.RUN)
    started = []

    def popen(cmd, preexec_fn=None):
        started.append((cmd, preexec_fn))
        return FakeProc(100 + len(started))

    events = iter([(55, 0), (101, 256), (102, 0)])
    killed = []
    monkeypatch.setattr(os, "kill", lambda pid, s: killed.append(pid))
    waited = []
    dhcp = []
    services = [supervisor.Service("a", ["a"], [1]), supervisor.Service("b", ["b"], umask=0o007)]
    code = supervisor.run(services, dhcp_wait=lambda: dhcp.append(1), popen=popen,
                          waitpid=lambda pid, f: waited.append(pid) or next(events), sig=lambda *a: None)
    assert code == 1 and killed == [102] and dhcp == [1]
    assert started[0][1] is None and started[1][1] is not None
    started[1][1]()
    assert json.load(open(paths.HEALTH))[0]["ports"] == [1]


def test_supervisor_stop_and_errors(fs, monkeypatch):
    os.makedirs(paths.RUN)

    def stop(pid, f):
        if pid == -1:
            supervisor._stop(signal.SIGTERM, None)
        raise ChildProcessError()

    def gone(pid, s):
        raise ProcessLookupError()
    monkeypatch.setattr(os, "kill", gone)
    assert supervisor.run([supervisor.Service("a", ["a"])], popen=lambda c, preexec_fn: FakeProc(7),
                          waitpid=stop, sig=lambda *a: None) == 0
    assert supervisor.run([supervisor.Service("a", ["a"])], popen=lambda c, preexec_fn: FakeProc(7),
                          waitpid=lambda p, f: (_ for _ in ()).throw(ChildProcessError()), sig=lambda *a: None) == 1

    def fail():
        raise RuntimeError("no lease")
    assert supervisor.run([supervisor.Service("a", ["a"])], dhcp_wait=fail,
                          popen=lambda c, preexec_fn: FakeProc(7), waitpid=lambda p, f: (7, 0),
                          sig=lambda *a: None) == 1


def test_health(fs, capsys):
    os.makedirs(paths.RUN)
    assert supervisor.health() == 1
    tcp = fs / "tcp"
    tcp.write_text("  sl  local_address rem_address   st\n   0: 00000000:01BD 00000000:0000 0A\n"
                   "   1: 00000000:0016 00000000:0000 01\n")
    assert supervisor.listening(445, (str(tcp),)) and not supervisor.listening(22, (str(tcp),))
    open(paths.HEALTH, "w").write(json.dumps([{"name": "smbd", "pid": 1, "ports": [445]},
                                              {"name": "x", "pid": 2, "ports": []}]))
    orig = supervisor.listening
    supervisor.listening = lambda p: orig(p, (str(tcp),))
    try:
        assert supervisor.health(alive=lambda pid: True) == 0
        assert supervisor.health(alive=lambda pid: pid == 1) == 1
    finally:
        supervisor.listening = orig
    assert "x not running" in capsys.readouterr().out
    open(paths.HEALTH, "w").write(json.dumps([{"name": "me", "pid": os.getpid(), "ports": []}]))
    assert supervisor.health() == 0


def test_metrics_port_in_use(cfg, monkeypatch):
    import errno as e

    def busy(*a):
        raise OSError(e.EADDRINUSE, "Address already in use")
    monkeypatch.setattr(metrics, "_Server", busy)
    with pytest.raises(metrics.MetricsError, match="port 9483: Address already in use"):
        metrics.serve(cfg)

    def no_v6(*a):
        raise OSError(e.EAFNOSUPPORT, "no IPv6")
    monkeypatch.setattr(metrics, "_Server", no_v6)
    monkeypatch.setattr(metrics, "_Server4", busy)
    with pytest.raises(metrics.MetricsError, match="set metrics.port"):
        metrics.serve(cfg)


def test_supervisor_ignores_signals_while_stopping(fs, monkeypatch):
    os.makedirs(paths.RUN)
    handlers = []
    monkeypatch.setattr(os, "kill", lambda pid, s: None)
    supervisor.run([supervisor.Service("a", ["a"])], popen=lambda c, preexec_fn: FakeProc(7),
                   waitpid=lambda p, f: (7, 0), sig=lambda s, h: handlers.append((s, h)))
    assert handlers[-2:] == [(signal.SIGTERM, signal.SIG_IGN), (signal.SIGINT, signal.SIG_IGN)]

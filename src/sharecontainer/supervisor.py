"""PID 1: starts the services, reaps processes and stops the container when a service dies."""

import json
import os
import signal
import subprocess
from dataclasses import dataclass, field

from . import paths, sysops


@dataclass
class Service:
    name: str
    cmd: list
    ports: list = field(default_factory=list)
    umask: object = None


class Stop(Exception):
    pass


def _stop(signum, frame):
    raise Stop()


def start(service, popen=subprocess.Popen):
    umask = service.umask
    pre = (lambda: os.umask(umask)) if umask is not None else None
    sysops.log(f"starting {service.name}")
    return popen(service.cmd, preexec_fn=pre)


def run(services, dhcp_wait=None, wait_after=1, popen=subprocess.Popen, waitpid=os.waitpid, sig=signal.signal):
    """Returns the exit code of the container; dhcp_wait runs once the first wait_after services (the DHCP
    clients) started."""
    sig(signal.SIGTERM, _stop)
    sig(signal.SIGINT, _stop)
    procs = {}
    code = 0
    try:
        for i, s in enumerate(services):
            procs[start(s, popen).pid] = s
            if i == wait_after - 1 and dhcp_wait:
                dhcp_wait()
        write_health(procs)
        while True:
            pid, status = waitpid(-1, 0)
            if pid in procs:
                sysops.log(f"{procs[pid].name} stopped (status {status}); stopping the container")
                del procs[pid]
                code = 1
                break
    except Stop:
        sysops.log("stopping")
    except ChildProcessError:
        code = 1
    except Exception as e:  # noqa: BLE001 - any start failure stops the container cleanly
        sysops.log(f"cannot start: {e}")
        code = 1
    for pid in procs:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    for pid in list(procs):
        try:
            waitpid(pid, 0)
        except ChildProcessError:
            pass
    return code


def write_health(procs):
    data = [{"name": s.name, "pid": pid, "ports": s.ports} for pid, s in procs.items()]
    sysops.write_file(paths.HEALTH, json.dumps(data) + "\n", 0o600)


def listening(port, tables=("/proc/net/tcp", "/proc/net/tcp6")):
    for t in tables:
        for line in (sysops.read_file(t, "") or "").splitlines()[1:]:
            f = line.split()
            if len(f) > 3 and f[3] == "0A" and int(f[1].rsplit(":", 1)[1], 16) == port:
                return True
    return False


def health(alive=lambda pid: os.path.exists(f"/proc/{pid}")):
    """0 when every service runs and listens on its ports."""
    try:
        data = json.loads(sysops.read_file(paths.HEALTH, ""))
    except ValueError:
        print("not started")
        return 1
    bad = []
    for s in data:
        if not alive(s["pid"]):
            bad.append(f"{s['name']} not running")
        bad += [f"{s['name']} not listening on {p}" for p in s["ports"] if not listening(p)]
    for b in bad:
        print(b)
    return 1 if bad else 0

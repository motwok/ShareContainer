"""Command line: run, check, passwd, keys, health, metrics, ssh-command, davauth."""

import os
import sys

from . import config, credentials, davauth, metrics, network, paths, sshcmd, start, supervisor

USAGE = """usage: sharecontainer COMMAND
  run                      start the container (default)
  check [FILE]             validate the configuration
  passwd [--stdin] USER    set a user's password for SMB, SSH and WebDAV
  keys add USER [FILE|-]   add SSH public keys (file or stdin)
  keys list USER           list a user's SSH public keys
  keys remove USER NUMBER  remove a key (number from keys list)
  health                   health check of the running container"""


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd, args = (argv[0], argv[1:]) if argv else ("run", [])
    try:
        if cmd == "run":
            return start.main()
        if cmd == "check":
            cfg = config.load(args[0] if args else paths.CONFIG_FILE)
            print(f"configuration valid: {cfg.name}")
            return 0
        if cmd == "passwd":
            credentials.passwd(args)
            return 0
        if cmd == "keys":
            credentials.keys(args)
            return 0
        if cmd == "health":
            return supervisor.health()
        if cmd == "metrics":
            metrics.serve(config.load(paths.CONFIG_FILE))
            return 0
        if cmd == "ssh-command":
            return sshcmd.main()
        if cmd == "davauth":
            return davauth.main()
        if cmd == "dhcp-event":
            return network.dhcp_event(args[0] if args else "", os.environ)
        if cmd == "watch-addresses":
            return network.watch(args)
    except config.ConfigError as e:
        for err in e.errors:
            print(err, file=sys.stderr)
        return 2
    except credentials.UsageError as e:
        print(e, file=sys.stderr)
        return 2
    except metrics.MetricsError as e:
        print(e, file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

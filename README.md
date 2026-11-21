# ShareContainer

[![License](https://img.shields.io/github/license/motwok/ShareContainer)](LICENSE)
[![Build](https://github.com/motwok/ShareContainer/actions/workflows/build.yml/badge.svg)](https://github.com/motwok/ShareContainer/actions/workflows/build.yml)

A file server in a Docker container, convenient to configure: SMB with Multichannel so that a single
client can use more than one link, plus WebDAV and, over SSH, SFTP, scp, rsync and Borg.

## What sets it apart: SMB Multichannel

A single TCP connection uses a single link. SMB Multichannel lets one client use several connections at
once, so its throughput adds up over several links. ShareContainer configures it for you:

- **Several network cards, no teaming:** list several interfaces; a client with several network cards
  connects over each of them and uses all links together.
- **NIC team or bond:** ShareContainer announces the interface as RSS capable. Windows then opens several
  SMB connections to the same server address, and the team (LACP) on the client and the bond on the
  server spread them over their links.
- One switch in the configuration, off by default.
- Interface names and speeds come from the configuration, nothing is guessed.

How to get the full bandwidth (flow control, connection count) and a measurement:
[docs/multichannel.md](docs/multichannel.md).

## Features

- **One YAML file** configures everything: server, interfaces, protocols, users, groups and shares
  ([reference](docs/configuration.md)). It is validated at start; an invalid file stops the container
  with a clear list of errors.
- **Protocols:** SMB, WebDAV (HTTP or HTTPS) and over SSH: SFTP, scp, rsync, Borg 1 and Borg 2. Each one
  is switched on in the configuration; per user and per share you choose which ones may be used.
- **Same rights everywhere:** the read and write lists of a share are set as POSIX ACLs, files belong to
  the user who wrote them, over every protocol.
- **No passwords in the configuration:** one command sets a user's password for all protocols; SSH public
  keys are added, listed and removed with another one.
- **Everything in volumes:** configuration, passwords, SSH keys and SSH host keys. Rebuild the container,
  mount the volumes, and everything is back.
- **Home directories, guest access, recycle bin, macOS support, Windows ACLs, NetBIOS, WS-Discovery and
  mDNS**, each a switch.
- **Host network or macvlan**, with an address from Docker or from your DHCP server (which registers the
  name in your DNS).
- **Prometheus metrics** on port 9482: sessions, channels, connections, open files and locks per share,
  bytes and requests.

## Quick start

1. Write `config/share.yaml`; start with [examples/share.yaml](examples/share.yaml) and the
   [reference](docs/configuration.md).
2. Start the container, for example with [examples/compose-host.yaml](examples/compose-host.yaml):

   ```sh
   docker compose -f compose-host.yaml up -d
   ```

3. Set the passwords:

   ```sh
   docker exec -it fileserver passwd alice
   ```

4. For SSH keys:

   ```sh
   docker exec -i fileserver keys add alice - < alice.pub
   docker exec fileserver keys list alice
   docker exec fileserver keys remove alice 1
   ```

## Network

- **Host network** (`network_mode: host`, [example](examples/compose-host.yaml)): the container uses the
  host's interfaces; needed for Multichannel over a bond. Samba, an sshd on the configured port, Avahi
  or wsdd must not run on the host for the protocols you switch on, and the ports below must be free
  (otherwise set another `ssh.port`, `webdav.port` or `metrics.port`).
- **macvlan with an address from Docker** ([example](examples/compose-macvlan.yaml)): the container has
  its own address on the LAN. The Docker host itself cannot reach it over the macvlan parent.
- **macvlan with DHCP** ([example](examples/compose-macvlan-dhcp.yaml)): set `dhcp: true` on the
  interface and add `NET_ADMIN`. The container sends its name to the DHCP server and does not start
  without a lease.
- IPv6 is served where the network provides it. For macvlan create the network with IPv6 (`--ipv6`,
  your prefix as `--subnet` and a small `--ip-range` for Docker's own address). In DHCP mode the
  container also takes the addresses the router announces (SLAAC), waits for them at start and drops
  Docker's IPv6 default route when the router sends one. DHCPv6 is not used.
- Samba listens on the addresses it finds at start. When the addresses of the configured interfaces
  change (new DHCP address, new IPv6 prefix), the container stops so that Docker restarts it on the new
  ones: use a restart policy such as `restart: unless-stopped`.

| Port | Protocol | When |
|---|---|---|
| 445/tcp | SMB | `smb.enabled` |
| 137-138/udp | NetBIOS | `smb.netbios` |
| 3702/udp, 5357/tcp | WS-Discovery | `smb.wsd` |
| 5353/udp | mDNS | `smb.mdns` |
| 2022/tcp | SSH (SFTP, scp, rsync, Borg) | `ssh.enabled` |
| 8080/tcp or 8443/tcp | WebDAV | `webdav.enabled` |
| 9482/tcp | metrics | `metrics.enabled` (on by default) |

## Volumes

| Path | Content |
|---|---|
| `/config` | `share.yaml` and, for HTTPS, `tls/cert.pem` and `tls/key.pem`. Made readable by root only. |
| `/var/lib/samba` | Samba's password database, SSH and WebDAV password hashes, SSH keys and host keys. **Back it up.** |
| `/shares/<name>` | Share data (or the `path` of a share). |
| `/user` | Home directories. |

## Using the protocols

| Protocol | Address |
|---|---|
| SMB | `\\server\<share>`, home `\\server\<user>` |
| WebDAV | `http://server:8080/<share>/`, home `/home/` |
| SFTP | `sftp -P 2022 alice@server`; the shares and `home` are folders |
| scp | `scp -P 2022 file alice@server:<share>/` (current scp; the legacy protocol `scp -O` is not served) |
| rsync | `rsync -a -e 'ssh -p 2022' dir/ alice@server:<share>/dir/` |
| Borg 1 | `borg init ssh://alice@server:2022/./<share>/repo` |
| Borg 2 | `BORG_REMOTE_PATH=borg2 borg2 -r ssh://alice@server:2022/./<share>/repo repo-create` |

SSH offers no shell. Borg repositories can be created on shares the user may write to and in the home.
WebDAV over the internet belongs behind a TLS reverse proxy or uses `webdav.https`.

**Files used over SMB and another protocol at the same time:** clients' cached writes are flushed before
another protocol opens a file, but SMB's share modes ("deny write", for example of an open Office
document) and byte-range locks are not visible to SSH or WebDAV. Do not edit the same file over SMB and
another protocol at once.

## Status

Early development; there is no release yet.

## Support Me

If ShareContainer helps you, you can support it: [Buy Me a Coffee](https://ko-fi.com/motwok)

## License

[GNU AGPL v3](LICENSE). See [NOTICE](NOTICE) for third-party components.

ShareContainer is an independent project and is not affiliated with or endorsed by Microsoft or the
Samba Team. SMB refers to the Server Message Block protocol. Samba is a trademark of Software Freedom
Conservancy.

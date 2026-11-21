# Configuration reference

ShareContainer reads one file, `/config/share.yaml`, at every start. Nothing else is configured inside
the container: no environment variables (only `TZ` for the time zone, read by the C library). Docker
settings (network, volumes, capabilities) stay in your compose file.

An invalid file stops the start with exit code 2 and a list of every problem in the log. Check a file
before you deploy it:

```sh
docker run --rm -v ./share.yaml:/config/share.yaml:ro ghcr.io/motwok/sharecontainer check
```

Unknown keys are errors, so typing mistakes do not go unnoticed. A key with the value `null` is the same
as a missing key. Every switch is `false` unless stated otherwise.

## Complete example

```yaml
server:
  name: FILESERVER
  workgroup: WORKGROUP
  log_level: 1
network:
  interfaces:
    - name: bond0
      speed: 4000000000
smb:
  enabled: true
  multichannel: true
  macos: true
  recycle: false
  guest: false
  windows_acls: false
  netbios: false
  wsd: true
  mdns: true
  min_protocol: SMB3
  encryption: default
  signing: default
  extra:
    server string: Files
ssh:
  enabled: true
  port: 2022
  password_login_disabled: true
  password_login: false
webdav:
  enabled: true
  https: false
  port: 8080
metrics:
  enabled: true
  port: 9483
homes:
  enabled: true
groups:
  - name: family
    gid: 2000
users:
  - name: alice
    uid: 2001
    groups:
      - family
  - name: bob
    uid: 2002
    groups:
      - family
    protocols:
      - smb
      - webdav
    home: false
  - name: anonymous
    uid: 2099
    protocols:
      - smb
shares:
  - name: photos
    read:
      - "@family"
    write:
      - alice
  - name: public
    guest: true
    read:
      - anonymous
      - "@family"
    write:
      - alice
  - name: backup
    path: /backup
    write:
      - alice
    protocols:
      - sftp
      - rsync
      - borg
```

## server

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Server name: NetBIOS name, mDNS and WS-Discovery name, DHCP host name. Up to 15 letters, digits and `-`. |
| `workgroup` | Samba's default | Workgroup of the server. |
| `log_level` | `1` | Samba log level 0 to 10; from 2 Apache logs at `info`. Logs go to `docker logs`. |

## network

`interfaces` lists the interfaces the server uses, at least one. They must exist in the container: in
host mode the host's interfaces (for example `bond0`, `bond0.10`, `br0`), with macvlan or bridge
networks the container's (`eth0`).

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Interface name. |
| `speed` | required | Link speed in bit/s, reported to SMB clients (for a 4 x 1 GbE bond: `4000000000`). |
| `dhcp` | `false` | Take the IPv4 address from the LAN's DHCP server (macvlan only, needs `NET_ADMIN`, see the README); IPv6 by SLAAC. |

Samba listens only on these interfaces.

## smb

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Serve SMB on port 445. |
| `multichannel` | `false` | SMB Multichannel: the interfaces are announced as RSS capable, so Windows opens several connections. |
| `min_protocol` | `SMB3` | Oldest dialect allowed: `SMB2_02`, `SMB2_10`, `SMB3`, `SMB3_00`, `SMB3_02`, `SMB3_11`. |
| `encryption` | `default` | `server smb encrypt`: `default`, `off`, `if_required`, `desired`, `required`. |
| `signing` | `default` | `server signing`: `default`, `auto`, `mandatory`, `disabled`. Samba sets signing for the whole server only. |
| `windows_acls` | `false` | Store Windows ACLs (`vfs_acl_xattr`); needs extended attributes on the share file systems. |
| `macos` | `false` | macOS support (`vfs_fruit`, Time Machine friendly metadata); needs extended attributes. |
| `recycle` | `false` | Recycle bin: deleted files go to `.recycle/<user>` in the share. |
| `guest` | `false` | Guest access, see [Guest](#guest). |
| `netbios` | `false` | NetBIOS name service (nmbd, 137-138/udp). |
| `wsd` | `false` | WS-Discovery (wsdd2), so Windows lists the server under Network (3702/udp). |
| `mdns` | `false` | mDNS/Bonjour (Avahi), so macOS and Linux find the server (5353/udp). |
| `extra` | none | Further `smb.conf` parameters for `[global]`, written unchanged. |

`macos`, `recycle`, `guest` and `encryption` can be set per share too. File locking: ShareContainer
always sets `kernel oplocks = yes`, so a client's cached writes are flushed before SSH or WebDAV access
opens the same file.

## ssh

One sshd for SFTP, scp, rsync and Borg. There is no shell and no forwarding.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Serve SSH. |
| `port` | `2022` | Port; in host mode 22 belongs to the host's sshd. |
| `password_login_disabled` | `true` | Turns password login off for everyone; only SSH keys work. |
| `password_login` | `false` | With the switch above off: whether users may log in with their password. Per user overridable. |

The guest `anonymous` logs in with its empty password regardless of these switches.

## webdav

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Serve WebDAV (Apache). The container needs `cap_add: DAC_READ_SEARCH, SYS_NICE`. |
| `https` | `false` | Serve HTTPS with `/config/tls/cert.pem` and `/config/tls/key.pem` (the start fails without them). Without it, put a TLS reverse proxy in front. |
| `port` | `8080`, with `https` `8443` | Port. |

## metrics

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Prometheus metrics on `/metrics`. |
| `port` | `9483` | Port. |

## homes

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Users get a home directory `/user/<name>`, created at start; per user overridable. |

Mount `/user` (or `/user/<name>` per user) where the data should live. A home directory belongs to its
user (mode 0700). Over SMB it is `\\server\<user>`, over SSH `home/`, over WebDAV `/home/`.

## groups

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Group name (lower case). |
| `gid` | required | Group id, 1 to 65532. |

Every user also gets a private group with its own name and gid = uid, so a gid must not equal a uid.
Names and ids of the image's system groups and users (for example `staff`, `users`, `www-data`) cannot be
used; the start fails with a message.

## users

| Key | Default | Meaning |
|---|---|---|
| `name` | required | User name (lower case). |
| `uid` | required | User id, 1 to 65532; files the user writes belong to it. |
| `groups` | none | Groups of the user. |
| `protocols` | all | Protocols the user may use: `smb`, `webdav`, `sftp` (SFTP and scp), `rsync`, `borg`. |
| `password_login` | from `ssh` | Allow SSH password login for this user. |
| `home` | from `homes` | Give this user a home directory. |

Passwords are not in this file. Set them in the running container:

```sh
docker exec -it fileserver passwd alice
```

## shares

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Share name: letters, digits, `_`, `.`, `-`. Not `home`, `homes` or a user name with a home directory. |
| `path` | `/shares/<name>` | Folder in the container; mount your data there. |
| `read` | none | Users and `@groups` that may read. |
| `write` | none | Users and `@groups` that may read and write. |
| `protocols` | all | Protocols that serve this share. |
| `macos`, `recycle`, `guest`, `encryption` | from `smb` | Per-share override. |
| `extra` | none | Further `smb.conf` parameters for this share. |

The lists are set as POSIX ACLs on the share folder, so every protocol sees the same rights; users on no
list have no access at all. The top folder belongs to root. At every start the folder's ACLs are set;
existing files and folders below are updated only when the lists changed. The file system must support
POSIX ACLs (ext4, XFS, Btrfs, ZFS with `acltype=posix`).

SFTP cannot be restricted per share (there is no chroot), so a share may only exclude `sftp` if none of
its users may use SFTP.

## Guest

The guest is the user `anonymous`: configure it like any other user (uid, protocols) and put it on the
lists of the shares it may use. Its password is always empty.

- SMB: shares with `guest: true` accept connections without a password as `anonymous`.
- SFTP, scp, rsync, Borg and WebDAV: log in as `anonymous` with an empty password.
- `anonymous` never gets a home directory.

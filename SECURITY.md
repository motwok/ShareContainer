# Security Policy

ShareContainer runs a file server (SMB, WebDAV, SFTP, scp, rsync and Borg over SSH) on the host network
and stores user accounts, password hashes and SSH keys. That makes it security-sensitive by nature, and
reports are taken seriously.

## Reporting a vulnerability

**Please report vulnerabilities privately; do not open a public issue, pull request, or discussion for a
security problem.**

Use **GitHub's private vulnerability reporting**:

1. Go to the repository's **Security** tab ->
   **[Report a vulnerability](https://github.com/motwok/ShareContainer/security/advisories/new)**.
2. Describe the issue with enough detail to reproduce and assess it.

This keeps the report private between you and the maintainer and integrates with GitHub Security
Advisories for a coordinated fix and disclosure.

### What to include

- A clear description of the vulnerability and its **impact**.
- **Steps to reproduce** (or a proof of concept).
- Affected **version** (image tag or digest), the **host platform** and the **Docker version**.
- Any suggested mitigation, if you have one.

## What to expect

This is a single-maintainer project, so responses are best-effort rather than bound to a fixed SLA. You
can expect an acknowledgement of your report, an assessment, and, for confirmed issues, a coordinated fix
and disclosure. Credit is given to reporters who want it.

Please give a reasonable amount of time for a fix before any public disclosure.

## Supported versions

Only the **latest release** (`:latest`) receives security fixes. Older releases are not patched; please
update to the newest one.

| Version | Supported |
|---|---|
| Latest release (`:latest`) | yes |
| Older releases | no |

## Vulnerabilities in the bundled servers

Vulnerabilities in Samba are reported to the Samba Team, see
<https://www.samba.org/samba/security/>; those in OpenSSH, Apache, rsync or Borg to their projects.
ShareContainer picks up fixed packages with the next image release.

## Scope

ShareContainer deliberately does things that can look alarming but are by design:

- it uses the **host network** (`network_mode: host`) and listens on ports of the host, or a
  **macvlan** network with its own address,
- in DHCP mode on macvlan it runs with **`NET_ADMIN`** added, to set the address it leased,
- with WebDAV switched on it runs with **`DAC_READ_SEARCH`** and **`SYS_NICE`** added, which Apache's
  `mpm-itk` needs to serve each request as the logged-in user,
- it runs Samba, sshd and Apache as **root** inside the container; they switch to the logged-in user
  for file access,
- it creates **Unix users and groups** inside the container from its configuration file,
- it keeps the **password hashes** (Samba, SSH, WebDAV), the users' **SSH public keys** and the **SSH
  host keys** in a volume. The Samba (NT) hash is as good as the password for logging on to SMB
  (pass-the-hash): protect the volume and its backups,
- WebDAV can be served over plain **HTTP**, for use behind a TLS reverse proxy,
- **guest access** can be switched on: the user `anonymous` with an empty password, over every
  protocol it is allowed to use,
- arbitrary `smb.conf` parameters can be passed through.

These documented behaviors are **not** vulnerabilities on their own. Genuine security issues include, for
example: access to a share or path that the configuration does not grant; disclosure of passwords or
password hashes beyond the volume that holds them; execution of untrusted or attacker-controlled code;
or files outside the configured volumes and bind mounts being changed.

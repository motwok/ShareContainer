FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0

ARG VERSION=dev

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-vfs-modules \
      openssh-server openssh-sftp-server rsync borgbackup borgbackup2 \
      apache2 libapache2-mpm-itk \
      avahi-daemon wsdd2 udhcpc iproute2 acl \
      python3 python3-yaml python3-bcrypt \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* /etc/avahi/services/* \
 && rm -f /etc/samba/smb.conf \
 && dpkg-query -W -f '${Package} ${Version}\n' > /usr/share/sharecontainer-packages.txt

COPY src/sharecontainer /usr/lib/sharecontainer/sharecontainer
COPY bin/ /usr/local/bin/
RUN chmod 755 /usr/local/bin/* \
 && python3 -m compileall -q /usr/lib/sharecontainer \
 && echo "$VERSION" > /usr/share/sharecontainer-version

LABEL org.opencontainers.image.title="ShareContainer" \
      org.opencontainers.image.description="File server: SMB with Multichannel, WebDAV, SFTP, scp, rsync and Borg" \
      org.opencontainers.image.source="https://github.com/motwok/ShareContainer" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="$VERSION"

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/local/bin/sharecontainer", "health"]
ENTRYPOINT ["/usr/local/bin/sharecontainer"]
CMD ["run"]

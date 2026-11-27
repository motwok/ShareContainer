FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      smbclient openssh-client rsync borgbackup borgbackup2 curl sshpass ca-certificates dnsmasq \
 && rm -rf /var/lib/apt/lists/*

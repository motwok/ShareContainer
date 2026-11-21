#!/bin/sh
# Smoke test over every protocol: IMAGE=sharecontainer:test sh tests/smoke/run.sh
set -u
IMAGE=${IMAGE:-sharecontainer:test}
HERE=$(cd "$(dirname "$0")" && pwd)
NET=sc-smoke
WORK=$(mktemp -d)
FAILED=0

cleanup() {
  docker rm -f sc sc-client sc-bad sc-dhcp sc-dnsmasq >/dev/null 2>&1
  docker network rm $NET sc-dhcpnet >/dev/null 2>&1
  docker volume rm sc-state >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT
cleanup

ok() { echo "ok   $1"; }
fail() { echo "FAIL $1"; FAILED=$((FAILED + 1)); }
check() { name=$1; shift; if "$@" >"$WORK/out" 2>&1; then ok "$name"; else fail "$name"; sed 's/^/     /' "$WORK/out" | tail -15; fi; }
deny() { name=$1; shift; if "$@" >"$WORK/out" 2>&1; then fail "$name (should be denied)"; tail -5 "$WORK/out"; else ok "$name"; fi; }
client() { docker exec -i sc-client sh -c "$1"; }
sc() { docker exec -i sc "$@"; }

docker build -q -t sc-smoke-client -f "$HERE/client.Dockerfile" "$HERE" >/dev/null || exit 1
docker network create $NET >/dev/null
mkdir -p "$WORK/config" "$WORK/shares" "$WORK/user"
cp "$HERE/share.yaml" "$WORK/config/share.yaml"

# Invalid configuration: no start, exit 2.
printf 'server:\n  name: BAD\nnetwork:\n  interfaces: []\n' > "$WORK/bad.yaml"
docker run --name sc-bad -v "$WORK/bad.yaml:/config/share.yaml:ro" "$IMAGE" >/dev/null 2>&1
check "invalid configuration does not start (exit 2)" test "$(docker inspect -f '{{.State.ExitCode}}' sc-bad)" = 2

docker run -d --name sc --network $NET --hostname smoke --cap-add DAC_READ_SEARCH --cap-add SYS_NICE \
  -v "$WORK/config:/config" -v sc-state:/var/lib/samba -v "$WORK/shares:/shares" -v "$WORK/user:/user" \
  "$IMAGE" >/dev/null
docker run -d --name sc-client --network $NET sc-smoke-client sleep infinity >/dev/null

healthy=no
for i in $(seq 1 60); do
  s=$(docker inspect -f '{{.State.Health.Status}}' sc 2>/dev/null)
  [ "$s" = healthy ] && { healthy=yes; break; }
  [ "$(docker inspect -f '{{.State.Running}}' sc)" = true ] || break
  sc /usr/local/bin/sharecontainer health >/dev/null 2>&1 && { healthy=yes; break; }
  sleep 2
done
check "container starts and is healthy" test $healthy = yes
[ $healthy = yes ] || { docker logs sc 2>&1 | tail -40; exit 1; }

printf 'alicepw\n' | sc passwd --stdin alice >/dev/null
printf 'bobpw\n' | sc passwd --stdin bob >/dev/null
printf 'carolpw\n' | sc passwd --stdin carol >/dev/null
deny "passwd refuses the guest" sh -c "printf 'x\n' | docker exec -i sc passwd --stdin anonymous"

client "ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519 && printf 'Host sc\n  Port 2022\n  StrictHostKeyChecking accept-new\n  BatchMode yes\n' > /root/.ssh/config"
client "cat /root/.ssh/id_ed25519.pub" | sc keys add alice - >/dev/null
check "keys list shows the key" sh -c "docker exec sc keys list alice | grep -q ED25519"
client "head -c 2000000 /dev/urandom > /tmp/f && echo hello > /tmp/h"

# SMB
check "smb: alice writes to data" client "smbclient //sc/data -U alice%alicepw -m SMB3 -c 'put /tmp/f f.bin'"
check "smb: bob reads from data" client "smbclient //sc/data -U bob%bobpw -m SMB3 -c 'get f.bin /tmp/g'"
deny "smb: bob cannot write to data" client "smbclient //sc/data -U bob%bobpw -m SMB3 -c 'put /tmp/h bob.txt'"
deny "smb: carol has no access to data" client "smbclient //sc/data -U carol%carolpw -m SMB3 -c ls"
check "smb: alice writes to public" client "smbclient //sc/public -U alice%alicepw -c 'put /tmp/h readme.txt'"
check "smb: guest reads public" client "smbclient -N //sc/public -c 'get readme.txt /tmp/r'"
deny "smb: guest cannot write public" client "smbclient -N //sc/public -c 'put /tmp/h x.txt'"
check "smb: alice home" client "smbclient //sc/alice -U alice%alicepw -c 'put /tmp/h home.txt'"
deny "smb: backup is not an SMB share" client "smbclient //sc/backup -U alice%alicepw -c ls"
check "smb: file belongs to alice" test "$(stat -c %u "$WORK/shares/data/f.bin")" = 3001
check "acl: share folder has the lists" sh -c "docker exec sc getfacl -p /shares/data | grep -q 'group:team:r-x'"

# SSH
check "sftp: alice with key sees her view" sh -c "docker exec sc-client sh -c \"echo ls -1 | sftp -b - alice@sc\" | tr '\n' ' ' | grep -q 'backup.*data.*home.*public'"
check "sftp: alice uploads to data" client "echo 'put /tmp/h data/sftp.txt' | sftp -b - alice@sc"
check "scp: alice uploads to home" client "scp -q /tmp/h alice@sc:home/scp.txt"
deny "scp -O (legacy) is refused" client "scp -O -q /tmp/h alice@sc:home/legacy.txt"
check "sftp: bob with password reads data" client "echo 'get data/sftp.txt /tmp/s' | sshpass -p bobpw sftp -o BatchMode=no -P 2022 -b - bob@sc"
deny "sftp: bob cannot write data" client "echo 'put /tmp/h data/bob2.txt' | sshpass -p bobpw sftp -o BatchMode=no -P 2022 -b - bob@sc"
deny "ssh: no shell" client "ssh alice@sc id"
deny "ssh: carol (SMB only) is refused" client "sshpass -p carolpw ssh -o BatchMode=no -p 2022 carol@sc true"
check "rsync: alice uploads to backup" client "mkdir -p /tmp/rs && cp /tmp/f /tmp/rs/ && rsync -a -e 'ssh -p 2022' /tmp/rs/ alice@sc:backup/rs/"
check "rsync: alice downloads from data" client "rsync -a -e 'ssh -p 2022' alice@sc:data/sftp.txt /tmp/rs2.txt"
deny "rsync: outside the view is refused" client "rsync -a -e 'ssh -p 2022' alice@sc:/etc/passwd /tmp/p"
check "borg 1: init, create, list" client "export BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=yes BORG_RELOCATED_REPO_ACCESS_IS_OK=yes; borg init -e none ssh://alice@sc:2022/./backup/b1 && borg create ssh://alice@sc:2022/./backup/b1::a1 /tmp/rs && borg list ssh://alice@sc:2022/./backup/b1 | grep -q a1"
check "borg 2: create, list" client "export BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=yes BORG_REMOTE_PATH=borg2; borg2 -r ssh://alice@sc:2022/./backup/b2 repo-create -e none && borg2 -r ssh://alice@sc:2022/./backup/b2 create a1 /tmp/rs && borg2 -r ssh://alice@sc:2022/./backup/b2 repo-list | grep -q a1"
deny "borg: repository outside the allowed folders" client "export BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=yes; borg init -e none ssh://alice@sc:2022/tmp/evil"
check "sftp: guest with empty password reads public" client "echo 'get public/readme.txt /tmp/g2' | sshpass -p '' sftp -o BatchMode=no -P 2022 -b - anonymous@sc"
check "ssh: host key kept in the volume" sh -c "docker exec sc ls /var/lib/samba/ssh/host/ssh_host_ed25519_key"

# WebDAV
dav() { client "curl -s -o /dev/null -w '%{http_code}' $1"; }
check "webdav: alice PUT data (201)" test "$(dav "-u alice:alicepw -T /tmp/h http://sc:8080/data/dav.txt")" = 201
check "webdav: file belongs to alice" test "$(stat -c %u "$WORK/shares/data/dav.txt")" = 3001
check "webdav: bob GET data (200)" test "$(dav "-u bob:bobpw http://sc:8080/data/dav.txt")" = 200
check "webdav: bob PUT data denied (403)" test "$(dav "-u bob:bobpw -T /tmp/h http://sc:8080/data/bob.txt")" = 403
check "webdav: wrong password (401)" test "$(dav "-u alice:wrong http://sc:8080/data/dav.txt")" = 401
check "webdav: no credentials (401)" test "$(dav "http://sc:8080/data/")" = 401
check "webdav: carol not allowed (401)" test "$(dav "-u carol:carolpw http://sc:8080/public/readme.txt")" = 401
check "webdav: guest GET public (200)" test "$(dav "-u anonymous: http://sc:8080/public/readme.txt")" = 200
check "webdav: alice home (201)" test "$(dav "-u alice:alicepw -T /tmp/h http://sc:8080/home/dav-home.txt")" = 201
check "webdav: home file in alice's home" test -f "$WORK/user/alice/dav-home.txt"
check "webdav: backup not served (401/404)" sh -c "c=\$(docker exec sc-client curl -s -o /dev/null -w '%{http_code}' -u alice:alicepw http://sc:8080/backup/); [ \$c = 404 ] || [ \$c = 403 ]"
check "webdav: PROPFIND" test "$(dav "-u alice:alicepw -X PROPFIND -H 'Depth: 1' http://sc:8080/data/")" = 207

# Metrics and restart
check "metrics answer" sh -c "docker exec sc-client curl -s http://sc:9482/metrics | grep -q '^sharecontainer_up 1'"
check "metrics count sessions" sh -c "docker exec sc-client curl -s http://sc:9482/metrics | grep -q '^sharecontainer_smb_sessions'"
docker restart sc >/dev/null
sleep 8
check "after restart: passwords still valid" client "smbclient //sc/data -U alice%alicepw -c ls"
check "after restart: same host key" client "echo ls | sftp -b - alice@sc"
docker rm -f sc >/dev/null
docker run -d --name sc --network $NET --hostname smoke --cap-add DAC_READ_SEARCH --cap-add SYS_NICE \
  -v "$WORK/config:/config" -v sc-state:/var/lib/samba -v "$WORK/shares:/shares" -v "$WORK/user:/user" \
  "$IMAGE" >/dev/null
sleep 10
check "after rebuild: SMB password still valid" client "smbclient //sc/data -U alice%alicepw -c ls"
check "after rebuild: SSH key and host key still valid" client "echo ls | sftp -b - alice@sc"
check "after rebuild: WebDAV password still valid" test "$(dav "-u alice:alicepw http://sc:8080/data/dav.txt")" = 200

# DHCP mode: the container takes its address from a DHCP server and drops Docker's address.
docker network create --subnet 172.31.250.0/24 --ip-range 172.31.250.0/26 sc-dhcpnet >/dev/null
docker run -d --name sc-dnsmasq --network sc-dhcpnet --cap-add NET_ADMIN sc-smoke-client sh -c \
  "apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y dnsmasq >/dev/null 2>&1 && dnsmasq -d --port=0 --dhcp-range=172.31.250.200,172.31.250.220,1h --log-dhcp" >/dev/null
printf 'server:\n  name: SCDHCP\nnetwork:\n  interfaces:\n    - name: eth0\n      speed: 1000000000\n      dhcp: true\nsmb:\n  enabled: true\nmetrics:\n  enabled: false\n' > "$WORK/dhcp.yaml"
for i in $(seq 1 60); do docker logs sc-dnsmasq 2>&1 | grep -q "DHCP, IP range" && break; sleep 2; done
docker run -d --name sc-dhcp --network sc-dhcpnet --cap-add NET_ADMIN -v "$WORK/dhcp.yaml:/config/share.yaml:ro" "$IMAGE" >/dev/null
for i in $(seq 1 40); do docker logs sc-dhcp 2>&1 | grep -q "DHCP address" && break; sleep 2; done
check "dhcp: lease from the DHCP server" sh -c "docker logs sc-dhcp 2>&1 | grep -q 'DHCP address 172.31.250.2'"
check "dhcp: host name sent" sh -c "docker logs sc-dnsmasq 2>&1 | grep -qi scdhcp"
check "dhcp: Docker's address dropped" sh -c "! docker exec sc-dhcp ip -4 addr show eth0 | grep -q '172.31.250.[0-9]/\|172.31.250.[1-5][0-9]/\|172.31.250.6[0-3]/'"

echo
if [ $FAILED -gt 0 ]; then
  echo "$FAILED check(s) failed"
  docker logs sc 2>&1 | tail -30
  exit 1
fi
echo "all checks passed"

#!/bin/sh
# The live test of the unifi plugin, pkg/plugins/unifi, against a self-hosted UniFi Network
# Application in a container, with its MongoDB: it starts them, sets the application up as its
# first-run wizard would, with an admin, runs the test, and removes them. It needs Docker, Go, curl
# and OpenSSL, and takes a few minutes, most of them the application's start. CI runs it.
#
# The application is of the version written here, so that a run tells of the code.
set -eu
cd "$(dirname "$0")/.."

UNIFI_IMAGE=${UNIFI_IMAGE:-lscr.io/linuxserver/unifi-network-application:10.6.109-ls155}
MONGO_IMAGE=${MONGO_IMAGE:-mongo@sha256:41e8195b2791692695e1dc9bd21cd51d0a3af05fff8ace9304a5c1acf94f1ae1}

password=live-$$
prefix=ipv6disc-live-$$
work=$(mktemp -d)
cleanup() {
	docker rm -f "$prefix-unifi" "$prefix-mongo" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# A user of each of the application's databases, made at MongoDB's first start.
cat >"$work/mongo.js" <<EOF
for (const name of ["unifi", "unifi_stat", "unifi_audit"]) {
	db.getSiblingDB(name).createUser({user: "unifi", pwd: "$password", roles: [{role: "dbOwner", db: name}]});
}
EOF
# The application in MongoDB's network, which has the port.
docker run -d --name "$prefix-mongo" -p 127.0.0.1::8443/tcp \
	-v "$work/mongo.js:/docker-entrypoint-initdb.d/unifi.js:ro" "$MONGO_IMAGE" >/dev/null
docker run -d --name "$prefix-unifi" --network "container:$prefix-mongo" \
	-e MONGO_USER=unifi -e MONGO_PASS="$password" -e MONGO_HOST=127.0.0.1 -e MONGO_PORT=27017 \
	-e MONGO_DBNAME=unifi -e MONGO_AUTHSOURCE=unifi "$UNIFI_IMAGE" >/dev/null
unifi=https://127.0.0.1:$(docker port "$prefix-mongo" 8443/tcp | sed -n '1s/.*://p')

deadline=$(($(date +%s) + 600))
until curl -fsk "$unifi/status" | grep -q '"up":true'; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		echo "live-unifi: the UniFi Network Application did not come up" >&2
		docker logs --tail 40 "$prefix-unifi" >&2
		exit 1
	fi
	sleep 5
done
curl -fsk -o /dev/null -H 'Content-Type: application/json' "$unifi/api/cmd/sitemgr" \
	-d "{\"cmd\":\"add-default-admin\",\"name\":\"admin\",\"email\":\"admin@example.test\",\"x_password\":\"$password\"}"
curl -fsk -o /dev/null -H 'Content-Type: application/json' "$unifi/api/cmd/system" -d '{"cmd":"set-installed"}'
fingerprint=$(openssl s_client -connect "${unifi#https://}" </dev/null 2>/dev/null | openssl x509 -outform der | openssl dgst -sha256 -r | cut -d' ' -f1)

echo "live-unifi: UniFi Network Application ($UNIFI_IMAGE)" >&2
IPV6DISC_LIVE_UNIFI="interval=60s,address=$unifi,username=admin,password=$password,tls_fingerprint=$fingerprint" \
	go test -count=1 -v -run '^TestLiveUniFi$' "$@" ./pkg/plugins/unifi

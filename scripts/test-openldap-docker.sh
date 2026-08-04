#!/bin/sh

set -eu

die() {
	printf 'test-openldap-docker: %s\n' "$*" >&2
	exit 1
}

if [ "$#" -ne 0 ]; then
	die "this script accepts configuration through LDAP_GO_OPENLDAP_DOCKER_IMAGE, LDAP_GO_OPENLDAP_DOCKER_CACHE_VOLUME, and GOPROXY"
fi

if ! command -v docker >/dev/null 2>&1; then
	die "docker is required"
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
dockerfile=$script_dir/Dockerfile.openldap-test

if [ ! -f "$dockerfile" ]; then
	die "Dockerfile was not found: $dockerfile"
fi

image=${LDAP_GO_OPENLDAP_DOCKER_IMAGE:-ldap-go-openldap-test:1.25-bookworm}
cache_volume=${LDAP_GO_OPENLDAP_DOCKER_CACHE_VOLUME:-ldap-go-openldap-2.6.13-cache}
goproxy=${GOPROXY:-https://goproxy.cn,direct}

if [ -z "$image" ]; then
	die "LDAP_GO_OPENLDAP_DOCKER_IMAGE must not be empty"
fi
case "$cache_volume" in
	''|*[!A-Za-z0-9_.-]*)
		die "LDAP_GO_OPENLDAP_DOCKER_CACHE_VOLUME must be a Docker named volume"
		;;
esac
case "$cache_volume" in
	[A-Za-z0-9]*) ;;
	*) die "LDAP_GO_OPENLDAP_DOCKER_CACHE_VOLUME must start with an alphanumeric character" ;;
esac

docker build \
	--file "$dockerfile" \
	--tag "$image" \
	"$script_dir"

exec docker run \
	--rm \
	--init \
	--ulimit nofile=4096:4096 \
	--volume "$root:/workspace:ro" \
	--volume "$cache_volume:/var/cache/ldap-go-openldap" \
	--env PATH=/usr/local/go/bin:/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
	--env "GOPROXY=$goproxy" \
	--env LDAP_GO_FAIL_ON_OPTIONAL_SKIP=1 \
	--env OPENLDAP_SOURCE_CACHE=/var/cache/ldap-go-openldap/source \
	--env BUILD=/var/cache/ldap-go-openldap/build \
	"$image" \
	./scripts/test-openldap-full.sh

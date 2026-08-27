#!/bin/sh

set -eu

die() {
	printf 'test-platform-builds: %s\n' "$*" >&2
	exit 1
}

if [ "$#" -ne 0 ]; then
	die "this script accepts no arguments"
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cache_root=$(mktemp -d "${TMPDIR:-/tmp}/ldap-go-platform-builds.XXXXXX")
trap 'rm -rf -- "$cache_root"' EXIT HUP INT TERM

targets='linux amd64
linux arm64
darwin amd64
darwin arm64
windows amd64
freebsd amd64'

printf '%s\n' "$targets" | while read -r goos goarch; do
	[ -n "$goos" ] || continue
	printf 'Building %s/%s with CGO_ENABLED=0...\n' "$goos" "$goarch"
	(
		cd "$root"
		CGO_ENABLED=0 \
		GOOS=$goos \
		GOARCH=$goarch \
		GOCACHE="$cache_root/$goos-$goarch" \
		go build ./...
	)
done

printf 'Platform build matrix passed: 6 targets.\n'

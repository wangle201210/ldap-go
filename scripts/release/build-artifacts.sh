#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/common.sh"

root=$(release_root)
targets='linux amd64
linux arm64
darwin amd64
darwin arm64
windows amd64
freebsd amd64'

usage() {
	printf '%s\n' 'usage: build-artifacts.sh [--list-targets]'
}

case ${1:-} in
'') ;;
--list-targets)
	printf '%s\n' "$targets"
	exit 0
	;;
-h|--help)
	usage
	exit 0
	;;
*)
	usage >&2
	exit 2
	;;
esac

version=${RELEASE_VERSION:-$(git -C "$root" describe --tags --always --dirty)}
case $version in
''|*[!A-Za-z0-9._-]*)
	release_die "RELEASE_VERSION must contain only letters, digits, dot, underscore, and hyphen"
	;;
esac
artifact_dir=$(release_make_artifact_dir ldap-go-release-build)
work_dir=$artifact_dir/.work
mkdir -p "$work_dir"
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM

printf 'Building release %s into %s\n' "$version" "$artifact_dir"
printf '%s\n' "$targets" | while read -r goos goarch; do
	[ -n "$goos" ] || continue
	name=ldap-go_${version}_${goos}_${goarch}
	stage=$work_dir/$name
	mkdir -p "$stage"
	binary=$stage/ldap-go
	if [ "$goos" = windows ]; then
		binary=$binary.exe
	fi
	printf 'Building %s/%s...\n' "$goos" "$goarch"
	(
		cd "$root"
		CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build \
			-trimpath -ldflags "-s -w -X main.version=$version" \
			-o "$binary" ./cmd/ldap-go
		)
		cp "$root/README.md" "$stage/README.md"
		cp "$root/README.zh-CN.md" "$stage/README.zh-CN.md"
		cp -R "$root/docs" "$stage/docs"
		cp -R "$root/examples" "$stage/examples"
		cp "$root/LICENSE" "$stage/LICENSE"
	if [ "$goos" = windows ]; then
		(
			cd "$work_dir"
			zip -q -r "$artifact_dir/$name.zip" "$name"
		)
	else
		tar -C "$work_dir" -czf "$artifact_dir/$name.tar.gz" "$name"
	fi
done

(
	cd "$artifact_dir"
	set -- ./*.tar.gz ./*.zip
	for artifact do
		[ -f "$artifact" ] || continue
		release_sha256 "${artifact#./}"
	done >SHA256SUMS
	[ -s SHA256SUMS ] || release_die "no release archives were built"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -c SHA256SUMS
	else
		shasum -a 256 -c SHA256SUMS
	fi
)

printf 'Release artifacts and SHA256SUMS are ready: %s\n' "$artifact_dir"

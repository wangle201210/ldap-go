#!/bin/sh

set -eu

release_die() {
	printf 'release: %s\n' "$*" >&2
	exit 1
}

release_root() {
	CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd
}

release_sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$@"
	else
		release_die "sha256sum or shasum is required"
	fi
}

release_previous_ref() {
	root=$1
	if [ -n "${RELEASE_PREVIOUS_REF:-}" ]; then
		git -C "$root" rev-parse --verify "${RELEASE_PREVIOUS_REF}^{commit}" >/dev/null 2>&1 ||
			release_die "RELEASE_PREVIOUS_REF does not resolve to a commit: $RELEASE_PREVIOUS_REF"
		printf '%s\n' "$RELEASE_PREVIOUS_REF"
		return
	fi

	current=$(git -C "$root" rev-parse HEAD)
	for tag in $(git -C "$root" tag --merged HEAD --sort=-version:refname 'v[0-9]*'); do
		tag_commit=$(git -C "$root" rev-list -n 1 "$tag")
		if [ "$tag_commit" != "$current" ]; then
			printf '%s\n' "$tag"
			return
		fi
	done

	if [ "${RELEASE_REQUIRE_PREVIOUS_TAG:-0}" = 1 ]; then
		release_die "no previous release tag found; set RELEASE_PREVIOUS_REF explicitly"
	fi
	git -C "$root" rev-parse --verify HEAD^ >/dev/null 2>&1 ||
		release_die "no previous release tag or parent commit is available"
	printf '%s\n' 'HEAD^'
}

release_make_artifact_dir() {
	prefix=$1
	if [ -n "${RELEASE_ARTIFACT_DIR:-}" ]; then
		case $RELEASE_ARTIFACT_DIR in
		/*) artifact_dir=$RELEASE_ARTIFACT_DIR ;;
		*) artifact_dir=$PWD/$RELEASE_ARTIFACT_DIR ;;
		esac
		if [ -e "$artifact_dir" ]; then
			release_die "artifact directory already exists: $artifact_dir"
		fi
		mkdir -p "$artifact_dir"
	else
		artifact_dir=$(mktemp -d "${TMPDIR:-/tmp}/$prefix.XXXXXX")
	fi
	printf '%s\n' "$artifact_dir"
}

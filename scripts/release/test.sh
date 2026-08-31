#!/bin/sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

for script in "$root"/scripts/release/*.sh; do
	sh -n "$script"
	[ -x "$script" ] || {
		printf 'release-test: script is not executable: %s\n' "$script" >&2
		exit 1
	}
done

targets=$($root/scripts/release/build-artifacts.sh --list-targets)
target_count=$(printf '%s\n' "$targets" | awk 'NF == 2 { count++ } END { print count + 0 }')
[ "$target_count" -eq 6 ] || {
	printf 'release-test: expected 6 build targets, got %s\n' "$target_count" >&2
	exit 1
}
for target in 'linux amd64' 'linux arm64' 'darwin amd64' \
	'darwin arm64' 'windows amd64' 'freebsd amd64'; do
	printf '%s\n' "$targets" | grep -F -x "$target" >/dev/null || {
		printf 'release-test: missing build target %s\n' "$target" >&2
		exit 1
	}
done

previous_ref=$($root/scripts/release/upgrade-gate.sh --print-previous-ref)
git -C "$root" rev-parse --verify "$previous_ref^{commit}" >/dev/null

dry_run=$(RELEASE_DRY_RUN=1 "$root/scripts/release/upgrade-gate.sh")
case $dry_run in
*previous_ref=*previous_commit=*current_commit=*) ;;
*)
	printf 'release-test: unexpected upgrade dry-run output: %s\n' "$dry_run" >&2
	exit 1
	;;
esac

if RELEASE_PREVIOUS_REF=refs/heads/definitely-missing \
	"$root/scripts/release/upgrade-gate.sh" --print-previous-ref >/dev/null 2>&1; then
	printf 'release-test: invalid previous ref was accepted\n' >&2
	exit 1
fi

if RELEASE_VERSION='invalid/version' \
	"$root/scripts/release/build-artifacts.sh" >/dev/null 2>&1; then
	printf 'release-test: unsafe release version was accepted\n' >&2
	exit 1
fi

grep -F 'release-gate:' "$root/Makefile" >/dev/null
grep -F 'release-build:' "$root/Makefile" >/dev/null
grep -F 'release-upgrade-gate:' "$root/Makefile" >/dev/null
grep -F 'cp -R "$root/docs" "$stage/docs"' \
	"$root/scripts/release/build-artifacts.sh" >/dev/null
grep -F 'cp -R "$root/examples" "$stage/examples"' \
	"$root/scripts/release/build-artifacts.sh" >/dev/null

for document in \
	README.md \
	docs/operations.md \
	docs/migration-and-passwords.md \
	docs/implementation-status.md \
	docs/compatibility.md \
	examples/base.ldif; do
	[ -r "$root/$document" ] || {
		printf 'release-test: required document is missing: %s\n' "$document" >&2
		exit 1
	}
done

nightly=$root/.github/workflows/nightly-production.yml
[ -r "$nightly" ] || {
	printf 'release-test: nightly production workflow is missing\n' >&2
	exit 1
}
for contract in \
	'schedule:' \
	'workflow_dispatch:' \
	'./scripts/test-openldap-full.sh' \
	'./scripts/qualification/nightly.sh' \
	'./scripts/test-fuzz.sh' \
	'make platform-builds'; do
	grep -F -- "$contract" "$nightly" >/dev/null || {
		printf 'release-test: nightly workflow is missing %s\n' "$contract" >&2
		exit 1
	}
done

upgrade=$root/scripts/release/upgrade-gate.sh
for contract in \
	'fixture_profile=enhanced' \
	'olcDbIndex: releaseExactName eq,sub' \
	'releaseExactName=Alice+releaseFoldName=Engineering' \
	'dn: olcDatabase={2}mdb,cn=config' \
	'verify_live_semantics'; do
	grep -F -- "$contract" "$upgrade" >/dev/null || {
		printf 'release-test: enhanced upgrade fixture is missing %s\n' "$contract" >&2
		exit 1
	}
done

printf 'Release script checks passed: 6 targets; previous ref %s.\n' "$previous_ref"

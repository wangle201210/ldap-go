#!/bin/sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
runner=$root/scripts/qualification/run.sh

for script in "$root"/scripts/qualification/*.sh; do
	sh -n "$script"
done

output=$(QUALIFICATION_DRY_RUN=1 "$runner")
case "$output" in
*'mode=smoke'*'connections=4'*'restarts=1'*) ;;
*)
	printf 'qualification-test: unexpected smoke configuration: %s\n' "$output" >&2
	exit 1
	;;
esac

output=$(
	QUALIFICATION_DRY_RUN=1 \
	QUALIFICATION_MODE=soak \
	QUALIFICATION_CONNECTIONS=8 \
	QUALIFICATION_RESTARTS=2 \
	QUALIFICATION_DURATION_SECONDS=30 \
	QUALIFICATION_OPERATIONS=search,modify \
	"$runner"
)
case "$output" in
*'mode=soak'*'duration=30'*'connections=8'*'operations=search,modify'*) ;;
*)
	printf 'qualification-test: unexpected override configuration: %s\n' "$output" >&2
	exit 1
	;;
esac

if QUALIFICATION_DRY_RUN=1 QUALIFICATION_OPERATIONS=search,invalid \
	"$runner" >/dev/null 2>&1; then
	printf 'qualification-test: invalid operation was accepted\n' >&2
	exit 1
fi

if QUALIFICATION_DRY_RUN=1 QUALIFICATION_CONNECTIONS=0 \
	"$runner" >/dev/null 2>&1; then
	printf 'qualification-test: zero connections were accepted\n' >&2
	exit 1
fi

if QUALIFICATION_DRY_RUN=1 QUALIFICATION_OPERATIONS=search,,modify \
	"$runner" >/dev/null 2>&1; then
	printf 'qualification-test: empty operation token was accepted\n' >&2
	exit 1
fi

printf 'Production qualification script checks passed.\n'

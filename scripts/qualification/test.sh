#!/bin/sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
runner=$root/scripts/qualification/run.sh
nightly=$root/scripts/qualification/nightly.sh
scale=$root/scripts/qualification/scale.sh
compare_openldap=$root/scripts/qualification/compare-openldap.sh

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

output=$(QUALIFICATION_NIGHTLY_DRY_RUN=1 "$nightly")
case "$output" in
*'nightly_profile=bounded'*'soak_seconds=300'*'soak_connections=16'*'scale_entries=100000'*'mode=smoke'*'mode=soak'*'scale_profile=nightly'*'entries=100000'*) ;;
*)
	printf 'qualification-test: unexpected nightly configuration: %s\n' "$output" >&2
	exit 1
	;;
esac

if QUALIFICATION_NIGHTLY_DRY_RUN=1 QUALIFICATION_NIGHTLY_SOAK_SECONDS=1801 \
	"$nightly" >/dev/null 2>&1; then
	printf 'qualification-test: unbounded nightly duration was accepted\n' >&2
	exit 1
fi

if QUALIFICATION_NIGHTLY_DRY_RUN=1 QUALIFICATION_NIGHTLY_SCALE_ENTRIES=250001 \
	"$nightly" >/dev/null 2>&1; then
	printf 'qualification-test: unbounded nightly scale entry count was accepted\n' >&2
	exit 1
fi

if QUALIFICATION_NIGHTLY_DRY_RUN=1 QUALIFICATION_NIGHTLY_CONNECTIONS=65 \
	"$nightly" >/dev/null 2>&1; then
	printf 'qualification-test: unbounded nightly connection count was accepted\n' >&2
	exit 1
fi

output=$(QUALIFICATION_NIGHTLY_DRY_RUN=1 \
	QUALIFICATION_NIGHTLY_SOAK_SECONDS=060 \
	QUALIFICATION_NIGHTLY_CONNECTIONS=004 \
	QUALIFICATION_NIGHTLY_RESTARTS=001 "$nightly")
case "$output" in
*'soak_seconds=60'*'soak_connections=4'*'soak_restarts=1'*) ;;
*)
	printf 'qualification-test: leading-zero inputs were not normalized: %s\n' "$output" >&2
	exit 1
	;;
esac

output=$(QUALIFICATION_SCALE_DRY_RUN=1 "$scale")
case "$output" in
*'scale_profile=smoke'*'entries=1000'*'max_entries=250000'*'page_size=200'*'acceptance_ceilings='*) ;;
*)
	printf 'qualification-test: unexpected scale smoke configuration: %s\n' "$output" >&2
	exit 1
	;;
esac

output=$(QUALIFICATION_SCALE_DRY_RUN=1 \
	QUALIFICATION_SCALE_PROFILE=nightly \
	QUALIFICATION_SCALE_ENTRIES=0100000 \
	QUALIFICATION_SCALE_PAGE_SIZE=01000 \
	QUALIFICATION_SCALE_MAX_RSS_BYTES=02147483648 "$scale")
case "$output" in
*'scale_profile=nightly'*'entries=100000'*'page_size=1000'*'rss_bytes:2147483648'*) ;;
*)
	printf 'qualification-test: scale leading-zero inputs were not normalized: %s\n' "$output" >&2
	exit 1
	;;
esac

if QUALIFICATION_SCALE_DRY_RUN=1 QUALIFICATION_SCALE_ENTRIES=1 \
	"$scale" >/dev/null 2>&1; then
	printf 'qualification-test: one-entry scale fixture was accepted\n' >&2
	exit 1
fi

if QUALIFICATION_SCALE_DRY_RUN=1 QUALIFICATION_SCALE_ENTRIES=250001 \
	"$scale" >/dev/null 2>&1; then
	printf 'qualification-test: scale entry ceiling was not enforced\n' >&2
	exit 1
fi

if QUALIFICATION_SCALE_DRY_RUN=1 QUALIFICATION_SCALE_ENTRIES=100 \
	QUALIFICATION_SCALE_PAGE_SIZE=101 "$scale" >/dev/null 2>&1; then
	printf 'qualification-test: oversized page was accepted\n' >&2
	exit 1
fi

output=$(QUALIFICATION_COMPARE_DRY_RUN=1 "$compare_openldap")
case "$output" in
*'entries=1000'*'page_size=200'*'indexed_searches=1000'*'unindexed_searches=100'*'paged_traversals=10'*'modifications=200'*'concurrency=8'*'searches_per_connection=250'*'data_parity=1'*) ;;
*)
	printf 'qualification-test: unexpected OpenLDAP comparison configuration: %s\n' "$output" >&2
	exit 1
	;;
esac

output=$(QUALIFICATION_COMPARE_DRY_RUN=1 \
	QUALIFICATION_COMPARE_ENTRIES=01000 \
	QUALIFICATION_COMPARE_PAGE_SIZE=0100 \
	QUALIFICATION_COMPARE_INDEXED_SEARCHES=0200 "$compare_openldap")
case "$output" in
*'entries=1000'*'page_size=100'*'indexed_searches=200'*) ;;
*)
	printf 'qualification-test: OpenLDAP comparison leading-zero inputs were not normalized: %s\n' "$output" >&2
	exit 1
	;;
esac

if QUALIFICATION_COMPARE_DRY_RUN=1 QUALIFICATION_COMPARE_ENTRIES=100 \
	QUALIFICATION_COMPARE_MODIFICATIONS=101 "$compare_openldap" >/dev/null 2>&1; then
	printf 'qualification-test: oversized OpenLDAP comparison modification count was accepted\n' >&2
	exit 1
fi

if QUALIFICATION_COMPARE_DRY_RUN=1 QUALIFICATION_COMPARE_LDAP_GO_PORT=23000 \
	QUALIFICATION_COMPARE_OPENLDAP_PORT=23000 "$compare_openldap" >/dev/null 2>&1; then
	printf 'qualification-test: duplicate OpenLDAP comparison ports were accepted\n' >&2
	exit 1
fi

if QUALIFICATION_COMPARE_DRY_RUN=1 QUALIFICATION_COMPARE_DATA_PARITY=2 \
	"$compare_openldap" >/dev/null 2>&1; then
	printf 'qualification-test: invalid OpenLDAP data parity mode was accepted\n' >&2
	exit 1
fi

printf 'Production qualification script checks passed.\n'

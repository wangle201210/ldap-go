#!/bin/sh

set -eu

die() {
	printf 'nightly-qualification: %s\n' "$*" >&2
	exit 1
}

require_uint() {
	name=$1
	value=$2
	case "$value" in
	''|*[!0-9]*) die "$name must be a non-negative integer, got: $value" ;;
	esac
}

normalize_uint() {
	normalized=$(printf '%s\n' "$1" | sed 's/^0*//')
	printf '%s\n' "${normalized:-0}"
}

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
runner=$root/scripts/qualification/run.sh
scale_runner=$root/scripts/qualification/scale.sh

soak_seconds=${QUALIFICATION_NIGHTLY_SOAK_SECONDS:-300}
soak_connections=${QUALIFICATION_NIGHTLY_CONNECTIONS:-16}
soak_restarts=${QUALIFICATION_NIGHTLY_RESTARTS:-2}
scale_entries=${QUALIFICATION_NIGHTLY_SCALE_ENTRIES:-100000}
dry_run=${QUALIFICATION_NIGHTLY_DRY_RUN:-0}

require_uint QUALIFICATION_NIGHTLY_SOAK_SECONDS "$soak_seconds"
require_uint QUALIFICATION_NIGHTLY_CONNECTIONS "$soak_connections"
require_uint QUALIFICATION_NIGHTLY_RESTARTS "$soak_restarts"
require_uint QUALIFICATION_NIGHTLY_SCALE_ENTRIES "$scale_entries"
soak_seconds=$(normalize_uint "$soak_seconds")
soak_connections=$(normalize_uint "$soak_connections")
soak_restarts=$(normalize_uint "$soak_restarts")
scale_entries=$(normalize_uint "$scale_entries")
scale_page_size=10000
[ "$scale_entries" -ge "$scale_page_size" ] || scale_page_size=$scale_entries
[ "$soak_seconds" -ge 60 ] && [ "$soak_seconds" -le 1800 ] ||
	die "QUALIFICATION_NIGHTLY_SOAK_SECONDS must be between 60 and 1800"
[ "$soak_connections" -ge 1 ] && [ "$soak_connections" -le 64 ] ||
	die "QUALIFICATION_NIGHTLY_CONNECTIONS must be between 1 and 64"
[ "$soak_restarts" -le 6 ] ||
	die "QUALIFICATION_NIGHTLY_RESTARTS must be at most 6"
[ "$scale_entries" -ge 1000 ] && [ "$scale_entries" -le 250000 ] ||
	die "QUALIFICATION_NIGHTLY_SCALE_ENTRIES must be between 1000 and 250000"
case "$dry_run" in 0|1) ;; *) die "QUALIFICATION_NIGHTLY_DRY_RUN must be 0 or 1" ;; esac

restart_interval=0
if [ "$soak_restarts" -gt 0 ]; then
	restart_interval=$((soak_seconds / (soak_restarts + 1)))
	[ "$restart_interval" -gt 0 ] || die "computed restart interval must be positive"
fi

if [ "$dry_run" = 1 ]; then
	printf 'nightly_profile=bounded smoke_seconds=15 soak_seconds=%s soak_connections=%s soak_restarts=%s scale_entries=%s\n' \
		"$soak_seconds" "$soak_connections" "$soak_restarts" "$scale_entries"
	QUALIFICATION_DRY_RUN=1 "$runner"
	QUALIFICATION_DRY_RUN=1 \
	QUALIFICATION_MODE=soak \
	QUALIFICATION_DURATION_SECONDS=$soak_seconds \
		QUALIFICATION_CONNECTIONS=$soak_connections \
		QUALIFICATION_RESTARTS=$soak_restarts \
		QUALIFICATION_RESTART_INTERVAL_SECONDS=$restart_interval \
		"$runner"
	QUALIFICATION_SCALE_DRY_RUN=1 \
		QUALIFICATION_SCALE_PROFILE=nightly \
		QUALIFICATION_SCALE_ENTRIES=$scale_entries \
		QUALIFICATION_SCALE_PAGE_SIZE=$scale_page_size \
		"$scale_runner"
	exit 0
fi

artifact_root=${QUALIFICATION_NIGHTLY_ARTIFACT_DIR:-${TMPDIR:-/tmp}/ldap-go-nightly-qualification-$$}
case "$artifact_root" in /*) ;; *) artifact_root=$root/$artifact_root ;; esac
[ ! -e "$artifact_root" ] || die "artifact directory already exists: $artifact_root"
mkdir -p "$artifact_root"

printf 'Running bounded qualification smoke...\n'
QUALIFICATION_MODE=smoke \
QUALIFICATION_ARTIFACT_DIR=$artifact_root/smoke \
	"$runner"

printf 'Running bounded qualification soak for %ss with %s clients...\n' \
	"$soak_seconds" "$soak_connections"
QUALIFICATION_MODE=soak \
QUALIFICATION_DURATION_SECONDS=$soak_seconds \
QUALIFICATION_CONNECTIONS=$soak_connections \
QUALIFICATION_RESTARTS=$soak_restarts \
QUALIFICATION_RESTART_INTERVAL_SECONDS=$restart_interval \
QUALIFICATION_BATCH_SIZE=20 \
QUALIFICATION_MAX_FAILURE_PERCENT=10 \
QUALIFICATION_MIN_SUCCESSFUL_OPS_PER_SECOND=1 \
QUALIFICATION_ARTIFACT_DIR=$artifact_root/soak \
	"$runner"

printf 'Running bounded large-directory qualification for %s entries...\n' "$scale_entries"
QUALIFICATION_SCALE_PROFILE=nightly \
QUALIFICATION_SCALE_ENTRIES=$scale_entries \
QUALIFICATION_SCALE_PAGE_SIZE=$scale_page_size \
QUALIFICATION_SCALE_ARTIFACT_DIR=$artifact_root/scale \
	"$scale_runner"

printf 'Nightly qualification passed; artifacts: %s\n' "$artifact_root"

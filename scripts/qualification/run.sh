#!/bin/sh

set -eu

die() {
	printf 'production-qualification: %s\n' "$*" >&2
	exit 1
}

require_uint() {
	name=$1
	value=$2
	case "$value" in
	''|*[!0-9]*) die "$name must be a non-negative integer, got: $value" ;;
	esac
}

require_positive() {
	require_uint "$1" "$2"
	[ "$2" -gt 0 ] || die "$1 must be greater than zero"
}

has_operation() {
	case ",$operations_csv," in
	*,"$1",*) return 0 ;;
	*) return 1 ;;
	esac
}

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
worker_script=$root/scripts/qualification/worker.sh
mode=${QUALIFICATION_MODE:-smoke}

case "$mode" in
smoke)
	default_duration=15
	default_connections=4
	default_restarts=1
	default_batch_size=10
	default_max_failure_percent=20
	;;
soak)
	default_duration=3600
	default_connections=128
	default_restarts=12
	default_batch_size=100
	default_max_failure_percent=5
	;;
*) die "QUALIFICATION_MODE must be smoke or soak, got: $mode" ;;
esac

duration=${QUALIFICATION_DURATION_SECONDS:-$default_duration}
connections=${QUALIFICATION_CONNECTIONS:-$default_connections}
restarts=${QUALIFICATION_RESTARTS:-$default_restarts}
batch_size=${QUALIFICATION_BATCH_SIZE:-$default_batch_size}
operations_csv=${QUALIFICATION_OPERATIONS:-search,compare,modify,bind,add-delete}
startup_timeout=${QUALIFICATION_STARTUP_TIMEOUT_SECONDS:-15}
shutdown_timeout=${QUALIFICATION_SHUTDOWN_TIMEOUT_SECONDS:-15}
retry_delay=${QUALIFICATION_RETRY_DELAY_SECONDS:-1}
max_failure_percent=${QUALIFICATION_MAX_FAILURE_PERCENT:-$default_max_failure_percent}
minimum_throughput=${QUALIFICATION_MIN_SUCCESSFUL_OPS_PER_SECOND:-1}
client_timeout=${QUALIFICATION_CLIENT_TIMEOUT:-3s}
kill_signal=${QUALIFICATION_KILL_SIGNAL:-KILL}
listen_host=${QUALIFICATION_LISTEN_HOST:-127.0.0.1}
dry_run=${QUALIFICATION_DRY_RUN:-0}

require_positive QUALIFICATION_DURATION_SECONDS "$duration"
require_positive QUALIFICATION_CONNECTIONS "$connections"
require_uint QUALIFICATION_RESTARTS "$restarts"
require_positive QUALIFICATION_BATCH_SIZE "$batch_size"
require_positive QUALIFICATION_STARTUP_TIMEOUT_SECONDS "$startup_timeout"
require_positive QUALIFICATION_SHUTDOWN_TIMEOUT_SECONDS "$shutdown_timeout"
require_uint QUALIFICATION_RETRY_DELAY_SECONDS "$retry_delay"
require_uint QUALIFICATION_MAX_FAILURE_PERCENT "$max_failure_percent"
[ "$max_failure_percent" -le 100 ] || die "QUALIFICATION_MAX_FAILURE_PERCENT must be at most 100"
require_uint QUALIFICATION_MIN_SUCCESSFUL_OPS_PER_SECOND "$minimum_throughput"
case "$dry_run" in 0|1) ;; *) die "QUALIFICATION_DRY_RUN must be 0 or 1" ;; esac
case "$kill_signal" in KILL|TERM|INT|HUP) ;; *) die "QUALIFICATION_KILL_SIGNAL must be KILL, TERM, INT, or HUP" ;; esac
[ "$listen_host" = 127.0.0.1 ] || [ "$listen_host" = localhost ] ||
	die "QUALIFICATION_LISTEN_HOST must remain loopback-only"

[ -n "$operations_csv" ] || die "QUALIFICATION_OPERATIONS must not be empty"
case "$operations_csv" in
,*|*,|*,,*) die "QUALIFICATION_OPERATIONS contains an empty token" ;;
esac
old_ifs=$IFS
IFS=,
set -- $operations_csv
IFS=$old_ifs
[ "$#" -gt 0 ] || die "QUALIFICATION_OPERATIONS must not be empty"
for operation in "$@"; do
	case "$operation" in
	search|compare|modify|bind|add-delete) ;;
	*) die "unsupported QUALIFICATION_OPERATIONS token: $operation" ;;
	esac
done

if [ "$restarts" -gt 0 ]; then
	restart_interval=${QUALIFICATION_RESTART_INTERVAL_SECONDS:-$((duration / (restarts + 1)))}
	require_positive QUALIFICATION_RESTART_INTERVAL_SECONDS "$restart_interval"
	[ "$restart_interval" -lt "$duration" ] ||
		die "restart interval must be shorter than the qualification duration"
else
	restart_interval=0
fi
max_recovery_seconds=${QUALIFICATION_MAX_RECOVERY_SECONDS:-$startup_timeout}
require_positive QUALIFICATION_MAX_RECOVERY_SECONDS "$max_recovery_seconds"

if [ "$dry_run" = 1 ]; then
	printf 'mode=%s duration=%s connections=%s restarts=%s batch=%s operations=%s\n' \
		"$mode" "$duration" "$connections" "$restarts" "$batch_size" "$operations_csv"
	exit 0
fi

[ -x "$worker_script" ] || die "worker script is not executable: $worker_script"

timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
artifact_dir=${QUALIFICATION_ARTIFACT_DIR:-${TMPDIR:-/tmp}/ldap-go-qualification-$timestamp-$$}
case "$artifact_dir" in
/*) ;;
*) artifact_dir=$root/$artifact_dir ;;
esac
[ ! -e "$artifact_dir" ] || die "artifact directory already exists: $artifact_dir"
mkdir -p "$artifact_dir/workers"

binary=${QUALIFICATION_BINARY:-$artifact_dir/ldap-go}
if [ -n "${QUALIFICATION_BINARY:-}" ]; then
	case "$binary" in /*) ;; *) binary=$root/$binary ;; esac
	[ -x "$binary" ] || die "QUALIFICATION_BINARY is not executable: $binary"
else
	command -v go >/dev/null 2>&1 || die "go is required to build ldap-go"
	printf 'Building qualification binary...\n'
	(cd "$root" && go build -o "$binary" ./cmd/ldap-go)
fi

base_dn=dc=qualification,dc=test
qualification_ou="ou=qualification,$base_dn"
root_dn="cn=admin,$base_dn"
root_password=${QUALIFICATION_ROOT_PASSWORD:-qualification-local-secret}
[ -n "$root_password" ] || die "QUALIFICATION_ROOT_PASSWORD must not be empty"
case "$root_password" in
*'
'*) die "QUALIFICATION_ROOT_PASSWORD must not contain a newline" ;;
esac
password_file=$artifact_dir/root-password
database=$artifact_dir/directory.db
seed_ldif=$artifact_dir/seed.ldif
stop_file=$artifact_dir/stop
server_log=$artifact_dir/server.log
crash_events=$artifact_dir/crash-events.tsv
started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

{
	printf 'mode=%s\n' "$mode"
	printf 'duration_seconds=%s\n' "$duration"
	printf 'concurrent_client_streams=%s\n' "$connections"
	printf 'batch_size=%s\n' "$batch_size"
	printf 'operations=%s\n' "$operations_csv"
	printf 'restarts=%s\n' "$restarts"
	printf 'restart_interval_seconds=%s\n' "$restart_interval"
	printf 'kill_signal=%s\n' "$kill_signal"
	printf 'client_timeout=%s\n' "$client_timeout"
	printf 'maximum_failure_percent=%s\n' "$max_failure_percent"
	printf 'minimum_successful_operations_per_second=%s\n' "$minimum_throughput"
	printf 'maximum_recovery_seconds=%s\n' "$max_recovery_seconds"
	printf 'listen_host=%s\n' "$listen_host"
} >"$artifact_dir/effective-config.env"

# ldap-go and OpenLDAP treat every byte in a -y password file as credential
# material, including a trailing line ending.
(umask 077 && printf '%s' "$root_password" >"$password_file")
trap 'rm -f "$password_file"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
{
	printf 'dn: %s\n' "$base_dn"
	printf 'objectClass: top\nobjectClass: domain\ndc: qualification\n\n'
	printf 'dn: %s\n' "$qualification_ou"
	printf 'objectClass: top\nobjectClass: organizationalUnit\nou: qualification\n\n'
	worker=1
	while [ "$worker" -le "$connections" ]; do
		worker_id=$(printf '%04d' "$worker")
		printf 'dn: uid=qualification-%s,%s\n' "$worker_id" "$qualification_ou"
		printf 'objectClass: top\n'
		printf 'objectClass: person\n'
		printf 'objectClass: organizationalPerson\n'
		printf 'objectClass: inetOrgPerson\n'
		printf 'uid: qualification-%s\n' "$worker_id"
		printf 'cn: Qualification Worker %s\n' "$worker_id"
		printf 'sn: Worker\n\n'
		worker=$((worker + 1))
	done
} >"$seed_ldif"

"$binary" import -db "$database" -ldif "$seed_ldif" -replace \
	>"$artifact_dir/import.log"

server_pid=
worker_pids=
generation=0
cleanup_running=0

stop_server() {
	signal=$1
	[ -n "$server_pid" ] || return 0
	if kill -0 "$server_pid" 2>/dev/null; then
		kill -"$signal" "$server_pid" 2>/dev/null || true
		remaining=$shutdown_timeout
		while kill -0 "$server_pid" 2>/dev/null && [ "$remaining" -gt 0 ]; do
			sleep 1
			remaining=$((remaining - 1))
		done
		if kill -0 "$server_pid" 2>/dev/null; then
			kill -KILL "$server_pid" 2>/dev/null || true
		fi
	fi
	wait "$server_pid" 2>/dev/null || true
	server_pid=
}

cleanup() {
	status=$?
	[ "$cleanup_running" -eq 0 ] || exit "$status"
	cleanup_running=1
	: >"$stop_file"
	for pid in $worker_pids; do
		kill -TERM "$pid" 2>/dev/null || true
	done
	for pid in $worker_pids; do
		wait "$pid" 2>/dev/null || true
	done
	stop_server TERM
	rm -f "$password_file"
	if [ "$status" -ne 0 ]; then
		printf 'Qualification failed; artifacts retained at %s\n' "$artifact_dir" >&2
	fi
	exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

start_server() {
	listen=$1
	generation=$((generation + 1))
	stdout_file=$artifact_dir/server-$generation.stdout
	: >"$stdout_file"
	LDAP_GO_ROOT_PASSWORD=$root_password \
		"$binary" serve \
		-db "$database" \
		-listen "$listen" \
		-root-dn "$root_dn" \
		-max-connections "$((connections + 32))" \
		-max-concurrent-operations "$((connections + 16))" \
		-shutdown-timeout "${shutdown_timeout}s" \
		-log-level warn \
		>"$stdout_file" 2>>"$server_log" &
	server_pid=$!
	remaining=$startup_timeout
	server_uri=
	while [ "$remaining" -gt 0 ]; do
		server_uri=$(sed -n 's/^ldap-go listening on \(ldap:\/\/.*\)$/\1/p' "$stdout_file" | sed -n '1p')
		[ -z "$server_uri" ] || break
		if ! kill -0 "$server_pid" 2>/dev/null; then
			wait "$server_pid" 2>/dev/null || true
			server_pid=
			die "server generation $generation exited before readiness; see $server_log"
		fi
		sleep 1
		remaining=$((remaining - 1))
	done
	[ -n "$server_uri" ] || die "server generation $generation did not become ready"
	remaining=$startup_timeout
	while [ "$remaining" -gt 0 ]; do
		if "$binary" ldapwhoami \
			-H "$server_uri" -x -D "$root_dn" -y "$password_file" \
			-timeout "$client_timeout" \
			>"$artifact_dir/readiness-probe.out" 2>>"$server_log"; then
			return 0
		fi
		if ! kill -0 "$server_pid" 2>/dev/null; then
			wait "$server_pid" 2>/dev/null || true
			server_pid=
			die "server generation $generation exited during LDAP readiness probe"
		fi
		sleep 1
		remaining=$((remaining - 1))
	done
	die "server generation $generation did not pass an authenticated LDAP readiness probe"
}

start_server "$listen_host:0"
listen_address=${server_uri#ldap://}
printf 'Server ready at %s; artifacts: %s\n' "$server_uri" "$artifact_dir"

deadline=$(( $(date +%s) + duration ))
worker=1
while [ "$worker" -le "$connections" ]; do
	"$worker_script" \
		"$binary" "$server_uri" "$root_dn" "$password_file" "$base_dn" \
		"$worker" "$deadline" "$batch_size" "$client_timeout" \
		"$artifact_dir" "$operations_csv" "$stop_file" "$retry_delay" &
	pid=$!
	worker_pids="$worker_pids $pid"
	worker=$((worker + 1))
done

: >"$crash_events"
restart=1
next_restart=$(( $(date +%s) + restart_interval ))
while [ "$restart" -le "$restarts" ]; do
	now=$(date +%s)
	[ "$now" -lt "$deadline" ] || break
	if [ "$now" -lt "$next_restart" ]; then
		sleep 1
		continue
	fi
	printf 'Injecting %s into generation %s (%s/%s)...\n' \
		"$kill_signal" "$generation" "$restart" "$restarts"
	killed_at=$(date +%s)
	stop_server "$kill_signal"
	start_server "$listen_address"
	recovered_at=$(date +%s)
	printf '%s\t%s\t%s\t%s\n' \
		"$restart" "$kill_signal" "$killed_at" "$recovered_at" >>"$crash_events"
	restart=$((restart + 1))
	next_restart=$((next_restart + restart_interval))
done
restarts_completed=$((restart - 1))
[ "$restarts_completed" -eq "$restarts" ] ||
	die "completed $restarts_completed of $restarts requested restarts before the deadline"

while [ "$(date +%s)" -lt "$deadline" ]; do
	sleep 1
done
: >"$stop_file"
for pid in $worker_pids; do
	wait "$pid" || die "workload worker $pid failed"
done
worker_pids=

# Remove any temporary entry committed immediately before a forced process exit.
if has_operation add-delete; then
	worker=1
	while [ "$worker" -le "$connections" ]; do
		worker_id=$(printf '%04d' "$worker")
		temporary_dn="uid=qualification-temp-$worker_id,$qualification_ou"
		"$binary" ldapdelete \
			-H "$server_uri" -x -D "$root_dn" -y "$password_file" \
			-timeout "$client_timeout" "$temporary_dn" \
			>/dev/null 2>>"$artifact_dir/cleanup.log" || true
		worker=$((worker + 1))
	done
fi

"$binary" ldapsearch \
	-H "$server_uri" -x -D "$root_dn" -y "$password_file" \
	-timeout "$client_timeout" -LLL -b "$qualification_ou" \
	'(uid=qualification-*)' uid description \
	>"$artifact_dir/final-online.ldif"

stop_server TERM
"$binary" check -db "$database" >"$artifact_dir/check.log"
"$binary" export -db "$database" -ldif "$artifact_dir/final.ldif" \
	>"$artifact_dir/export.log"

metrics_count=$(find "$artifact_dir/workers" -name metrics.env -type f | wc -l | tr -d ' ')
[ "$metrics_count" -eq "$connections" ] ||
	die "found $metrics_count worker metric files, expected $connections"

set -- $(awk -F= '
	$1 == "attempted" { attempted += $2 }
	$1 == "succeeded" { succeeded += $2 }
	$1 == "failed" { failed += $2 }
	END { print attempted + 0, succeeded + 0, failed + 0 }
' "$artifact_dir"/workers/*/metrics.env)
attempted=$1
succeeded=$2
failed=$3
[ "$attempted" -gt 0 ] || die "workload attempted no LDAP operations"
[ "$succeeded" -gt 0 ] || die "workload completed no LDAP operations"
failure_percent=$(((failed * 100 + attempted - 1) / attempted))
[ "$failure_percent" -le "$max_failure_percent" ] ||
	die "failure ratio $failure_percent% exceeds $max_failure_percent%"

operation_stats=$artifact_dir/operation-stats.tsv
awk -F '\t' '
	{ attempted[$2] += $3; if ($4 == "ok") succeeded[$2] += $3; else failed[$2] += $3 }
	END {
		for (operation in attempted) {
			printf "%s\t%d\t%d\t%d\n", operation, attempted[operation], succeeded[operation], failed[operation]
		}
	}
' "$artifact_dir"/workers/*/events.tsv | sort >"$operation_stats"
if ! operation_error=$(awk -F '\t' \
	-v requested="$operations_csv" \
	-v maximum="$max_failure_percent" '
	BEGIN {
		count=split(requested, names, ",")
		for (item = 1; item <= count; item++) wanted[names[item]]=1
	}
	{
		seen[$1]=1
		if ($3 <= 0 && error == "") error=$1 " completed no successful operations"
		if ($4 * 100 > maximum * $2 && error == "") {
			error=$1 " failure ratio exceeds " maximum "%"
		}
	}
	END {
		for (name in wanted) {
			if (!seen[name] && error == "") error="missing operation metrics for " name
		}
		if (error != "") { print error; exit 1 }
	}
' "$operation_stats"); then
	die "$operation_error"
fi

online_count=$(grep -c '^dn: uid=qualification-[0-9][0-9]*,ou=qualification,dc=qualification,dc=test$' \
	"$artifact_dir/final-online.ldif" || true)
[ "$online_count" -eq "$connections" ] ||
	die "online validation found $online_count worker entries, expected $connections"

require_description=0
has_operation modify && require_description=1
expected_descriptions=$artifact_dir/expected-descriptions.tsv
: >"$expected_descriptions"
if [ "$require_description" -eq 1 ]; then
	for metrics in "$artifact_dir"/workers/*/metrics.env; do
		awk -F= '
			$1 == "worker" { worker=$2 }
			$1 == "last_modify_sequence" { print worker "\t" $2 }
		' "$metrics" >>"$expected_descriptions"
	done
fi
awk -v expected="$connections" -v require_description="$require_description" \
	-v expected_file="$expected_descriptions" '
	BEGIN {
		FS="\t"
		while ((getline expected_line < expected_file) > 0) {
			split(expected_line, fields, "\t")
			expected_description[fields[1]]="qualification-worker-" fields[1] "-sequence-" fields[2]
		}
		close(expected_file)
		RS=""; FS="\n"
	}
	{
		dn=""; uid=""; description=""
		for (line = 1; line <= NF; line++) {
			if ($line ~ /^dn: /) dn=substr($line, 5)
			if ($line ~ /^uid: /) uid=substr($line, 6)
			if ($line ~ /^description: /) description=substr($line, 14)
		}
		prefix="uid=qualification-"
		suffix=",ou=qualification,dc=qualification,dc=test"
		if (index(dn, prefix) != 1) next
		if (length(dn) <= length(prefix) + length(suffix)) next
		if (substr(dn, length(dn) - length(suffix) + 1) != suffix) next
		id=substr(dn, length(prefix) + 1, length(dn) - length(prefix) - length(suffix))
		if (uid != "qualification-" id) bad=1
		if (require_description && description != expected_description[id]) bad=1
		seen[id]++
		count++
	}
	END {
		if (count != expected || bad) exit 1
		for (worker = 1; worker <= expected; worker++) {
			id=sprintf("%04d", worker)
			if (seen[id] != 1) exit 1
		}
	}
' "$artifact_dir/final.ldif" || die "offline LDIF content validation failed"

if grep -q '^dn: uid=qualification-temp-' "$artifact_dir/final.ldif"; then
	die "temporary add/delete entries remain after recovery cleanup"
fi

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		printf 'unavailable\n'
	fi
}

export_sha256=$(sha256_file "$artifact_dir/final.ldif")
binary_sha256=$(sha256_file "$binary")
observed_max_recovery_seconds=0
if [ -s "$crash_events" ]; then
	observed_max_recovery_seconds=$(awk -F '\t' '
		{ recovery = $4 - $3; if (recovery > maximum) maximum = recovery }
		END { print maximum + 0 }
	' "$crash_events")
fi
[ "$observed_max_recovery_seconds" -le "$max_recovery_seconds" ] ||
	die "maximum restart recovery ${observed_max_recovery_seconds}s exceeds ${max_recovery_seconds}s"

finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
throughput=$((succeeded / duration))
[ "$throughput" -ge "$minimum_throughput" ] ||
	die "throughput $throughput successful operations/s is below $minimum_throughput"
report=$artifact_dir/report.json
{
	printf '{\n'
	printf '  "result": "pass",\n'
	printf '  "mode": "%s",\n' "$mode"
	printf '  "started_at": "%s",\n' "$started_at"
	printf '  "finished_at": "%s",\n' "$finished_at"
	printf '  "duration_seconds": %s,\n' "$duration"
	printf '  "concurrent_client_streams": %s,\n' "$connections"
	printf '  "batch_size": %s,\n' "$batch_size"
	printf '  "operations": "%s",\n' "$operations_csv"
	printf '  "restarts_requested": %s,\n' "$restarts"
	printf '  "restarts_completed": %s,\n' "$restarts_completed"
	printf '  "kill_signal": "%s",\n' "$kill_signal"
	printf '  "attempted_operations": %s,\n' "$attempted"
	printf '  "successful_operations": %s,\n' "$succeeded"
	printf '  "failed_operations": %s,\n' "$failed"
	printf '  "failure_percent": %s,\n' "$failure_percent"
	printf '  "successful_operations_per_second": %s,\n' "$throughput"
	printf '  "minimum_successful_operations_per_second": %s,\n' "$minimum_throughput"
	printf '  "maximum_restart_recovery_seconds": %s,\n' "$observed_max_recovery_seconds"
	printf '  "allowed_maximum_restart_recovery_seconds": %s,\n' "$max_recovery_seconds"
	printf '  "validated_entries": %s,\n' "$online_count"
	printf '  "binary_sha256": "%s",\n' "$binary_sha256"
	printf '  "export_sha256": "%s"\n' "$export_sha256"
	printf '}\n'
} >"$report"

rm -f "$password_file"
trap - EXIT
trap - HUP INT TERM
printf 'Qualification passed: %s successful operations, %s failed during fault windows.\n' \
	"$succeeded" "$failed"
printf 'Report: %s\n' "$report"

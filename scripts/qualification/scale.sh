#!/bin/sh

set -eu

phase=validation
result=fail
report_ready=0
server_pid=
rss_monitor_pid=
command_pid=

die() {
	printf 'scale-qualification: %s\n' "$*" >&2
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

require_positive() {
	require_uint "$1" "$2"
	[ "$2" -gt 0 ] || die "$1 must be greater than zero"
}

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
profile=${QUALIFICATION_SCALE_PROFILE:-smoke}
case "$profile" in
smoke)
	default_entries=1000
	default_page_size=200
	;;
nightly)
	default_entries=100000
	default_page_size=10000
	;;
*) die "QUALIFICATION_SCALE_PROFILE must be smoke or nightly, got: $profile" ;;
esac

entries=${QUALIFICATION_SCALE_ENTRIES:-$default_entries}
max_entries=${QUALIFICATION_SCALE_MAX_ENTRIES:-250000}
page_size=${QUALIFICATION_SCALE_PAGE_SIZE:-$default_page_size}
safety_timeout=${QUALIFICATION_SCALE_SAFETY_TIMEOUT_SECONDS:-1800}
startup_timeout=${QUALIFICATION_SCALE_STARTUP_TIMEOUT_SECONDS:-180}
shutdown_timeout=${QUALIFICATION_SCALE_SHUTDOWN_TIMEOUT_SECONDS:-60}
unindexed_time_limit=${QUALIFICATION_SCALE_UNINDEXED_TIME_LIMIT_SECONDS:-60}
client_timeout=${QUALIFICATION_SCALE_CLIENT_TIMEOUT:-120s}
dry_run=${QUALIFICATION_SCALE_DRY_RUN:-0}

max_generate_ms=${QUALIFICATION_SCALE_MAX_GENERATE_MS:-0}
max_import_ms=${QUALIFICATION_SCALE_MAX_IMPORT_MS:-0}
max_reindex_ms=${QUALIFICATION_SCALE_MAX_REINDEX_MS:-0}
max_startup_ms=${QUALIFICATION_SCALE_MAX_STARTUP_MS:-0}
max_indexed_search_ms=${QUALIFICATION_SCALE_MAX_INDEXED_SEARCH_MS:-0}
max_unindexed_search_ms=${QUALIFICATION_SCALE_MAX_UNINDEXED_SEARCH_MS:-0}
max_paging_ms=${QUALIFICATION_SCALE_MAX_PAGING_MS:-0}
max_mutation_ms=${QUALIFICATION_SCALE_MAX_MUTATION_MS:-0}
max_shutdown_ms=${QUALIFICATION_SCALE_MAX_SHUTDOWN_MS:-0}
max_rss_bytes=${QUALIFICATION_SCALE_MAX_RSS_BYTES:-0}
max_rss_growth_bytes=${QUALIFICATION_SCALE_MAX_RSS_GROWTH_BYTES:-0}
max_database_bytes=${QUALIFICATION_SCALE_MAX_DATABASE_BYTES:-0}
search_candidate_bytes=${QUALIFICATION_SCALE_SEARCH_CANDIDATE_BYTES:-}
search_memory_bytes=${QUALIFICATION_SCALE_SEARCH_MEMORY_BYTES:-}

for pair in \
	"QUALIFICATION_SCALE_ENTRIES:$entries" \
	"QUALIFICATION_SCALE_MAX_ENTRIES:$max_entries" \
	"QUALIFICATION_SCALE_PAGE_SIZE:$page_size" \
	"QUALIFICATION_SCALE_SAFETY_TIMEOUT_SECONDS:$safety_timeout" \
	"QUALIFICATION_SCALE_STARTUP_TIMEOUT_SECONDS:$startup_timeout" \
	"QUALIFICATION_SCALE_SHUTDOWN_TIMEOUT_SECONDS:$shutdown_timeout" \
	"QUALIFICATION_SCALE_UNINDEXED_TIME_LIMIT_SECONDS:$unindexed_time_limit"; do
	name=${pair%%:*}
	value=${pair#*:}
	require_positive "$name" "$value"
done
for pair in \
	"QUALIFICATION_SCALE_MAX_GENERATE_MS:$max_generate_ms" \
	"QUALIFICATION_SCALE_MAX_IMPORT_MS:$max_import_ms" \
	"QUALIFICATION_SCALE_MAX_REINDEX_MS:$max_reindex_ms" \
	"QUALIFICATION_SCALE_MAX_STARTUP_MS:$max_startup_ms" \
	"QUALIFICATION_SCALE_MAX_INDEXED_SEARCH_MS:$max_indexed_search_ms" \
	"QUALIFICATION_SCALE_MAX_UNINDEXED_SEARCH_MS:$max_unindexed_search_ms" \
	"QUALIFICATION_SCALE_MAX_PAGING_MS:$max_paging_ms" \
	"QUALIFICATION_SCALE_MAX_MUTATION_MS:$max_mutation_ms" \
	"QUALIFICATION_SCALE_MAX_SHUTDOWN_MS:$max_shutdown_ms" \
	"QUALIFICATION_SCALE_MAX_RSS_BYTES:$max_rss_bytes" \
	"QUALIFICATION_SCALE_MAX_RSS_GROWTH_BYTES:$max_rss_growth_bytes" \
	"QUALIFICATION_SCALE_MAX_DATABASE_BYTES:$max_database_bytes"; do
	name=${pair%%:*}
	value=${pair#*:}
	require_uint "$name" "$value"
done

entries=$(normalize_uint "$entries")
max_entries=$(normalize_uint "$max_entries")
page_size=$(normalize_uint "$page_size")
safety_timeout=$(normalize_uint "$safety_timeout")
startup_timeout=$(normalize_uint "$startup_timeout")
shutdown_timeout=$(normalize_uint "$shutdown_timeout")
unindexed_time_limit=$(normalize_uint "$unindexed_time_limit")
if [ -z "$search_candidate_bytes" ]; then
	search_candidate_bytes=$((entries * 8192))
	[ "$search_candidate_bytes" -ge 67108864 ] || search_candidate_bytes=67108864
else
	require_positive QUALIFICATION_SCALE_SEARCH_CANDIDATE_BYTES "$search_candidate_bytes"
	search_candidate_bytes=$(normalize_uint "$search_candidate_bytes")
fi
[ "$search_candidate_bytes" -le 2147483648 ] ||
	die "QUALIFICATION_SCALE_SEARCH_CANDIDATE_BYTES must not exceed 2147483648"
if [ -z "$search_memory_bytes" ]; then
	search_memory_bytes=$((search_candidate_bytes * 2))
else
	require_positive QUALIFICATION_SCALE_SEARCH_MEMORY_BYTES "$search_memory_bytes"
	search_memory_bytes=$(normalize_uint "$search_memory_bytes")
fi
max_generate_ms=$(normalize_uint "$max_generate_ms")
max_import_ms=$(normalize_uint "$max_import_ms")
max_reindex_ms=$(normalize_uint "$max_reindex_ms")
max_startup_ms=$(normalize_uint "$max_startup_ms")
max_indexed_search_ms=$(normalize_uint "$max_indexed_search_ms")
max_unindexed_search_ms=$(normalize_uint "$max_unindexed_search_ms")
max_paging_ms=$(normalize_uint "$max_paging_ms")
max_mutation_ms=$(normalize_uint "$max_mutation_ms")
max_shutdown_ms=$(normalize_uint "$max_shutdown_ms")
max_rss_bytes=$(normalize_uint "$max_rss_bytes")
max_rss_growth_bytes=$(normalize_uint "$max_rss_growth_bytes")
max_database_bytes=$(normalize_uint "$max_database_bytes")

[ "$max_entries" -le 250000 ] ||
	die "QUALIFICATION_SCALE_MAX_ENTRIES must not exceed the absolute safety cap of 250000"
[ "$entries" -ge 2 ] ||
	die "QUALIFICATION_SCALE_ENTRIES must be at least 2"
[ "$entries" -le "$max_entries" ] ||
	die "QUALIFICATION_SCALE_ENTRIES $entries exceeds QUALIFICATION_SCALE_MAX_ENTRIES $max_entries"
[ "$page_size" -le "$entries" ] ||
	die "QUALIFICATION_SCALE_PAGE_SIZE must not exceed QUALIFICATION_SCALE_ENTRIES"
[ "$search_memory_bytes" -le 4294967296 ] ||
	die "QUALIFICATION_SCALE_SEARCH_MEMORY_BYTES must not exceed 4294967296"
[ "$search_memory_bytes" -ge "$search_candidate_bytes" ] ||
	die "QUALIFICATION_SCALE_SEARCH_MEMORY_BYTES must be at least QUALIFICATION_SCALE_SEARCH_CANDIDATE_BYTES"
case "$client_timeout" in
''|*[!0-9a-zA-Z.]*) die "QUALIFICATION_SCALE_CLIENT_TIMEOUT contains unsupported characters" ;;
esac
case "$dry_run" in 0|1) ;; *) die "QUALIFICATION_SCALE_DRY_RUN must be 0 or 1" ;; esac

if [ "$dry_run" = 1 ]; then
	printf 'scale_profile=%s entries=%s max_entries=%s page_size=%s safety_timeout=%s search_candidate_bytes=%s search_memory_bytes=%s acceptance_ceilings=%s\n' \
		"$profile" "$entries" "$max_entries" "$page_size" "$safety_timeout" "$search_candidate_bytes" "$search_memory_bytes" \
		"generate_ms:$max_generate_ms,import_ms:$max_import_ms,reindex_ms:$max_reindex_ms,startup_ms:$max_startup_ms,indexed_ms:$max_indexed_search_ms,unindexed_ms:$max_unindexed_search_ms,paging_ms:$max_paging_ms,mutation_ms:$max_mutation_ms,shutdown_ms:$max_shutdown_ms,rss_bytes:$max_rss_bytes,rss_growth_bytes:$max_rss_growth_bytes,database_bytes:$max_database_bytes"
	exit 0
fi

timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
artifact_dir=${QUALIFICATION_SCALE_ARTIFACT_DIR:-${TMPDIR:-/tmp}/ldap-go-scale-qualification-$timestamp-$$}
case "$artifact_dir" in /*) ;; *) artifact_dir=$root/$artifact_dir ;; esac
[ ! -e "$artifact_dir" ] || die "artifact directory already exists: $artifact_dir"
mkdir -p "$artifact_dir"

binary=${QUALIFICATION_SCALE_BINARY:-$artifact_dir/ldap-go}
if [ -n "${QUALIFICATION_SCALE_BINARY:-}" ]; then
	case "$binary" in /*) ;; *) binary=$root/$binary ;; esac
	[ -x "$binary" ] || die "QUALIFICATION_SCALE_BINARY is not executable: $binary"
else
	command -v go >/dev/null 2>&1 || die "go is required to build ldap-go"
	printf 'Building scale qualification binary...\n'
	(cd "$root" && go build -o "$binary" ./cmd/ldap-go)
fi

clock_probe=$(date +%s%N 2>/dev/null || true)
case "$clock_probe" in
''|*N*) clock_resolution_ms=1000 ;;
*) clock_resolution_ms=1 ;;
esac

now_ms() {
	if [ "$clock_resolution_ms" -eq 1 ]; then
		nanoseconds=$(date +%s%N)
		printf '%s\n' "${nanoseconds%??????}"
	else
		printf '%s000\n' "$(date +%s)"
	fi
}

process_running() {
	pid=$1
	kill -0 "$pid" 2>/dev/null || return 1
	state=$(ps -o stat= -p "$pid" 2>/dev/null | awk 'NR == 1 { print $1 }')
	case "$state" in ''|Z*) return 1 ;; esac
	return 0
}

last_duration_ms=0
run_bounded() {
	run_label=$1
	run_stdout=$2
	run_stderr=$3
	shift 3
	run_started=$(now_ms)
	"$@" >"$run_stdout" 2>"$run_stderr" &
	command_pid=$!
	run_deadline=$(( $(date +%s) + safety_timeout ))
	while process_running "$command_pid"; do
		if [ "$(date +%s)" -ge "$run_deadline" ]; then
			kill -TERM "$command_pid" 2>/dev/null || true
			sleep 1
			kill -KILL "$command_pid" 2>/dev/null || true
			wait "$command_pid" 2>/dev/null || true
			command_pid=
			die "$run_label exceeded the ${safety_timeout}s safety timeout"
		fi
		sleep 0.1
	done
	set +e
	wait "$command_pid"
	run_status=$?
	set -e
	command_pid=
	run_finished=$(now_ms)
	last_duration_ms=$((run_finished - run_started))
	[ "$run_status" -eq 0 ] || die "$run_label failed; see $run_stderr"
}

enforce_ceiling() {
	ceiling_name=$1
	observed=$2
	ceiling=$3
	[ "$ceiling" -eq 0 ] && return 0
	[ "$observed" -le "$ceiling" ] ||
		die "$ceiling_name observed $observed exceeds configured ceiling $ceiling"
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		printf 'unavailable\n'
	fi
}

rss_bytes_for_pid() {
	rss_pid=$1
	if [ -r "/proc/$rss_pid/status" ]; then
		awk '/^VmRSS:/ { printf "%.0f\n", $2 * 1024; found=1; exit } END { if (!found) exit 1 }' \
			"/proc/$rss_pid/status" 2>/dev/null || true
		return
	fi
	ps -o rss= -p "$rss_pid" 2>/dev/null |
		awk 'NR == 1 && $1 ~ /^[0-9]+$/ { printf "%.0f\n", $1 * 1024; found=1 } END { if (!found) exit 1 }' || true
}

record_rss() {
	rss_label=$1
	rss_value=$(rss_bytes_for_pid "$server_pid")
	case "$rss_value" in
	''|*[!0-9]*) rss_available=false; rss_value=0 ;;
	*) rss_available=true ;;
	esac
	printf '%s\t%s\t%s\t%s\n' "$(now_ms)" "$generation" "$rss_label" "$rss_value" >>"$rss_samples"
	printf '%s\n' "$rss_value"
}

start_rss_monitor() {
	monitor_server_pid=$server_pid
	monitor_generation=$generation
	(
		while process_running "$monitor_server_pid"; do
			monitor_value=$(rss_bytes_for_pid "$monitor_server_pid")
			case "$monitor_value" in ''|*[!0-9]*) ;; *)
				printf '%s\t%s\tperiodic\t%s\n' "$(now_ms)" "$monitor_generation" "$monitor_value" >>"$rss_samples"
				;;
			esac
			sleep 1
		done
	) &
	rss_monitor_pid=$!
}

stop_rss_monitor() {
	[ -n "$rss_monitor_pid" ] || return 0
	kill -TERM "$rss_monitor_pid" 2>/dev/null || true
	wait "$rss_monitor_pid" 2>/dev/null || true
	rss_monitor_pid=
}

base_dn=dc=scale,dc=qualification
people_dn=ou=people,$base_dn
root_dn=cn=admin,$base_dn
root_password=${QUALIFICATION_SCALE_ROOT_PASSWORD:-scale-qualification-local-secret}
[ -n "$root_password" ] || die "QUALIFICATION_SCALE_ROOT_PASSWORD must not be empty"
case "$root_password" in *'
'*) die "QUALIFICATION_SCALE_ROOT_PASSWORD must not contain a newline" ;; esac

database=$artifact_dir/directory.db
seed_ldif=$artifact_dir/seed.ldif
password_file=$artifact_dir/root-password
server_log=$artifact_dir/server.log
rss_samples=$artifact_dir/rss-samples.tsv
report=$artifact_dir/report.json
effective_config=$artifact_dir/effective-config.env
started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
generation=0
server_uri=
rss_available=false

generate_ms=0
import_ms=0
reindex_ms=0
startup_initial_ms=0
startup_restart_ms=0
startup_max_ms=0
indexed_search_ms=0
unindexed_search_ms=0
paging_ms=0
modify_ms=0
delete_ms=0
mutation_ms=0
shutdown_initial_ms=0
shutdown_final_ms=0
shutdown_max_ms=0
rss_before_bytes=0
rss_after_workload_bytes=0
rss_after_restart_bytes=0
rss_peak_bytes=0
rss_growth_bytes=0
database_bytes=0
binary_sha256=unavailable
ldif_sha256=unavailable
validated_paged_entries=0
entries_after_delete=$entries

write_report() {
	if [ -s "$rss_samples" ]; then
		reported_peak=$(awk -F '\t' '$4 + 0 > maximum { maximum=$4 + 0 } END { print maximum + 0 }' "$rss_samples")
		if [ "$reported_peak" -gt "$rss_peak_bytes" ]; then
			rss_peak_bytes=$reported_peak
		fi
	fi
	if [ "$rss_peak_bytes" -gt 0 ]; then
		rss_available=true
	fi
	if [ "$rss_before_bytes" -gt 0 ] && [ "$rss_after_workload_bytes" -gt 0 ]; then
		rss_growth_bytes=$((rss_after_workload_bytes - rss_before_bytes))
	fi
	if [ -f "$database" ]; then
		database_bytes=$(wc -c <"$database" | tr -d ' ')
	fi
	if [ -x "$binary" ]; then
		binary_sha256=$(sha256_file "$binary")
	fi
	if [ -f "$seed_ldif" ]; then
		ldif_sha256=$(sha256_file "$seed_ldif")
	fi
	finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	{
		printf '{\n'
		printf '  "report_version": 1,\n'
		printf '  "result": "%s",\n' "$result"
		if [ "$result" = pass ]; then
			printf '  "failed_phase": null,\n'
		else
			printf '  "failed_phase": "%s",\n' "$phase"
		fi
		printf '  "profile": "%s",\n' "$profile"
		printf '  "started_at": "%s",\n' "$started_at"
		printf '  "finished_at": "%s",\n' "$finished_at"
		printf '  "entries_requested": %s,\n' "$entries"
		printf '  "entries_after_delete": %s,\n' "$entries_after_delete"
		printf '  "validated_paged_entries": %s,\n' "$validated_paged_entries"
		printf '  "page_size": %s,\n' "$page_size"
		printf '  "clock_resolution_ms": %s,\n' "$clock_resolution_ms"
		printf '  "timings_ms": {\n'
		printf '    "generate_ldif": %s,\n' "$generate_ms"
		printf '    "import": %s,\n' "$import_ms"
		printf '    "reindex": %s,\n' "$reindex_ms"
		printf '    "startup_initial": %s,\n' "$startup_initial_ms"
		printf '    "startup_restart": %s,\n' "$startup_restart_ms"
		printf '    "startup_max": %s,\n' "$startup_max_ms"
		printf '    "indexed_equality_search": %s,\n' "$indexed_search_ms"
		printf '    "unindexed_bounded_search": %s,\n' "$unindexed_search_ms"
		printf '    "paged_search": %s,\n' "$paging_ms"
		printf '    "modify": %s,\n' "$modify_ms"
		printf '    "delete": %s,\n' "$delete_ms"
		printf '    "mutation_total": %s,\n' "$mutation_ms"
		printf '    "graceful_shutdown_initial": %s,\n' "$shutdown_initial_ms"
		printf '    "graceful_shutdown_final": %s,\n' "$shutdown_final_ms"
		printf '    "graceful_shutdown_max": %s\n' "$shutdown_max_ms"
		printf '  },\n'
		printf '  "resources": {\n'
		printf '    "rss_available": %s,\n' "$rss_available"
		printf '    "rss_before_bytes": %s,\n' "$rss_before_bytes"
		printf '    "rss_after_workload_bytes": %s,\n' "$rss_after_workload_bytes"
		printf '    "rss_after_restart_bytes": %s,\n' "$rss_after_restart_bytes"
		printf '    "rss_peak_sampled_bytes": %s,\n' "$rss_peak_bytes"
		printf '    "rss_growth_bytes": %s,\n' "$rss_growth_bytes"
		printf '    "database_bytes": %s\n' "$database_bytes"
		printf '  },\n'
		printf '  "ceilings": {\n'
		printf '    "generate_ms": %s, "import_ms": %s, "reindex_ms": %s,\n' "$max_generate_ms" "$max_import_ms" "$max_reindex_ms"
		printf '    "startup_ms": %s, "indexed_search_ms": %s, "unindexed_search_ms": %s,\n' "$max_startup_ms" "$max_indexed_search_ms" "$max_unindexed_search_ms"
		printf '    "paging_ms": %s, "mutation_ms": %s, "shutdown_ms": %s,\n' "$max_paging_ms" "$max_mutation_ms" "$max_shutdown_ms"
		printf '    "rss_bytes": %s, "rss_growth_bytes": %s, "database_bytes": %s\n' "$max_rss_bytes" "$max_rss_growth_bytes" "$max_database_bytes"
		printf '  },\n'
		printf '  "safety": {"maximum_entries": %s, "command_timeout_seconds": %s, "startup_timeout_seconds": %s, "shutdown_timeout_seconds": %s, "unindexed_time_limit_seconds": %s, "search_candidate_bytes": %s, "search_memory_bytes": %s},\n' \
			"$max_entries" "$safety_timeout" "$startup_timeout" "$shutdown_timeout" "$unindexed_time_limit" "$search_candidate_bytes" "$search_memory_bytes"
		printf '  "binary_sha256": "%s",\n' "$binary_sha256"
		printf '  "seed_ldif_sha256": "%s"\n' "$ldif_sha256"
		printf '}\n'
	} >"$report"
}

force_stop_server() {
	stop_rss_monitor
	[ -n "$server_pid" ] || return 0
	if process_running "$server_pid"; then
		kill -TERM "$server_pid" 2>/dev/null || true
		sleep 1
		kill -KILL "$server_pid" 2>/dev/null || true
	fi
	wait "$server_pid" 2>/dev/null || true
	server_pid=
}

cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	[ -n "$command_pid" ] && kill -KILL "$command_pid" 2>/dev/null || true
	force_stop_server
	rm -f "$password_file"
	if [ "$report_ready" -eq 1 ]; then
		write_report
	fi
	if [ "$status" -ne 0 ]; then
		printf 'Scale qualification failed in phase %s; artifacts retained at %s\n' "$phase" "$artifact_dir" >&2
	fi
	exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
report_ready=1

{
	printf 'profile=%s\n' "$profile"
	printf 'entries=%s\n' "$entries"
	printf 'maximum_entries=%s\n' "$max_entries"
	printf 'page_size=%s\n' "$page_size"
	printf 'safety_timeout_seconds=%s\n' "$safety_timeout"
	printf 'startup_timeout_seconds=%s\n' "$startup_timeout"
	printf 'shutdown_timeout_seconds=%s\n' "$shutdown_timeout"
	printf 'unindexed_time_limit_seconds=%s\n' "$unindexed_time_limit"
	printf 'client_timeout=%s\n' "$client_timeout"
	printf 'search_candidate_bytes=%s\n' "$search_candidate_bytes"
	printf 'search_memory_bytes=%s\n' "$search_memory_bytes"
	printf 'max_generate_ms=%s\n' "$max_generate_ms"
	printf 'max_import_ms=%s\n' "$max_import_ms"
	printf 'max_reindex_ms=%s\n' "$max_reindex_ms"
	printf 'max_startup_ms=%s\n' "$max_startup_ms"
	printf 'max_indexed_search_ms=%s\n' "$max_indexed_search_ms"
	printf 'max_unindexed_search_ms=%s\n' "$max_unindexed_search_ms"
	printf 'max_paging_ms=%s\n' "$max_paging_ms"
	printf 'max_mutation_ms=%s\n' "$max_mutation_ms"
	printf 'max_shutdown_ms=%s\n' "$max_shutdown_ms"
	printf 'max_rss_bytes=%s\n' "$max_rss_bytes"
	printf 'max_rss_growth_bytes=%s\n' "$max_rss_growth_bytes"
	printf 'max_database_bytes=%s\n' "$max_database_bytes"
} >"$effective_config"

(umask 077 && printf '%s' "$root_password" >"$password_file")
: >"$rss_samples"

generate_fixture() {
	cat <<'EOF'
dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
entryUUID: 30000000-0000-4000-8000-000000000000

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=scale,dc=qualification
olcRootDN: cn=admin,dc=scale,dc=qualification
olcDbIndex: uid eq
entryUUID: 31111111-1111-4111-8111-111111111111

dn: dc=scale,dc=qualification
objectClass: top
objectClass: domain
dc: scale

dn: ou=people,dc=scale,dc=qualification
objectClass: top
objectClass: organizationalUnit
ou: people

EOF
	awk -v count="$entries" '
		BEGIN {
			for (entry = 1; entry <= count; entry++) {
				id=sprintf("%06d", entry)
				printf "dn: uid=scale-%s,ou=people,dc=scale,dc=qualification\n", id
				print "objectClass: top"
				print "objectClass: person"
				print "objectClass: organizationalPerson"
				print "objectClass: inetOrgPerson"
				printf "uid: scale-%s\n", id
				printf "cn: Scale User %s\n", id
				printf "sn: User%s\n", id
				printf "description: cohort-%03d\n\n", entry % 1000
			}
		}
	'
}

phase=generate_ldif
run_bounded "LDIF generation" "$seed_ldif" "$artifact_dir/generate.err" generate_fixture
generate_ms=$last_duration_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_GENERATE_MS "$generate_ms" "$max_generate_ms"
ldif_sha256=$(sha256_file "$seed_ldif")

phase=import
run_bounded "LDIF import" "$artifact_dir/import.log" "$artifact_dir/import.err" \
	"$binary" import -db "$database" -ldif "$seed_ldif" -replace
import_ms=$last_duration_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_IMPORT_MS "$import_ms" "$max_import_ms"

phase=reindex
run_bounded "offline reindex" "$artifact_dir/reindex.log" "$artifact_dir/reindex.err" \
	"$binary" slapindex -db "$database" -n 1 uid
reindex_ms=$last_duration_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_REINDEX_MS "$reindex_ms" "$max_reindex_ms"

start_server() {
	generation=$((generation + 1))
	server_stdout=$artifact_dir/server-$generation.stdout
	: >"$server_stdout"
	server_started=$(now_ms)
	LDAP_GO_ROOT_PASSWORD=$root_password \
		"$binary" serve \
		-db "$database" \
		-listen 127.0.0.1:0 \
		-root-dn "$root_dn" \
		-search-limit "$((entries + 100))" \
		-search-candidate-limit "$((entries + 100))" \
		-search-candidate-bytes "$search_candidate_bytes" \
		-search-memory-bytes "$search_memory_bytes" \
		-shutdown-timeout "${shutdown_timeout}s" \
		-log-level warn \
		>"$server_stdout" 2>>"$server_log" &
	server_pid=$!
	ready_deadline=$(( $(date +%s) + startup_timeout ))
	server_uri=
	while [ "$(date +%s)" -lt "$ready_deadline" ]; do
		server_uri=$(sed -n 's/^ldap-go listening on \(ldap:\/\/.*\)$/\1/p' "$server_stdout" | sed -n '1p')
		if [ -n "$server_uri" ]; then
			if "$binary" ldapwhoami -H "$server_uri" -x -D "$root_dn" -y "$password_file" \
				-timeout "$client_timeout" >"$artifact_dir/readiness-$generation.out" 2>>"$server_log"; then
				server_finished=$(now_ms)
				last_duration_ms=$((server_finished - server_started))
				start_rss_monitor
				return 0
			fi
		fi
		process_running "$server_pid" || die "server generation $generation exited before readiness"
		sleep 1
	done
	die "server generation $generation did not become ready within ${startup_timeout}s"
}

graceful_stop_server() {
	stop_rss_monitor
	stop_started=$(now_ms)
	kill -TERM "$server_pid" 2>/dev/null || die "could not signal server generation $generation"
	stop_deadline=$(( $(date +%s) + shutdown_timeout ))
	while process_running "$server_pid"; do
		if [ "$(date +%s)" -ge "$stop_deadline" ]; then
			kill -KILL "$server_pid" 2>/dev/null || true
			wait "$server_pid" 2>/dev/null || true
			server_pid=
			die "server generation $generation did not stop gracefully within ${shutdown_timeout}s"
		fi
		sleep 1
	done
	set +e
	wait "$server_pid"
	stop_status=$?
	set -e
	server_pid=
	[ "$stop_status" -eq 0 ] || die "server generation $generation exited with status $stop_status"
	stop_finished=$(now_ms)
	last_duration_ms=$((stop_finished - stop_started))
}

phase=startup_initial
start_server
startup_initial_ms=$last_duration_ms
startup_max_ms=$startup_initial_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_STARTUP_MS "$startup_initial_ms" "$max_startup_ms"
rss_before_bytes=$(record_rss before_workload)

middle=$(((entries + 1) / 2))
middle_id=$(printf '%06d' "$middle")
middle_dn="uid=scale-$middle_id,$people_dn"

phase=indexed_search
run_bounded "indexed equality Search" "$artifact_dir/indexed-search.ldif" "$artifact_dir/indexed-search.err" \
	"$binary" ldapsearch -H "$server_uri" -x -D "$root_dn" -y "$password_file" \
	-timeout "$client_timeout" -LLL -b "$people_dn" -z 2 "(uid=scale-$middle_id)" uid
indexed_search_ms=$last_duration_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_INDEXED_SEARCH_MS "$indexed_search_ms" "$max_indexed_search_ms"
indexed_count=$(grep -c "^dn: $middle_dn$" "$artifact_dir/indexed-search.ldif" || true)
[ "$indexed_count" -eq 1 ] || die "indexed equality Search returned $indexed_count matching entries, expected 1"

phase=unindexed_search
run_bounded "unindexed bounded Search" "$artifact_dir/unindexed-search.ldif" "$artifact_dir/unindexed-search.err" \
	"$binary" ldapsearch -H "$server_uri" -x -D "$root_dn" -y "$password_file" \
	-timeout "$client_timeout" -LLL -b "$people_dn" -z 1 -l "$unindexed_time_limit" \
	'(description=qualification-value-that-does-not-exist)' uid
unindexed_search_ms=$last_duration_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_UNINDEXED_SEARCH_MS "$unindexed_search_ms" "$max_unindexed_search_ms"
unindexed_count=$(grep -c '^dn: ' "$artifact_dir/unindexed-search.ldif" || true)
[ "$unindexed_count" -eq 0 ] || die "unindexed negative Search unexpectedly returned $unindexed_count entries"

phase=paged_search
run_bounded "paged Search" "$artifact_dir/paged-search.ldif" "$artifact_dir/paged-search.err" \
	"$binary" ldapsearch -H "$server_uri" -x -D "$root_dn" -y "$password_file" \
	-timeout "$client_timeout" -LLL -page-size "$page_size" -b "$people_dn" '(uid=scale-*)' uid
paging_ms=$last_duration_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_PAGING_MS "$paging_ms" "$max_paging_ms"
validated_paged_entries=$(grep -c '^dn: uid=scale-[0-9][0-9]*,ou=people,dc=scale,dc=qualification$' \
	"$artifact_dir/paged-search.ldif" || true)
[ "$validated_paged_entries" -eq "$entries" ] ||
	die "paged Search returned $validated_paged_entries entries, expected $entries"

modify_ldif=$artifact_dir/modify.ldif
cat >"$modify_ldif" <<EOF
dn: uid=scale-000001,$people_dn
changetype: modify
replace: description
description: modified-by-scale-qualification

EOF

phase=modify
run_bounded "Modify" "$artifact_dir/modify.log" "$artifact_dir/modify.err" \
	"$binary" ldapmodify -H "$server_uri" -x -D "$root_dn" -y "$password_file" \
	-timeout "$client_timeout" -f "$modify_ldif"
modify_ms=$last_duration_ms

last_id=$(printf '%06d' "$entries")
deleted_dn="uid=scale-$last_id,$people_dn"
phase=delete
run_bounded "Delete" "$artifact_dir/delete.log" "$artifact_dir/delete.err" \
	"$binary" ldapdelete -H "$server_uri" -x -D "$root_dn" -y "$password_file" \
	-timeout "$client_timeout" "$deleted_dn"
delete_ms=$last_duration_ms
entries_after_delete=$((entries - 1))
mutation_ms=$((modify_ms + delete_ms))
enforce_ceiling QUALIFICATION_SCALE_MAX_MUTATION_MS "$mutation_ms" "$max_mutation_ms"
rss_after_workload_bytes=$(record_rss after_workload)

phase=graceful_shutdown_initial
graceful_stop_server
shutdown_initial_ms=$last_duration_ms
shutdown_max_ms=$shutdown_initial_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_SHUTDOWN_MS "$shutdown_initial_ms" "$max_shutdown_ms"
phase=database_size
database_bytes=$(wc -c <"$database" | tr -d ' ')
enforce_ceiling QUALIFICATION_SCALE_MAX_DATABASE_BYTES "$database_bytes" "$max_database_bytes"

phase=startup_restart
start_server
startup_restart_ms=$last_duration_ms
startup_max_ms=$startup_initial_ms
[ "$startup_restart_ms" -le "$startup_max_ms" ] || startup_max_ms=$startup_restart_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_STARTUP_MS "$startup_max_ms" "$max_startup_ms"
rss_after_restart_bytes=$(record_rss after_restart)

phase=restart_validation
run_bounded "post-restart persistence Search" "$artifact_dir/post-restart.ldif" "$artifact_dir/post-restart.err" \
	"$binary" ldapsearch -H "$server_uri" -x -D "$root_dn" -y "$password_file" \
	-timeout "$client_timeout" -LLL -b "$people_dn" '(|(uid=scale-000001)(uid=scale-'"$last_id"'))' uid description
grep -q '^description: modified-by-scale-qualification$' "$artifact_dir/post-restart.ldif" ||
	die "modified value was not durable across restart"
if grep -q "^dn: $deleted_dn$" "$artifact_dir/post-restart.ldif"; then
	die "deleted entry reappeared after restart"
fi

phase=graceful_shutdown_final
graceful_stop_server
shutdown_final_ms=$last_duration_ms
shutdown_max_ms=$shutdown_initial_ms
[ "$shutdown_final_ms" -le "$shutdown_max_ms" ] || shutdown_max_ms=$shutdown_final_ms
enforce_ceiling QUALIFICATION_SCALE_MAX_SHUTDOWN_MS "$shutdown_max_ms" "$max_shutdown_ms"

phase=offline_check
run_bounded "offline database check" "$artifact_dir/check.log" "$artifact_dir/check.err" \
	"$binary" check -db "$database"

if [ -s "$rss_samples" ]; then
	rss_peak_bytes=$(awk -F '\t' '$4 + 0 > maximum { maximum=$4 + 0 } END { print maximum + 0 }' "$rss_samples")
fi
if [ "$rss_peak_bytes" -gt 0 ]; then
	rss_available=true
fi
if [ "$rss_after_workload_bytes" -ge "$rss_before_bytes" ]; then
	rss_growth_bytes=$((rss_after_workload_bytes - rss_before_bytes))
else
	rss_growth_bytes=$((rss_after_workload_bytes - rss_before_bytes))
fi
if [ "$max_rss_bytes" -gt 0 ] || [ "$max_rss_growth_bytes" -gt 0 ]; then
	[ "$rss_available" = true ] || die "RSS ceilings were configured but RSS measurement is unavailable"
fi
enforce_ceiling QUALIFICATION_SCALE_MAX_RSS_BYTES "$rss_peak_bytes" "$max_rss_bytes"
if [ "$rss_growth_bytes" -gt 0 ]; then
	enforce_ceiling QUALIFICATION_SCALE_MAX_RSS_GROWTH_BYTES "$rss_growth_bytes" "$max_rss_growth_bytes"
fi

binary_sha256=$(sha256_file "$binary")
phase=complete
result=pass
write_report
report_ready=0
rm -f "$password_file"
trap - EXIT HUP INT TERM
printf 'Scale qualification passed for %s entries.\n' "$entries"
printf 'Report: %s\n' "$report"

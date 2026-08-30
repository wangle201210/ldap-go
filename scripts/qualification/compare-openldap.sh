#!/bin/sh

set -eu

die() {
	printf 'compare-openldap: %s\n' "$*" >&2
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

normalize_uint() {
	normalized=$(printf '%s\n' "$1" | sed 's/^0*//')
	printf '%s\n' "${normalized:-0}"
}

find_tool() {
	name=$1
	shift
	if command -v "$name" >/dev/null 2>&1; then
		command -v "$name"
		return
	fi
	for candidate in "$@"; do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	die "required tool $name was not found"
}

if [ "$#" -ne 0 ]; then
	die "this script accepts configuration through environment variables only"
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
entries=${QUALIFICATION_COMPARE_ENTRIES:-1000}
max_entries=${QUALIFICATION_COMPARE_MAX_ENTRIES:-250000}
page_size=${QUALIFICATION_COMPARE_PAGE_SIZE:-200}
indexed_searches=${QUALIFICATION_COMPARE_INDEXED_SEARCHES:-1000}
unindexed_searches=${QUALIFICATION_COMPARE_UNINDEXED_SEARCHES:-100}
paged_traversals=${QUALIFICATION_COMPARE_PAGED_TRAVERSALS:-10}
modifications=${QUALIFICATION_COMPARE_MODIFICATIONS:-200}
concurrency=${QUALIFICATION_COMPARE_CONCURRENCY:-8}
searches_per_connection=${QUALIFICATION_COMPARE_SEARCHES_PER_CONNECTION:-250}
startup_timeout=${QUALIFICATION_COMPARE_STARTUP_TIMEOUT_SECONDS:-30}
dry_run=${QUALIFICATION_COMPARE_DRY_RUN:-0}
ldap_go_port=${QUALIFICATION_COMPARE_LDAP_GO_PORT:-$((20000 + ($$ % 10000)))}
openldap_port=${QUALIFICATION_COMPARE_OPENLDAP_PORT:-$((ldap_go_port + 1))}

for pair in \
	"QUALIFICATION_COMPARE_ENTRIES:$entries" \
	"QUALIFICATION_COMPARE_MAX_ENTRIES:$max_entries" \
	"QUALIFICATION_COMPARE_PAGE_SIZE:$page_size" \
	"QUALIFICATION_COMPARE_INDEXED_SEARCHES:$indexed_searches" \
	"QUALIFICATION_COMPARE_UNINDEXED_SEARCHES:$unindexed_searches" \
	"QUALIFICATION_COMPARE_PAGED_TRAVERSALS:$paged_traversals" \
	"QUALIFICATION_COMPARE_MODIFICATIONS:$modifications" \
	"QUALIFICATION_COMPARE_CONCURRENCY:$concurrency" \
	"QUALIFICATION_COMPARE_SEARCHES_PER_CONNECTION:$searches_per_connection" \
	"QUALIFICATION_COMPARE_STARTUP_TIMEOUT_SECONDS:$startup_timeout" \
	"QUALIFICATION_COMPARE_LDAP_GO_PORT:$ldap_go_port" \
	"QUALIFICATION_COMPARE_OPENLDAP_PORT:$openldap_port"; do
	name=${pair%%:*}
	value=${pair#*:}
	require_positive "$name" "$value"
done

entries=$(normalize_uint "$entries")
max_entries=$(normalize_uint "$max_entries")
page_size=$(normalize_uint "$page_size")
indexed_searches=$(normalize_uint "$indexed_searches")
unindexed_searches=$(normalize_uint "$unindexed_searches")
paged_traversals=$(normalize_uint "$paged_traversals")
modifications=$(normalize_uint "$modifications")
concurrency=$(normalize_uint "$concurrency")
searches_per_connection=$(normalize_uint "$searches_per_connection")
startup_timeout=$(normalize_uint "$startup_timeout")
ldap_go_port=$(normalize_uint "$ldap_go_port")
openldap_port=$(normalize_uint "$openldap_port")

search_candidate_bytes=$((entries * 8192))
[ "$search_candidate_bytes" -ge 67108864 ] || search_candidate_bytes=67108864
[ "$search_candidate_bytes" -le 2147483648 ] || search_candidate_bytes=2147483648
search_memory_bytes=$((search_candidate_bytes * 2))

require_uint QUALIFICATION_COMPARE_DRY_RUN "$dry_run"
case "$dry_run" in 0|1) ;; *) die "QUALIFICATION_COMPARE_DRY_RUN must be 0 or 1" ;; esac
[ "$max_entries" -le 250000 ] || die "QUALIFICATION_COMPARE_MAX_ENTRIES must not exceed 250000"
[ "$entries" -le "$max_entries" ] || die "entry count $entries exceeds maximum $max_entries"
[ "$page_size" -le "$entries" ] || die "page size must not exceed entry count"
[ "$modifications" -le "$entries" ] || die "modification count must not exceed entry count"
[ "$concurrency" -le 256 ] || die "concurrency must not exceed 256"
[ "$indexed_searches" -le 1000000 ] || die "indexed search count must not exceed 1000000"
[ "$unindexed_searches" -le 100000 ] || die "unindexed search count must not exceed 100000"
[ "$paged_traversals" -le 10000 ] || die "paged traversal count must not exceed 10000"
[ "$searches_per_connection" -le 100000 ] || die "searches per connection must not exceed 100000"
[ "$ldap_go_port" -le 65535 ] || die "ldap-go port must not exceed 65535"
[ "$openldap_port" -le 65535 ] || die "OpenLDAP port must not exceed 65535"
[ "$ldap_go_port" -ne "$openldap_port" ] || die "server ports must be different"
case "${QUALIFICATION_COMPARE_ROOT_PASSWORD:-scale-qualification-local-secret}" in
*' '*|*'	'*|*'\'*|*'#'*) die "QUALIFICATION_COMPARE_ROOT_PASSWORD contains unsupported slapd.conf characters" ;;
esac

if [ "$dry_run" = 1 ]; then
	printf 'entries=%s max_entries=%s page_size=%s indexed_searches=%s unindexed_searches=%s paged_traversals=%s modifications=%s concurrency=%s searches_per_connection=%s\n' \
		"$entries" "$max_entries" "$page_size" "$indexed_searches" "$unindexed_searches" \
		"$paged_traversals" "$modifications" "$concurrency" "$searches_per_connection"
	exit 0
fi

if [ -n "${OPENLDAP_ENV_FILE:-}" ]; then
	[ -r "$OPENLDAP_ENV_FILE" ] || die "OPENLDAP_ENV_FILE is not readable: $OPENLDAP_ENV_FILE"
	# shellcheck disable=SC1090
	. "$OPENLDAP_ENV_FILE"
fi

slapd=$(find_tool slapd \
	"${OPENLDAP_SLAPD:-}" \
	/opt/homebrew/opt/openldap/libexec/slapd \
	/usr/lib/openldap/slapd \
	/usr/sbin/slapd)
slapadd=$(find_tool slapadd \
	"${OPENLDAP_SLAPADD:-}" \
	/opt/homebrew/opt/openldap/sbin/slapadd \
	/usr/sbin/slapadd)
ldapsearch=$(find_tool ldapsearch \
	"${OPENLDAP_BUILD:-}/clients/tools/ldapsearch" \
	/opt/homebrew/opt/openldap/bin/ldapsearch \
	/usr/bin/ldapsearch)
ldapmodify=$(find_tool ldapmodify \
	"${OPENLDAP_BUILD:-}/clients/tools/ldapmodify" \
	/opt/homebrew/opt/openldap/bin/ldapmodify \
	/usr/bin/ldapmodify)
ldapwhoami=$(find_tool ldapwhoami \
	"${OPENLDAP_BUILD:-}/clients/tools/ldapwhoami" \
	/opt/homebrew/opt/openldap/bin/ldapwhoami \
	/usr/bin/ldapwhoami)

schema_dir=${OPENLDAP_SCHEMA_DIR:-}
if [ -z "$schema_dir" ]; then
	for candidate in \
		/opt/homebrew/etc/openldap/schema \
		/etc/ldap/schema \
		/etc/openldap/schema; do
		if [ -f "$candidate/core.schema" ]; then
			schema_dir=$candidate
			break
		fi
	done
fi
[ -n "$schema_dir" ] && [ -f "$schema_dir/core.schema" ] ||
	die "OpenLDAP schemas were not found; set OPENLDAP_SCHEMA_DIR or OPENLDAP_ENV_FILE"

version_output=$("$slapd" -VV 2>&1 || true)
openldap_version=$(printf '%s\n' "$version_output" |
	sed -n 's/.*slapd \([^[:space:]]*\).*/\1/p' | head -n 1)
expected_version=${OPENLDAP_EXPECTED_VERSION:-2.6.13}
[ "$openldap_version" = "$expected_version" ] ||
	die "OpenLDAP $expected_version is required, found ${openldap_version:-unknown}"

timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
artifact_dir=${QUALIFICATION_COMPARE_ARTIFACT_DIR:-${TMPDIR:-/tmp}/ldap-go-openldap-comparison-$timestamp-$$}
case "$artifact_dir" in /*) ;; *) artifact_dir=$root/$artifact_dir ;; esac
[ ! -e "$artifact_dir" ] || die "artifact directory already exists: $artifact_dir"
mkdir -p "$artifact_dir/openldap-data"
chmod 700 "$artifact_dir/openldap-data"

binary=${QUALIFICATION_COMPARE_BINARY:-$artifact_dir/ldap-go}
if [ -n "${QUALIFICATION_COMPARE_BINARY:-}" ]; then
	case "$binary" in /*) ;; *) binary=$root/$binary ;; esac
	[ -x "$binary" ] || die "QUALIFICATION_COMPARE_BINARY is not executable: $binary"
else
	command -v go >/dev/null 2>&1 || die "go is required to build ldap-go"
	printf 'Building comparison binary...\n'
	(cd "$root" && go build -o "$binary" ./cmd/ldap-go)
fi

root_dn=cn=admin,dc=scale,dc=qualification
people_dn=ou=people,dc=scale,dc=qualification
password=${QUALIFICATION_COMPARE_ROOT_PASSWORD:-scale-qualification-local-secret}
password_file=$artifact_dir/password
seed_ldif=$artifact_dir/seed.ldif
content_ldif=$artifact_dir/content.ldif
ldap_go_db=$artifact_dir/ldap-go.db
openldap_data=$artifact_dir/openldap-data
slapd_conf=$artifact_dir/slapd.conf
report=$artifact_dir/report.json
results=$artifact_dir/results.tsv
ldap_go_uri=ldap://127.0.0.1:$ldap_go_port
openldap_uri=ldap://127.0.0.1:$openldap_port
ldap_go_pid=
openldap_pid=

(umask 077 && printf '%s' "$password" >"$password_file")

process_running() {
	pid=$1
	kill -0 "$pid" 2>/dev/null || return 1
	state=$(ps -o stat= -p "$pid" 2>/dev/null | awk 'NR == 1 {print $1}')
	case "$state" in ''|Z*) return 1 ;; esac
	return 0
}

stop_process() {
	pid=$1
	[ -n "$pid" ] || return 0
	if process_running "$pid"; then
		kill -TERM "$pid" 2>/dev/null || true
		deadline=$(( $(date +%s) + 10 ))
		while process_running "$pid" && [ "$(date +%s)" -lt "$deadline" ]; do
			sleep 0.05
		done
	fi
	if process_running "$pid"; then
		kill -KILL "$pid" 2>/dev/null || true
	fi
	wait "$pid" 2>/dev/null || true
}

cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	stop_process "$ldap_go_pid"
	stop_process "$openldap_pid"
	rm -f "$password_file"
	if [ "$status" -ne 0 ]; then
		printf 'Comparison failed; artifacts retained at %s\n' "$artifact_dir" >&2
	fi
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

clock_probe=$(date +%s%N 2>/dev/null || true)
case "$clock_probe" in ''|*N*) clock_resolution_ms=1000 ;; *) clock_resolution_ms=1 ;; esac
now_ms() {
	if [ "$clock_resolution_ms" -eq 1 ]; then
		nanoseconds=$(date +%s%N)
		printf '%s\n' "${nanoseconds%??????}"
	else
		printf '%s000\n' "$(date +%s)"
	fi
}

measure() {
	variable=$1
	shift
	started=$(now_ms)
	"$@"
	finished=$(now_ms)
	eval "$variable=$((finished - started))"
}

rss_bytes_for_pid() {
	rss_pid=$1
	if [ -r "/proc/$rss_pid/status" ]; then
		awk '/^VmRSS:/ {printf "%.0f\n", $2 * 1024; found=1; exit} END {if (!found) exit 1}' \
			"/proc/$rss_pid/status" 2>/dev/null || true
		return
	fi
	ps -o rss= -p "$rss_pid" 2>/dev/null |
		awk 'NR == 1 && $1 ~ /^[0-9]+$/ {printf "%.0f\n", $1 * 1024; found=1} END {if (!found) exit 1}' || true
}

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
	awk -v count="$entries" 'BEGIN {
		for (entry=1; entry<=count; entry++) {
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
	}'
}

generate_fixture >"$seed_ldif"
awk '/^dn: dc=scale,dc=qualification$/ {copy=1} copy {print}' "$seed_ldif" >"$content_ldif"
awk -v count="$indexed_searches" -v entries="$entries" 'BEGIN {
	for (i=1; i<=count; i++) printf "scale-%06d\n", ((i-1) % entries) + 1
}' >"$artifact_dir/indexed-values.txt"
awk -v count="$unindexed_searches" 'BEGIN {
	for (i=1; i<=count; i++) printf "absent-%06d\n", i
}' >"$artifact_dir/unindexed-values.txt"
awk -v count="$searches_per_connection" -v entries="$entries" 'BEGIN {
	for (i=1; i<=count; i++) printf "scale-%06d\n", ((i-1) % entries) + 1
}' >"$artifact_dir/concurrent-values.txt"
awk -v count="$modifications" 'BEGIN {
	for (i=1; i<=count; i++) {
		printf "dn: uid=scale-%06d,ou=people,dc=scale,dc=qualification\n", i
		print "changetype: modify"
		print "replace: description"
		printf "description: benchmark-%06d\n\n", i
	}
}' >"$artifact_dir/modify.ldif"

cat >"$slapd_conf" <<EOF
include $schema_dir/core.schema
include $schema_dir/cosine.schema
include $schema_dir/inetorgperson.schema
pidfile $artifact_dir/slapd.pid
argsfile $artifact_dir/slapd.args
loglevel none
sizelimit $((entries + 100))
database mdb
maxsize 4294967296
suffix "dc=scale,dc=qualification"
rootdn "$root_dn"
rootpw $password
directory $openldap_data
index uid eq
EOF

cat >"$artifact_dir/effective-config.env" <<EOF
entries=$entries
page_size=$page_size
indexed_searches=$indexed_searches
unindexed_searches=$unindexed_searches
paged_traversals=$paged_traversals
modifications=$modifications
concurrency=$concurrency
searches_per_connection=$searches_per_connection
openldap_version=$openldap_version
EOF

printf 'Importing %s entries into both servers...\n' "$entries"
measure ldap_go_import_ms "$binary" import -db "$ldap_go_db" -ldif "$seed_ldif" -replace \
	>"$artifact_dir/ldap-go-import.log" 2>"$artifact_dir/ldap-go-import.err"
measure ldap_go_reindex_ms "$binary" slapindex -db "$ldap_go_db" -n 1 uid \
	>"$artifact_dir/ldap-go-reindex.log" 2>"$artifact_dir/ldap-go-reindex.err"
measure openldap_import_ms "$slapadd" -f "$slapd_conf" -l "$content_ldif" \
	>"$artifact_dir/openldap-import.log" 2>"$artifact_dir/openldap-import.err"

wait_ready() {
	uri=$1
	pid=$2
	deadline=$(( $(date +%s) + startup_timeout ))
	while ! "$ldapwhoami" -H "$uri" -x -D "$root_dn" -y "$password_file" \
		-o nettimeout=1 >/dev/null 2>&1; do
		process_running "$pid" || die "server exited before readiness: $uri"
		[ "$(date +%s)" -lt "$deadline" ] || die "server readiness timed out: $uri"
		sleep 0.01
	done
}

ldap_go_started=$(now_ms)
LDAP_GO_ROOT_PASSWORD=$password "$binary" serve \
	-db "$ldap_go_db" -listen "127.0.0.1:$ldap_go_port" -root-dn "$root_dn" \
	-search-limit "$((entries + 100))" -search-candidate-limit "$((entries + 100))" \
	-search-candidate-bytes "$search_candidate_bytes" -search-memory-bytes "$search_memory_bytes" \
	>"$artifact_dir/ldap-go-server.log" 2>&1 &
ldap_go_pid=$!
wait_ready "$ldap_go_uri" "$ldap_go_pid"
ldap_go_startup_ms=$(( $(now_ms) - ldap_go_started ))

openldap_started=$(now_ms)
"$slapd" -f "$slapd_conf" -h "$openldap_uri" -d 0 \
	>"$artifact_dir/openldap-server.log" 2>&1 &
openldap_pid=$!
wait_ready "$openldap_uri" "$openldap_pid"
openldap_startup_ms=$(( $(now_ms) - openldap_started ))

search_indexed() {
	uri=$1
	output=$2
	"$ldapsearch" -H "$uri" -x -D "$root_dn" -y "$password_file" \
		-LLL -b "$people_dn" -f "$artifact_dir/indexed-values.txt" '(uid=%s)' uid >"$output"
}

search_unindexed() {
	uri=$1
	"$ldapsearch" -H "$uri" -x -D "$root_dn" -y "$password_file" \
		-LLL -b "$people_dn" -f "$artifact_dir/unindexed-values.txt" '(description=%s)' uid >/dev/null
}

search_paged() {
	uri=$1
	iteration=0
	while [ "$iteration" -lt "$paged_traversals" ]; do
		"$ldapsearch" -H "$uri" -x -D "$root_dn" -y "$password_file" \
			-LLL -E "pr=$page_size/noprompt" -b "$people_dn" '(uid=scale-*)' uid >/dev/null
		iteration=$((iteration + 1))
	done
}

search_concurrent() {
	uri=$1
	worker=0
	pids=
	while [ "$worker" -lt "$concurrency" ]; do
		"$ldapsearch" -H "$uri" -x -D "$root_dn" -y "$password_file" \
			-LLL -b "$people_dn" -f "$artifact_dir/concurrent-values.txt" '(uid=%s)' uid >/dev/null &
		pids="$pids $!"
		worker=$((worker + 1))
	done
	for pid in $pids; do
		wait "$pid"
	done
}

modify_batch() {
	uri=$1
	"$ldapmodify" -H "$uri" -x -D "$root_dn" -y "$password_file" \
		-f "$artifact_dir/modify.ldif" >/dev/null
}

printf 'Validating equal request and result counts...\n'
search_indexed "$ldap_go_uri" "$artifact_dir/ldap-go-indexed-validation.ldif"
search_indexed "$openldap_uri" "$artifact_dir/openldap-indexed-validation.ldif"
ldap_go_indexed_count=$(awk '/^dn: uid=scale-[0-9]+,ou=people,dc=scale,dc=qualification$/ {count++} END {print count+0}' \
	"$artifact_dir/ldap-go-indexed-validation.ldif")
openldap_indexed_count=$(awk '/^dn: uid=scale-[0-9]+,ou=people,dc=scale,dc=qualification$/ {count++} END {print count+0}' \
	"$artifact_dir/openldap-indexed-validation.ldif")
[ "$ldap_go_indexed_count" -eq "$indexed_searches" ] ||
	die "ldap-go returned $ldap_go_indexed_count indexed results, expected $indexed_searches"
[ "$openldap_indexed_count" -eq "$indexed_searches" ] ||
	die "OpenLDAP returned $openldap_indexed_count indexed results, expected $indexed_searches"

# Warm both servers, then measure each pair in both orders.
"$ldapsearch" -H "$ldap_go_uri" -x -D "$root_dn" -y "$password_file" \
	-LLL -b "$people_dn" '(uid=scale-000001)' uid >/dev/null
"$ldapsearch" -H "$openldap_uri" -x -D "$root_dn" -y "$password_file" \
	-LLL -b "$people_dn" '(uid=scale-000001)' uid >/dev/null

printf 'Measuring indexed and unindexed Search...\n'
measure openldap_indexed_1_ms search_indexed "$openldap_uri" /dev/null
measure ldap_go_indexed_1_ms search_indexed "$ldap_go_uri" /dev/null
measure ldap_go_indexed_2_ms search_indexed "$ldap_go_uri" /dev/null
measure openldap_indexed_2_ms search_indexed "$openldap_uri" /dev/null
measure openldap_unindexed_1_ms search_unindexed "$openldap_uri"
measure ldap_go_unindexed_1_ms search_unindexed "$ldap_go_uri"
measure ldap_go_unindexed_2_ms search_unindexed "$ldap_go_uri"
measure openldap_unindexed_2_ms search_unindexed "$openldap_uri"

printf 'Measuring paging and concurrent Search...\n'
measure openldap_paged_1_ms search_paged "$openldap_uri"
measure ldap_go_paged_1_ms search_paged "$ldap_go_uri"
measure ldap_go_paged_2_ms search_paged "$ldap_go_uri"
measure openldap_paged_2_ms search_paged "$openldap_uri"
measure openldap_concurrent_1_ms search_concurrent "$openldap_uri"
measure ldap_go_concurrent_1_ms search_concurrent "$ldap_go_uri"
measure ldap_go_concurrent_2_ms search_concurrent "$ldap_go_uri"
measure openldap_concurrent_2_ms search_concurrent "$openldap_uri"

printf 'Measuring and validating Modify...\n'
measure openldap_modify_ms modify_batch "$openldap_uri"
measure ldap_go_modify_ms modify_batch "$ldap_go_uri"

for side in ldap-go openldap; do
	case "$side" in ldap-go) uri=$ldap_go_uri ;; openldap) uri=$openldap_uri ;; esac
	"$ldapsearch" -H "$uri" -x -D "$root_dn" -y "$password_file" \
		-LLL -E "pr=$page_size/noprompt" -b "$people_dn" '(uid=scale-*)' uid \
		>"$artifact_dir/$side-all.ldif"
	unique=$(awk '/^dn: uid=scale-[0-9]+,ou=people,dc=scale,dc=qualification$/ {print}' \
		"$artifact_dir/$side-all.ldif" | sort -u | wc -l | tr -d ' ')
	[ "$unique" -eq "$entries" ] || die "$side returned $unique unique entries, expected $entries"
	"$ldapsearch" -H "$uri" -x -D "$root_dn" -y "$password_file" \
		-LLL -b "$people_dn" '(description=benchmark-*)' description \
		>"$artifact_dir/$side-modified.ldif"
	modified=$(awk '/^description: benchmark-[0-9]+$/ {count++} END {print count+0}' \
		"$artifact_dir/$side-modified.ldif")
	[ "$modified" -eq "$modifications" ] ||
		die "$side exposed $modified modified entries, expected $modifications"
	case "$side" in
	ldap-go) ldap_go_unique=$unique; ldap_go_modified=$modified ;;
	openldap) openldap_unique=$unique; openldap_modified=$modified ;;
	esac
done

ldap_go_rss_bytes=$(rss_bytes_for_pid "$ldap_go_pid")
openldap_rss_bytes=$(rss_bytes_for_pid "$openldap_pid")
case "$ldap_go_rss_bytes:$openldap_rss_bytes" in
	*[!0-9:]*|:*|*:) ldap_go_rss_bytes=0; openldap_rss_bytes=0 ;;
esac
ldap_go_db_bytes=$(wc -c <"$ldap_go_db" | tr -d ' ')
openldap_db_bytes=$(find "$openldap_data" -type f -exec wc -c {} \; |
	awk '{total += $1} END {print total+0}')

ldap_go_indexed_ms=$(( (ldap_go_indexed_1_ms + ldap_go_indexed_2_ms) / 2 ))
openldap_indexed_ms=$(( (openldap_indexed_1_ms + openldap_indexed_2_ms) / 2 ))
ldap_go_unindexed_ms=$(( (ldap_go_unindexed_1_ms + ldap_go_unindexed_2_ms) / 2 ))
openldap_unindexed_ms=$(( (openldap_unindexed_1_ms + openldap_unindexed_2_ms) / 2 ))
ldap_go_paged_ms=$(( (ldap_go_paged_1_ms + ldap_go_paged_2_ms) / 2 ))
openldap_paged_ms=$(( (openldap_paged_1_ms + openldap_paged_2_ms) / 2 ))
ldap_go_concurrent_ms=$(( (ldap_go_concurrent_1_ms + ldap_go_concurrent_2_ms) / 2 ))
openldap_concurrent_ms=$(( (openldap_concurrent_1_ms + openldap_concurrent_2_ms) / 2 ))
ldap_go_import_index_ms=$((ldap_go_import_ms + ldap_go_reindex_ms))

ratio() {
	awk -v numerator="$1" -v denominator="$2" 'BEGIN {
		if (denominator == 0) print "n/a"; else printf "%.2f", numerator / denominator
	}'
}

{
	printf 'metric\tldap_go\topenldap\tldap_go_over_openldap\tworkload\n'
	printf 'offline_import_plus_index_ms\t%s\t%s\t%s\t%s entries with uid equality index\n' \
		"$ldap_go_import_index_ms" "$openldap_import_ms" "$(ratio "$ldap_go_import_index_ms" "$openldap_import_ms")" "$entries"
	printf 'startup_ready_ms\t%s\t%s\t%s\tauthenticated WhoAmI readiness\n' \
		"$ldap_go_startup_ms" "$openldap_startup_ms" "$(ratio "$ldap_go_startup_ms" "$openldap_startup_ms")"
	printf 'indexed_search_ms\t%s\t%s\t%s\t%s sequential searches per round\n' \
		"$ldap_go_indexed_ms" "$openldap_indexed_ms" "$(ratio "$ldap_go_indexed_ms" "$openldap_indexed_ms")" "$indexed_searches"
	printf 'unindexed_negative_ms\t%s\t%s\t%s\t%s full negative scans per round\n' \
		"$ldap_go_unindexed_ms" "$openldap_unindexed_ms" "$(ratio "$ldap_go_unindexed_ms" "$openldap_unindexed_ms")" "$unindexed_searches"
	printf 'paged_search_ms\t%s\t%s\t%s\t%s full traversals per round, page size %s\n' \
		"$ldap_go_paged_ms" "$openldap_paged_ms" "$(ratio "$ldap_go_paged_ms" "$openldap_paged_ms")" "$paged_traversals" "$page_size"
	printf 'concurrent_indexed_ms\t%s\t%s\t%s\t%s connections x %s searches per round\n' \
		"$ldap_go_concurrent_ms" "$openldap_concurrent_ms" "$(ratio "$ldap_go_concurrent_ms" "$openldap_concurrent_ms")" "$concurrency" "$searches_per_connection"
	printf 'modify_ms\t%s\t%s\t%s\t%s replaces\n' \
		"$ldap_go_modify_ms" "$openldap_modify_ms" "$(ratio "$ldap_go_modify_ms" "$openldap_modify_ms")" "$modifications"
	printf 'rss_bytes\t%s\t%s\t%s\tafter workload\n' \
		"$ldap_go_rss_bytes" "$openldap_rss_bytes" "$(ratio "$ldap_go_rss_bytes" "$openldap_rss_bytes")"
	printf 'database_bytes\t%s\t%s\t%s\tlogical file size\n' \
		"$ldap_go_db_bytes" "$openldap_db_bytes" "$(ratio "$ldap_go_db_bytes" "$openldap_db_bytes")"
	printf 'unique_entries\t%s\t%s\t1.00\tpaged correctness\n' "$ldap_go_unique" "$openldap_unique"
	printf 'modified_entries\t%s\t%s\t1.00\tpost-write correctness\n' "$ldap_go_modified" "$openldap_modified"
} >"$results"

finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
cat >"$report" <<EOF
{
  "report_version": 1,
  "result": "pass",
  "finished_at": "$finished_at",
  "openldap_version": "$openldap_version",
  "openldap_commit": "${OPENLDAP_COMMIT:-unknown}",
  "entries": $entries,
  "page_size": $page_size,
  "workloads": {
    "indexed_searches": $indexed_searches,
    "unindexed_searches": $unindexed_searches,
    "paged_traversals": $paged_traversals,
    "modifications": $modifications,
    "concurrency": $concurrency,
    "searches_per_connection": $searches_per_connection
  },
  "timings_ms": {
    "ldap_go": {"import": $ldap_go_import_ms, "reindex": $ldap_go_reindex_ms, "import_plus_index": $ldap_go_import_index_ms, "startup": $ldap_go_startup_ms, "indexed": $ldap_go_indexed_ms, "unindexed": $ldap_go_unindexed_ms, "paged": $ldap_go_paged_ms, "concurrent": $ldap_go_concurrent_ms, "modify": $ldap_go_modify_ms},
    "openldap": {"import_plus_index": $openldap_import_ms, "startup": $openldap_startup_ms, "indexed": $openldap_indexed_ms, "unindexed": $openldap_unindexed_ms, "paged": $openldap_paged_ms, "concurrent": $openldap_concurrent_ms, "modify": $openldap_modify_ms}
  },
  "resources": {
    "ldap_go": {"rss_bytes": $ldap_go_rss_bytes, "database_bytes": $ldap_go_db_bytes},
    "openldap": {"rss_bytes": $openldap_rss_bytes, "database_bytes": $openldap_db_bytes}
  },
  "correctness": {
    "ldap_go": {"indexed_results": $ldap_go_indexed_count, "unique_entries": $ldap_go_unique, "modified_entries": $ldap_go_modified},
    "openldap": {"indexed_results": $openldap_indexed_count, "unique_entries": $openldap_unique, "modified_entries": $openldap_modified}
  }
}
EOF

stop_process "$ldap_go_pid"
ldap_go_pid=
stop_process "$openldap_pid"
openldap_pid=
rm -f "$password_file"
trap - EXIT HUP INT TERM

printf 'OpenLDAP comparison passed.\n'
printf 'Results: %s\n' "$results"
printf 'Report: %s\n' "$report"
sed -n '1,20p' "$results"

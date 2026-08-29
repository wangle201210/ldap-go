#!/bin/sh

set -u

die() {
	printf 'qualification-worker: %s\n' "$*" >&2
	exit 1
}

if [ "$#" -ne 13 ]; then
	die "expected 13 arguments, got $#"
fi

binary=$1
uri=$2
root_dn=$3
password_file=$4
base_dn=$5
worker_number=$6
deadline=$7
batch_size=$8
client_timeout=$9
artifact_dir=${10}
operations_csv=${11}
stop_file=${12}
retry_delay=${13}

worker_id=$(printf '%04d' "$worker_number")
uid=qualification-$worker_id
entry_dn="uid=$uid,ou=qualification,$base_dn"
temporary_dn="uid=qualification-temp-$worker_id,ou=qualification,$base_dn"
worker_dir=$artifact_dir/workers/$worker_id
mkdir -p "$worker_dir" || die "cannot create $worker_dir"

search_batch=$worker_dir/search.batch
modify_batch=$worker_dir/modify.ldif
add_ldif=$worker_dir/add.ldif
events=$worker_dir/events.tsv
errors=$worker_dir/errors.log
metrics=$worker_dir/metrics.env
metrics_tmp=$worker_dir/metrics.env.tmp

: >"$search_batch"
: >"$events"
: >"$errors"

index=1
while [ "$index" -le "$batch_size" ]; do
	printf '%s\n' "$uid" >>"$search_batch"
	index=$((index + 1))
done

{
	printf 'dn: %s\n' "$temporary_dn"
	printf 'objectClass: top\n'
	printf 'objectClass: person\n'
	printf 'objectClass: organizationalPerson\n'
	printf 'objectClass: inetOrgPerson\n'
	printf 'uid: qualification-temp-%s\n' "$worker_id"
	printf 'cn: Qualification Temporary %s\n' "$worker_id"
	printf 'sn: Temporary\n'
} >"$add_ldif"

attempted=0
succeeded=0
failed=0
stop_requested=0
last_modify_sequence=0

write_metrics() {
	{
		printf 'worker=%s\n' "$worker_id"
		printf 'attempted=%s\n' "$attempted"
		printf 'succeeded=%s\n' "$succeeded"
		printf 'failed=%s\n' "$failed"
		printf 'last_modify_sequence=%s\n' "$last_modify_sequence"
	} >"$metrics_tmp"
	mv "$metrics_tmp" "$metrics"
}

request_stop() {
	stop_requested=1
}

trap request_stop HUP INT TERM
trap write_metrics EXIT

run_search() {
	# ldapsearch batch mode keeps one authenticated connection for the batch.
	search_output=$worker_dir/search.out
	if ! "$binary" ldapsearch \
		-H "$uri" -x -D "$root_dn" -y "$password_file" \
		-timeout "$client_timeout" -LLL \
		-b "$base_dn" -s sub -f "$search_batch" '(uid=%s)' uid \
		>"$search_output" 2>>"$errors"; then
		return 1
	fi
	result_count=$(grep -Fxc "dn: $entry_dn" "$search_output" || true)
	[ "$result_count" -eq "$batch_size" ]
}

run_modify() {
	next_sequence=$((last_modify_sequence + 1))
	: >"$modify_batch"
	index=1
	while [ "$index" -le "$batch_size" ]; do
		{
			printf 'dn: %s\n' "$entry_dn"
			printf 'changetype: modify\n'
			printf 'replace: description\n'
			printf 'description: qualification-worker-%s-sequence-%s\n\n' \
				"$worker_id" "$next_sequence"
		} >>"$modify_batch"
		index=$((index + 1))
	done
	# ldapmodify likewise sends all records over one authenticated connection.
	if "$binary" ldapmodify \
		-H "$uri" -x -D "$root_dn" -y "$password_file" \
		-timeout "$client_timeout" -f "$modify_batch" \
		>/dev/null 2>>"$errors"; then
		last_modify_sequence=$next_sequence
		return 0
	fi
	return 1
}

run_compare() {
	compare_output=$worker_dir/compare.out
	# LDAP Compare TRUE is result code 6, matching the historical command.
	"$binary" ldapcompare \
		-H "$uri" -x -D "$root_dn" -y "$password_file" \
		-timeout "$client_timeout" "$entry_dn" "uid:$uid" \
		>"$compare_output" 2>>"$errors"
	status=$?
	[ "$status" -eq 6 ] && grep -qx 'TRUE' "$compare_output"
}

run_bind() {
	"$binary" ldapwhoami \
		-H "$uri" -x -D "$root_dn" -y "$password_file" \
		-timeout "$client_timeout" >/dev/null 2>>"$errors"
}

run_add_delete() {
	# A previous KILL can leave this worker's temporary entry committed after the
	# client loses its response. Make the operation retryable by cleaning it first.
	"$binary" ldapdelete \
		-H "$uri" -x -D "$root_dn" -y "$password_file" \
		-timeout "$client_timeout" "$temporary_dn" \
		>/dev/null 2>&1 || true
	"$binary" ldapadd \
		-H "$uri" -x -D "$root_dn" -y "$password_file" \
		-timeout "$client_timeout" -f "$add_ldif" \
		>/dev/null 2>>"$errors" || return 1
	"$binary" ldapdelete \
		-H "$uri" -x -D "$root_dn" -y "$password_file" \
		-timeout "$client_timeout" "$temporary_dn" \
		>/dev/null 2>>"$errors"
}

operation_weight() {
	case "$1" in
	search|modify) printf '%s\n' "$batch_size" ;;
	*) printf '1\n' ;;
	esac
}

run_operation() {
	case "$1" in
	search) run_search ;;
	compare) run_compare ;;
	modify) run_modify ;;
	bind) run_bind ;;
	add-delete) run_add_delete ;;
	*) return 1 ;;
	esac
}

operations=$(printf '%s' "$operations_csv" | tr ',' ' ')
# The orchestrator validates every token before starting workers.
# shellcheck disable=SC2086
set -- $operations

while [ "$stop_requested" -eq 0 ] && [ ! -e "$stop_file" ]; do
	for operation in "$@"; do
		now=$(date +%s)
		if [ "$stop_requested" -ne 0 ] || [ -e "$stop_file" ] || [ "$now" -ge "$deadline" ]; then
			stop_requested=1
			break
		fi
		weight=$(operation_weight "$operation")
		attempted=$((attempted + weight))
		started=$(date +%s)
		if run_operation "$operation"; then
			succeeded=$((succeeded + weight))
			status=ok
		else
			failed=$((failed + weight))
			status=failed
		fi
		finished=$(date +%s)
		printf '%s\t%s\t%s\t%s\n' \
			"$finished" "$operation" "$weight" "$status" >>"$events"
		if [ "$status" = failed ] && [ "$finished" -lt "$deadline" ]; then
			sleep "$retry_delay"
		fi
		# Keep the variables in the event log sufficient for post-run throughput
		# analysis without requiring high-resolution date extensions.
		: "$started"
	done
done

exit 0

#!/bin/sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

fuzz_time=${LDAP_GO_FUZZ_TIME:-5s}
minimize_time=${LDAP_GO_FUZZ_MINIMIZE_TIME:-100x}
parallel=${LDAP_GO_FUZZ_PARALLEL:-2}

run_target() {
	package=$1
	target=$2
	printf '\nFuzzing %s/%s for %s\n' "$package" "$target" "$fuzz_time"
	go test "$package" \
		-run '^$' \
		-fuzz "^${target}$" \
		-fuzztime "$fuzz_time" \
		-fuzzminimizetime "$minimize_time" \
		-parallel "$parallel"
}

run_target ./internal/ldapwire FuzzReadMessageRoundTrip
run_target ./internal/ldapwire FuzzDecodeFilterRoundTrip
run_target ./internal/directory FuzzParseDNRoundTrip
run_target ./internal/schema FuzzSchemaDescriptionRoundTrip
run_target ./internal/migration FuzzLDIFSemanticRoundTrip

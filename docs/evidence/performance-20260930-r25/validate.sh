#!/bin/sh
set -eu
cd /var/tmp/ldap-go-direct-get-20260930
audit=/var/tmp/ldap-go-perf-20260930-r25-lazy-get
export CGO_ENABLED=0
go test ./internal/storage ./internal/server -run '^Test(GetReadOnly|EntryReadLease|CompareReadLease)' -count=1 >"$audit/focused.txt" 2>&1
go test ./... >"$audit/go-test.txt" 2>&1
go vet ./... >"$audit/go-vet.txt" 2>&1
. /var/tmp/ldap-go-openldap-reference-r20-rebuilt/openldap-reference.env
reference_tests=$(awk '/^=== RUN   / && $3 !~ /\// {printf "%s%s", sep, $3; sep="|"}' /Users/wanna/mine/github/ldap-go/docs/evidence/performance-20260930-r19/openldap-differential.txt)
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 go test ./internal/server -run "^($reference_tests)$" -count=1 -timeout=5m -v >"$audit/openldap-differential.txt" 2>&1
printf 'Full validation passed.\n'

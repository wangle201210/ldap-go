#!/bin/sh
set -eu
cd /var/tmp/ldap-go-normalized-prefix-20260930
audit=/var/tmp/ldap-go-perf-20260930-r21
export CGO_ENABLED=0
go test ./... >"$audit/go-test-final.txt" 2>&1
go vet ./... >"$audit/go-vet-final.txt" 2>&1
. /var/tmp/ldap-go-openldap-reference-r20-rebuilt/openldap-reference.env
reference_tests=$(awk '/^=== RUN   / && $3 !~ /\// {printf "%s%s", sep, $3; sep="|"}' /Users/wanna/mine/github/ldap-go/docs/evidence/performance-20260930-r19/openldap-differential.txt)
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 go test ./internal/server -run "^($reference_tests)$" -count=1 -timeout=5m -v >"$audit/openldap-differential-final.txt" 2>&1
go test -c -o "$audit/server-final.test" ./internal/server
printf 'Full tests, vet and native differential checks passed.\n'

#!/bin/sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

find_tool() {
	name=$1
	shift
	if command -v "$name" >/dev/null 2>&1; then
		command -v "$name"
		return
	fi
	for candidate in "$@"; do
		if [ -x "$candidate" ]; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	printf 'required OpenLDAP tool %s was not found\n' "$name" >&2
	exit 1
}

slapd=$(find_tool slapd \
	/opt/homebrew/opt/openldap/libexec/slapd \
	/usr/lib/openldap/slapd \
	/usr/sbin/slapd)
slapadd=$(find_tool slapadd \
	/opt/homebrew/opt/openldap/sbin/slapadd \
	/usr/sbin/slapadd)

tool_dirs="$(dirname "$slapd"):$(dirname "$slapadd")"
for directory in \
	/opt/homebrew/opt/openldap/bin \
	/opt/homebrew/opt/openldap/sbin \
	/opt/homebrew/opt/openldap/libexec \
	/usr/bin \
	/usr/sbin
do
	if [ -d "$directory" ]; then
		tool_dirs="$tool_dirs:$directory"
	fi
done
PATH="$tool_dirs:$PATH"
export PATH

for tool in slapcat slaptest ldapsearch ldapmodify ldapwhoami ldapexop; do
	find_tool "$tool" >/dev/null
done

schema_dir=${OPENLDAP_SCHEMA_DIR:-}
if [ -z "$schema_dir" ]; then
	for candidate in \
		/opt/homebrew/etc/openldap/schema \
		/etc/ldap/schema \
		/etc/openldap/schema
	do
		if [ -f "$candidate/core.schema" ]; then
			schema_dir=$candidate
			break
		fi
	done
fi
if [ -z "$schema_dir" ] || [ ! -f "$schema_dir/core.schema" ]; then
	printf 'OpenLDAP core.schema was not found; set OPENLDAP_SCHEMA_DIR\n' >&2
	exit 1
fi
OPENLDAP_SCHEMA_DIR=$schema_dir
export OPENLDAP_SCHEMA_DIR

version_output=$("$slapd" -VV 2>&1 || true)
version=$(printf '%s\n' "$version_output" | sed -n 's/.*slapd \([^[:space:]]*\).*/\1/p' | head -n 1)
expected_version=${OPENLDAP_EXPECTED_VERSION:-2.6.13}
if [ "$version" != "$expected_version" ]; then
	printf 'OpenLDAP version %s is required, found %s at %s\n' \
		"$expected_version" "${version:-unknown}" "$slapd" >&2
	exit 1
fi

printf 'OpenLDAP reference: %s (%s)\n' "$version" "$slapd"
if [ -n "${OPENLDAP_COMMIT:-}" ]; then
	printf 'OpenLDAP commit:    %s (verified=%s)\n' \
		"$OPENLDAP_COMMIT" "${OPENLDAP_REFERENCE_VERIFIED:-unknown}"
fi
printf 'OpenLDAP schema:    %s\n' "$OPENLDAP_SCHEMA_DIR"

log=$(mktemp "${TMPDIR:-/tmp}/ldap-go-openldap.XXXXXX")
trap 'rm -f "$log"' EXIT HUP INT TERM

test_status=0
test_parallel=${LDAP_GO_OPENLDAP_PARALLEL:-1}
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
	go test ./internal/server \
		-count=1 \
		-timeout=30m \
		-parallel="$test_parallel" \
		-v >"$log" 2>&1 || test_status=$?
if [ "$test_status" -ne 0 ]; then
	cat "$log"
	exit "$test_status"
fi

skips=$(sed -n 's/^--- SKIP: \([^ (]*\).*/\1/p' "$log")
unexpected_skips=
for skipped in $skips; do
	case "$skipped" in
		TestOpenLDAPClientSASLSCRAMSHA256Bind|\
		TestLDAPGoSyncreplConsumesOpenLDAPProviderWithSCRAMSHA256|\
		TestOpenLDAPReferenceLDAPBackend|\
		TestOpenLDAPReferenceMeta*|\
		TestOpenLDAPReferenceDerefOverlayRegistration|\
		TestOpenLDAPReferenceDerefControlValidation|\
		TestOpenLDAPReferenceDerefResponseSemantics|\
		TestOpenLDAPReferenceHomedirOverlay|\
		TestOpenLDAPReferenceNullBackend|\
		TestOpenLDAPReferencePBindOverlay|\
		TestOpenLDAPReferenceRemoteAuthOverlay|\
		TestOpenLDAPReferenceRelayBackend)
			if [ "${LDAP_GO_FAIL_ON_OPTIONAL_SKIP:-0}" = "1" ]; then
				unexpected_skips="${unexpected_skips}${unexpected_skips:+ }$skipped"
			fi
			;;
		*)
			unexpected_skips="${unexpected_skips}${unexpected_skips:+ }$skipped"
			;;
	esac
done

if ! grep -q '^--- PASS: TestOpenLDAPReferenceCoreProtocolDifferential ' "$log"; then
	printf 'mandatory core OpenLDAP differential did not run\n' >&2
	exit 1
fi
if [ -n "$unexpected_skips" ]; then
	printf 'unexpected skipped top-level tests: %s\n' "$unexpected_skips" >&2
	exit 1
fi

passes=$(sed -n 's/^--- PASS: \(Test[^ (]*\).*/\1/p' "$log" | wc -l | tr -d ' ')
if [ -n "$skips" ]; then
	printf 'OpenLDAP suite passed: %s top-level tests; optional skips:\n%s\n' \
		"$passes" "$skips"
else
	printf 'OpenLDAP suite passed: %s top-level tests; no skips\n' "$passes"
fi

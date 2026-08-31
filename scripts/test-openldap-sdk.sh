#!/bin/sh

set -eu

die() {
	printf 'test-openldap-sdk: %s\n' "$*" >&2
	exit 1
}

if [ "$#" -ne 0 ]; then
	die "this script accepts configuration through OPENLDAP_ENV_FILE only"
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
env_file=${OPENLDAP_ENV_FILE:-}
[ -n "$env_file" ] || die "OPENLDAP_ENV_FILE is required"
[ -r "$env_file" ] || die "OPENLDAP_ENV_FILE is not readable: $env_file"
# shellcheck disable=SC1090
. "$env_file"

verified_commit=d172686d3d270bc961b78f3ff00d7019c8dfb094
[ "${OPENLDAP_REFERENCE_VERIFIED:-0}" = 1 ] ||
	die "the OpenLDAP reference environment is not verified"
[ "${OPENLDAP_COMMIT:-}" = "$verified_commit" ] ||
	die "OpenLDAP commit is ${OPENLDAP_COMMIT:-unset}, expected $verified_commit"
[ "${OPENLDAP_VERIFIED_COMMIT:-}" = "$verified_commit" ] ||
	die "verified OpenLDAP commit is ${OPENLDAP_VERIFIED_COMMIT:-unset}, expected $verified_commit"
[ "${OPENLDAP_ACTUAL_VERSION:-}" = 2.6.13 ] ||
	die "OpenLDAP version is ${OPENLDAP_ACTUAL_VERSION:-unset}, expected 2.6.13"
[ -x "${OPENLDAP_SLAPD:-}" ] || die "OPENLDAP_SLAPD is not executable"
[ -x "${OPENLDAP_SLAPADD:-}" ] || die "OPENLDAP_SLAPADD is not executable"
[ -f "${OPENLDAP_SCHEMA_DIR:-}/core.schema" ] ||
	die "OPENLDAP_SCHEMA_DIR has no core.schema"

LDAP_GO_OPENLDAP_REFERENCE_TESTS=1
export LDAP_GO_OPENLDAP_REFERENCE_TESTS

cd "$root"
exec go test -count=1 -timeout=5m -v ./internal/server \
	-run '^TestOpenLDAPReferenceGoLDAPSDKStateMachineDifferential$'

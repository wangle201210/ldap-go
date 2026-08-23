#!/bin/sh

set -eu

die() {
	printf 'test-build-openldap-reference: %s\n' "$*" >&2
	exit 1
}

shell_quote() {
	printf "'"
	printf '%s' "$1" | sed "s/'/'\\\\''/g"
	printf "'"
}

write_export() {
	printf 'export %s=' "$1"
	shell_quote "$2"
	printf '\n'
}

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
script=$root/scripts/build-openldap-reference.sh

sh -n "$script" || die "build script has invalid shell syntax"

assignments=$(sed -n '/^[[:space:]]*runtime_dependency_path=.*runtime_dependency_path/p' "$script")
assignment_count=$(printf '%s\n' "$assignments" | sed '/^$/d' | wc -l | tr -d '[:space:]')
if [ "$assignment_count" -ne 5 ]; then
	die "expected one runtime dependency assignment for each of ODBC, OpenSSL, libtool, libevent, and Cyrus SASL; found $assignment_count"
fi

odbc_prefix='/opt/ODBC Test'
odbc_lib_dir='/opt/ODBC Test/lib'
openssl_prefix='/opt/OpenSSL Test'
libtool_prefix='/opt/Libtool Test'
libevent_lib_dir='/opt/Libevent Test/lib64'
cyrus_sasl_lib_dir='/opt/Cyrus SASL Test/lib'
runtime_dependency_path=
eval "$assignments"

expected_dependency_path='/opt/Cyrus SASL Test/lib:/opt/Libevent Test/lib64:/opt/Libtool Test/lib:/opt/OpenSSL Test/lib:/opt/ODBC Test/lib'
if [ "$runtime_dependency_path" != "$expected_dependency_path" ]; then
	die "runtime dependency assignments overwrote or omitted an earlier dependency: $runtime_dependency_path"
fi

if ! sed -n '/^[[:space:]]*\*--with-odbc\*) set -- .*--with-odbc=unixodbc/p' "$script" |
	grep -F -- '--with-odbc=unixodbc' >/dev/null 2>&1; then
	die "ODBC_PREFIX does not force the unixODBC configure backend"
fi

if grep -F '"$built_slapd" -VVV 2>&1 || true' "$script" >/dev/null 2>&1; then
	die "slapd feature verification still ignores a non-zero exit status"
fi
if ! grep -F 'the built slapd -VVV exited' "$script" >/dev/null 2>&1; then
	die "slapd feature verification does not report a non-zero exit status"
fi
if ! grep -F '"$odbc_prefix/lib64"' "$script" >/dev/null 2>&1; then
	die "ODBC library discovery does not support lib64"
fi
if ! grep -F 'lib/*-linux-gnu' "$script" >/dev/null 2>&1; then
	die "ODBC library discovery does not support multiarch directories"
fi

runtime_setup=$(sed -n '/^openldap_library_path=/,/^if feature_output=/p' "$script" | sed '$d')
if [ -z "$runtime_setup" ]; then
	die "could not locate runtime library path setup"
fi

artifact_build_dir='/tmp/OpenLDAP Reference Build'
DYLD_FALLBACK_LIBRARY_PATH='/ambient/dyld-fallback'
eval "$runtime_setup"

expected_openldap_path='/tmp/OpenLDAP Reference Build/libraries/libldap/.libs:/tmp/OpenLDAP Reference Build/libraries/liblber/.libs'
expected_runtime_path="$expected_openldap_path:$expected_dependency_path"
if [ "$openldap_library_path" != "$expected_openldap_path" ]; then
	die "OpenLDAP runtime library path was generated incorrectly: $openldap_library_path"
fi
if [ "$runtime_library_path" != "$expected_runtime_path" ]; then
	die "runtime library path did not preserve all dependency paths: $runtime_library_path"
fi
if [ "$dyld_fallback_path" != "$expected_dependency_path:/ambient/dyld-fallback" ]; then
	die "DYLD fallback path did not preserve dependencies and the existing environment: $dyld_fallback_path"
fi

env_writer=$(sed -n '/^tool_path=/,/^} >"\$env_file"$/p' "$script")
if [ -z "$env_writer" ]; then
	die "could not locate reference environment writer"
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/ldap-go-openldap-build-test.XXXXXX") ||
	die "could not create temporary directory"
trap 'rm -rf "$tmp_dir"' 0 1 2 15
env_file=$tmp_dir/openldap-reference.env

# The writer must replace an environment file from an earlier build, not append
# new exports after stale runtime paths.
printf '%s\n' "export LD_LIBRARY_PATH='/stale/without-unixodbc'" >"$env_file"

slap_tool_dir='/tmp/OpenLDAP Reference Build/reference-tools'
source_dir='/tmp/OpenLDAP Source'
revision=synthetic-revision
verified_revision=verified-revision
allow_unverified_reference=0
requested_build_dir=$artifact_build_dir
effective_build_dir=$artifact_build_dir
prefix_dir='/tmp/OpenLDAP Reference Build/prefix'
cppflags=
ldflags=
slapd='/tmp/OpenLDAP Reference Build/servers/slapd/slapd'
slapadd='/tmp/OpenLDAP Reference Build/reference-tools/slapadd'
lloadd='/tmp/OpenLDAP Reference Build/servers/lloadd/lloadd'
schema_dir='/tmp/OpenLDAP Source/servers/slapd/schema'
version=2.6.13
expected_runtime_version=2.6.13
sasl_plugin_path="$cyrus_sasl_lib_dir/sasl2"
eval "$env_writer"

sh -n "$env_file" || die "generated reference environment has invalid shell syntax"
if grep -F '/stale/without-unixodbc' "$env_file" >/dev/null 2>&1; then
	die "reference environment writer retained stale runtime paths"
fi

(
	PATH='/ambient/bin'
	DYLD_LIBRARY_PATH='/ambient/dyld'
	DYLD_FALLBACK_LIBRARY_PATH='/ambient/dyld-fallback'
	LD_LIBRARY_PATH='/ambient/ld'
	SASL_PATH='/ambient/sasl'
	. "$env_file"

	if [ "$DYLD_LIBRARY_PATH" != "$expected_openldap_path:/ambient/dyld" ]; then
		die "generated DYLD_LIBRARY_PATH is incomplete: $DYLD_LIBRARY_PATH"
	fi
	if [ "$DYLD_FALLBACK_LIBRARY_PATH" != "$expected_dependency_path:/ambient/dyld-fallback" ]; then
		die "generated DYLD_FALLBACK_LIBRARY_PATH lost a dependency: $DYLD_FALLBACK_LIBRARY_PATH"
	fi
	if [ "$LD_LIBRARY_PATH" != "$expected_runtime_path:/ambient/ld" ]; then
		die "generated LD_LIBRARY_PATH lost OpenLDAP or dependency paths: $LD_LIBRARY_PATH"
	fi
	if [ "$SASL_PATH" != "$cyrus_sasl_lib_dir/sasl2:/ambient/sasl" ]; then
		die "generated SASL_PATH is incomplete: $SASL_PATH"
	fi
)

printf 'build-openldap-reference runtime dependency path test passed\n'

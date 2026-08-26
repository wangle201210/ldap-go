#!/bin/sh

set -eu

die() {
	printf 'test-openldap: %s\n' "$*" >&2
	exit 1
}

if [ "$#" -ne 0 ]; then
	die "this script accepts configuration through OPENLDAP_ENV_FILE, HAPROXY_SOURCE, HAPROXY_COMMIT, LDAP_GO_OPENLDAP_STRICT, LDAP_GO_FAIL_ON_OPTIONAL_SKIP, LDAP_GO_OPENLDAP_PARALLEL, LDAP_GO_SQLITE_ODBC_DRIVER, LDAP_GO_OPENLDAP_GSSAPI_AUTO, and the exported OpenLDAP reference environment"
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

strict=${LDAP_GO_OPENLDAP_STRICT:-0}
fail_on_optional_skip=${LDAP_GO_FAIL_ON_OPTIONAL_SKIP:-$strict}
for flag_name in strict fail_on_optional_skip; do
	case "$flag_name" in
		strict) flag_value=$strict ;;
		fail_on_optional_skip) flag_value=$fail_on_optional_skip ;;
	esac
	case "$flag_value" in
		0|1) ;;
		*) die "$flag_name must be 0 or 1, got: $flag_value" ;;
	esac
done
if [ "$strict" = "1" ] && [ "$fail_on_optional_skip" != "1" ]; then
	die "strict mode requires LDAP_GO_FAIL_ON_OPTIONAL_SKIP=1"
fi

if [ -n "${OPENLDAP_ENV_FILE:-}" ]; then
	if [ ! -r "$OPENLDAP_ENV_FILE" ]; then
		die "OPENLDAP_ENV_FILE is not readable: $OPENLDAP_ENV_FILE"
	fi
	# shellcheck disable=SC1090
	. "$OPENLDAP_ENV_FILE"
fi

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

find_optional_tool() {
	name=$1
	shift
	for candidate in "$@"; do
		if [ -x "$candidate" ]; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	if command -v "$name" >/dev/null 2>&1; then
		command -v "$name"
		return
	fi
	return 1
}

slapd=$(find_tool slapd \
	"${OPENLDAP_SLAPD:-}" \
	/opt/homebrew/opt/openldap/libexec/slapd \
	/usr/lib/openldap/slapd \
	/usr/sbin/slapd)
slapadd=$(find_tool slapadd \
	"${OPENLDAP_SLAPADD:-}" \
	/opt/homebrew/opt/openldap/sbin/slapadd \
	/usr/sbin/slapadd)
slappasswd=$(find_tool slappasswd \
	"${OPENLDAP_SLAPPASSWD:-}" \
	/opt/homebrew/opt/openldap/sbin/slappasswd \
	/usr/sbin/slappasswd)
lloadd=$(find_tool lloadd \
	"${OPENLDAP_LLOADD:-}" \
	/opt/homebrew/opt/openldap/libexec/lloadd \
	/usr/lib/openldap/lloadd \
	/usr/sbin/lloadd)
OPENLDAP_LLOADD=$lloadd
export OPENLDAP_LLOADD

# The reference builder places argv[0]-preserving slap* links next to slapadd.
# Keep that directory ahead of libtool's servers/slapd wrappers, which lose the
# requested tool name when they exec .libs/slapd.
tool_dirs="$(dirname "$slapadd"):$(dirname "$slapd"):$(dirname "$lloadd")"
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

if [ "$strict" = "1" ]; then
	for capability in \
		OPENLDAP_HAS_BACKEND_PASSWD \
		OPENLDAP_HAS_BACKEND_DNSSRV \
		OPENLDAP_HAS_BACKEND_ASYNCMETA \
		OPENLDAP_HAS_SLAPD_CRYPT
	do
		eval "capability_value=\${$capability:-}"
		if [ "$capability_value" != "1" ]; then
			die "strict reference environment is missing $capability=1; rebuild it with LDAP_GO_OPENLDAP_REBUILD=1"
		fi
	done
fi
if ! command -v go >/dev/null 2>&1; then
	die "go was not found"
fi

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
	die "OpenLDAP core.schema was not found; set OPENLDAP_SCHEMA_DIR"
fi
OPENLDAP_SCHEMA_DIR=$schema_dir
export OPENLDAP_SCHEMA_DIR

version_output=$("$slapd" -VV 2>&1 || true)
version=$(printf '%s\n' "$version_output" | sed -n 's/.*slapd \([^[:space:]]*\).*/\1/p' | head -n 1)
expected_version=${OPENLDAP_EXPECTED_VERSION:-2.6.13}
if [ "$version" != "$expected_version" ]; then
	die "OpenLDAP version $expected_version is required, found ${version:-unknown} at $slapd"
fi
lloadd_version_output=$("$lloadd" -VV 2>&1 || true)
lloadd_version=$(printf '%s\n' "$lloadd_version_output" | sed -n 's/.*lloadd \([^[:space:]]*\).*/\1/p' | head -n 1)
if [ "$lloadd_version" != "$expected_version" ]; then
	die "OpenLDAP lloadd version $expected_version is required, found ${lloadd_version:-unknown} at $lloadd"
fi

feature_output=$("$slapd" -VVV 2>&1) ||
	die "cannot inspect OpenLDAP reference features at $slapd"
for backend in passwd dnssrv asyncmeta; do
	case "$feature_output" in
		*"    $backend"*) ;;
		*) die "OpenLDAP reference does not expose required backend: $backend" ;;
	esac
done
crypt_probe=$($slappasswd -s ldap-go-strict-crypt-probe -h '{CRYPT}' 2>&1) ||
	die "OpenLDAP reference does not support {CRYPT}: $crypt_probe"
case "$crypt_probe" in
	'{CRYPT}'?*) ;;
	*) die "OpenLDAP reference returned an invalid {CRYPT} probe: $crypt_probe" ;;
esac

gssapi_auto=${LDAP_GO_OPENLDAP_GSSAPI_AUTO:-1}
case "$gssapi_auto" in
	0|1) ;;
	*) die "LDAP_GO_OPENLDAP_GSSAPI_AUTO must be 0 or 1, got: $gssapi_auto" ;;
esac
gssapi_reference=0
krb5kdc=
if [ "$gssapi_auto" = "1" ]; then
	krb5kdc=$(find_optional_tool krb5kdc \
		/opt/homebrew/opt/krb5/sbin/krb5kdc \
		/usr/local/opt/krb5/sbin/krb5kdc \
		/usr/sbin/krb5kdc || true)
fi
if [ -n "$krb5kdc" ]; then
	krb5_sbin=$(dirname "$krb5kdc")
	krb5_prefix=$(dirname "$krb5_sbin")
	krb5_bin=$krb5_prefix/bin
	kdb5_util=$(find_optional_tool kdb5_util "$krb5_sbin/kdb5_util" /usr/sbin/kdb5_util || true)
	kadmin_local=$(find_optional_tool kadmin.local "$krb5_sbin/kadmin.local" /usr/sbin/kadmin.local || true)
	kinit=$(find_optional_tool kinit "$krb5_bin/kinit" /usr/bin/kinit || true)
	for tool_value in "$kdb5_util" "$kadmin_local" "$kinit"; do
		if [ -z "$tool_value" ]; then
			die "local MIT KDC was detected but its kdb5_util, kadmin.local, or kinit companion is missing"
		fi
	done
	plugin_viewer=$(find_optional_tool pluginviewer \
		/opt/homebrew/opt/cyrus-sasl/sbin/pluginviewer \
		/usr/local/opt/cyrus-sasl/sbin/pluginviewer || true)
	if [ -z "$plugin_viewer" ]; then
		plugin_viewer=$(find_optional_tool saslpluginviewer \
			/usr/sbin/saslpluginviewer || true)
	fi
	if [ -z "$plugin_viewer" ]; then
		die "local MIT KDC was detected but no Cyrus SASL plugin viewer is installed"
	fi
	if ! "$plugin_viewer" -m GSSAPI >/dev/null 2>&1; then
		die "local MIT KDC was detected but the Cyrus SASL GSSAPI plugin is unavailable"
	fi
	PATH="$krb5_sbin:$krb5_bin:$PATH"
	export PATH
	LDAP_GO_KRB5KDC=$krb5kdc
	LDAP_GO_KDB5_UTIL=$kdb5_util
	LDAP_GO_KADMIN_LOCAL=$kadmin_local
	LDAP_GO_KINIT=$kinit
	export LDAP_GO_KRB5KDC LDAP_GO_KDB5_UTIL LDAP_GO_KADMIN_LOCAL LDAP_GO_KINIT
	gssapi_reference=1
fi
LDAP_GO_OPENLDAP_GSSAPI_TESTS=$gssapi_reference
export LDAP_GO_OPENLDAP_GSSAPI_TESTS

scram_plugin_viewer=
if command -v pluginviewer >/dev/null 2>&1; then
	scram_plugin_viewer=$(command -v pluginviewer)
elif command -v saslpluginviewer >/dev/null 2>&1; then
	scram_plugin_viewer=$(command -v saslpluginviewer)
else
	for candidate in \
		/opt/homebrew/opt/cyrus-sasl/sbin/pluginviewer \
		/usr/local/opt/cyrus-sasl/sbin/pluginviewer
	do
		if [ -x "$candidate" ]; then
			scram_plugin_viewer=$candidate
			break
		fi
	done
fi
scram_channel_binding_reference=0
if [ -n "$scram_plugin_viewer" ]; then
	scram_plugin_output=$($scram_plugin_viewer -c 2>&1 || true)
	case "$scram_plugin_output" in *'SASL mechanism: SCRAM-SHA-1'*) scram_sha1=1 ;; *) scram_sha1=0 ;; esac
	case "$scram_plugin_output" in *'SASL mechanism: SCRAM-SHA-256'*) scram_sha256=1 ;; *) scram_sha256=0 ;; esac
	case "$scram_plugin_output" in *'SASL mechanism: SCRAM-SHA-512'*) scram_sha512=1 ;; *) scram_sha512=0 ;; esac
	case "$scram_plugin_output" in *'CHANNEL_BINDING'*) scram_binding=1 ;; *) scram_binding=0 ;; esac
	if [ "$scram_sha1$scram_sha256$scram_sha512$scram_binding" = "1111" ]; then
		scram_channel_binding_reference=1
	fi
fi
if [ "$strict" = "1" ] && [ "$scram_channel_binding_reference" != "1" ]; then
	die "strict reference environment lacks Cyrus SCRAM SHA-1/256/512 channel binding"
fi
LDAP_GO_TEST_OPENLDAP_SCRAM_PLUS=$scram_channel_binding_reference
export LDAP_GO_TEST_OPENLDAP_SCRAM_PLUS

find_sqlite_odbc_driver() {
	if [ -n "${LDAP_GO_SQLITE_ODBC_DRIVER:-}" ]; then
		if [ ! -f "$LDAP_GO_SQLITE_ODBC_DRIVER" ]; then
			die "LDAP_GO_SQLITE_ODBC_DRIVER is not a file: $LDAP_GO_SQLITE_ODBC_DRIVER"
		fi
		printf '%s\n' "$LDAP_GO_SQLITE_ODBC_DRIVER"
		return
	fi
	for candidate in \
		/opt/homebrew/opt/sqliteodbc/lib/libsqlite3odbc.dylib \
		/opt/homebrew/opt/sqliteodbc/lib/libsqlite3odbc.so \
		/usr/local/lib/libsqlite3odbc.so \
		/usr/lib/odbc/libsqlite3odbc.so \
		/usr/lib/*-linux-gnu/odbc/libsqlite3odbc.so \
		/usr/lib/*-linux-gnu/odbc/libsqlite3odbc-*.so
	do
		if [ -f "$candidate" ]; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	return 1
}

sqlite_odbc_driver=
if sqlite_odbc_driver=$(find_sqlite_odbc_driver); then
	LDAP_GO_SQLITE_ODBC_DRIVER=$sqlite_odbc_driver
	export LDAP_GO_SQLITE_ODBC_DRIVER
elif [ "$strict" = "1" ]; then
	die "strict OpenLDAP SQL differential requires a SQLite ODBC driver; install sqliteodbc or set LDAP_GO_SQLITE_ODBC_DRIVER"
fi

printf 'OpenLDAP reference: %s (%s)\n' "$version" "$slapd"
printf 'OpenLDAP lloadd:     %s (%s)\n' "$lloadd_version" "$OPENLDAP_LLOADD"
if [ -n "${OPENLDAP_COMMIT:-}" ]; then
	printf 'OpenLDAP commit:    %s (verified=%s)\n' \
		"$OPENLDAP_COMMIT" "${OPENLDAP_REFERENCE_VERIFIED:-unknown}"
fi
printf 'OpenLDAP schema:    %s\n' "$OPENLDAP_SCHEMA_DIR"
printf 'Required features:  passwd dnssrv asyncmeta {CRYPT}\n'
printf 'GSSAPI topology:    %s\n' "$(if [ "$gssapi_reference" = "1" ]; then printf enabled; else printf unavailable; fi)"
if [ -n "$sqlite_odbc_driver" ]; then
	printf 'SQL fixture:        SQLite ODBC (%s)\n' "$sqlite_odbc_driver"
else
	printf 'SQL fixture:        unavailable (optional outside strict mode)\n'
fi
printf 'Execution:          strict=%s package-parallelism=1 test-parallelism=%s\n' \
	"$strict" "${LDAP_GO_OPENLDAP_PARALLEL:-1}"

log=$(mktemp "${TMPDIR:-/tmp}/ldap-go-openldap.XXXXXX")
trap 'rm -f "$log"' EXIT HUP INT TERM

test_status=0
test_parallel=${LDAP_GO_OPENLDAP_PARALLEL:-1}
case "$test_parallel" in
	''|*[!0-9]*|0) die "LDAP_GO_OPENLDAP_PARALLEL must be a positive integer" ;;
esac
printf 'Running OpenLDAP reference differentials and related topology tests...\n'
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
go test -p=1 \
		./internal/server \
		./internal/lloadd \
		./internal/migration \
		./cmd/ldap-go \
		-count=1 \
		-timeout=60m \
		-parallel="$test_parallel" \
		-v >"$log" 2>&1 || test_status=$?
if [ "$test_status" -ne 0 ]; then
	printf 'OpenLDAP suite failed (go test exit %s); complete output follows:\n' \
		"$test_status" >&2
	cat "$log"
	exit "$test_status"
fi

skips=$(sed -n 's/^--- SKIP: \([^ (]*\).*/\1/p' "$log")
unexpected_skips=
for skipped in $skips; do
	case "$skipped" in
		TestBackendTCPUserTimeoutLinux)
			# The kernel option is Linux-only; Darwin and Windows exercise the
			# explicit unsupported-platform path in separate tests.
			;;
		TestOpenLDAPReferenceGSSAPIDifferential)
			# A local MIT KDC plus Cyrus GSSAPI is an optional external
			# dependency. Once auto-detected, this test becomes mandatory.
			if [ "$gssapi_reference" = "1" ]; then
				unexpected_skips="${unexpected_skips}${unexpected_skips:+ }$skipped"
			fi
			;;
		TestOpenLDAPClientSASLSCRAMSHA256Bind|\
		TestOpenLDAPCyrusSASLSCRAMTLSChannelBinding|\
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
		TestOpenLDAPReferenceRelayBackend|\
		TestOpenLDAPReferenceSQLBackend|\
		TestOpenLDAPReferenceSQLBackendModifyDNAutocommitFailure|\
		TestOpenLDAPReferenceSockBackend)
			if [ "$fail_on_optional_skip" = "1" ]; then
				unexpected_skips="${unexpected_skips}${unexpected_skips:+ }$skipped"
			fi
			;;
		*)
			unexpected_skips="${unexpected_skips}${unexpected_skips:+ }$skipped"
			;;
	esac
done

mandatory_tests='TestOpenLDAPReferenceCoreProtocolDifferential
TestOpenLDAPReferenceUnknownOperationDisconnect
TestOpenLDAPReferenceLDAPSearchSortAndUFN
TestOpenLDAPReferenceLDAPSearchLegacyOutputAndContinuousMode
TestOpenLDAPReferenceLDAPSearchDefaultErrorAndReferenceOutput
TestOpenLDAPReferenceLDAPSearchReferenceEmptyDNDifferential
TestOpenLDAPLDAPCompareHistoricalExtensionBehavior
TestOpenLDAPLDAPCompareVerboseBehavior
TestOpenLDAPReferenceSlapaddContinueAndQuickExitBehavior
TestOpenLDAPLloaddProxyProtocolOpaqueOptionsSourceContract
TestOpenLDAPReferenceTransactionControlCombinations
TestOpenLDAPReferenceLanguageAttributeOptionProjection
TestOpenLDAPReferenceMatchedValuesControl
TestOpenLDAPReferenceObjectClassAttributeSelection
TestOpenLDAPReferenceDomainScopeAndSearchOptions
TestOpenLDAPReferenceSessionTrackingControl
TestOpenLDAPReferenceTreeDeleteMDBProtocol
TestOpenLDAPReferenceTreeDeleteBackSQL
TestOpenLDAP2613TreeDeleteSourceContract
TestOpenLDAPReferenceLDAPv2ControlsDisconnect
TestOpenLDAPReferenceHiddenControlDiscovery
TestOpenLDAPMDBIndexSemanticSourceContract
TestOpenLDAPReferenceApproximateMatching
TestOpenLDAPReferencePasswdBackendDifferential
TestOpenLDAPReferenceDNSSRVBackendDifferential
TestOpenLDAPReferenceAsyncMetaBackendDifferential
TestOpenLDAPReferenceCryptDifferential
TestOpenLDAPReferenceDNMultiAVADifferential
TestOpenLDAPReferenceDNIdentityModifyDNPrettyForm
TestOpenLDAPReferenceLDIFDNIdentityCompatibility
TestOpenLDAPReferenceLloaddSourceContract
TestOpenLDAPReferenceLloaddResultDifferential
TestOpenLDAPReferenceLloaddBindProxyAuthzDifferential
TestGlobalTLSOnlineCertificateReload
TestGlobalTLSVerifyClientDemand
TestConfigRuntimeBackendTLS
TestBackendLDAPSThenServiceBind
TestBackendStartTLSThenServiceBind
TestBackendStartTLSOptionalAndCriticalFailure
TestBackendTLSCertificateValidationFailsClosed
TestBackendTLSRevocationFailsClosed
TestNewProxyClonesAndValidatesClientTLS
TestClientStartTLSRoutesBindAndSearchAfterUpgrade
TestClientStartTLSRejectsOutstandingSearchAndThenRecovers
TestClientStartTLSRejectsBindInProgress
TestClientStartTLSRequiresLDAPv3AndNoRequestValue
TestClientStartTLSWithoutConfigurationIsUnavailable
TestClientStartTLSHandshakeFailureClosesConnection
TestLloaddCommandServesStartTLSAndLDAPSListeners
TestLDAPClientSASLPlainWireExchange
TestLDAPClientSASLDigestMD5WireExchange
TestLDAPClientSASLDigestMD5RejectsInvalidServerProof
TestLDAPClientSASLErrorDoesNotEchoServerDiagnostic
TestLDAPClientSASLPlainOverRequiredStartTLS
TestLDAPClientSASLDigestMD5ProjectServer
TestLDAPClientSASLCRAMMD5ProjectServer
TestLDAPClientSASLSCRAMProjectServer
TestLDAPClientSASLSCRAMRejectsInvalidServerSignature
TestLDAPClientSASLSCRAMRejectsUnsafeServerFirst
TestLDAPClientSASLCRAMMD5RejectsMalformedChallenge
TestLDAPClientSASLExternalMutualTLS
TestLDAPClientSASLValidation
TestPcacheSchemaAwareTemplateContainment
TestPcacheSubstringContainmentDirection
TestPcacheExtensibleTemplateSemantics
TestPcacheSchemaFilterKeyCanonicalization
TestPcacheTemplateSupportsExtensibleFilters'
strict_mandatory_tests='TestOpenLDAPGlobalTLSConfigurationRebuildsContextSourceContract
TestOpenLDAPReferencePcachePhaseOne
TestOpenLDAPReferenceSQLBackend
TestOpenLDAPReferenceSQLBackendModifyDNAutocommitFailure'
if [ "$strict" = "1" ]; then
	mandatory_tests="$mandatory_tests
$strict_mandatory_tests"
fi
if [ "$gssapi_reference" = "1" ]; then
	mandatory_tests="$mandatory_tests
TestOpenLDAPReferenceGSSAPIDifferential"
fi
if [ "$scram_channel_binding_reference" = "1" ]; then
	mandatory_tests="$mandatory_tests
TestOpenLDAPCyrusSASLSCRAMTLSChannelBinding"
fi

missing_tests=
for required_test in $mandatory_tests; do
	if ! grep -F -q -- "--- PASS: $required_test " "$log"; then
		missing_tests="${missing_tests}${missing_tests:+ }$required_test"
	fi
done
if [ -n "$missing_tests" ]; then
	printf 'mandatory tests did not report PASS: %s\n' "$missing_tests" >&2
	printf 'their RUN/PASS/SKIP lines follow:\n' >&2
	for required_test in $missing_tests; do
		grep -F -- "$required_test" "$log" >&2 || true
	done
	exit 1
fi
if [ -n "$unexpected_skips" ]; then
	printf 'unexpected skipped top-level tests: %s\n' "$unexpected_skips" >&2
	for skipped in $unexpected_skips; do
		grep -F -- "$skipped" "$log" >&2 || true
	done
	exit 1
fi

passes=$(sed -n 's/^--- PASS: \(Test[^ (]*\).*/\1/p' "$log" | wc -l | tr -d ' ')
if [ -n "$skips" ]; then
	printf 'OpenLDAP suite passed: %s top-level tests; allowed optional skips:\n%s\n' \
		"$passes" "$skips"
else
	printf 'OpenLDAP suite passed: %s top-level tests; no skips\n' "$passes"
fi
printf 'Mandatory coverage passed: OpenLDAP differentials, source contracts, and local TLS/SASL/pcache topology regressions.\n'

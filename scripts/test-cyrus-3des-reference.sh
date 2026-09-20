#!/bin/sh
# Supplemental interoperability evidence, NOT an unmodified-Cyrus strict pass.
# OpenLDAP stays unmodified. Only the temporary Cyrus plugin is patched.
set -eu

die() {
	printf 'test-cyrus-3des-reference: %s\n' "$*" >&2
	exit 1
}

[ "$#" -eq 0 ] || die "configuration is through environment variables only"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ -r "${OPENLDAP_ENV_FILE:-}" ] || die "OPENLDAP_ENV_FILE is required"
# shellcheck disable=SC1090
. "$OPENLDAP_ENV_FILE"
[ "${OPENLDAP_REFERENCE_VERIFIED:-0}" = 1 ] || die "OpenLDAP reference is not verified"
[ "${OPENLDAP_ACTUAL_VERSION:-}" = 2.6.13 ] || die "requires OpenLDAP 2.6.13"
[ "${OPENLDAP_VERIFIED_COMMIT:-}" = d172686d3d270bc961b78f3ff00d7019c8dfb094 ] ||
	die "requires the pinned OpenLDAP 2.6.13 reference environment"

if [ -n "${CYRUS_3DES_ARTIFACT_DIR:-}" ]; then
	[ ! -e "$CYRUS_3DES_ARTIFACT_DIR" ] || die "artifact directory already exists"
	mkdir -p "$CYRUS_3DES_ARTIFACT_DIR"
	artifacts=$(CDPATH= cd -- "$CYRUS_3DES_ARTIFACT_DIR" && pwd)
else
	artifacts=$(mktemp -d "${TMPDIR:-/tmp}/ldap-go-cyrus-3des.XXXXXX")
fi
printf 'Reference artifacts: %s\n' "$artifacts"
for command in curl tar patch autoreconf make go; do
	command -v "$command" >/dev/null 2>&1 || die "missing dependency: $command"
done
digest() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

cyrus_commit=7a6b45b177070198fed0682bea5fa87c18abb084
archive_sha256=5ca0cb386426ca644918947c54bbe6aacc2962bc38019d8a6befc454c0e174b8
archive="$artifacts/cyrus-sasl.tar.gz"
source_dir="$artifacts/cyrus-sasl-$cyrus_commit"
patch_file="$root/scripts/fixtures/cyrus-sasl-2.1.28-des-parity.patch"
curl --fail --location --silent --show-error --retry 2 \
	"https://codeload.github.com/cyrusimap/cyrus-sasl/tar.gz/$cyrus_commit" -o "$archive"
[ "$(digest "$archive")" = "$archive_sha256" ] || die "Cyrus source archive checksum mismatch"
tar -xzf "$archive" -C "$artifacts"
cp "$patch_file" "$artifacts/provider.patch"
(
	cd "$source_dir"
	patch -p1 < "$patch_file"
	autoreconf -fi
	if [ -n "${OPENLDAP_OPENSSL_PREFIX:-}" ]; then
		set -- "--with-openssl=$OPENLDAP_OPENSSL_PREFIX"
	else
		set --
	fi
	./configure --prefix="$artifacts/prefix" --with-dblib=none \
		--disable-saslauthd --disable-gssapi --disable-ldapdb --disable-sql \
		--disable-srp --disable-otp --disable-ntlm --disable-passdss "$@"
	make -j2 -C include
	make -j2 -C common
	make -j2 -C plugins libdigestmd5.la
) > "$artifacts/build.log" 2>&1 || die "Cyrus build failed; see $artifacts/build.log"

# SASL_PATH is process-local: no installation or system-library replacement.
SASL_PATH="$source_dir/plugins/.libs"
CGO_ENABLED=0
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1
LDAP_GO_CYRUS_3DES_TESTS=1
LDAP_GO_CYRUS_3DES_REFERENCE_DIR=$artifacts
export SASL_PATH CGO_ENABLED LDAP_GO_OPENLDAP_REFERENCE_TESTS LDAP_GO_CYRUS_3DES_TESTS LDAP_GO_CYRUS_3DES_REFERENCE_DIR
{
	printf 'reference_kind=OpenLDAP-2.6.13-with-locally-patched-Cyrus-2.1.28\n'
	printf 'openldap_commit=%s\ncyrus_commit=%s\n' "$OPENLDAP_VERIFIED_COMMIT" "$cyrus_commit"
	printf 'archive_sha256=%s\npatch_sha256=%s\n' "$archive_sha256" "$(digest "$patch_file")"
	printf 'patched_digestmd5_sha256=%s\n' "$(digest "$source_dir/plugins/digestmd5.c")"
	printf 'sasl_path=%s\nCGO_ENABLED=0\n' "$SASL_PATH"
	go version
	uname -a
} > "$artifacts/provenance.txt"
cd "$root"
# The native-to-native control must succeed before testing either Go direction.
if ! go test ./internal/server -count=1 -timeout=90s -v \
	-run '^TestOpenLDAPReferenceDIGESTMD5Native3DES$' > "$artifacts/native-control.log" 2>&1; then
	cat "$artifacts/native-control.log"
	die "native 3DES self-check failed"
fi
if ! go test ./internal/server -count=1 -timeout=90s -v \
	-run '^(TestOpenLDAPSyncreplDIGESTMD5SecurityLayers|TestOpenLDAPClientSASLDigestMD5Bind)$' \
	> "$artifacts/interop.log" 2>&1; then
	cat "$artifacts/interop.log"
	die "Go/native 3DES interoperability failed"
fi
cat "$artifacts/provenance.txt" "$artifacts/native-control.log" "$artifacts/interop.log"
if grep -Eq -- '--- SKIP:|no tests to run' "$artifacts/native-control.log" "$artifacts/interop.log"; then
	die "a required reference test did not execute"
fi
printf 'PASS: locally patched Cyrus evidence only; the unmodified-provider strict result is unchanged.\n'

#!/bin/sh

set -eu

die() {
	printf 'test-openldap-full: %s\n' "$*" >&2
	exit 1
}

if [ "$#" -ne 0 ]; then
	die "this script accepts configuration through OPENLDAP_SOURCE, OPENLDAP_SOURCE_CACHE, OPENLDAP_ALLOW_UNVERIFIED_REFERENCE, BUILD, PREFIX, JOBS, OPENSSL_PREFIX, LIBTOOL_PREFIX, CYRUS_SASL_PREFIX, LIBEVENT_PREFIX, ODBC_PREFIX, OPENLDAP_ENV_FILE, and LDAP_GO_OPENLDAP_REBUILD"
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

verified_revision=d172686d3d270bc961b78f3ff00d7019c8dfb094
verified_tag=OPENLDAP_REL_ENG_2_6_13
rebuild=${LDAP_GO_OPENLDAP_REBUILD:-0}
case "$rebuild" in
	0|1) ;;
	*) die "LDAP_GO_OPENLDAP_REBUILD must be 0 or 1, got: $rebuild" ;;
esac

build_input=${BUILD:-${TMPDIR:-/tmp}/ldap-go-openldap-reference-2.6}
case "$build_input" in
	/*) default_env=$build_input/openldap-reference.env ;;
	*) default_env=$root/$build_input/openldap-reference.env ;;
esac
env_file=${OPENLDAP_ENV_FILE:-$default_env}
OPENLDAP_ENV_FILE=$env_file
export OPENLDAP_ENV_FILE

requested_source=${OPENLDAP_SOURCE:-}
reuse_environment=0
if [ "$rebuild" = "0" ] && [ -r "$env_file" ]; then
	# shellcheck disable=SC1090
	. "$env_file"
	reuse_environment=1
	if [ -n "$requested_source" ]; then
		requested_source_dir=$(CDPATH= cd -- "$requested_source" 2>/dev/null && pwd) ||
			die "OPENLDAP_SOURCE does not exist or is not readable: $requested_source"
		environment_source_dir=$(CDPATH= cd -- "${OPENLDAP_SOURCE:-}" 2>/dev/null && pwd) ||
			die "reused environment has an unreadable OPENLDAP_SOURCE: ${OPENLDAP_SOURCE:-unset}"
		if [ "$requested_source_dir" != "$environment_source_dir" ]; then
			die "OPENLDAP_ENV_FILE references $environment_source_dir, but OPENLDAP_SOURCE requests $requested_source_dir; set LDAP_GO_OPENLDAP_REBUILD=1"
		fi
	fi
	printf 'Reusing OpenLDAP reference environment: %s\n' "$env_file"
fi

if [ "$reuse_environment" = "0" ] && [ -z "${OPENLDAP_SOURCE:-}" ]; then
	if ! command -v git >/dev/null 2>&1; then
		die "git is required to fetch the pinned OpenLDAP reference source"
	fi
	source_cache=${OPENLDAP_SOURCE_CACHE:-${TMPDIR:-/tmp}/ldap-go-openldap-source-2.6.13}
	if [ ! -e "$source_cache" ]; then
		cache_parent=$(dirname -- "$source_cache")
		mkdir -p "$cache_parent" || die "cannot create source-cache parent: $cache_parent"
		cache_parent=$(CDPATH= cd -- "$cache_parent" && pwd)
		cache_name=$(basename -- "$source_cache")
		staging=$(mktemp -d "$cache_parent/.${cache_name}.XXXXXX") ||
			die "cannot create source-cache staging directory"
		cleanup_staging() {
			rm -rf -- "$staging"
		}
		trap cleanup_staging EXIT HUP INT TERM
		git clone --depth 1 --branch "$verified_tag" \
			https://github.com/OPENLDAP/openldap.git "$staging/source" ||
			die "failed to clone the pinned OpenLDAP $verified_tag source"
		mv "$staging/source" "$source_cache" ||
			die "cannot publish the pinned OpenLDAP source cache: $source_cache"
		trap - EXIT HUP INT TERM
		rmdir "$staging"
	fi
	if [ ! -d "$source_cache/.git" ]; then
		die "OPENLDAP_SOURCE_CACHE is not an OpenLDAP Git checkout: $source_cache"
	fi
	cache_revision=$(git -C "$source_cache" rev-parse HEAD 2>/dev/null || true)
	if [ "$cache_revision" != "$verified_revision" ]; then
		die "cached OpenLDAP source is at ${cache_revision:-unknown}, expected $verified_revision; remove that managed cache or set OPENLDAP_SOURCE explicitly"
	fi
	if ! cache_status=$(git -C "$source_cache" status --porcelain --untracked-files=normal); then
		die "cannot inspect cached OpenLDAP source status: $source_cache"
	fi
	if [ -n "$cache_status" ]; then
		die "cached OpenLDAP source has local changes: $source_cache"
	fi
	OPENLDAP_SOURCE=$source_cache
	export OPENLDAP_SOURCE
fi

if [ "$reuse_environment" = "0" ]; then
	printf 'Building OpenLDAP reference once for this environment...\n'
	"$root/scripts/build-openldap-reference.sh"
fi

if [ ! -r "$env_file" ]; then
	die "reference environment was not generated: $env_file"
fi
# shellcheck disable=SC1090
. "$env_file"

for reference_tool in OPENLDAP_SLAPD OPENLDAP_SLAPADD OPENLDAP_LLOADD; do
	case "$reference_tool" in
		OPENLDAP_SLAPD) reference_path=${OPENLDAP_SLAPD:-} ;;
		OPENLDAP_SLAPADD) reference_path=${OPENLDAP_SLAPADD:-} ;;
		OPENLDAP_LLOADD) reference_path=${OPENLDAP_LLOADD:-} ;;
	esac
	if [ -z "$reference_path" ] || [ ! -x "$reference_path" ]; then
		die "$reference_tool from $env_file is not executable: ${reference_path:-unset}; set LDAP_GO_OPENLDAP_REBUILD=1"
	fi
done
if [ -z "${OPENLDAP_SCHEMA_DIR:-}" ] || [ ! -f "$OPENLDAP_SCHEMA_DIR/core.schema" ]; then
	die "OPENLDAP_SCHEMA_DIR from $env_file has no core.schema: ${OPENLDAP_SCHEMA_DIR:-unset}"
fi

if [ "${OPENLDAP_ALLOW_UNVERIFIED_REFERENCE:-0}" != "1" ]; then
	if [ "${OPENLDAP_REFERENCE_VERIFIED:-0}" != "1" ] ||
		[ "${OPENLDAP_COMMIT:-}" != "$verified_revision" ] ||
		[ "${OPENLDAP_VERIFIED_COMMIT:-}" != "$verified_revision" ]; then
		die "generated reference environment is not verified OpenLDAP 2.6.13 evidence"
	fi
fi

LDAP_GO_OPENLDAP_STRICT=1
LDAP_GO_FAIL_ON_OPTIONAL_SKIP=1
export LDAP_GO_OPENLDAP_STRICT LDAP_GO_FAIL_ON_OPTIONAL_SKIP

exec "$root/scripts/test-openldap.sh"

#!/bin/sh

set -eu

die() {
	printf 'build-openldap-reference: %s\n' "$*" >&2
	exit 1
}

need_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		die "required command '$1' was not found"
	fi
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

ensure_symlink() {
	target=$1
	link=$2
	if [ -L "$link" ]; then
		current_target=$(readlink "$link")
		if [ "$current_target" != "$target" ]; then
			die "path alias points somewhere else: $link -> $current_target"
		fi
		return
	fi
	if [ -e "$link" ]; then
		die "path alias already exists and is not a symbolic link: $link"
	fi
	ln -s "$target" "$link" || die "cannot create path alias: $link"
}

if [ "$#" -ne 0 ]; then
	die "this script accepts configuration through OPENLDAP_SOURCE, OPENLDAP_ALLOW_UNVERIFIED_REFERENCE, BUILD, PREFIX, JOBS, OPENSSL_PREFIX, LIBTOOL_PREFIX, CYRUS_SASL_PREFIX, LIBEVENT_PREFIX, ODBC_PREFIX, and OPENLDAP_ENV_FILE"
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

verified_version=2.6.13
verified_revision=d172686d3d270bc961b78f3ff00d7019c8dfb094
allow_unverified_reference=${OPENLDAP_ALLOW_UNVERIFIED_REFERENCE:-0}
case "$allow_unverified_reference" in
	0|1) ;;
	*) die "OPENLDAP_ALLOW_UNVERIFIED_REFERENCE must be 0 or 1, got: $allow_unverified_reference" ;;
esac

source_input=${OPENLDAP_SOURCE:-../openldap-reference}
if ! source_dir=$(CDPATH= cd -- "$source_input" 2>/dev/null && pwd); then
	die "OPENLDAP_SOURCE does not exist or is not readable: $source_input"
fi
configure=$source_dir/configure
if [ ! -f "$configure" ] || [ ! -x "$configure" ]; then
	die "OpenLDAP configure is not executable: $configure"
fi

build_input=${BUILD:-${TMPDIR:-/tmp}/ldap-go-openldap-reference-2.6}
mkdir -p "$build_input" || die "cannot create BUILD directory: $build_input"
requested_build_dir=$(CDPATH= cd -- "$build_input" && pwd)
if [ "$requested_build_dir" = "$source_dir" ]; then
	die "BUILD must be an out-of-tree directory"
fi

prefix_input=${PREFIX:-$requested_build_dir/prefix}
mkdir -p "$prefix_input" || die "cannot create PREFIX directory: $prefix_input"
prefix_dir=$(CDPATH= cd -- "$prefix_input" && pwd)

env_input=${OPENLDAP_ENV_FILE:-$requested_build_dir/openldap-reference.env}
env_parent=$(dirname -- "$env_input")
mkdir -p "$env_parent" || die "cannot create environment file directory: $env_parent"
env_parent=$(CDPATH= cd -- "$env_parent" && pwd)
env_file=$env_parent/$(basename -- "$env_input")

make_command=${MAKE:-make}
for command_name in awk cc cksum git grep head sed "$make_command"; do
	need_command "$command_name"
done

effective_source_dir=$source_dir
effective_build_dir=$requested_build_dir
effective_prefix_dir=$prefix_dir
artifact_build_dir=$requested_build_dir
case "$source_dir:$requested_build_dir:$prefix_dir" in
	*[[:space:]]*)
		for command_name in cksum id ln readlink; do
			need_command "$command_name"
		done
		alias_key=$(printf '%s\n' "$source_dir" "$requested_build_dir" "$prefix_dir" | cksum | awk '{print $1}')
		alias_root=/tmp/ldap-go-openldap-paths-$(id -u)-$alias_key
		mkdir -p "$alias_root" || die "cannot create whitespace-safe build aliases: $alias_root"
		ensure_symlink "$source_dir" "$alias_root/source"
		ensure_symlink "$prefix_dir" "$alias_root/prefix"
		effective_source_dir=$alias_root/source
		effective_prefix_dir=$alias_root/prefix
		if [ -n "$(printf '%s' "$requested_build_dir" | sed -n '/[[:space:]]/p')" ]; then
			effective_build_dir=$alias_root/build
			mkdir -p "$effective_build_dir" || die "cannot create whitespace-safe BUILD directory: $effective_build_dir"
			artifact_build_dir=$requested_build_dir/.openldap-work-$alias_key
			ensure_symlink "$effective_build_dir" "$artifact_build_dir"
		fi
		;;
esac
configure=$effective_source_dir/configure

major=$(sed -n 's/^ol_major=//p' "$source_dir/build/version.var" | head -n 1)
minor=$(sed -n 's/^ol_minor=//p' "$source_dir/build/version.var" | head -n 1)
if [ "$major" != 2 ] || [ "$minor" != 6 ]; then
	die "OPENLDAP_SOURCE must be an OpenLDAP 2.6 tree (found ${major:-unknown}.${minor:-unknown})"
fi

jobs=${JOBS:-}
if [ -z "$jobs" ] && command -v getconf >/dev/null 2>&1; then
	jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
fi
if [ -z "$jobs" ] && command -v sysctl >/dev/null 2>&1; then
	jobs=$(sysctl -n hw.ncpu 2>/dev/null || true)
fi
jobs=${jobs:-2}
case "$jobs" in
	''|*[!0-9]*|0)
		die "JOBS must be a positive integer, got: $jobs"
		;;
esac

configure_help=$("$configure" --help 2>&1) || die "failed to inspect configure options"

set -- \
	"--prefix=$effective_prefix_dir" \
	--enable-slapd=yes \
	--enable-balancer=yes \
	--enable-crypt=yes \
	--enable-shared=yes \
	--disable-static \
	--with-tls=openssl

case "$configure_help" in
	*--enable-modules*) set -- "$@" --enable-modules=yes ;;
esac
case "$configure_help" in
	*--with-systemd*) set -- "$@" --without-systemd ;;
esac

missing_features=
enabled_backends=
for feature in asyncmeta dnssrv ldap meta null passwd relay mdb sock sql; do
	case "$configure_help" in
		*--enable-$feature*)
			set -- "$@" "--enable-$feature=yes"
			enabled_backends="${enabled_backends}${enabled_backends:+ }$feature"
			;;
		*)
			missing_features="${missing_features}${missing_features:+ }backend:$feature"
			;;
	esac
done

enabled_overlays=
for feature in \
	accesslog auditlog autoca collect constraint dds deref dyngroup dynlist \
	homedir memberof nestgroup otp ppolicy proxycache refint remoteauth \
	retcode rwm seqmod sssvlv syncprov translucent unique valsort
do
	case "$configure_help" in
		*--enable-$feature*)
			set -- "$@" "--enable-$feature=yes"
			enabled_overlays="${enabled_overlays}${enabled_overlays:+ }$feature"
			;;
		*)
			missing_features="${missing_features}${missing_features:+ }overlay:$feature"
			;;
	esac
done

for feature in dynacl aci; do
	case "$configure_help" in
		*--enable-$feature*) set -- "$@" "--enable-$feature=yes" ;;
		*) missing_features="${missing_features}${missing_features:+ }server:$feature" ;;
	esac
done

case "$configure_help" in
	*--with-cyrus-sasl*) set -- "$@" --with-cyrus-sasl ;;
	*) missing_features="${missing_features}${missing_features:+ }library:cyrus-sasl" ;;
esac

cppflags=${CPPFLAGS:-}
ldflags=${LDFLAGS:-}
pkg_config_path=${PKG_CONFIG_PATH:-}
runtime_dependency_path=

odbc_prefix=${ODBC_PREFIX:-}
if [ -z "$odbc_prefix" ] && [ "$(uname -s 2>/dev/null || true)" = Darwin ] && command -v brew >/dev/null 2>&1; then
	brew_odbc=$(brew --prefix unixodbc 2>/dev/null || true)
	if [ -n "$brew_odbc" ] && [ -f "$brew_odbc/include/sql.h" ]; then
		odbc_prefix=$brew_odbc
	fi
fi
if [ -n "$odbc_prefix" ]; then
	case "$odbc_prefix" in
		*[[:space:]]*) die "ODBC_PREFIX must not contain whitespace: $odbc_prefix" ;;
	esac
	odbc_prefix=$(CDPATH= cd -- "$odbc_prefix" 2>/dev/null && pwd) ||
		die "ODBC_PREFIX is not an accessible directory: $odbc_prefix"
	if [ ! -f "$odbc_prefix/include/sql.h" ] || [ ! -f "$odbc_prefix/include/sqlext.h" ]; then
		die "ODBC headers were not found below ODBC_PREFIX: $odbc_prefix"
	fi
	odbc_lib_dir=
	for candidate in "$odbc_prefix/lib" "$odbc_prefix/lib64" "$odbc_prefix"/lib/*-linux-gnu; do
		if [ -d "$candidate" ] && {
			[ -f "$candidate/libodbc.dylib" ] ||
			[ -f "$candidate/libodbc.so" ] ||
			[ -f "$candidate/libodbc.a" ];
		}; then
			odbc_lib_dir=$candidate
			break
		fi
	done
	if [ -z "$odbc_lib_dir" ]; then
		die "ODBC library was not found below ODBC_PREFIX: $odbc_prefix"
	fi
	cppflags="-I$odbc_prefix/include${cppflags:+ $cppflags}"
	ldflags="-L$odbc_lib_dir${ldflags:+ $ldflags}"
	runtime_dependency_path="$odbc_lib_dir${runtime_dependency_path:+:$runtime_dependency_path}"
	case "$configure_help" in
		*--with-odbc*) set -- "$@" --with-odbc=unixodbc ;;
		*) die "the pinned source configure does not expose --with-odbc" ;;
	esac
fi

openssl_prefix=${OPENSSL_PREFIX:-}
if [ -z "$openssl_prefix" ] && [ "$(uname -s 2>/dev/null || true)" = Darwin ] && command -v brew >/dev/null 2>&1; then
	brew_openssl=$(brew --prefix openssl@3 2>/dev/null || true)
	if [ -n "$brew_openssl" ] && [ -d "$brew_openssl" ]; then
		openssl_prefix=$brew_openssl
	fi
fi
if [ -n "$openssl_prefix" ]; then
	if [ ! -f "$openssl_prefix/include/openssl/ssl.h" ]; then
		die "OpenSSL headers were not found below OPENSSL_PREFIX: $openssl_prefix"
	fi
	cppflags="-I$openssl_prefix/include${cppflags:+ $cppflags}"
	ldflags="-L$openssl_prefix/lib${ldflags:+ $ldflags}"
	if [ -d "$openssl_prefix/lib/pkgconfig" ]; then
		pkg_config_path="$openssl_prefix/lib/pkgconfig${pkg_config_path:+:$pkg_config_path}"
	fi
	runtime_dependency_path="$openssl_prefix/lib${runtime_dependency_path:+:$runtime_dependency_path}"
fi

libtool_prefix=${LIBTOOL_PREFIX:-}
if [ -z "$libtool_prefix" ] && [ "$(uname -s 2>/dev/null || true)" = Darwin ] && command -v brew >/dev/null 2>&1; then
	brew_libtool=$(brew --prefix libtool 2>/dev/null || true)
	if [ -n "$brew_libtool" ] && [ -f "$brew_libtool/include/ltdl.h" ]; then
		libtool_prefix=$brew_libtool
	fi
fi
if [ -n "$libtool_prefix" ]; then
	if [ ! -f "$libtool_prefix/include/ltdl.h" ]; then
		die "libltdl headers were not found below LIBTOOL_PREFIX: $libtool_prefix"
	fi
	if [ ! -f "$libtool_prefix/lib/libltdl.dylib" ] &&
		[ ! -f "$libtool_prefix/lib/libltdl.so" ] &&
		[ ! -f "$libtool_prefix/lib/libltdl.a" ]; then
		die "libltdl library was not found below LIBTOOL_PREFIX: $libtool_prefix"
	fi
	cppflags="-I$libtool_prefix/include${cppflags:+ $cppflags}"
	ldflags="-L$libtool_prefix/lib${ldflags:+ $ldflags}"
	runtime_dependency_path="$libtool_prefix/lib${runtime_dependency_path:+:$runtime_dependency_path}"
fi

libevent_prefix=${LIBEVENT_PREFIX:-}
if [ -n "$libevent_prefix" ]; then
	if ! libevent_prefix=$(CDPATH= cd -- "$libevent_prefix" 2>/dev/null && pwd); then
		die "LIBEVENT_PREFIX does not exist or is not readable: ${LIBEVENT_PREFIX}"
	fi
elif [ "$(uname -s 2>/dev/null || true)" = Darwin ] && command -v brew >/dev/null 2>&1; then
	brew_libevent=$(brew --prefix libevent 2>/dev/null || true)
	if [ -n "$brew_libevent" ] && [ -f "$brew_libevent/include/event2/event.h" ]; then
		libevent_prefix=$(CDPATH= cd -- "$brew_libevent" && pwd)
	fi
fi

libevent_lib_dir=
if [ -n "$libevent_prefix" ]; then
	if [ ! -f "$libevent_prefix/include/event2/event.h" ]; then
		die "libevent headers were not found below LIBEVENT_PREFIX: $libevent_prefix"
	fi
	for candidate in "$libevent_prefix/lib" "$libevent_prefix/lib64"; do
		if { [ -f "$candidate/libevent.dylib" ] || [ -f "$candidate/libevent.so" ] || [ -f "$candidate/libevent.a" ]; } &&
			{ [ -f "$candidate/libevent_extra.dylib" ] || [ -f "$candidate/libevent_extra.so" ] || [ -f "$candidate/libevent_extra.a" ]; }; then
			libevent_lib_dir=$candidate
			break
		fi
	done
	if [ -z "$libevent_lib_dir" ]; then
		die "libevent and libevent_extra libraries were not found below LIBEVENT_PREFIX: $libevent_prefix"
	fi
	cppflags="-I$libevent_prefix/include${cppflags:+ $cppflags}"
	ldflags="-L$libevent_lib_dir${ldflags:+ $ldflags}"
	if [ -d "$libevent_lib_dir/pkgconfig" ]; then
		pkg_config_path="$libevent_lib_dir/pkgconfig${pkg_config_path:+:$pkg_config_path}"
	fi
	runtime_dependency_path="$libevent_lib_dir${runtime_dependency_path:+:$runtime_dependency_path}"
fi

cyrus_sasl_prefix=${CYRUS_SASL_PREFIX:-}
if [ -n "$cyrus_sasl_prefix" ]; then
	if ! cyrus_sasl_prefix=$(CDPATH= cd -- "$cyrus_sasl_prefix" 2>/dev/null && pwd); then
		die "CYRUS_SASL_PREFIX does not exist or is not readable: ${CYRUS_SASL_PREFIX}"
	fi
elif [ "$(uname -s 2>/dev/null || true)" = Darwin ] && command -v brew >/dev/null 2>&1; then
	brew_cyrus_sasl=$(brew --prefix cyrus-sasl 2>/dev/null || true)
	if [ -n "$brew_cyrus_sasl" ] && [ -f "$brew_cyrus_sasl/include/sasl/sasl.h" ]; then
		cyrus_sasl_prefix=$(CDPATH= cd -- "$brew_cyrus_sasl" && pwd)
	fi
fi

cyrus_sasl_lib_dir=
sasl_plugin_path=
if [ -n "$cyrus_sasl_prefix" ]; then
	if [ ! -f "$cyrus_sasl_prefix/include/sasl/sasl.h" ]; then
		die "Cyrus SASL headers were not found below CYRUS_SASL_PREFIX: $cyrus_sasl_prefix"
	fi
	for candidate in "$cyrus_sasl_prefix/lib" "$cyrus_sasl_prefix/lib64"; do
		if [ -f "$candidate/libsasl2.dylib" ] || [ -f "$candidate/libsasl2.so" ] || [ -f "$candidate/libsasl2.a" ]; then
			cyrus_sasl_lib_dir=$candidate
			break
		fi
	done
	if [ -z "$cyrus_sasl_lib_dir" ]; then
		die "Cyrus SASL library was not found below CYRUS_SASL_PREFIX: $cyrus_sasl_prefix"
	fi
	cppflags="-I$cyrus_sasl_prefix/include${cppflags:+ $cppflags}"
	ldflags="-L$cyrus_sasl_lib_dir${ldflags:+ $ldflags}"
	if [ -d "$cyrus_sasl_lib_dir/pkgconfig" ]; then
		pkg_config_path="$cyrus_sasl_lib_dir/pkgconfig${pkg_config_path:+:$pkg_config_path}"
	fi
	runtime_dependency_path="$cyrus_sasl_lib_dir${runtime_dependency_path:+:$runtime_dependency_path}"
	if [ -d "$cyrus_sasl_lib_dir/sasl2" ]; then
		sasl_plugin_path=$cyrus_sasl_lib_dir/sasl2
	fi
fi

if ! revision=$(git -C "$source_dir" rev-parse HEAD 2>/dev/null); then
	die "OPENLDAP_SOURCE must be a Git checkout at the verified OpenLDAP $verified_version revision $verified_revision"
fi
if [ "$allow_unverified_reference" -ne 1 ]; then
	if [ "$revision" != "$verified_revision" ]; then
		die "OPENLDAP_SOURCE is at $revision; reference behavior is pinned to OpenLDAP $verified_version commit $verified_revision (set OPENLDAP_ALLOW_UNVERIFIED_REFERENCE=1 only for upstream diagnostics)"
	fi
	if ! source_status=$(git -C "$source_dir" status --porcelain --untracked-files=normal); then
		die "cannot inspect OPENLDAP_SOURCE status: $source_dir"
	fi
	if [ -n "$source_status" ]; then
		die "OPENLDAP_SOURCE has local changes; a clean OpenLDAP $verified_version checkout is required"
	fi
else
	printf 'WARNING: building unverified OpenLDAP revision %s; parity expectations remain pinned to %s (%s).\n' \
		"$revision" "$verified_version" "$verified_revision" >&2
fi

configure_checksum=$(cksum "$configure" | awk '{print $1 ":" $2}')
configuration_signature=$(
	{
		printf 'revision=%s\n' "$revision"
		printf 'configure=%s\n' "$configure_checksum"
		printf 'source=%s\n' "$effective_source_dir"
		printf 'prefix=%s\n' "$effective_prefix_dir"
		printf 'CC=%s\n' "${CC:-}"
		printf 'CFLAGS=%s\n' "${CFLAGS:-}"
		printf 'CPPFLAGS=%s\n' "$cppflags"
		printf 'LDFLAGS=%s\n' "$ldflags"
		printf 'LIBS=%s\n' "${LIBS:-}"
		printf 'PKG_CONFIG_PATH=%s\n' "$pkg_config_path"
		printf 'LIBTOOL_PREFIX=%s\n' "$libtool_prefix"
		printf 'CYRUS_SASL_PREFIX=%s\n' "$cyrus_sasl_prefix"
		printf 'LIBEVENT_PREFIX=%s\n' "$libevent_prefix"
		printf 'ODBC_PREFIX=%s\n' "$odbc_prefix"
		for argument in "$@"; do
			printf 'argument=%s\n' "$argument"
		done
	} | cksum | awk '{print $1 ":" $2}'
)
configuration_stamp=$effective_build_dir/.ldap-go-reference-config

printf 'OpenLDAP source: %s\n' "$source_dir"
printf 'OpenLDAP commit: %s\n' "$revision"
printf 'Verified reference: OpenLDAP %s (%s)\n' "$verified_version" "$verified_revision"
printf 'Build directory: %s\n' "$requested_build_dir"
printf 'Configure prefix: %s\n' "$prefix_dir"
printf 'OpenSSL prefix: %s\n' "${openssl_prefix:-system default}"
printf 'libtool prefix: %s\n' "${libtool_prefix:-system default}"
printf 'Cyrus SASL prefix: %s\n' "${cyrus_sasl_prefix:-system default}"
printf 'libevent prefix: %s\n' "${libevent_prefix:-system default}"
printf 'ODBC prefix: %s\n' "${odbc_prefix:-system default}"
if [ "$effective_build_dir" != "$requested_build_dir" ]; then
	printf 'Whitespace-safe work directory: %s\n' "$effective_build_dir"
fi
printf 'Parallel jobs: %s\n' "$jobs"
if [ -n "$missing_features" ]; then
	die "the pinned source configure does not expose required features: $missing_features"
else
	printf 'Not supported by this configure: none\n'
fi

stored_signature=
if [ -f "$configuration_stamp" ]; then
	stored_signature=$(sed -n '1p' "$configuration_stamp")
fi
if [ "$stored_signature" = "$configuration_signature" ] && [ -x "$effective_build_dir/config.status" ]; then
	printf 'Configuration unchanged; reusing generated Makefiles.\n'
else
	if ! (
		cd "$effective_build_dir"
		CPPFLAGS=$cppflags
		LDFLAGS=$ldflags
		PKG_CONFIG_PATH=$pkg_config_path
		export CPPFLAGS LDFLAGS PKG_CONFIG_PATH
		"$configure" "$@"
	); then
		die "configure failed; inspect $effective_build_dir/config.log"
	fi

	printf 'Generating dependency files...\n'
	for dependency_dir in include libraries servers/slapd servers/lloadd clients/tools; do
		"$make_command" -C "$effective_build_dir/$dependency_dir" depend
	done
	printf '%s\n' "$configuration_signature" >"$configuration_stamp"
fi

printf 'Building OpenLDAP libraries...\n'
"$make_command" -C "$effective_build_dir/libraries" -j "$jobs"

printf 'Building slapd and slap tools...\n'
"$make_command" -C "$effective_build_dir/servers/slapd" -j "$jobs"

printf 'Building lloadd...\n'
"$make_command" -C "$effective_build_dir/servers/lloadd" -j "$jobs"

printf 'Building LDAP client tools...\n'
"$make_command" -C "$effective_build_dir/clients/tools" -j "$jobs"

slapd=$artifact_build_dir/servers/slapd/slapd
lloadd=$artifact_build_dir/servers/lloadd/lloadd
built_slapd=$effective_build_dir/servers/slapd/slapd
schema_dir=$source_dir/servers/slapd/schema
for required_path in \
	"$built_slapd" \
	"$effective_build_dir/servers/slapd/.libs/slapd" \
	"$effective_build_dir/servers/lloadd/lloadd" \
	"$effective_build_dir/servers/slapd/slapadd" \
	"$effective_build_dir/servers/slapd/slapcat" \
	"$effective_build_dir/servers/slapd/slappasswd" \
	"$effective_build_dir/servers/slapd/slaptest" \
	"$effective_build_dir/clients/tools/ldapsearch" \
	"$effective_build_dir/clients/tools/ldapmodify" \
	"$effective_build_dir/clients/tools/ldapwhoami" \
	"$effective_build_dir/clients/tools/ldapexop"
do
	if [ ! -x "$required_path" ]; then
		die "expected build artifact is missing or not executable: $required_path"
	fi
done
if [ ! -f "$schema_dir/core.schema" ]; then
	die "OpenLDAP core schema is missing: $schema_dir/core.schema"
fi

# A module-enabled libtool wrapper invokes .libs/slapd with "slapd" as argv[0]
# for every generated slap* tool. Link each tool name directly to the real
# binary so basename dispatch is preserved. The -T interface is not equivalent:
# notably, "slapd -T test -f ... -F ..." exits 1 during config conversion.
slap_tool_dir=$artifact_build_dir/reference-tools
mkdir -p "$slap_tool_dir" || die "cannot create slap tool wrapper directory: $slap_tool_dir"
slap_tool_binary=$effective_build_dir/servers/slapd/.libs/slapd
for tool_name in \
	slapacl \
	slapadd \
	slapauth \
	slapcat \
	slapdn \
	slapindex \
	slapmodify \
	slappasswd \
	slaptest
do
	tool_pathname=$slap_tool_dir/$tool_name
	ln -sf "$slap_tool_binary" "$tool_pathname" ||
		die "cannot create slap tool link: $tool_pathname"
done
slapadd=$slap_tool_dir/slapadd
slappasswd=$slap_tool_dir/slappasswd

openldap_library_path=$artifact_build_dir/libraries/libldap/.libs:$artifact_build_dir/libraries/liblber/.libs
runtime_library_path=$openldap_library_path
if [ -n "$runtime_dependency_path" ]; then
	runtime_library_path=$runtime_library_path:$runtime_dependency_path
fi
dyld_fallback_path=$runtime_dependency_path
if [ -n "${DYLD_FALLBACK_LIBRARY_PATH:-}" ]; then
	dyld_fallback_path="${dyld_fallback_path}${dyld_fallback_path:+:}$DYLD_FALLBACK_LIBRARY_PATH"
fi
if feature_output=$(DYLD_LIBRARY_PATH="$openldap_library_path${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
	DYLD_FALLBACK_LIBRARY_PATH="$dyld_fallback_path" \
	LD_LIBRARY_PATH="$runtime_library_path${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$built_slapd" -VVV 2>&1); then
	:
else
	feature_status=$?
	die "the built slapd -VVV exited $feature_status: $feature_output"
fi
if [ -z "$feature_output" ]; then
	die "the built slapd cannot start; runtime library path: $runtime_library_path"
fi

for feature in $enabled_backends; do
	case "$feature_output" in
		*"    $feature"*) ;;
		*) die "slapd -VVV does not list configured backend: $feature" ;;
	esac
done
for feature in $enabled_overlays; do
	listed_feature=$feature
	if [ "$feature" = proxycache ]; then
		listed_feature=pcache
	fi
	case "$feature_output" in
		*"    $listed_feature"*) ;;
		*) die "slapd -VVV does not list configured overlay: $feature" ;;
	esac
done

crypt_probe_password=ldap-go-reference-crypt-probe
if ! crypt_probe_output=$(DYLD_LIBRARY_PATH="$openldap_library_path${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
	DYLD_FALLBACK_LIBRARY_PATH="$dyld_fallback_path" \
	LD_LIBRARY_PATH="$runtime_library_path${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$slappasswd" -s "$crypt_probe_password" -h '{CRYPT}' 2>&1); then
	die "the built slappasswd does not support {CRYPT}: $crypt_probe_output"
fi
case "$crypt_probe_output" in
	'{CRYPT}'?*) ;;
	*) die "the built slappasswd returned an invalid {CRYPT} probe: $crypt_probe_output" ;;
esac

version=$(printf '%s\n' "$feature_output" | sed -n 's/.*slapd \([^[:space:]]*\).*/\1/p' | head -n 1)
if [ -z "$version" ]; then
	die "could not determine the built slapd version"
fi
if [ "$allow_unverified_reference" -ne 1 ] && [ "$version" != "$verified_version" ]; then
	die "the pinned source built slapd $version; expected $verified_version"
fi
expected_runtime_version=$verified_version
if [ "$allow_unverified_reference" -eq 1 ]; then
	expected_runtime_version=$version
fi

tool_path=$slap_tool_dir:$artifact_build_dir/servers/slapd:$artifact_build_dir/servers/lloadd:$artifact_build_dir/clients/tools
{
	printf '# Generated by scripts/build-openldap-reference.sh.\n'
	write_export OPENLDAP_SOURCE "$source_dir"
	write_export OPENLDAP_COMMIT "$revision"
	write_export OPENLDAP_VERIFIED_COMMIT "$verified_revision"
	write_export OPENLDAP_REFERENCE_VERIFIED "$((1 - allow_unverified_reference))"
	write_export OPENLDAP_BUILD "$requested_build_dir"
	write_export OPENLDAP_BUILD_WORK "$effective_build_dir"
	write_export OPENLDAP_PREFIX "$prefix_dir"
	write_export OPENLDAP_CPPFLAGS "$cppflags"
	write_export OPENLDAP_LDFLAGS "$ldflags"
	write_export OPENLDAP_OPENSSL_PREFIX "$openssl_prefix"
	write_export OPENLDAP_LIBTOOL_PREFIX "$libtool_prefix"
	write_export OPENLDAP_SLAPD "$slapd"
	write_export OPENLDAP_SLAPADD "$slapadd"
	write_export OPENLDAP_SLAPPASSWD "$slappasswd"
	write_export OPENLDAP_LLOADD "$lloadd"
	write_export OPENLDAP_HAS_BACKEND_PASSWD "1"
	write_export OPENLDAP_HAS_BACKEND_DNSSRV "1"
	write_export OPENLDAP_HAS_BACKEND_ASYNCMETA "1"
	write_export OPENLDAP_HAS_SLAPD_CRYPT "1"
	write_export OPENLDAP_SCHEMA_DIR "$schema_dir"
	write_export OPENLDAP_ACTUAL_VERSION "$version"
	write_export OPENLDAP_EXPECTED_VERSION "$expected_runtime_version"
	printf 'export PATH='
	shell_quote "$tool_path"
	printf '${PATH:+":${PATH}"}\n'
	printf 'export DYLD_LIBRARY_PATH='
	shell_quote "$openldap_library_path"
	printf '${DYLD_LIBRARY_PATH:+":${DYLD_LIBRARY_PATH}"}\n'
	if [ -n "$runtime_dependency_path" ]; then
		printf 'export DYLD_FALLBACK_LIBRARY_PATH='
		shell_quote "$runtime_dependency_path"
		printf '${DYLD_FALLBACK_LIBRARY_PATH:+":${DYLD_FALLBACK_LIBRARY_PATH}"}\n'
	fi
	printf 'export LD_LIBRARY_PATH='
	shell_quote "$runtime_library_path"
	printf '${LD_LIBRARY_PATH:+":${LD_LIBRARY_PATH}"}\n'
	if [ -n "$sasl_plugin_path" ]; then
		printf 'export SASL_PATH='
		shell_quote "$sasl_plugin_path"
		printf '${SASL_PATH:+":${SASL_PATH}"}\n'
	fi
} >"$env_file"

printf '%s\n' "$feature_output"
printf 'Reference environment: %s\n' "$env_file"
printf "Load it with: . %s\n" "$(shell_quote "$env_file")"
if [ -n "$sasl_plugin_path" ]; then
	printf 'Cyrus SASL plugins: %s\n' "$sasl_plugin_path"
else
	printf 'Cyrus SASL mechanisms are runtime plugins; the strict suite will fail if SCRAM-SHA-256 is unavailable.\n'
fi

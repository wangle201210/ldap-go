#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/common.sh"

root=$(release_root)

usage() {
	printf '%s\n' 'usage: upgrade-gate.sh [--print-previous-ref]'
}

case ${1:-} in
'') ;;
--print-previous-ref)
	release_previous_ref "$root"
	exit 0
	;;
-h|--help)
	usage
	exit 0
	;;
*)
	usage >&2
	exit 2
	;;
esac

previous_ref=$(release_previous_ref "$root")
previous_commit=$(git -C "$root" rev-parse "$previous_ref^{commit}")
current_commit=$(git -C "$root" rev-parse HEAD)

if [ "${RELEASE_DRY_RUN:-0}" = 1 ]; then
	printf 'previous_ref=%s previous_commit=%s current_commit=%s\n' \
		"$previous_ref" "$previous_commit" "$current_commit"
	exit 0
fi

artifact_dir=$(release_make_artifact_dir ldap-go-release-upgrade)
work_dir=$artifact_dir/work
previous_source=$work_dir/previous-source
bin_dir=$work_dir/bin
mkdir -p "$previous_source" "$bin_dir"

cleanup() {
	if [ -n "${live_pid:-}" ]; then
		kill -TERM "$live_pid" 2>/dev/null || true
		wait "$live_pid" 2>/dev/null || true
	fi
	rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

printf 'Release upgrade gate artifacts: %s\n' "$artifact_dir"
printf 'Building previous version %s (%s)...\n' "$previous_ref" "$previous_commit"
git -C "$root" archive "$previous_commit" | tar -x -C "$previous_source"
(
	cd "$previous_source"
	CGO_ENABLED=0 go build \
		-ldflags "-s -w -X main.version=$previous_commit" \
		-o "$bin_dir/ldap-go-previous" ./cmd/ldap-go
)

printf 'Building current version %s...\n' "$current_commit"
(
	cd "$root"
	CGO_ENABLED=0 go build \
		-ldflags "-s -w -X main.version=$current_commit" \
		-o "$bin_dir/ldap-go-current" ./cmd/ldap-go
)

command_has_flag() {
	binary=$1
	command=$2
	flag=$3
	help=$("$binary" "$command" -h 2>&1 || true)
	printf '%s\n' "$help" | grep -F -- "$flag" >/dev/null 2>&1
}

fixture_profile=legacy
if command_has_flag "$bin_dir/ldap-go-previous" import -database &&
	command_has_flag "$bin_dir/ldap-go-previous" slapadd -n &&
	command_has_flag "$bin_dir/ldap-go-previous" slapcat -n &&
	command_has_flag "$bin_dir/ldap-go-current" import -database &&
	command_has_flag "$bin_dir/ldap-go-current" slapcat -n; then
	fixture_profile=enhanced
fi

fixture_ldif=$work_dir/fixture.ldif
cat >"$fixture_ldif" <<'EOF'
dn: dc=release,dc=example
objectClass: top
objectClass: domain
dc: release

dn: ou=people,dc=release,dc=example
objectClass: top
objectClass: organizationalUnit
ou: people

dn: uid=upgrade,ou=people,dc=release,dc=example
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: upgrade
cn: Release Upgrade
sn: Upgrade
description: N-1 database compatibility fixture
mail: upgrade@release.example
userPassword: {SSHA}r9NiHsBldWaw++R8LBeZQOY3qCevWYxK

dn: cn=ops,dc=release,dc=example
objectClass: top
objectClass: groupOfNames
cn: ops
member: uid=upgrade,ou=people,dc=release,dc=example
EOF

config_ldif=$work_dir/config.ldif
primary_ldif=$work_dir/primary.ldif
secondary_ldif=$work_dir/secondary.ldif
cat >"$config_ldif" <<'EOF'
dn: cn=config
objectClass: olcGlobal
cn: config
olcDefaultSearchBase: releaseExactName=Tenant+releaseFoldName=Release

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}releasegate,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}releasegate
olcAttributeTypes: ( 1.3.6.1.4.1.55555.90.1 NAME ( 'releaseExactName' 'releaseExactAlias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcAttributeTypes: ( 1.3.6.1.4.1.55555.90.2 NAME ( 'releaseFoldName' 'releaseFoldAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcObjectClasses: ( 1.3.6.1.4.1.55555.90.3 NAME 'releaseGateEntry' SUP top STRUCTURAL MUST cn MAY ( releaseExactName $ releaseFoldName $ uid $ description ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
entryUUID: 10000000-0000-4000-8000-000000000000

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: releaseExactName=Tenant+releaseFoldName=Release
olcRootDN: cn=admin,releaseExactName=Tenant+releaseFoldName=Release
olcDbIndex: releaseExactName eq,sub
olcDbIndex: releaseFoldName eq,sub
olcDbIndex: uid eq
olcAccess: {0}to * by * read
entryUUID: 11111111-1111-4111-8111-111111111111

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: dc=secondary,dc=release
olcRootDN: cn=admin,dc=secondary,dc=release
olcDbIndex: uid eq
olcDbIndex: cn eq,sub
olcAccess: {0}to * by * read
entryUUID: 22222222-2222-4222-8222-222222222222
EOF

cat >"$primary_ldif" <<'EOF'
dn: releaseExactName=Tenant+releaseFoldName=Release
objectClass: top
objectClass: releaseGateEntry
cn: Release Primary
releaseExactName: Tenant
releaseFoldName: Release
description: primary indexed partition

dn: releaseExactName=Alice+releaseFoldName=Engineering,releaseExactName=Tenant+releaseFoldName=Release
objectClass: top
objectClass: releaseGateEntry
cn: Exact Upper
uid: exact-upper
releaseExactName: Alice
releaseFoldName: Engineering

dn: releaseExactName=alice+releaseFoldName=engineering,releaseExactName=Tenant+releaseFoldName=Release
objectClass: top
objectClass: releaseGateEntry
cn: Exact Lower
uid: exact-lower
releaseExactName: alice
releaseFoldName: engineering
EOF

cat >"$secondary_ldif" <<'EOF'
dn: dc=secondary,dc=release
objectClass: top
objectClass: domain
dc: secondary
description: secondary indexed partition

dn: uid=secondary,dc=secondary,dc=release
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: secondary
cn: Secondary Partition
sn: Partition
EOF

export_fixture() {
	binary=$1
	database=$2
	prefix=$3
	if [ "$fixture_profile" = enhanced ]; then
		"$binary" slapcat -db "$database" -n 0 -l "$prefix-config.ldif"
		"$binary" slapcat -db "$database" -n 1 -g -l "$prefix-primary.ldif"
		"$binary" slapcat -db "$database" -n 2 -g -l "$prefix-secondary.ldif"
		: >"$prefix.ldif"
		for part in config primary secondary; do
			cat "$prefix-$part.ldif" >>"$prefix.ldif"
		done
	else
		"$binary" export -db "$database" -ldif "$prefix.ldif"
	fi
}

normalize_ldif_semantics() {
	source=$1
	destination=$2
	unfolded=$work_dir/unfolded-$$
	awk '
		NR == 1 { logical=$0; next }
		/^ / { logical=logical substr($0, 2); next }
		{ if (logical != "") print logical; logical=$0 }
		END { if (logical != "") print logical }
	' "$source" >"$unfolded"
	awk '
		/^dn: / { dn=$0 }
		NF > 0 { print dn "\t" $0 }
	' "$unfolded" | LC_ALL=C sort >"$destination"
	rm -f "$unfolded"
}

compare_ldif_semantics() {
	left=$1
	right=$2
	left_normalized=$3
	right_normalized=$4
	normalize_ldif_semantics "$left" "$left_normalized"
	normalize_ldif_semantics "$right" "$right_normalized"
	cmp "$left_normalized" "$right_normalized"
}

require_line_count() {
	expected=$1
	pattern=$2
	path=$3
	count=$(grep -c -- "$pattern" "$path" || true)
	[ "$count" -eq "$expected" ] || {
		printf 'expected %s lines matching %s in %s, got %s\n' \
			"$expected" "$pattern" "$path" "$count" >&2
		return 1
	}
}

verify_live_semantics() {
	binary=$1
	database=$2
	prefix=$3
	stdout_file=$prefix-server.stdout
	log_file=$prefix-server.log
	LDAP_GO_ROOT_PASSWORD=release-gate-local-secret \
		"$binary" serve -db "$database" -listen 127.0.0.1:0 -log-level warn \
		>"$stdout_file" 2>"$log_file" &
	live_pid=$!
	remaining=30
	uri=
	while [ "$remaining" -gt 0 ]; do
		uri=$(sed -n 's/^ldap-go listening on \(ldap:\/\/.*\)$/\1/p' "$stdout_file" | sed -n '1p')
		[ -z "$uri" ] || break
		if ! kill -0 "$live_pid" 2>/dev/null; then
			wait "$live_pid" 2>/dev/null || true
			live_pid=
			printf 'current server exited before readiness; see %s\n' "$log_file" >&2
			return 1
		fi
		sleep 1
		remaining=$((remaining - 1))
	done
	[ -n "$uri" ] || return 1

	primary_base='releaseExactName=Tenant+releaseFoldName=Release'
	"$binary" ldapsearch -H "$uri" -x -LLL -b "$primary_base" \
		'(releaseExactName=Alice)' releaseExactName releaseFoldName \
		>"$prefix-case-exact.ldif"
	require_line_count 1 '^dn: releaseExactName=Alice+releaseFoldName=Engineering,' \
		"$prefix-case-exact.ldif"
	require_line_count 0 '^dn: releaseExactName=alice+releaseFoldName=engineering,' \
		"$prefix-case-exact.ldif"

	"$binary" ldapsearch -H "$uri" -x -LLL -b "$primary_base" \
		'(releaseFoldName=engineering)' releaseExactName releaseFoldName \
		>"$prefix-case-ignore.ldif"
	require_line_count 2 '^dn: releaseExactName=.*+releaseFoldName=[Ee]ngineering,' \
		"$prefix-case-ignore.ldif"

	"$binary" ldapsearch -H "$uri" -x -LLL -b dc=secondary,dc=release \
		'(uid=secondary)' uid cn >"$prefix-secondary.ldif"
	require_line_count 1 '^dn: uid=secondary,dc=secondary,dc=release$' \
		"$prefix-secondary.ldif"

	kill -TERM "$live_pid"
	wait "$live_pid"
	live_pid=
}

previous_db=$work_dir/previous.db
previous_backup=$work_dir/previous.backup.db
upgraded_db=$work_dir/upgraded.db
restored_previous_db=$work_dir/restored-previous.db
current_backup=$work_dir/current.backup.db
restored_current_db=$work_dir/restored-current.db
roundtrip_db=$work_dir/roundtrip.db

printf 'Creating N-1 database fixture...\n'
if [ "$fixture_profile" = enhanced ]; then
	"$bin_dir/ldap-go-previous" import \
		-db "$previous_db" -ldif "$config_ldif" -replace
	"$bin_dir/ldap-go-previous" slapadd \
		-db "$previous_db" -n 1 -l "$primary_ldif" -S 7 -w
	"$bin_dir/ldap-go-previous" slapadd \
		-db "$previous_db" -n 2 -l "$secondary_ldif" -S 7 -w
else
	printf 'Previous CLI lacks selected-database support; using legacy fixture.\n'
	"$bin_dir/ldap-go-previous" import \
		-db "$previous_db" -ldif "$fixture_ldif" -replace
fi
"$bin_dir/ldap-go-previous" check -db "$previous_db"
export_fixture "$bin_dir/ldap-go-previous" "$previous_db" "$artifact_dir/previous"
"$bin_dir/ldap-go-previous" backup \
	-db "$previous_db" -out "$previous_backup"

printf 'Opening and rebuilding the N-1 database with the current binary...\n'
cp "$previous_db" "$upgraded_db"
"$bin_dir/ldap-go-current" check -db "$upgraded_db"
"$bin_dir/ldap-go-current" rebuild -db "$upgraded_db"
"$bin_dir/ldap-go-current" check -db "$upgraded_db"
export_fixture "$bin_dir/ldap-go-current" "$upgraded_db" "$artifact_dir/upgraded"
cmp "$artifact_dir/previous.ldif" "$artifact_dir/upgraded.ldif"
if [ "$fixture_profile" = enhanced ]; then
	verify_live_semantics "$bin_dir/ldap-go-current" "$upgraded_db" \
		"$artifact_dir/upgraded-live"
fi

printf 'Restoring an N-1 backup with the current binary...\n'
"$bin_dir/ldap-go-current" restore \
	-backup "$previous_backup" -db "$restored_previous_db"
"$bin_dir/ldap-go-current" check -db "$restored_previous_db"
export_fixture "$bin_dir/ldap-go-current" "$restored_previous_db" \
	"$artifact_dir/restored-previous"
cmp "$artifact_dir/upgraded.ldif" "$artifact_dir/restored-previous.ldif"
if [ "$fixture_profile" = enhanced ]; then
	verify_live_semantics "$bin_dir/ldap-go-current" "$restored_previous_db" \
		"$artifact_dir/restored-previous-live"
fi

printf 'Testing current backup and restore...\n'
"$bin_dir/ldap-go-current" backup \
	-db "$upgraded_db" -out "$current_backup"
"$bin_dir/ldap-go-current" restore \
	-backup "$current_backup" -db "$restored_current_db"
"$bin_dir/ldap-go-current" check -db "$restored_current_db"
export_fixture "$bin_dir/ldap-go-current" "$restored_current_db" \
	"$artifact_dir/restored-current"
cmp "$artifact_dir/upgraded.ldif" "$artifact_dir/restored-current.ldif"
if [ "$fixture_profile" = enhanced ]; then
	verify_live_semantics "$bin_dir/ldap-go-current" "$restored_current_db" \
		"$artifact_dir/restored-current-live"
fi

printf 'Testing canonical LDIF export/import/export round trip...\n'
if [ "$fixture_profile" = enhanced ]; then
	"$bin_dir/ldap-go-current" import -db "$roundtrip_db" \
		-ldif "$artifact_dir/upgraded-config.ldif" -replace
	"$bin_dir/ldap-go-current" import -db "$roundtrip_db" -database 1 \
		-ldif "$artifact_dir/upgraded-primary.ldif" -replace
	"$bin_dir/ldap-go-current" import -db "$roundtrip_db" -database 2 \
		-ldif "$artifact_dir/upgraded-secondary.ldif" -replace
else
	"$bin_dir/ldap-go-current" import \
		-db "$roundtrip_db" -ldif "$artifact_dir/upgraded.ldif" -replace
fi
"$bin_dir/ldap-go-current" check -db "$roundtrip_db"
export_fixture "$bin_dir/ldap-go-current" "$roundtrip_db" "$artifact_dir/roundtrip"
if [ "$fixture_profile" = enhanced ]; then
	compare_ldif_semantics \
		"$artifact_dir/upgraded.ldif" "$artifact_dir/roundtrip.ldif" \
		"$artifact_dir/upgraded.semantic" "$artifact_dir/roundtrip.semantic"
	verify_live_semantics "$bin_dir/ldap-go-current" "$roundtrip_db" \
		"$artifact_dir/roundtrip-live"
else
	cmp "$artifact_dir/upgraded.ldif" "$artifact_dir/roundtrip.ldif"
fi

cp "$previous_backup" "$artifact_dir/previous.backup.db"
cp "$current_backup" "$artifact_dir/current.backup.db"
cat >"$artifact_dir/upgrade-report.txt" <<EOF
previous_ref=$previous_ref
previous_commit=$previous_commit
current_commit=$current_commit
fixture_profile=$fixture_profile
database_upgrade=passed
previous_backup_restore=passed
current_backup_restore=passed
ldif_roundtrip=passed
config_metadata=$([ "$fixture_profile" = enhanced ] && printf passed || printf unsupported-by-previous-cli)
custom_case_exact_schema=$([ "$fixture_profile" = enhanced ] && printf passed || printf unsupported-by-previous-cli)
multi_ava_dn=$([ "$fixture_profile" = enhanced ] && printf passed || printf unsupported-by-previous-cli)
multiple_partitions=$([ "$fixture_profile" = enhanced ] && printf passed || printf unsupported-by-previous-cli)
indexed_live_search=$([ "$fixture_profile" = enhanced ] && printf passed || printf unsupported-by-previous-cli)
EOF

(
	cd "$artifact_dir"
	set -- \
		current.backup.db previous.backup.db \
		previous.ldif upgraded.ldif restored-previous.ldif \
		restored-current.ldif roundtrip.ldif upgrade-report.txt
	if [ "$fixture_profile" = enhanced ]; then
		set -- "$@" \
			previous-config.ldif previous-primary.ldif previous-secondary.ldif \
			upgraded-config.ldif upgraded-primary.ldif upgraded-secondary.ldif \
			restored-previous-config.ldif restored-previous-primary.ldif \
			restored-previous-secondary.ldif restored-current-config.ldif \
			restored-current-primary.ldif restored-current-secondary.ldif \
			roundtrip-config.ldif roundtrip-primary.ldif roundtrip-secondary.ldif \
			upgraded.semantic roundtrip.semantic \
			upgraded-live-case-exact.ldif upgraded-live-case-ignore.ldif \
			upgraded-live-secondary.ldif \
			restored-previous-live-case-exact.ldif \
			restored-previous-live-case-ignore.ldif \
			restored-previous-live-secondary.ldif \
			restored-current-live-case-exact.ldif \
			restored-current-live-case-ignore.ldif \
			restored-current-live-secondary.ldif \
			roundtrip-live-case-exact.ldif roundtrip-live-case-ignore.ldif \
			roundtrip-live-secondary.ldif
	fi
	release_sha256 "$@" >UPGRADE_SHA256SUMS
)

printf 'Release upgrade gate passed: %s -> %s\n' \
	"$previous_ref" "$current_commit"

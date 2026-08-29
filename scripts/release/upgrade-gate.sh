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

previous_db=$work_dir/previous.db
previous_backup=$work_dir/previous.backup.db
upgraded_db=$work_dir/upgraded.db
restored_previous_db=$work_dir/restored-previous.db
current_backup=$work_dir/current.backup.db
restored_current_db=$work_dir/restored-current.db
roundtrip_db=$work_dir/roundtrip.db

printf 'Creating N-1 database fixture...\n'
"$bin_dir/ldap-go-previous" import \
	-db "$previous_db" -ldif "$fixture_ldif" -replace
"$bin_dir/ldap-go-previous" check -db "$previous_db"
"$bin_dir/ldap-go-previous" export \
	-db "$previous_db" -ldif "$artifact_dir/previous.ldif"
"$bin_dir/ldap-go-previous" backup \
	-db "$previous_db" -out "$previous_backup"

printf 'Opening and rebuilding the N-1 database with the current binary...\n'
cp "$previous_db" "$upgraded_db"
"$bin_dir/ldap-go-current" check -db "$upgraded_db"
"$bin_dir/ldap-go-current" rebuild -db "$upgraded_db"
"$bin_dir/ldap-go-current" check -db "$upgraded_db"
"$bin_dir/ldap-go-current" export \
	-db "$upgraded_db" -ldif "$artifact_dir/upgraded.ldif"
cmp "$artifact_dir/previous.ldif" "$artifact_dir/upgraded.ldif"

printf 'Restoring an N-1 backup with the current binary...\n'
"$bin_dir/ldap-go-current" restore \
	-backup "$previous_backup" -db "$restored_previous_db"
"$bin_dir/ldap-go-current" check -db "$restored_previous_db"
"$bin_dir/ldap-go-current" export \
	-db "$restored_previous_db" -ldif "$artifact_dir/restored-previous.ldif"
cmp "$artifact_dir/upgraded.ldif" "$artifact_dir/restored-previous.ldif"

printf 'Testing current backup and restore...\n'
"$bin_dir/ldap-go-current" backup \
	-db "$upgraded_db" -out "$current_backup"
"$bin_dir/ldap-go-current" restore \
	-backup "$current_backup" -db "$restored_current_db"
"$bin_dir/ldap-go-current" check -db "$restored_current_db"
"$bin_dir/ldap-go-current" export \
	-db "$restored_current_db" -ldif "$artifact_dir/restored-current.ldif"
cmp "$artifact_dir/upgraded.ldif" "$artifact_dir/restored-current.ldif"

printf 'Testing canonical LDIF export/import/export round trip...\n'
"$bin_dir/ldap-go-current" import \
	-db "$roundtrip_db" -ldif "$artifact_dir/upgraded.ldif" -replace
"$bin_dir/ldap-go-current" check -db "$roundtrip_db"
"$bin_dir/ldap-go-current" export \
	-db "$roundtrip_db" -ldif "$artifact_dir/roundtrip.ldif"
cmp "$artifact_dir/upgraded.ldif" "$artifact_dir/roundtrip.ldif"

cp "$previous_backup" "$artifact_dir/previous.backup.db"
cp "$current_backup" "$artifact_dir/current.backup.db"
cat >"$artifact_dir/upgrade-report.txt" <<EOF
previous_ref=$previous_ref
previous_commit=$previous_commit
current_commit=$current_commit
database_upgrade=passed
previous_backup_restore=passed
current_backup_restore=passed
ldif_roundtrip=passed
EOF

(
	cd "$artifact_dir"
	release_sha256 \
		current.backup.db previous.backup.db \
		previous.ldif upgraded.ldif restored-previous.ldif \
		restored-current.ldif roundtrip.ldif upgrade-report.txt \
		>UPGRADE_SHA256SUMS
)

printf 'Release upgrade gate passed: %s -> %s\n' \
	"$previous_ref" "$current_commit"

#!/bin/sh
set -eu
mode=${1:-default}
case "$mode" in default|explicit|swap|explicit-swap|explicit-aa) ;; *) exit 2;; esac
. /var/tmp/ldap-go-openldap-reference-r20-rebuilt/openldap-reference.env
audit=/var/tmp/ldap-go-perf-20260930-r25-lazy-get
baseline=/var/tmp/ldap-go-perf-20260930-r22
seeds=/var/tmp/ldap-go-perf-20260930-r20-request
source_dir=/var/tmp/ldap-go-r20-reference-recovery
out=$audit/network-${2:-$mode}
mkdir "$out"
umask 077
LDAP_BENCH_PASSWORD=$(openssl rand -hex 24)
export LDAP_BENCH_PASSWORD
printf '%s' "$LDAP_BENCH_PASSWORD" >"$out/password"
pids=
cleanup() {
  for pid in $pids; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in $pids; do wait "$pid" 2>/dev/null || true; done
  pids=
  rm -f "$out/password"
  if [ -f "$out/openldap/slapd.conf" ]; then
    sed -i '' 's/^rootpw .*/rootpw REMOVED_DISPOSABLE_CREDENTIAL/' "$out/openldap/slapd.conf"
  fi
}
trap cleanup EXIT HUP INT TERM
root_dn=cn=admin,dc=scale,dc=qualification
people_dn=ou=people,dc=scale,dc=qualification
sides='before current openldap'
if [ "$mode" = swap ] || [ "$mode" = explicit-swap ]; then sides='current before openldap'; fi
port_for() {
  case "$1:$mode" in
    before:swap|before:explicit-swap|current:default|current:explicit|current:explicit-aa) printf 29582;;
    current:swap|current:explicit-swap|before:default|before:explicit|before:explicit-aa) printf 29581;;
    openldap:*) printf 29583;;
  esac
}
for side in $sides; do
  port=$(port_for "$side")
  uri=ldap://127.0.0.1:$port
  directory=$out/$side
  mkdir "$directory"
  if [ "$side" = openldap ]; then
    mkdir "$directory/data"
    cp -c "$source_dir/openldap-1/data/data.mdb" "$directory/data/data.mdb"
    sed -e '/^rootpw /d' -e 's|^index uid eq|index uid,member eq|' \
      -e "s|^directory .*|directory $directory/data|" \
      -e "s|^pidfile .*|pidfile $directory/slapd.pid|" \
      -e "s|^argsfile .*|argsfile $directory/slapd.args|" \
      -e "s|^include .*/core.schema|include $OPENLDAP_SCHEMA_DIR/core.schema|" \
      -e "s|^include .*/cosine.schema|include $OPENLDAP_SCHEMA_DIR/cosine.schema|" \
      -e "s|^include .*/inetorgperson.schema|include $OPENLDAP_SCHEMA_DIR/inetorgperson.schema|" \
      "$source_dir/openldap-1/slapd.conf" >"$directory/slapd.conf"
    printf 'rootpw %s\n' "$LDAP_BENCH_PASSWORD" >>"$directory/slapd.conf"
    if [ "$mode" = explicit ] || [ "$mode" = explicit-swap ] || [ "$mode" = explicit-aa ]; then
      printf '%s\n' 'access to attrs=userPassword by self write by anonymous auth by * none' 'access to * by users read by * none' >>"$directory/slapd.conf"
    fi
    slapindex -f "$directory/slapd.conf" -n 1 member >"$directory/reindex.log" 2>&1
    slapd -f "$directory/slapd.conf" -h "$uri" -d 0 >"$directory/server.log" 2>&1 &
  else
    seed=$seeds/member-index.db
    if [ "$mode" = explicit ] || [ "$mode" = explicit-swap ] || [ "$mode" = explicit-aa ]; then seed=$seeds/member-acl.db; fi
    cp -c "$seed" "$directory/data.db"
    binary=$audit/current
    if [ "$side" = before ] && [ "$mode" != explicit-aa ]; then binary=$baseline/current; fi
    LDAP_GO_ROOT_PASSWORD="$LDAP_BENCH_PASSWORD" "$binary" serve \
      -db "$directory/data.db" -listen 127.0.0.1:$port -root-dn "$root_dn" \
      -search-limit 100100 -search-candidate-limit 100100 \
      -search-candidate-bytes 819200000 -search-memory-bytes 1638400000 \
      >"$directory/server.log" 2>&1 &
  fi
  pid=$!
  pids="$pids $pid"
  deadline=$(( $(date +%s) + 60 ))
  until ldapwhoami -H "$uri" -x -D "$root_dn" -y "$out/password" -o nettimeout=1 >/dev/null 2>&1; do
    kill -0 "$pid"
    [ "$(date +%s)" -lt "$deadline" ]
    sleep 0.05
  done
  "$source_dir/ldapbench" -uri "$uri" -bind-dn "$root_dn" -password-env LDAP_BENCH_PASSWORD \
    -base dc=scale,dc=qualification -people "$people_dn" -read-only -n 2 -entries 100000 \
    -label "$side-warmup" >"$directory/warmup.json"
done
run_common() {
  "$seeds/ldapcommonbench-group" \
    -endpoint before=ldap://127.0.0.1:$(port_for before) \
    -endpoint current=ldap://127.0.0.1:$(port_for current) \
    -endpoint openldap=ldap://127.0.0.1:$(port_for openldap) \
    -base dc=scale,dc=qualification -root-bind-dn "$root_dn" \
    -root-password-env LDAP_BENCH_PASSWORD -timeout 30s -setup-disposable \
    -people "$people_dn" "$@"
}
run_common -stages groupCompareTrueFirst,groupCompareTrueLast,groupCompareFalse \
  -group-sizes 10,1000 -n 1000 -repeats 7 >"$out/groups.json"
run_common -uid scale-001001 -stages userBind,userBindWrong,base,equality \
  -n 1000 -repeats 7 >"$out/hot.json"
printf 'run\tcanonical_entries\tcanonical_cksum\tcanonical_bytes\n' >"$out/validation.tsv"
for side in before current openldap; do
  directory=$out/$side
  ldapsearch -H ldap://127.0.0.1:$(port_for "$side") -x -D "$root_dn" -y "$out/password" \
    -LLL -o ldif-wrap=no -E pr=10000/noprompt -b dc=scale,dc=qualification '(objectClass=*)' '*' >"$directory/data.ldif"
  "$source_dir/ldifcanonical" -in "$directory/data.ldif" >"$directory/data.unsorted"
  LC_ALL=C sort "$directory/data.unsorted" >"$directory/data.canonical"
  rm "$directory/data.unsorted"
  count=$(wc -l <"$directory/data.canonical" | tr -d ' ')
  [ "$count" -eq 100002 ]
  set -- $(cksum "$directory/data.canonical")
  [ "$1" = 2143929969 ]
  [ "$2" = 42712438 ]
  printf '%s\t%s\t%s\t%s\n' "$side" "$count" "$1" "$2" >>"$out/validation.tsv"
  cmp "$source_dir/data.canonical" "$directory/data.canonical"
done
cleanup
trap - EXIT HUP INT TERM
rm "$out/before/data.db" "$out/current/data.db" "$out/openldap/data/data.mdb"
printf 'Comparison and canonical exports passed.\n'

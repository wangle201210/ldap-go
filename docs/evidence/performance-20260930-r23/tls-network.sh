#!/bin/sh
set -eu
mode=${1:?use ldaps or starttls}
case "$mode" in ldaps|starttls) ;; *) exit 2;; esac
. /var/tmp/ldap-go-openldap-reference-r20-rebuilt/openldap-reference.env
audit=/var/tmp/ldap-go-perf-20260930-r23-input
source_dir=/var/tmp/ldap-go-r20-reference-recovery
out=$audit/tls-$mode
mkdir "$out"
umask 077
openssl=/opt/homebrew/opt/openssl@3/bin/openssl
"$openssl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
  -keyout "$out/key.pem" -out "$out/cert.pem" -days 1 -subj /CN=ldapcommonbench \
  -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
  -addext 'basicConstraints=critical,CA:TRUE' >"$out/certificate.log" 2>&1
LDAP_BENCH_PASSWORD=$("$openssl" rand -hex 24)
LDAPTLS_CACERT=$out/cert.pem
export LDAP_BENCH_PASSWORD LDAPTLS_CACERT
printf '%s' "$LDAP_BENCH_PASSWORD" >"$out/password"
pids=
cleanup() {
  for pid in $pids; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in $pids; do wait "$pid" 2>/dev/null || true; done
  pids=
  rm -f "$out/password" "$out/key.pem"
  if [ -f "$out/openldap/slapd.conf" ]; then
    sed -i '' 's/^rootpw .*/rootpw REMOVED_DISPOSABLE_CREDENTIAL/' "$out/openldap/slapd.conf"
  fi
}
trap cleanup EXIT HUP INT TERM
scheme=ldap
upgrade=-ZZ
if [ "$mode" = ldaps ]; then scheme=ldaps; upgrade=; fi
root_dn=cn=admin,dc=scale,dc=qualification
people_dn=ou=people,dc=scale,dc=qualification
for side in ldapgo openldap; do
  port=29681
  if [ "$side" = openldap ]; then port=29683; fi
  uri=$scheme://127.0.0.1:$port
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
    printf 'rootpw %s\nTLSCertificateFile %s\nTLSCertificateKeyFile %s\nTLSCACertificateFile %s\n' \
      "$LDAP_BENCH_PASSWORD" "$out/cert.pem" "$out/key.pem" "$out/cert.pem" >>"$directory/slapd.conf"
    slapindex -f "$directory/slapd.conf" -n 1 member >"$directory/reindex.log" 2>&1
    slapd -f "$directory/slapd.conf" -h "$uri" -d 0 >"$directory/server.log" 2>&1 &
  else
    cp -c /var/tmp/ldap-go-perf-20260930-r20-request/member-index.db "$directory/data.db"
    implicit=false
    if [ "$mode" = ldaps ]; then implicit=true; fi
    LDAP_GO_ROOT_PASSWORD="$LDAP_BENCH_PASSWORD" /var/tmp/ldap-go-perf-20260930-r22/current serve \
      -db "$directory/data.db" -listen 127.0.0.1:$port -root-dn "$root_dn" \
      -ldaps="$implicit" -tls-cert "$out/cert.pem" -tls-key "$out/key.pem" \
      -search-limit 100100 -search-candidate-limit 100100 \
      -search-candidate-bytes 819200000 -search-memory-bytes 1638400000 \
      >"$directory/server.log" 2>&1 &
  fi
  pid=$!
  pids="$pids $pid"
  deadline=$(( $(date +%s) + 60 ))
  until ldapwhoami -H "$uri" $upgrade -x -D "$root_dn" -y "$out/password" -o nettimeout=1 >/dev/null 2>&1; do
    kill -0 "$pid"
    [ "$(date +%s)" -lt "$deadline" ]
    sleep 0.05
  done
done
run_common() {
  start=false
  if [ "$mode" = starttls ]; then start=true; fi
  "$audit/ldapcommonbench-tls" \
    -endpoint ldapgo=$scheme://127.0.0.1:29681 -endpoint openldap=$scheme://127.0.0.1:29683 \
    -tls-ca "$out/cert.pem" -start-tls="$start" \
    -base dc=scale,dc=qualification -root-bind-dn "$root_dn" \
    -root-password-env LDAP_BENCH_PASSWORD -timeout 30s -setup-disposable \
    -people "$people_dn" "$@"
}
run_common -uid scale-001001 -stages userBind,userBindWrong,base,equality \
  -n 2 -repeats 1 >"$out/smoke.json"
run_common -uid scale-001001 -stages userBind,userBindWrong,base,equality \
  -n 1000 -repeats 7 >"$out/hot.json"
run_common -stages groupCompareTrueFirst,groupCompareTrueLast,groupCompareFalse \
  -group-sizes 10,1000 -n 1000 -repeats 7 >"$out/groups.json"
printf 'run\tcanonical_entries\tcanonical_cksum\tcanonical_bytes\n' >"$out/validation.tsv"
for side in ldapgo openldap; do
  port=29681
  if [ "$side" = openldap ]; then port=29683; fi
  directory=$out/$side
  ldapsearch -H $scheme://127.0.0.1:$port $upgrade -x -D "$root_dn" -y "$out/password" \
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
rm "$out/ldapgo/data.db" "$out/openldap/data/data.mdb"
printf 'Verified TLS benchmark and canonical exports passed.\n'

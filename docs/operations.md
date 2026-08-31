# Operations

[Back to README](../README.md)

This guide covers the common runtime and production workflows. The exhaustive
behavioral boundary remains in the [implementation status](implementation-status.md)
and [compatibility matrix](compatibility.md).

## Build and initialize

```sh
mkdir -p ./bin ./data
go build -o ./bin/ldap-go ./cmd/ldap-go

./bin/ldap-go import \
  -db ./data/ldap-go.db \
  -ldif ./examples/base.ldif \
  -replace
```

Direct database commands are offline operations unless their help explicitly
says otherwise. Stop the server before using `import`, `export`, `check`,
`restore`, or `rebuild` against its database path.

## Start the directory server

Imported `olcRootDN` and `olcRootPW` values are loaded from `cn=config`. A
bootstrap override can be supplied without putting its password in process
arguments:

```sh
LDAP_GO_ROOT_PASSWORD='change-me' \
  ./bin/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389 \
  -root-dn cn=admin,dc=example,dc=com \
  -shutdown-timeout 30s
```

For local administration, add an LDAPI listener or run LDAPI only:

```sh
./bin/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen '' \
  -ldapi /var/run/ldap-go/ldapi \
  -ldapi-mode 0660

ldapsearch -x -H ldapi://%2Fvar%2Frun%2Fldap-go%2Fldapi/ \
  -D cn=admin,dc=example,dc=com -W \
  -b dc=example,dc=com '(objectClass=*)'
```

On Linux, macOS, and FreeBSD, LDAPI SASL EXTERNAL derives the OpenLDAP
peer-credential identity from the accepted kernel socket. It grants no
privilege by itself; configure `olcAuthzRegexp` and ACLs for selected UID/GID
identities.

## Web administration

Web Admin is an LDAP client process. It does not open ldap-go or OpenLDAP
database files, and every operation runs under the signed-in LDAP identity.

Connect to a local listener:

```sh
./bin/ldap-go web-admin \
  -listen 127.0.0.1:8080 \
  -ldap-url ldap://127.0.0.1:1389
```

Connect to a remote OpenLDAP server with StartTLS:

```sh
./bin/ldap-go web-admin \
  -listen 127.0.0.1:8080 \
  -ldap-url ldap://ldap.example.com:389 \
  -ldap-starttls \
  -ldap-tls-ca /etc/ldap/ca.pem
```

Use `ldaps://ldap.example.com:636` instead of `ldap://` and omit
`-ldap-starttls` for implicit TLS. Remote plaintext LDAP is rejected. Check
readiness before exposing the console:

```sh
curl --fail http://127.0.0.1:8080/readyz
```

Non-loopback HTTP requires `-tls-cert`, `-tls-key`, and a canonical
`-public-url`. See the [Web Admin feature matrix](webadmin-feature-matrix.md)
for functional and security boundaries.

## Backup and recovery

Offline backup and integrity commands operate directly on a stopped database:

```sh
./bin/ldap-go check -db ./data/ldap-go.db
./bin/ldap-go backup \
  -db ./data/ldap-go.db \
  -out ./data/ldap-go.backup.db
./bin/ldap-go restore \
  -backup ./data/ldap-go.backup.db \
  -db ./data/restored.db
./bin/ldap-go rebuild -db ./data/restored.db
```

For a running server, preconfigure a private destination and request a snapshot
through an authenticated LDAPI connection:

```sh
./bin/ldap-go serve \
  -db ./data/ldap-go.db \
  -ldapi /run/ldap-go/ldapi \
  -online-backup-dir /var/backups/ldap-go

./bin/ldap-go online-backup \
  -x -H ldapi://%2Frun%2Fldap-go%2Fldapi/ \
  -D cn=admin,dc=example,dc=com -W
```

Retention defaults to dry-run and requires `-apply` before deleting anything:

```sh
./bin/ldap-go backup-prune \
  -dir /var/backups/ldap-go \
  -prefix ldap-go- \
  -active-db /var/lib/ldap-go/ldap-go.db \
  -keep-last 7 -max-age 30d -format json

./bin/ldap-go backup-prune \
  -dir /var/backups/ldap-go \
  -prefix ldap-go- \
  -active-db /var/lib/ldap-go/ldap-go.db \
  -keep-last 7 -max-age 30d -apply
```

Restore is always offline. Keep the active database outside the backup
directory.

## Health and production checks

```sh
./bin/ldap-go health \
  -x -H ldapi://%2Frun%2Fldap-go%2Fldapi/ \
  -D cn=admin,dc=example,dc=com -W -json

./bin/ldap-go production-check \
  -db ./data/ldap-go.db -strict \
  -online-backup-dir /var/backups/ldap-go \
  -audit-log /var/log/ldap-go/audit.jsonl \
  -audit-key-file /etc/ldap-go/audit.key
```

`health` exits 2 when configured syncrepl consumers are unhealthy.
`production-check` exits 3 for confirmed failures and 4 when required evidence
is unknown. Run the repeatable capacity and crash suites described in
[production qualification](production-qualification.md) before deployment.

## Security auditing

Create a private HMAC key and configure the append-only JSON Lines audit log:

```sh
umask 077
openssl rand -hex 32 > ./data/audit.key

./bin/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389 \
  -audit-log ./data/audit.jsonl \
  -audit-key-file ./data/audit.key

./bin/ldap-go audit-verify \
  -audit-log ./data/audit.jsonl \
  -audit-key-file ./data/audit.key
```

Credentials, filter assertions, attribute values, and Password Modify values
are redacted before records reach the audit sink. Startup verifies the existing
HMAC-SHA-256 chain before appending.

## TLS and TLCP

Supplying a PEM certificate and key enables StartTLS:

```sh
./bin/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389 \
  -tls-cert ./server.crt \
  -tls-key ./server.key

ldapsearch -x -ZZ -H ldap://127.0.0.1:1389 \
  -b dc=example,dc=com '(objectClass=*)'
```

Add `-ldaps` for implicit TLS, or use `-ldaps-listen` to serve StartTLS and
LDAPS concurrently. TLS 1.2 is the minimum accepted version.

GB/T 38636 TLCP requires separate SM2 signing and encryption pairs:

```sh
./bin/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1636 \
  -tlcp-sign-cert ./server-sign.crt \
  -tlcp-sign-key ./server-sign.key \
  -tlcp-enc-cert ./server-enc.crt \
  -tlcp-enc-key ./server-enc.key \
  -tlcp-implicit
```

TLCP clients must implement GB/T 38636; stock TLS-only OpenLDAP clients cannot
connect to that transport. Full TLS, TLCP, client-certificate, SASL, and
syncrepl boundaries are listed in the
[implementation status](implementation-status.md#tls-tlcp-and-sasl).

## systemd and privilege separation

Use `serve -systemd-activation` to adopt descriptors beginning at fd 3. Exact
`LISTEN_FDNAMES` values `ldap`, `ldaps`, `tlcp`/`ldap+tlcp`, and `ldapi` select
the transport mode.

```ini
# ldap-go.socket
[Socket]
ListenStream=127.0.0.1:389
ListenStream=/run/ldap-go/ldapi
SocketMode=0660

[Install]
WantedBy=sockets.target

# ldap-go.service
[Service]
Type=notify
ExecStart=/usr/local/bin/ldap-go serve -systemd-activation -db /var/lib/ldap-go/directory.db
```

On supported Unix systems, `serve -u <user> -g <group> -r <jail>` opens or
adopts listeners before entering the jail and dropping privileges. With chroot,
use systemd activation for LDAPI and treat file arguments as paths inside the
jail.

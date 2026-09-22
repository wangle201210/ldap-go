# LDAP SDK probe

An internal, sequential probe using the existing `github.com/go-ldap/ldap/v3`
dependency. No external LDAP command, fixture importer, or server launcher is
used. Only connect to a disposable fixture explicitly supplied by its owner.
There are no default target URI, credentials, base DN, or people DN.

Build and parameter tests (no race detector or benchmarks):

```sh
CGO_ENABLED=0 GOFLAGS= go test ./internal/cmd/ldapbench
CGO_ENABLED=0 GOFLAGS= go build -o /var/tmp/ldapbench-sdk-probe ./internal/cmd/ldapbench
/var/tmp/ldapbench-sdk-probe -help
```

## Reproduce

Run before/current/native three times each, using a fresh disposable 100k
working copy for every invocation (nine copies total). The shared source is
`/var/tmp/ldap-go-perf-round2-20260922/fresh-100k`; keep it immutable. Start the
servers separately and supply each copy's actual URI and credentials. This
tool does not open fixture files, copy databases, or start servers.
That retained run includes parity edits to UIDs 2 and 3; restore their contiguous
range only in working copies using the
[qualification LDIF](../../../docs/evidence/performance-20260922-round4/restore-range.ldif),
or prepare a fresh fixture with `QUALIFICATION_COMPARE_DATA_PARITY=0`.

The expected people entries are `uid=scale-000001,<people>` through
`uid=scale-100000,<people>`, each with its matching `uid` attribute. `cn` is not
assumed or used. `-entries` changes the expected contiguous range for a local
dummy fixture. The probe samples the declared range; it does not certify the
entire fixture's size or that the server configured a `uid` equality index.

Set `LDAPBENCH_ROOT_PASSWORD` in the environment through your normal secret
entry mechanism. Write mode also requires `LDAPBENCH_USER_PASSWORD`, used only
for the temporary SSHA user. There is no password argument, file, stdin, or
implicit environment fallback; the named variables must be nonempty. Password
values and hashes are omitted from JSON.

Run in Bash after setting `BEFORE_URI_1` through `BEFORE_URI_3`,
`CURRENT_URI_1` through `CURRENT_URI_3`, and `NATIVE_URI_1` through
`NATIVE_URI_3` to the nine supplied instances. Use a fresh output directory.
The commands rotate target order and stop on any failure:

```bash
set -euo pipefail
export CGO_ENABLED=0
base='dc=scale,dc=qualification'
people="ou=people,$base"
bind_dn="cn=admin,$base"
common=(-bind-dn "$bind_dn" -password-env LDAPBENCH_ROOT_PASSWORD
        -base "$base" -people "$people" -entries 100000 -n 100 -timeout 10s)

run_probe() {
  /var/tmp/ldapbench-sdk-probe -uri "$3" -label "$1-$2" \
    "${common[@]}" -write -write-batch 100 \
    -user-password-env LDAPBENCH_USER_PASSWORD > "$1-$2.json"
}
run_probe before  1 "${BEFORE_URI_1:?}"
run_probe current 1 "${CURRENT_URI_1:?}"
run_probe native  1 "${NATIVE_URI_1:?}"
run_probe native  2 "${NATIVE_URI_2:?}"
run_probe before  2 "${BEFORE_URI_2:?}"
run_probe current 2 "${CURRENT_URI_2:?}"
run_probe current 3 "${CURRENT_URI_3:?}"
run_probe native  3 "${NATIVE_URI_3:?}"
run_probe before  3 "${BEFORE_URI_3:?}"
```

Write mode includes all read stages, so no preceding read-only warmup is needed.
For a separate read-only run, replace `-write -write-batch 100
-user-password-env LDAPBENCH_USER_PASSWORD` with `-read-only` and use another
copy/output file. Use the same built binary, fixture, indexing, machine load,
TLS settings and cache conditions across targets. Retain each JSON separately;
a nonzero exit means a partial/failed report, not a successful sample. This
tool performs no automatic warmup or concurrent workload.
Recorded measurements and their limits are in the
[broader operation report](../../../docs/performance-optimization-20260922-round4.md).

## Stages and results

Exactly one of `-read-only` and `-write` is required before any connection.
`-n` defaults to 100 and is clamped to 1..10000; `-write-batch` defaults to 100
and is clamped to 1..1000. JSON records the effective values. All connections
and requests have the supplied timeout. LDAPS uses normal certificate
verification; there is no insecure TLS option.

Both modes measure `rootBind`, `baseSearch`, `indexedEquality`, `compareTrue`,
`compareFalse`, `substringPrefix`, and `substringNegative`. Each has `n`
operations over a reused connection, with SDK result validation. Equality and
Compare sample across the UID range; prefix queries match up to 10 entries,
and negative queries must return none. Write mode adds `userBind` on an already
created SSHA user and independent `add`, `modify`, `modifyDN`, and `delete`
batches. Each write checks its SDK result and queries its postcondition.

Each stage has `operations` (attempted SDK calls), `total_ms` (summed call time,
including response validation), and `errors` (empty on success). Write
postcondition searches are counted in `verification_operations` and timed in
`verification_ms`, outside `total_ms`. `connect`, `userConnect`, `setup`, and
`cleanup` are separate stages. The cleanup stage includes reconnect, Bind and
Delete calls; it is not a pure Delete measurement. Stages stop at their first
failure, while cleanup attempts all known DNs unless its connection closes.

## Cleanup

All writes stay below a unique `ou=ldapbench-<128-bit token>,<base>` with an
ownership marker; existing people entries are never written. Setup creates the
SSHA user and separate modify/rename/delete batches before their measured stages.
After successfully creating the OU, cleanup runs on success, failure, SIGINT,
or SIGTERM. It reconnects as root, verifies the ownership marker, deletes only
known temporary DNs, then deletes the OU and verifies `noSuchObject`. Missing
old/deleted DNs are expected during cleanup. Cleanup errors also cause failure.
`run_dn` identifies the scope if a server outage or forced process termination
prevents cleanup. A lost initial OU Add response is reported for manual orphan
inspection; an existing OU is never adopted or recursively deleted.

Exit status: 0 success/help, 1 operation/verification/cleanup/output failure,
2 invalid arguments. Runtime and argument failures still produce JSON on stdout;
flag usage diagnostics go to stderr. Completed/partial stages remain in the
failure report. No fixture is discovered or imported, and read-only mode does
not send LDAP mutations (server-side Bind audit/last-bind overlays may still
update their own state).

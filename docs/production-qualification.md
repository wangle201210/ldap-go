# Production capacity and crash qualification

The qualification runner exercises a real `ldap-go serve` process through the
repository's own LDAP client commands. It is repeatable, loopback-only, and
keeps all evidence in a timestamped artifact directory.

This is a deployment qualification tool, not a microbenchmark. Use its results
to establish a tested operating envelope for a specific release, host, storage
device, filesystem, Go runtime, and server configuration. Results from one
environment do not establish limits for another.

## Entry points

Validate the shell scripts and their parameter contract without building or
starting a server:

```sh
make qualification-check
```

Run the default 15-second smoke profile with four concurrent client streams and
one forced server restart:

```sh
make qualification-smoke
```

Run the deterministic large-directory smoke profile. This is a separate
qualification because it measures import, index construction, startup, query,
resident memory, durable writes, and database size rather than sustained
concurrent throughput:

```sh
./scripts/qualification/scale.sh
```

Run the one-hour soak profile with 128 client streams, batches of 100 Search or
Modify operations per connection, and 12 forced restarts:

```sh
make qualification-soak
```

The runner builds `./cmd/ldap-go`, imports an isolated directory, starts the
server on an automatically assigned loopback port, and launches one workload
worker per configured client stream. Search and Modify use the CLI batch modes,
so each batch stays on one authenticated LDAP connection. Compare, Bind, and
Add/Delete use shorter connections. A client stream is therefore a concurrent
workload source; it is not a guarantee that every configured stream is inside
an LDAP operation at the same instant.

## Large-directory qualification

`scripts/qualification/scale.sh` generates deterministic LDIF and exercises a
real `ldap-go` binary with a bbolt database. The smoke profile defaults to 1,000
people. The bounded nightly profile defaults to 100,000 people:

```sh
QUALIFICATION_SCALE_PROFILE=nightly \
QUALIFICATION_SCALE_ARTIFACT_DIR=/var/tmp/ldap-go-scale-100k \
./scripts/qualification/scale.sh
```

The test performs and validates this ordered lifecycle:

1. Generate a stable `cn=config` plus content LDIF. `uid` has an equality
   index; `description` deliberately has no index.
2. Atomically import the LDIF, then run offline `slapindex` for `uid`.
3. Start a real loopback LDAP process on an ephemeral port and require an
   authenticated Who Am I readiness probe.
4. Measure an indexed equality Search, a bounded negative Search over the
   unindexed `description`, and RFC 2696 paging over the complete population.
5. Modify one entry, delete a different entry, and sample RSS before and after
   the workload.
6. Stop gracefully, measure bbolt size, restart the same database, verify the
   durable Modify/Delete results, sample RSS again, stop gracefully, and run an
   offline database check.

The generated LDIF is deterministic for a given entry count. Server ports,
timestamps, generated bbolt pages, and measured resource values are naturally
host-specific. The unindexed query has a client timeout, an LDAP time limit,
and the script-wide command deadline; it must return no entries successfully.

### Scale parameters

| Variable | Smoke default | Nightly default | Meaning |
| --- | ---: | ---: | --- |
| `QUALIFICATION_SCALE_PROFILE` | `smoke` | `nightly` | Select profile defaults |
| `QUALIFICATION_SCALE_ENTRIES` | `1000` | `100000` | Generated `inetOrgPerson` entries |
| `QUALIFICATION_SCALE_MAX_ENTRIES` | `250000` | `250000` | Run-local and absolute entry safety cap |
| `QUALIFICATION_SCALE_PAGE_SIZE` | `200` | `10000` | RFC 2696 page size; nightly keeps the default run near ten pages |
| `QUALIFICATION_SCALE_SEARCH_CANDIDATE_BYTES` | derived | derived | Per-Search retained-candidate budget: max(64 MiB, entries x 8 KiB), capped at 2 GiB |
| `QUALIFICATION_SCALE_SEARCH_MEMORY_BYTES` | derived | derived | Process retained-Search budget: twice the candidate budget, capped at 4 GiB |
| `QUALIFICATION_SCALE_SAFETY_TIMEOUT_SECONDS` | `1800` | `1800` | Hard deadline for each build/import/query/check command |
| `QUALIFICATION_SCALE_STARTUP_TIMEOUT_SECONDS` | `180` | `180` | Per-generation readiness deadline |
| `QUALIFICATION_SCALE_SHUTDOWN_TIMEOUT_SECONDS` | `60` | `60` | Graceful-stop deadline before forced cleanup |
| `QUALIFICATION_SCALE_UNINDEXED_TIME_LIMIT_SECONDS` | `60` | `60` | Server-side bound for the negative unindexed Search |
| `QUALIFICATION_SCALE_CLIENT_TIMEOUT` | `120s` | `120s` | LDAP client network/request timeout |
| `QUALIFICATION_SCALE_BINARY` | built locally | built locally | Existing executable to test |
| `QUALIFICATION_SCALE_ARTIFACT_DIR` | temporary path | temporary path | New evidence directory |
| `QUALIFICATION_SCALE_DRY_RUN` | `0` | `0` | Validate and print the effective profile without generating data |

`QUALIFICATION_SCALE_MAX_ENTRIES`, the retained-Search budgets, and the timeout
variables are safety bounds and always apply. The derived Search budgets allow
the test to page over its configured population without silently inheriting a
small-directory default, while preserving finite process admission. Performance
acceptance ceilings are independently configurable and default to `0`, meaning
record but do not reject:

- `QUALIFICATION_SCALE_MAX_GENERATE_MS`
- `QUALIFICATION_SCALE_MAX_IMPORT_MS`
- `QUALIFICATION_SCALE_MAX_REINDEX_MS`
- `QUALIFICATION_SCALE_MAX_STARTUP_MS`
- `QUALIFICATION_SCALE_MAX_INDEXED_SEARCH_MS`
- `QUALIFICATION_SCALE_MAX_UNINDEXED_SEARCH_MS`
- `QUALIFICATION_SCALE_MAX_PAGING_MS`
- `QUALIFICATION_SCALE_MAX_MUTATION_MS`
- `QUALIFICATION_SCALE_MAX_SHUTDOWN_MS`
- `QUALIFICATION_SCALE_MAX_RSS_BYTES`
- `QUALIFICATION_SCALE_MAX_RSS_GROWTH_BYTES`
- `QUALIFICATION_SCALE_MAX_DATABASE_BYTES`

This split is intentional. Repository-wide timing or RSS constants would be
flaky across developer laptops, shared CI runners, production storage classes,
and cold versus warm filesystem caches. Establish ceilings from repeated runs
on the target host class, retain the median and high-percentile evidence, then
set release thresholds with explicit headroom. For example:

```sh
QUALIFICATION_SCALE_PROFILE=nightly \
QUALIFICATION_SCALE_MAX_STARTUP_MS=45000 \
QUALIFICATION_SCALE_MAX_INDEXED_SEARCH_MS=1000 \
QUALIFICATION_SCALE_MAX_UNINDEXED_SEARCH_MS=30000 \
QUALIFICATION_SCALE_MAX_PAGING_MS=120000 \
QUALIFICATION_SCALE_MAX_RSS_BYTES=2147483648 \
QUALIFICATION_SCALE_MAX_DATABASE_BYTES=3221225472 \
./scripts/qualification/scale.sh
```

If an RSS ceiling is configured on a platform where neither `/proc` nor
`ps -o rss` provides a measurement, the qualification fails rather than
silently accepting an unverified ceiling. RSS is sampled once per second plus
at workload boundaries, so `rss_peak_sampled_bytes` is not a profiler-grade
instantaneous peak.

## OpenLDAP performance comparison

`scripts/qualification/compare-openldap.sh` runs ldap-go and the pinned
OpenLDAP 2.6.13 `slapd` side by side on loopback. It generates the same entries
for both databases, explicitly rebuilds `uid` and `objectClass` equality
indexes on both, and uses the
same OpenLDAP client binaries for every online operation. Each timed Search
pair runs in both orders and reports the integer mean, reducing ordering and
warm-cache bias.

Paged Search reports both `paged_cold_ms` for one uncached full traversal and
`paged_search_ms` for the repeated same-revision workload. Resource evidence
likewise retains immediate post-workload RSS and a second
`rss_quiescent_bytes` sample after ten idle seconds, so transient Go heap pages
and steady resident memory remain visible separately.
Indexed and unindexed batches follow the same convention:
`indexed_cold_ms`/`unindexed_cold_ms` capture the first batch, while
`indexed_search_ms`/`unindexed_negative_ms` report the subsequent repeated
rounds.

The `objectClass` index is part of the indexed baseline because slapd adds its
referral candidate branch to normal searches. With only `uid` indexed,
OpenLDAP's internal `(|(objectClass=referral)(uid=...))` candidate set falls
back to a full scan and does not measure an indexed lookup.

Build the reference once, then pass its generated environment file:

```sh
OPENLDAP_SOURCE=../openldap-reference \
BUILD=/var/tmp/ldap-go-openldap-reference \
  ./scripts/build-openldap-reference.sh

OPENLDAP_ENV_FILE=/var/tmp/ldap-go-openldap-reference/openldap-reference.env \
  make qualification-compare-openldap
```

The default workload imports 1,000 people and measures authenticated startup,
1,000 sequential indexed searches, 100 unindexed negative scans, ten complete
RFC 2696 traversals, eight concurrent connections with 250 indexed searches
each, and 200 Modify operations. Before accepting results, it verifies that
both servers returned the expected indexed request count, all unique paged
entries, and every modified value.

After timing and resource sampling, data parity is enabled by default. Both
servers receive the same Modify, ModifyDN, Delete, and Add sequence, followed
by duplicate-Add, missing-Modify, non-leaf-Delete, and Compare TRUE/FALSE
probes. Full paged subtree data plus indexed, compound, base, missing, and
substring query results are parsed as LDIF, canonicalized by DN/attribute/raw
value, externally sorted, and compared byte for byte. The full comparison asks
for `*`, so it covers every ordinary LDAP attribute while excluding generated
operational values such as timestamps and CSNs that are intentionally unique
to each server.

The bounded 100,000-entry profile used for scale comparison is:

```sh
QUALIFICATION_COMPARE_ENTRIES=100000 \
QUALIFICATION_COMPARE_PAGE_SIZE=10000 \
QUALIFICATION_COMPARE_INDEXED_SEARCHES=10000 \
QUALIFICATION_COMPARE_UNINDEXED_SEARCHES=10 \
QUALIFICATION_COMPARE_PAGED_TRAVERSALS=2 \
QUALIFICATION_COMPARE_MODIFICATIONS=1000 \
QUALIFICATION_COMPARE_CONCURRENCY=8 \
QUALIFICATION_COMPARE_SEARCHES_PER_CONNECTION=1000 \
QUALIFICATION_COMPARE_STARTUP_TIMEOUT_SECONDS=180 \
  make qualification-compare-openldap
```

The same profile is available as `make qualification-compare-openldap-100k`.

### Latest 100k evidence

The retained 2026-08-31 Apple M1 Pro run produced the following results. Lower
timing and resource values are better; a ratio below 1 favors ldap-go.

| Metric | ldap-go | OpenLDAP | ldap-go / OpenLDAP |
| --- | ---: | ---: | ---: |
| Import plus index | 105,727 ms | 832,618 ms | 0.13 |
| Startup ready | 272 ms | 96 ms | 2.83 |
| Indexed search, repeated | 720 ms | 608 ms | 1.18 |
| Indexed search, first batch | 1,953 ms | 617 ms | 3.17 |
| Unindexed negative, repeated | 30 ms | 338 ms | 0.09 |
| Unindexed negative, first batch | 1,016 ms | 390 ms | 2.61 |
| Paged traversal, repeated | 718 ms | 1,543 ms | 0.47 |
| Paged traversal, first | 2,012 ms | 715 ms | 2.81 |
| Concurrent indexed search | 258 ms | 275 ms | 0.94 |
| Modify | 565 ms | 3,780 ms | 0.15 |
| RSS after workload | 462.7 MiB | 93.6 MiB | 4.94 |
| RSS after 10 seconds idle | 207.2 MiB | 89.7 MiB | 2.31 |
| Database file | 118.1 MiB | 81.3 MiB | 1.45 |

Both servers returned 100,000 unique people and all 1,000 timed modifications.
The 15 canonical data, query, Bind, Compare, and error-result checks passed;
42,712,504 bytes of ordinary-attribute LDIF matched byte for byte. The full
workload, optimization deltas, interpretation, and the documented offline
host-suspension recheck are in
[OpenLDAP 100k comparison evidence](openldap-100k-evidence.md).

| Variable | Default | Meaning |
| --- | ---: | --- |
| `OPENLDAP_ENV_FILE` | unset | Environment generated by `build-openldap-reference.sh` |
| `QUALIFICATION_COMPARE_ENTRIES` | `1000` | Generated `inetOrgPerson` entries |
| `QUALIFICATION_COMPARE_MAX_ENTRIES` | `250000` | Run-local and absolute entry safety cap |
| `QUALIFICATION_COMPARE_PAGE_SIZE` | `200` | RFC 2696 page size |
| `QUALIFICATION_COMPARE_INDEXED_SEARCHES` | `1000` | Sequential searches per timed round |
| `QUALIFICATION_COMPARE_UNINDEXED_SEARCHES` | `100` | Negative full scans per timed round |
| `QUALIFICATION_COMPARE_PAGED_TRAVERSALS` | `10` | Complete paged traversals per timed round |
| `QUALIFICATION_COMPARE_MODIFICATIONS` | `200` | Replacements in one persistent connection |
| `QUALIFICATION_COMPARE_CONCURRENCY` | `8` | Concurrent indexed-search connections |
| `QUALIFICATION_COMPARE_SEARCHES_PER_CONNECTION` | `250` | Searches issued by each concurrent connection |
| `QUALIFICATION_COMPARE_DATA_PARITY` | `1` | Run canonical full-data, query, and result-code comparisons after timing |
| `QUALIFICATION_COMPARE_LDIF_CANONICALIZER` | built locally | Existing qualification LDIF canonicalizer executable |
| `QUALIFICATION_COMPARE_BINARY` | built locally | Existing ldap-go executable |
| `QUALIFICATION_COMPARE_ARTIFACT_DIR` | temporary path | New evidence directory |
| `QUALIFICATION_COMPARE_LDAP_GO_PORT` | process-derived | ldap-go loopback port |
| `QUALIFICATION_COMPARE_OPENLDAP_PORT` | next port | OpenLDAP loopback port |
| `QUALIFICATION_COMPARE_STARTUP_TIMEOUT_SECONDS` | `30` | Per-server readiness deadline |
| `QUALIFICATION_COMPARE_ROOT_PASSWORD` | local test value | Temporary root password, excluded from reports |
| `QUALIFICATION_COMPARE_DRY_RUN` | `0` | Validate and print configuration only |

The artifact directory contains `report.json`, `results.tsv`,
`data-parity-results.tsv`, both database files, generated LDIF, raw and
canonical query results, bounded mismatch diffs, effective configuration,
validation output, and server logs. In `results.tsv`,
`ldap_go_over_openldap` is `ldap-go / OpenLDAP`: for
timing and resource rows, a value above 1 means ldap-go took longer or used
more resources; a value below 1 favors ldap-go.

This comparison is a reproducible local regression benchmark, not a universal
capacity claim. Run repeated trials on the same otherwise-idle host and compare
medians. TLS, replication, overlay cost, storage durability settings, larger
working sets, latency percentiles, and production network or disk behavior
require separate qualification.

## Parameters

All tuning is through environment variables so the command line itself remains
stable and can be recorded by CI or an operations runbook.

| Variable | Smoke default | Soak default | Meaning |
| --- | ---: | ---: | --- |
| `QUALIFICATION_MODE` | `smoke` | `soak` | Select default profile |
| `QUALIFICATION_DURATION_SECONDS` | `15` | `3600` | Workload duration |
| `QUALIFICATION_CONNECTIONS` | `4` | `128` | Concurrent client streams and durable test entries |
| `QUALIFICATION_BATCH_SIZE` | `10` | `100` | Search/Modify operations sent per connection |
| `QUALIFICATION_OPERATIONS` | `search,compare,modify,bind,add-delete` | same | Ordered workload mix |
| `QUALIFICATION_RESTARTS` | `1` | `12` | Number of kill/restart cycles |
| `QUALIFICATION_RESTART_INTERVAL_SECONDS` | derived | derived | Seconds between fault injections |
| `QUALIFICATION_KILL_SIGNAL` | `KILL` | `KILL` | `KILL`, `TERM`, `INT`, or `HUP` |
| `QUALIFICATION_CLIENT_TIMEOUT` | `3s` | `3s` | Per-client network/request timeout |
| `QUALIFICATION_RETRY_DELAY_SECONDS` | `1` | `1` | Delay after a failed operation |
| `QUALIFICATION_MAX_FAILURE_PERCENT` | `20` | `5` | Maximum tolerated operation failures during fault windows |
| `QUALIFICATION_MIN_SUCCESSFUL_OPS_PER_SECOND` | `1` | `1` | Minimum aggregate successful throughput |
| `QUALIFICATION_MAX_RECOVERY_SECONDS` | startup timeout | startup timeout | Maximum kill-to-ready interval |
| `QUALIFICATION_STARTUP_TIMEOUT_SECONDS` | `15` | `15` | Readiness deadline per generation |
| `QUALIFICATION_SHUTDOWN_TIMEOUT_SECONDS` | `15` | `15` | Graceful-stop deadline before KILL |
| `QUALIFICATION_LISTEN_HOST` | `127.0.0.1` | `127.0.0.1` | Loopback listen host (`localhost` is also accepted) |
| `QUALIFICATION_BINARY` | built locally | built locally | Existing `ldap-go` executable to test |
| `QUALIFICATION_ARTIFACT_DIR` | temporary path | temporary path | New directory for database, logs, and reports |
| `QUALIFICATION_ROOT_PASSWORD` | local test value | local test value | Root password; never written to the JSON report |

Only exact operation tokens listed in the table are accepted. The listen host
is deliberately restricted to `127.0.0.1` or `localhost` because the fixture
uses simple authentication without TLS.

Example release-candidate run:

```sh
QUALIFICATION_MODE=soak \
QUALIFICATION_DURATION_SECONDS=21600 \
QUALIFICATION_CONNECTIONS=256 \
QUALIFICATION_BATCH_SIZE=250 \
QUALIFICATION_RESTARTS=24 \
QUALIFICATION_RESTART_INTERVAL_SECONDS=900 \
QUALIFICATION_ARTIFACT_DIR=/var/tmp/ldap-go-qualification-rc1 \
make qualification-soak
```

Capacity sweeps should change one main dimension at a time. Start with no fault
injection to find sustainable throughput, then repeat the accepted point with
KILL/restart enabled:

```sh
QUALIFICATION_DURATION_SECONDS=600 \
QUALIFICATION_CONNECTIONS=64 \
QUALIFICATION_RESTARTS=0 \
QUALIFICATION_OPERATIONS=search,compare \
make qualification-smoke
```

## Fault and data model

Each worker owns one durable `inetOrgPerson` entry. Every successful Modify
batch advances a worker-local sequence persisted in its metrics; final offline
LDIF must contain the last acknowledged sequence. Search and Compare target the
same entry. The
Add/Delete operation uses a worker-specific temporary entry. Before each Add it
removes residue from an interrupted prior attempt, and the orchestrator performs
one final residue cleanup after the last restart.

At each fault point the orchestrator signals only the server process, waits for
it to exit, starts the same database on the same port, and waits for the server's
readiness line, an authenticated LDAP Who Am I response, and a successful Base
Search of the qualification naming context. Clients
continue running and record failures observed while the
listener is unavailable. These expected availability failures still count
against `QUALIFICATION_MAX_FAILURE_PERCENT`, both globally and for each selected
operation. Every selected operation must succeed at least once. Setting the
threshold too high can hide an unacceptably long recovery window.

After the workload, the runner verifies all of the following:

- the final online LDAP search returns exactly one durable entry per worker;
- every expected DN and `uid` is present, with the deterministic description
  when Modify is enabled;
- no temporary Add/Delete entry remains;
- `ldap-go check` accepts the bbolt pages, buckets, keys, and metadata;
- `ldap-go export` can read the full database and produces valid expected LDIF;
- every worker emitted metrics, operations succeeded, and the failure threshold
  was not exceeded;
- every requested restart completed, recovery stayed below the configured
  maximum, and aggregate throughput met the configured minimum.
- every Search batch returned the expected target DN once per query rather than
  treating an empty successful Search as useful work.

## Evidence and acceptance

The artifact directory is retained on both success and failure. Its important
files are:

| File | Contents |
| --- | --- |
| `report.json` | Pass summary, workload totals, restart count, recovery time, throughput, and binary/export SHA-256 |
| `effective-config.env` | Non-secret effective workload and acceptance parameters, available even after a failed run |
| `operation-stats.tsv` | Attempted/succeeded/failed totals by LDAP operation |
| `crash-events.tsv` | Signal, kill timestamp, and ready timestamp for every restart |
| `server.log` | Server diagnostics across all generations |
| `workers/*/events.tsv` | Per-worker operation events |
| `workers/*/errors.log` | Client failures, including expected fault-window errors |
| `check.log` | Offline bbolt integrity report |
| `final-online.ldif` | Final online query evidence |
| `final.ldif` | Full offline export used for semantic validation |

The scale qualification writes its own `report.json`, `effective-config.env`,
`seed.ldif`, `rss-samples.tsv`, operation LDIF/log files, per-generation server
stdout, `server.log`, and `check.log`. Its JSON report contains every observed
duration, initial/post-workload/post-restart RSS, sampled peak RSS, RSS growth,
bbolt size, applied ceilings, safety bounds, validated page count, and binary
and seed-LDIF SHA-256 values. A runtime failure still emits a JSON report with
`result: "fail"` and the last phase before cleanup.

The temporary `-y` password file is mode `0600` while the run is active and is
removed on normal success, failure, or interruption. The password value is not
included in the configuration snapshot or report.

Archive the complete directory with the release candidate's commit, binary
digest, host inventory, filesystem/mount options, storage model, Go version,
and operating-system version. A production acceptance record should define
minimum throughput, maximum failure percentage, maximum restart recovery time,
and required soak duration before running the test. The repository defaults are
intended to catch functional regressions quickly; they are not production SLOs.

The concurrent runner currently reports operation throughput and whole-second
restart recovery intervals. The scale runner adds millisecond timings where
the host `date` supports nanoseconds and records its clock resolution otherwise.
It also samples server RSS. Continue to use external host telemetry for CPU,
instantaneous peak RSS, disk latency, fsync behavior, open descriptors, and
latency percentiles. Those measurements are environment-specific and should be
correlated with `crash-events.tsv`, worker events, and `rss-samples.tsv`.

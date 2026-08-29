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
readiness line and then requires an authenticated LDAP Who Am I probe. Clients
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

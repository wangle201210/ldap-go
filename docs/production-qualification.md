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

The temporary `-y` password file is mode `0600` while the run is active and is
removed on normal success, failure, or interruption. The password value is not
included in the configuration snapshot or report.

Archive the complete directory with the release candidate's commit, binary
digest, host inventory, filesystem/mount options, storage model, Go version,
and operating-system version. A production acceptance record should define
minimum throughput, maximum failure percentage, maximum restart recovery time,
and required soak duration before running the test. The repository defaults are
intended to catch functional regressions quickly; they are not production SLOs.

The runner currently reports operation throughput and whole-second restart
recovery intervals. Use external host telemetry for CPU, RSS, disk latency,
fsync behavior, open descriptors, and subsecond latency percentiles. Those
measurements are environment-specific and should be correlated by timestamps
with `crash-events.tsv` and the worker event logs.

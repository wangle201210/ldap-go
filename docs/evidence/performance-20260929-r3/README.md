# September 29, 2026 R3 evidence

Audit: `/var/tmp/ldap-go-perf-20260929-r3`; baseline `a9de7d4`.
The [report](../../common-ldap-performance.md) retains mixed results and the
continuing parity goal. The [R2 archive](../../common-ldap-performance-20260929-r2.md)
preserves the previous report byte-for-byte. No new profiles or trace evidence
are part of R3's measurements.

## Completed runs

- `explicit-final/` and `default-final/` preserve all smoke/hot/distributed/group
  JSONs, concurrent batches and validation records. Six exports match.
- `root-paired/` preserves literal/uppercase measured JSONs, both smoke reports,
  three startup warmup JSONs and validation. Each measured case has 105 samples:
  five stages, three endpoints, seven repeats, 1,000 primary calls per sample.
  Both smoke reports have 15 samples of two calls. All four have empty errors,
  27 setup Adds and all three endpoint cleanups complete. Three exports match.
- `online/` preserves 117 JSONs across nine fresh processes, plus CLI timings
  and export/RSS checks. Literal-root and uppercase-root serial variants remain
  separate from paired-root results. Nine exports match.
- `writes/` preserves nine original probes, startup timings and export/RSS
  checks: 20 writes per stage, before/current/OpenLDAP, three processes each.
  All use token `92cd12ef4156461e9e2807136111af53` and the same run DN, matching
  R2's fixed-write method. Nine exports match; no cross-round pooling is used.
- `write-recheck/` preserves 14 probes, startup timings and export/RSS checks:
  seven alternating before/current pairs, 100 writes per stage, `n=2` initial
  reads and the same fixed token. No new native measurement. Its 14 exports
  match. The original 13.5% ModifyDN slowdown remains; nonreproduction with
  larger batches does not establish causality or uniform gains.

All six scripts completed with coordinator-confirmed exit 0; completion logs
are retained as `*.log.txt`. **All 41 exports** match 100,002 entries, POSIX
checksum 2143929969 and 42,712,438 canonical bytes. Common/paired counts,
repeats and cleanup passed; read-stage errors are empty. Original write stages
have 20 postcondition checks each, 40 for ModifyDN; recheck counts are 100/200.
Cleanup has 104 original or 504 recheck operations and two verification calls
per process, without errors. No timing sample or outlier is discarded.
The coordinator independently verified all 41 export checks before removing
ephemeral benchmark-output LDIF/canonical files. JSONs, logs and validation
TSVs remain; source fixture databases and the round15 reference canonical
were retained.

## Grouping

`medians.tsv` contains 72 common groups keyed by run, batch, stage, method,
member count and endpoint. Each median uses three `total_ms` batches.
SSHA/plaintext, hot/distributed reads and group sizes stay separate. Smoke is
excluded; common CLI repeat 0 is warmup, 1-3 are measured. [Common tables](common-tables.md).
Recalculate the saved common reports from this directory without a workload:

```sh
python3 ../common-performance-20260924-r7/calculate.py.txt explicit-final default-final --output medians.tsv
```

`root-paired-medians.tsv` contains 30 groups keyed by variant, exact client
`root_bind_dn`, stage, method and endpoint. Each uses seven 1,000-call batches;
smoke and startup warmups remain excluded. [Paired-root tables](root-paired-tables.md).
The [repository runner](../../../internal/cmd/ldapcommonbench/README.md#optional-root-sdk-stages)
rotates per request and adds untimed WhoAmI after each primary call. Its
OU/eight-user fixture, service Bind and cleanup also generate untimed work.
Primary calls match the old fast probe, but that serial probe did not perform
WhoAmI after every request. Observer, fixture and sequence differences prevent
treating paired and serial results as interchangeable.

`read-medians.tsv` contains 108 groups keyed by variant, stage, operation count,
endpoint and unit. `probe`, `fast` and `normalized-root` each have nine batches
per endpoint. Literal client DN is `cn=admin,dc=scale,dc=qualification`;
uppercase is `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`. Root Base reads the fixed
container; equality/Compare use distributed UIDs across 100k, as shown by the
[unchanged fast-probe source](../performance-20260929-r1/helpers/fast-probe.go.txt).
User/extended probes retain measured repeats 0-2. Warmup JSONs are excluded.
CLI full-prefix has nine samples, other CLI stages three. RSS uses three byte
values. [Read tables and extended diagnostics](read-tables.md).

`write-medians.tsv` has 54 three-sample groups for all original stages,
startup and RSS. `write-recheck-medians.tsv` has eight seven-sample write
groups, 100 operations per stage. Setup, SDK postconditions and cleanup are
outside timed writes. Recheck and original/native results are never pooled.
All ratios use unrounded endpoint medians, not medians of paired percentages:
relative is `openldap/current*100`; reduction is `(1-current/before)*100`.
Frequency is qualitative.

## Components and validation

`dn-bench.txt` and `queue-bench.txt` retain every case and all three repetitions.
DN Parse versus Validate is a component comparison, not SDK latency. The
invalid case remains slower (1,230 to 1,266 ns), with 720 B/op and 33 allocs/op
unchanged. Schema DN and NameOptionalUID validation remains per-call, not cached.
Queue idle concurrent admission is 5.521 to 3.059 ns with **0 B/op and zero
allocations on both sides**: the reference idle slice was stack-optimized.
FullScan1024 is 2,935 to 761.8 ns, 9,472 to 0 B/op and one to zero allocations.
761.8 ns is the median of 761.8/764.2/720.8, not the minimum. No every-request
heap-allocation saving or new profile-allocation claim follows from these cases.

`dn-test.txt` records directory/schema success; `dn-fuzz.txt` records
1,177,275 executions and PASS. Final `go-test.txt` passed (server 137.480 s;
some packages cached). `go-vet.txt` is empty; exit 0 was confirmed by the
coordinator. `openldap-differential.txt` has 355 PASS records, no failures/skips
and terminal PASS (11.795 s). No race-detector result is claimed.

## Replay and identity

The common explicit/default, root-paired, full-read, full-write and write-recheck
recipes are archived as `*.sh.txt`. Credential literals are replaced with
required environment variables; other workload/timing logic is unchanged.
Supply `LDAP_BENCH_PASSWORD`, and `LDAP_BENCH_USER_PASSWORD` for write recipes.
Use unused output directories and matching existing fixture credentials.

Replays retain the persistent native environment at
`/var/tmp/ldap-go-openldap-reference-audit-2.6/openldap-reference.env`, round4
`online-accepted` fixtures/`ldapbench`, round6 `fast-probe`, round2
`ldifcanonical`, audit-local server/client binaries and member-index/member-ACL
databases, and the round15 canonical reference. These local dependencies are
not bundled. No passwords, binaries, databases, profiles, LDIF or large exports
are archived. No harness patches are needed; runner semantics are linked above.

[Executable SHA-256](executable-sha256.txt) was read from the frozen audit files:

```text
before (a9de7d4)  d93aea5cd433bbe3b20805074de8e670286f57eefa2ead015a5028dd53de189f
current           365079e52a578b2180f8fb10d2a647be9d5dd663177587f0a105b63e0ccbb5f3
```

Documentation preparation reads completed evidence and calculates statistics;
it ran no tests, builds, benchmarks or profiles and made no commits. Overall
parity remains unproven; the optimization goal remains active.

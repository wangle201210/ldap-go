# September 29, 2026 R4 evidence

Audit: `/var/tmp/ldap-go-perf-20260929-r4`; baseline `6f31d43`.
[Current report](../../common-ldap-performance.md),
[verbatim R3 archive](../../common-ldap-performance-20260929-r3.md).
Results remain mixed; the parity goal stays active and unproven.

## Results and grouping

- [Common tables](common-tables.md) and `medians.tsv`: 72 groups keyed by run,
  batch, stage, method, member count and endpoint; three `total_ms` batches
  each. SSHA/plaintext, hot/distributed and group sizes stay separate. Smoke
  is excluded; common CLI repeat 0 is warmup and 1-3 are measured.
- [Paired-root tables](root-paired-tables.md) and `root-paired-medians.tsv`:
  30 groups retaining exact client root DN, stage, method and endpoint;
  seven 1,000-call batches each. Literal/uppercase variants are separate.
  Both measured JSONs, smoke reports and three warmup JSONs are retained.
  The [runner](../../../internal/cmd/ldapcommonbench/README.md#optional-root-sdk-stages)
  adds per-request rotation, untimed WhoAmI and fixture work. Those differences
  prevent pooling with or replacing serial fast-probe measurements.
- [Read tables](read-tables.md) and `read-medians.tsv`: 108 groups retaining
  variant, stage, count, endpoint and unit. All 117 JSONs are in `online/`.
  SDK and CLI full-prefix rows use nine batches; other CLI stages and RSS use
  three. User/extended repeats 0-2 are measured; warmup JSONs are excluded.
  Root Base is a fixed container; equality/Compare distribute UIDs across 100k.
- `write-medians.tsv`: 54 three-sample groups for all stages, startup and RSS.
  `writes/` retains all nine probes and timings/validation. Every endpoint uses
  token `92cd12ef4156461e9e2807136111af53`, the same run DN and 20 writes per
  stage. Setup, postconditions and cleanup are outside timed write stages.
  No cross-round pooling is used.

All samples remain. Relative is `openldap/current*100`; time reduction is
`(1-current/before)*100`, using unrounded endpoint medians. Frequency is
qualitative. Common results can be recalculated without running a workload:

```sh
python3 ../common-performance-20260924-r7/calculate.py.txt explicit-final default-final --output medians.tsv
```

## Validation and component

All five scripts have completion logs and coordinator-confirmed exit 0.
**All 27 export records match** 100,002 entries, checksum 2143929969 and
42,712,438 canonical bytes. Common/paired errors, counts, repeats and cleanup
passed; read-stage errors are empty. Each write stage has 20 postcondition
checks, 40 for ModifyDN; cleanup has 104 operations and two verification calls.

`focused-test.txt` records schema 0.036 s/server 19.426 s. `go-test.txt` passed
(server 135.794 s; some packages cached); vet exit 0 was confirmed and
`go-vet.txt` is empty. Native logs contain 355 PASS records, no failures/skips
and terminal PASS in 9.813 s. No race-detector result is claimed.

`selection-bench.txt` preserves all 22 case/method groups and three repetitions
each. The 1,000-value median falls from 24,417 to 13,900 ns, 72,768 to
65,088 B/op and 1,006 to 16 allocations. These are selection-component results
only. Small, mixed, nil/empty and types-only cases remain, including slower
medians; no uniform SDK, every-request or profile-allocation claim follows.

## Replay

Common explicit/default, root-paired, full-read and full-write recipes are
archived as `*.sh.txt`; literals are replaced by environment passwords with
workload/timing logic preserved. Supply `LDAP_BENCH_PASSWORD`, plus
`LDAP_BENCH_USER_PASSWORD` for writes, and unused output directories.

Dependencies remain the persistent native environment
`/var/tmp/ldap-go-openldap-reference-audit-2.6/openldap-reference.env`, round4
`online-accepted` fixtures/`ldapbench`, round6 `fast-probe`, round2
`ldifcanonical`, audit-local binaries and member databases, and the round15
canonical reference. They are not bundled. No passwords, binaries, databases,
profiles, LDIF or large exports are archived. [Executable hashes](executable-sha256.txt)
were read from the frozen audit files. Documentation work ran no workloads
and made no commits.

# R5 conditional audit evidence

Audit: `/var/tmp/ldap-go-perf-20260929-r5`; baseline `f78523a`.
[Audit-specific report](../../audit-performance-20260929-r5.md). The
[formal common-performance report](../../common-ldap-performance.md) remains
R4. Overall parity is still unproven; this conditional validation scope does
not narrow or complete that goal.

## Results

- [Audit-enabled A/B](audited-paired-tables.md): before/current Go servers, real
  file AuditSink with HMAC and Sync; five repeats of 200 calls per literal/
  uppercase case. All 20 endpoint medians, probes, smoke reports, warmups,
  verification and two export records remain. Large uppercase regressions
  are retained; no native comparator or causal speedup claim is made.
- [A/A control](audited-aa-tables.md): **both servers use the same before
  binary**, labeled A1/A2 (raw `before`/`current`). Three repeats of 100 calls
  per case. This is noise evidence, not an optimization comparison; batch
  counts differ from A/B, so absolute totals are not comparable or pooled.
- [Standard common matrices](common-tables.md) and [standard root matrices](root-paired-tables.md)
  are regression controls only. No audit sink or runtime accesslog means
  `newAuditObservation` returns nil; the changed path is not exercised.
  All methods, DN spellings, group sizes, samples and negative rows remain.
- Full reads/writes were **not rerun in R5**. [R4 reads](../performance-20260929-r4/read-tables.md)
  and [R4 writes](../performance-20260929-r4/write-medians.tsv) are historical
  evidence only. Existing broad deficits remain; no R5 default-speedup or
  overall-parity claim follows.

## Integrity and validation

All five scripts completed with coordinator-confirmed exit 0. **All 13 export
records match** 100,002 entries, checksum 2143929969 and 42,712,438 canonical
bytes: six standard common, three standard root, two A/B and two A/A.
SDK errors, operation counts, repeats and cleanup checks passed.

[audit-validation.json](audit-validation.json) records verified log counts,
semantic equality and SHA-256 of the raw logs. A/B has 20,294 records and
900 semantic groups per endpoint; A/A has 6,254 records and 500 groups.
Both pairs match exactly after excluding only event `timestamp`,
`connection_id`, `message_id`, `remote_address` and `duration_micros`.
Per-endpoint `audit-verification.txt` files preserve verification after
server shutdown. Canonical counts are retained in each audited directory.
The coordinator's [summary helper](summarize-audit.mjs.txt) is archived unchanged.
**No raw audit logs or audit keys are archived.**

`audit-focused.txt` and `fast-audit-test.txt` passed. Full tests passed
(server 157.465 s); vet exit 0 was confirmed and its log is empty. Native
validation has 355 PASS records, no failures/skips and terminal PASS in
12.465 s. Fuzzing passed 158,207 executions on inputs bounded to 4,096 bytes,
including legacy panic-behavior comparison. No unbounded-input or race result
is claimed.

## Component and reproduction

`audit-bench.txt` retains 24 case/method/version groups and three repeats each.
BindSuccess **Observe** is 1,718 to 16.08 ns, 2,806 to 0 B/op and 55 to zero
allocations. **Code-only** current is 5.655 ns, not the observer or file sink.
Fallback cases remain. This is a conditional component allocation gain;
no allocation-profile, ordinary-request or production-latency gain is proven.

Common medians retain run, batch, stage, method, member count and endpoint;
paired medians also retain exact client DN. All ratios use unrounded medians;
frequency is qualitative. Native-relative ratios apply only to standard controls.
All raw probes and timing samples remain; smoke and warmups are separate.

Archived replay scripts preserve workload logic and require external
`LDAP_BENCH_PASSWORD` and, for audited runs, `LDAP_PERF_AUDIT_KEY` passed through
`LDAP_GO_AUDIT_KEY`. No secrets, binaries, databases, profiles or LDIF/large
exports are archived. Existing fixture/client paths and the persistent native
environment remain in the recipes. [Executable identities](executable-sha256.txt)
were read from the frozen binaries. Documentation work ran no workloads or
audit-verification commands and made no commits.

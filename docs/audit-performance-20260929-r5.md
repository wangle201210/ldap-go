# Conditional audit performance: R5

September 29, 2026; baseline `f78523a`. **The supported benefit is a conditional
audit-observer component allocation reduction. Production latency gains and
overall OpenLDAP parity are unproven.** The [formal common report](common-ldap-performance.md)
and its ordinary-operation tables remain R4.

## Change and applicability

The narrow recognizer accepts canonical short LDAPResult responses with empty
matched DN/diagnostic and no controls or extra fields. Other cases retain the
generic BER fallback. Observer fields, mutex and entry counter are preserved;
the standalone result-code helper also uses the recognizer.

Without an audit sink or runtime accesslog, `newAuditObservation` returns nil.
R5's standard common/root runs are therefore regression controls, not evidence
of an ordinary-request speedup. Full-read/write runs were not repeated;
[R4 reads](evidence/performance-20260929-r4/read-tables.md) and
[R4 writes](evidence/performance-20260929-r4/write-medians.tsv) remain historical
evidence with their existing limits and deficits.

## Component and production evidence

Three-repetition medians for BindSuccess Observe are **1,718 to 16.08 ns,
2,806 to 0 B/op and 55 to zero allocations**. The **5.655 ns code-only helper**
is a different benchmark, not the real observer or HMAC/Sync sink.
[All component cases](evidence/performance-20260929-r5/audit-bench.txt), including
generic fallback cases, remain. No new allocation-profile claim is made.

The audit-enabled A/B run uses real file AuditSink, HMAC and Sync on both Go
servers, with five repeats of 200 primary calls per literal/uppercase case.
[All A/B tables](evidence/performance-20260929-r5/audited-paired-tables.md)
retain mixed literal results and large uppercase regressions: Base
564.43/1,199.37 ms, equality 470.66/1,224.42 ms, false Compare
369.32/1,400.79 ms (before/current). These results are not discarded.

The [A/A control](evidence/performance-20260929-r5/audited-aa-tables.md) runs the
same baseline binary at both endpoints, labeled **A1/A2**, with three repeats
of 100 calls. Literal Base is 296.82/586.74 ms; uppercase true Compare is
812.88/118.22 ms. This large same-code variation makes file-Sync timing
unreliable for attributing the A/B differences to code. A/A is a noise
control, not speedup evidence; its different counts prevent absolute comparison
or pooling with A/B. Neither test establishes a causal latency benefit or
disproves the retained regressions. No native audit comparator is claimed.

## Validation and limits

All five scripts exited 0. **All 13 exports match** 100,002 entries, checksum
2143929969 and 42,712,438 canonical bytes (6 common + 3 root + 2 A/B + 2 A/A).
SDK errors, counts, repeats and cleanup passed. After shutdown, both A/B
logs verified 20,294 records; both A/A logs verified 6,254. Semantic maps match
exactly: 900 A/B groups and 500 A/A groups after excluding timestamp, connection
ID, message ID, remote address and duration. [Summary, hashes and helper](evidence/performance-20260929-r5/README.md#integrity-and-validation)
are archived, with canonical counts and verification logs; raw logs and keys are not.

Focused/differential checks and full Go tests passed (server 157.465 s), vet
exited 0, and native validation has 355 passes, no failures/skips (12.465 s).
Fuzzing passed 158,207 executions on inputs up to 4,096 bytes, comparing legacy
panic behavior as well as results. This does not claim unbounded coverage.
No race-detector result is claimed. [All evidence and replay dependencies](evidence/performance-20260929-r5/README.md).

Frozen executable SHA-256:

```text
before (f78523a)  14f64911aa8f5f1505f36e20b4eb735e7b6216afa27234d0df8a5cb2a6e17202
current           8551a06409eba3aeff3225748836fc5483c6ec778a207517b025a0df27b279ce
```

The overall parity goal remains active and unmet. Documentation preparation
ran no workloads, profiles or audit-verification commands and made no commits.

# R5 same-binary audit A/A control

Both server endpoints execute the **same baseline `f78523a` binary**. A1
maps to raw endpoint `before`; A2 maps to raw endpoint `current`. The latter
is a label only and does not execute R5's current server. The replay sets
`binary=$audit/before` for both. No native comparator is used.

Each median uses three batches of 100 primary calls, with the same real
file AuditSink, HMAC and Sync behavior as the A/B run. All repeats remain.
This measures timing variability, not optimization speedup. A/B uses five
batches of 200 calls: absolute totals are not commensurate and are not pooled.

| Client DN variant / 100 calls | A1 (ms) | A2 (ms) |
| --- | ---: | ---: |
| Literal / Root Bind | 326.00 | 393.01 |
| Literal / Root Base, hot container | 296.82 | 586.74 |
| Literal / Root equality, distributed | 479.00 | 456.73 |
| Literal / Root Compare true, distributed | 675.35 | 175.57 |
| Literal / Root Compare false, distributed | 463.49 | 422.08 |
| Uppercase / Root Bind | 344.70 | 366.33 |
| Uppercase / Root Base, hot container | 807.92 | 202.42 |
| Uppercase / Root equality, distributed | 598.50 | 222.39 |
| Uppercase / Root Compare true, distributed | 812.88 | 118.22 |
| Uppercase / Root Compare false, distributed | 390.88 | 425.18 |

Large variation with identical server code limits interpretation of A/B
file-sync timings. It does not explain away the retained A/B regressions
or establish a causal code effect, uniform gain or default-latency benefit.

Both smoke and measured reports have empty errors and complete cleanup.
Measured variants each contain 30 samples of 100 calls; smoke variants each
contain ten samples of two calls. Both stopped-server logs verified 6,254
records. After dropping the five documented nondeterministic event fields,
500 semantic groups and counts match exactly. [Summary and raw-log hashes](audit-validation.json),
[canonical counts](audited-aa/audit-semantic-counts.json),
[probes and verification](audited-aa/), [medians with label mapping](audited-aa-medians.tsv),
[completion](audited-aa.log.txt), [replay](audited-aa.sh.txt). Both exports match
100,002 entries, checksum 2143929969 and 42,712,438 canonical bytes.
Audit keys and raw audit logs are not archived.

# R11 Rejected Candidate

Status: **REJECTED_DIAGNOSTIC_ONLY**. No R11 production change was retained.

The candidate used compact owned value blocks when Compare added a missing
`subschemaSubentry`. A focused component benchmark reduced allocation in that
branch, but normal LDAP Add already stores this attribute. The SDK group
fixtures therefore bypassed the changed branch. Their latency differences
cannot be attributed to this candidate.

All original timings and negative rows remain diagnostic evidence. Five
workload scripts completed, with 15 matching canonical exports. Full tests,
vet and native checks passed for the withdrawn candidate; these are not
validation of the subsequent R12 implementation. See [status](generation-status.tsv),
[limitations](limitations.txt), [checks](checks.tsv) and [provenance](provenance.tsv).

The source was reverted before profiling the realistic group handler. R12 has
its own implementation, tests and measurements in [a separate archive](../performance-20260930-r12/README.md).
No R11 samples are pooled into the official report. SHA256SUMS covers this archive.

# R8b Evidence

Baseline: 2645eba. Fresh R8b measurements cover the final cold-path guard:
names.match is called only when names is non-nil; otherwise the old predicate
runs. Existing prepared-name state is reused without populating on misses or
adding a cache. See [provenance](provenance.tsv) for source and validation details.
[Frozen R8](../performance-20260930-r8/README.md) is linked diagnostic context only.

All eight workload scripts exited 0 per main; final source is frozen. R8b used
no profiling or fuzzing. The archive contains 167 raw JSON reports, 304 median groups and
47 canonical export checks: 27 original plus 3 paired paging, 3 paired prefix
and 14 independent write recheck exports.
[Checks](checks.tsv): 1534 checks, 0 failures.
[Export checks](export-checks.tsv) include SHA256 computed from all 47 actual source
canonical files, each 100,002 entries, cksum 2143929969 and 42,712,438 bytes.

[Medians](medians.tsv) and [comparisons](comparisons.tsv) preserve method, members,
endpoint and variant. All negatives remain. Independent
[paired paging](paged-recheck-comparisons.tsv), [paired prefix](prefix-recheck-comparisons.tsv)
and [write recheck](write-recheck-comparisons.tsv)
never replace or pool original samples. Warmup repeat 0 has separate paging/prefix
tables and is excluded from measured medians. Setup, warmup and verification
boundaries are recorded in [timing scope](timing-scope.tsv) and provenance.

Compare ran current first, then a fresh run of the immutable R7 baseline binary;
both unprofiled 1s x 3. Before/current labels identify implementations, not run
order. Schema component tables separate original, cloning, warmed current and
cold fallback, 300ms x 3. No intermediate logs or excluded benchmarks are copied
from R8. Shared-host measurements do not establish causality or uniform gains.

SHA256SUMS covers every archived file except itself. No passwords, databases,
LDIF, canonical fixture contents, binaries, profiles or personal process lists
are archived. Main owns temporary fixture deletion and formal reports.

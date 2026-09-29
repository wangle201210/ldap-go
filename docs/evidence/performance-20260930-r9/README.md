# R9 Evidence

**Native gap remains substantial.** The 1000-member last/missing group Compare cases
still achieve only about 4% of native OpenLDAP throughput despite roughly halving
baseline latency. Exact explicit/default values are in [limitations](limitations.txt)
and [group comparisons](group-compare-comparisons.tsv). All negative results remain.
These measurements do not establish aggregate parity or whole compatibility.

Production baseline: 6840e54. Separate test-only commit: 0a29f60, fixing a preexisting
LDIF 1ns deadline timer race. Final production uses one RLock without value clones
and lazy request-scoped assertion normalization reuse only for nonordered canonical
DN rules; server Compare error order is preserved. [Provenance](provenance.tsv)
records the environment, source/binary identities and completion signals.

All five workload scripts and final validation exited 0 per main. This archive has
31 raw JSON reports, 624 measured samples,
144 median groups and 15 canonical exports.
[Checks](checks.tsv): 430 checks, 0 failures.
All exports have 100,002 entries, cksum 2143929969 and 42,712,438 bytes;
[export checks](export-checks.tsv) include hashes of the actual canonical files.

Common explicit/default use three repeats; root literal/uppercase use seven.
New group Compare uses NONROOT, 20 operations x five repeats for first/last/missing
across 10/1000 members, shared fixture assertions and WhoAmI verification on every
endpoint. First/last denotes fixture insertion order, not native storage order.
SDK default stages are unchanged. [Medians](medians.tsv), [comparisons](comparisons.tsv)
and [counters](counters.tsv) retain method, member count, endpoint and access mode.
Setup, smoke, warmup and verification are outside measured medians; see [timing scope](timing-scope.tsv).

[Component tables](component-medians.tsv) use only final Compare (1s x three,
immutable before binary) and schema original/new oracles (300ms x three).
compare-single-scan-only.txt is SUPERSEDED diagnostic context and is excluded.
go-test-initial-failure.txt and baseline/current deadline reproductions are historical
diagnostics, not final validation failures. Baseline stress had 125 failures in
10,000 runs; the separate test fix passed 10,000 runs. [Log roles](log-status.tsv)
keep these distinct. Fresh [fuzz evidence](fuzz-status.tsv) records the actual run.

Broad read/write results remain [historical R8b](../performance-20260930-r8b/README.md);
they were not rerun or pooled into R9. SHA256SUMS covers every archived file except
itself. No databases, LDIF/canonical contents, binaries, password files or profiles
are archived. The evidence worker ran no workloads, Go builds or tests.

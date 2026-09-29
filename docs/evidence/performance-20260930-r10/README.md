# R10 Evidence

Baseline: R9 commit 19b05f640468b67af1c6aff478250cd36ffa6e0c. All five original
macros and both independent rechecks exited 0 per main's [final signal](generator/main-finished.txt).
This archive contains 39 raw JSON reports, 687 measured samples,
153 median groups and 21 canonical exports. [Checks](checks.tsv)
record 484 checks with 0 failures. Every export has 100,002 entries,
cksum 2143929969 and 42,712,438 bytes; [export checks](export-checks.tsv) include
SHA256 hashes of the actual canonical files, whose contents are not archived.

The request-scoped direct DN plan builds only after the first fully normalized
nonmatch, not a first match. It accepts at most eight single-AVA RDNs with ASCII
letters/digits/._- values, supported caseIgnore/Exact[IA5] rules and matching
attribute identities. All other cases retain full normalization and error order.
The existing simple DN depth recognizer is reused through a wrapper. No persistent
cache, public storage index, storage change or CGO is introduced. This does not
accelerate every DN or establish aggregate/native parity or whole compatibility.

[Medians](medians.tsv), [comparisons](comparisons.tsv) and [counters](counters.tsv)
preserve suite, access mode, identity, variant, stage, method, member count and
endpoint. All positive and negative results remain. Common runs use three
measured repeats, root literal/uppercase runs seven, and nonroot group Compare
uses 20 operations x five repeats for first/last/missing at 10/1000 members.
The same assertions and nonroot identity checks apply on every endpoint without
root fallback. First/last means fixture insertion order, not native storage order.
Setup, warmup, smoke and verification are excluded from measured medians.

[Independent rechecks](recheck-comparisons.tsv) use fresh endpoints and seven
repeats: default memberEquality has 100 operations; explicit wrong-password Bind
has 1,000 operations for each of SSHA/plaintext. Original regressions remain in
[common comparisons](common-comparisons.tsv); rechecks do not replace or pool with
them. The explicit recheck supplies a uid option, while Bind still uses shared
disposable fixture users. See [timing scope](timing-scope.tsv) and [provenance](provenance.tsv).

[Component comparisons](component-comparisons.tsv) have two distinct references:
the immutable before Compare binary was compiled from R9 19b05f6; before/current
Compare measurements are unprofiled 1s x three. Group component original/new
measurements are 300ms x three and compare the old pre-R9 public three-method
oracle with 2N normalization against R10. Those factors are not R9-to-R10 gains.

[Limitations](limitations.txt) retain exact 1000-member last/missing results and
the remaining native gap. Main's native source review found normalized a_nvals
and binary search conditional on the sorted flag, otherwise linear search;
there is no claim that the configured member attribute is sorted.

Final validation, including full tests, vet, focused tests, fuzz and native
differential tests, is recorded in [validation](generator/validation-main.txt),
[log status](log-status.tsv) and [fuzz status](fuzz-status.tsv). Environment: Apple
M1 Pro, Go 1.26.4, CGO_ENABLED=0, native OpenLDAP 2.6.13, 100k fixture.
Broad R8b results are historical and were not rerun or pooled into R10. R9-only
deadline, initial-failure and superseded diagnostics are not R10 evidence.

SHA256SUMS covers every archived file except itself. No passwords, databases,
LDIF/canonical contents, binaries or profiles are archived. The evidence worker
ran no performance workloads, builds or tests. Main owns the formal reports.

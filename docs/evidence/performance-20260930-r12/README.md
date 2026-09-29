# R12 Evidence

Baseline: R10 commit `31f3c087729e4ef9526d201412e7cc2d676d35a6`.
Main confirmed final validation and source freeze, then authorized publication in
[the macro signal](generator/main-finished.txt) and [final recheck signal](generator/recheck-finished.txt). The archive contains 31 official
raw JSON reports, 624 measured samples, 144 median groups and 18 handler component
samples, plus six separate first-only recheck samples. All 456 [checks](checks.tsv)
passed. All 15 [official exports](export-checks.tsv)
have 100,002 entries, cksum 2143929969, 42,712,438 bytes and identical SHA256.
Canonical contents are not archived.

The official runs are the first four successful macros plus the successful full
default group retry. [Run sources](run-sources.tsv) maps the logical default group
exclusively to `default-group-compare-retry`. The original default group script
exited 1 on disk-space exhaustion during canonical export after SDK calls had
completed. Its log, script, five JSON reports and partial export validation remain
under [diagnostic](diagnostic-status.tsv), labelled `FAILED_DIAGNOSTIC_ONLY` and
excluded from official samples, medians and exports. No samples are pooled with
the retry. `run-performance.sh.txt` records the original sequence;
`group-compare-default-retry.sh.txt` records the qualifying recovery.

R12 reuses a fully validated raw DN tail after the first comma only within a
request, copying it into an owned 512-byte buffer. Exact raw-tail hits validate
leaf syntax and attribute identity before combining leaf and cached tail results.
Changed tails follow the full R10 comparison; unsupported inputs retain full
normalization and error order. The tail is published only after every DN type
validates. The existing simple-DN eligibility limits still apply. There is no
persistent cache, retained borrowed tail, storage/index/authentication change or
CGO. [Memory evidence](memory-proof.tsv) distinguishes source ownership and
mutation/isolation coverage from allocation timing; no retained-heap result is claimed.

[Handler components](component-comparisons.tsv) use a fixed 1000-member root
fixture with stored operational attributes, including `subschemaSubentry`.
Before is R10 plus the same benchmark, compiled after R11 reversion; current is
R12. Both use three unprofiled 500ms repeats, excluding setup from `b.Loop` timing.

| Handler case | Before us/op | Current us/op | Time reduction |
| --- | ---: | ---: | ---: |
| First | 39.558 | 41.101 | -3.90% |
| Last | 198.513 | 103.786 | 47.72% |
| Missing | 188.560 | 90.839 | 51.82% |

The [separate first-only recheck](group-first-recheck-comparisons.tsv) uses six
fresh processes in order before1/current1/current2/before2/before3/current3,
one unprofiled 1s repeat each, with the same fixture and unchanged source.
Before/current medians are 40.150/40.979 us/op: current is 2.065% slower, with
89,568 B/op and 423 allocs/op on both sides. [All six observations](group-first-recheck-samples.tsv)
remain, including current2 at 46.008 us/op. These results do not replace or pool
with the original components or macros; no native endpoint or exports were added.
There is no claim that all Compare cases improve.

B/op and allocs/op are unchanged for each handler case. These root handler
measurements remain separate from [nonroot LDAP group comparisons](group-compare-comparisons.tsv),
which use 20 operations x five repeats, shared assertions and WhoAmI verification
without root fallback. Group1000 last/missing macro time reductions are
34.32%-38.82%; current throughput remains 45.30%-48.70% of native OpenLDAP for
those four cells. First/last denotes fixture insertion order, not native storage order.

[All comparisons](comparisons.tsv) retain every positive and negative result,
including 19 negative macro cells and the slower first handler case. The largest
macro increase is default Group10 first at 6.31%; no causal attribution is made
for unrelated stages. [Medians](medians.tsv), [samples](samples.tsv) and
[counters](counters.tsv) preserve access, identity, variant, method, stage, member
count and endpoint. Warmup, smoke, setup and verification stay outside measured
medians. See [timing scope](timing-scope.tsv) and [limitations](limitations.txt).

[Final validation](generator/validation-main.txt): schema 1.589s; TailReuse fuzz
995,633 executions with four workers, 31.025s; full-suite server 138.638s and
webadmin 0.449s; vet exit 0; native differential 355 PASS, 0 FAIL, 0 SKIP in
10.230s. Raw logs preserve cached package results. Environment: Apple M1 Pro,
Go 1.26.4, `CGO_ENABLED=0`, native OpenLDAP 2.6.13, 100k macro fixture.

R11 compact-clone code was withdrawn and reverted, and its separate archive is
`REJECTED_DIAGNOSTIC_ONLY`. SDK Add already stored `subschemaSubentry`, bypassing
that candidate's target branch. Its setup-inclusive exploratory profiles are not
R12 timing or memory evidence. No CompareUID component pair was supplied for R12;
no older component, broad workload or recheck results are copied or pooled here.
No aggregate/native parity or whole compatibility is claimed.

[Provenance](provenance.tsv), [source hashes](source-hashes.tsv) and
[binary hashes](binary-hashes.tsv) identify the evidence. `SHA256SUMS` covers every
archived file except itself. No passwords, databases, LDIF/canonical contents,
binaries or profiles are archived. The evidence worker ran no workloads, Go
builds or Go tests. Main owns the formal report.

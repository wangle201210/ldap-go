# September 29-30, 2026 R6 evidence

Audit: `/var/tmp/ldap-go-perf-20260929-r6`; baseline `45c8e5d`. This archive is generated from completed
saved evidence only. Execution crossed local midnight in Asia/Shanghai;
the round and archive paths retain `20260929-r6`. Raw timestamps remain.
See [the report](../../common-ldap-performance.md) and
[the verbatim R4 report](../../common-ldap-performance-20260929-r4.md).

## Scope and grouping

R6 extends simple Search decoding to minimally encoded long BER lengths.
Group Base, direct membership and nested BFS leaf requests exceed 127 content
bytes and are affected; scale-pool hot/distributed Base/equality were already
fast. [Common tables](common-tables.md) and `medians.tsv` retain 72 groups,
three total_ms batches each. ACL, hot/distributed, stage, method, member count
and endpoint are separate. [Root tables](root-paired-tables.md) retain 30
groups, seven batches each, including exact literal/uppercase root DNs.
`concurrent-medians.tsv` excludes repeat 0 as warmup and keeps repeats 1-3.
All per-request latency arrays, smoke reports and 15 warmup JSONs remain.
Setup, connections, verification and cleanup are outside timed SDK calls.

[Independent group rechecks](groups-recheck-tables.md) and
`groups-recheck-medians.tsv` retain six additional endpoint groups: explicit
and default access, seven 100-call batches of 1,000-member group Base each,
using fresh processes and the same initial seeds. The original three-repeat
group regressions remain unchanged. Rechecks are neither pooled with nor
substituted for the original common runs.

[Default distributed rechecks](distributed-recheck-tables.md) retain six
additional endpoint groups, seven 1,000-call batches of Base and equality.
They run before the group workload in the same fresh default recheck session.
The original default distributed regressions remain; these samples do not
replace or pool with them. That session still has only three final exports.

Relative = OpenLDAP/current * 100%; 100% is parity. Time reduction =
(1-current/before) * 100%, using unrounded medians. Negative rows remain.
Parity is assessed per operation. Fast writes never offset slow reads, and
no cross-method, cross-variant or cross-round aggregate establishes parity.

## Validation and component

`report-checks.tsv` records sample counts, operation counts, repeats, setup,
errors and cleanup for every measured/smoke report. All 15 R6 export records
match 100,002 entries, checksum 2143929969 and 42,712,438 canonical bytes.
Nine exports belong to the original three scripts; six belong to the two
independent group rechecks. Five completion logs and confirmed exits remain.
`completion.json` records commands, environment and confirmed exit status;
`log-status.tsv` counts only the records actually present in each complete
log. An empty vet log is not standalone proof of success. Cached packages,
CGO configuration, focused/full tests, native checks and fuzz runs remain
separate; no business-test count is inferred from incomplete/nonverbose logs.

`decode-test-initial.txt` retains the initial targeted failure at
`selected-attribute/truncated-0`: removing the complete optional attribute
field still gives a valid message. The fixture expectation was corrected by
skipping that valid case; no product fix followed from this failure. This
failed attempt is separate from the subsequent completed validation suite.

[Decode tables](decode-tables.md), `decode-samples.tsv`, `decode-medians.tsv`
and the complete before/current logs retain every recorded benchmark case,
repetition and metric. Only Long is used for the affected before/current
comparison; the new GroupBase/MemberEquality fixtures compare current with
current PacketReference. Already-fast Equality/Presence controls retain their
slower before/current medians. Both logs contain five repetitions per case,
with before benchtime 1s and current 500ms. Unequal sample durations and
shared-host variability limit causal claims. Component gains do not prove
SDK parity or that every query is faster.

## Historical coverage and replay

Broad serial reads, full scans, extended fixtures, RSS and fixed writes were
last measured in [September 29, 2026 R4](../performance-20260929-r4/README.md),
baseline `6f31d43`. They are historical evidence, not fresh R6 measurements.
No R4 samples or checks are added to R6 totals. The previous operational-
attribute gap remains outside the passing matrix. Shared-host timings do
not establish causality or deployment performance.

The five performance `*.sh.txt` recipes require environment passwords, unused output
directories, persistent native OpenLDAP dependencies and the historical
fixture/probe/canonical-reference paths named by each script. They are
archived without execution, together with `validate.sh.txt`. No passwords, binaries, databases, profiles,
LDIF or large exports are bundled. `executable-sha256.txt` hashes frozen
executables; `source-sha256.tsv` records source text hashes and sizes;
`SHA256SUMS` hashes every evidence file except itself. R4 is archived byte
for byte. Documentation preparation runs no builds, benchmarks or tests.
Exact component commands and their complete output are retained.

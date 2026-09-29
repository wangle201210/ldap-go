# September 30, 2026 R7 evidence

Baseline fa4d51a; Go 1.26.4, CGO_ENABLED=0, Apple M1 Pro, OpenLDAP 2.6.13.
Scope: pure DN syntax-cache use in core write and Compare entry/self ACL paths.
Production code stayed unchanged after the full suite.

[Common](common-tables.md): three batches per group; [paired root](root-tables.md): seven
per literal/uppercase variant; [full write probe](writes-tables.md): three fresh processes
per endpoint, fixed DNs, 20 reads/Bind/CRUD operations, setup 62, cleanup 104, connections 1.
[Concurrent](concurrent-tables.md) keeps repeats 1-3 and excludes warmup repeat 0.
[Default recheck](default-recheck-tables.md) keeps seven 1,000-operation batches per group.
[Write recheck](write-recheck-tables.md) keeps seven alternating before/current pairs:
CRUD 100, reads/Bind 2, setup 302, cleanup 504, connections 1; no OpenLDAP measurement.
Setup/cleanup and serial reads retain separate rows with actual counts. All tables use
unrounded batch total_ms medians, preserving stage, method, members, access and variant.
Original negatives remain. Rechecks and R6 are never pooled or substituted. Results are
mixed; faster Add/Delete rechecks do not erase slower Modify/Rename or establish parity.

checks.tsv records 602 checks, 0 failed. export-checks.tsv records 35/35 exports:
18 original + 3 default recheck + 14 write recheck, each 100,002 entries, cksum 2143929969,
42,712,438 canonical bytes. report-checks.tsv covers 49 raw JSON reports;
medians.tsv retains 200 endpoint groups. Raw latency, smoke, warmup, verification,
errors and cleanup fields remain. Common/root setup and verification are outside timed
SDK calls. Filesystem cleanup checks cover passwords/seed databases, not process liveness.
All six performance scripts exited 0; all six saved completion markers are checked.

Full go test ./... exited 0 (server 137.338s; 23 package-ok records, 15 cached).
Its launch overlapped final test edits; final focused validation passed in 1.633s.
validate.sh exited 0, including empty vet output and executable hashes.
Native evidence: 26 top-level tests, 355 PASS records including subtests, 0 FAIL, 0 SKIP,
terminal PASS, server 11.436s. log-status.tsv separates these counts.
No new R7 fuzz or race-detector run is claimed. All Go builds/checks use CGO_ENABLED=0.

[Compare component](compare-tables.md): three 1s repeats per side, both CPU-profiled;
process durations 59.030/59.988s. Profiles include expensive fixture setup, not query-only
work; component gains do not prove SDK parity. Shared-host timings limit causal claims.

Scripts retain their existing commands, external password references and fixture/tool
paths. Documentation preparation ran no workloads. [R6](../performance-20260929-r6/README.md)
was used only for layout/grouping reference. No passwords, databases, LDIF, binaries or
profiles are archived. SHA256SUMS covers every evidence file except itself.

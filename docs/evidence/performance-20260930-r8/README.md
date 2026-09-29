# R8 Candidate Investigation

R8 is PRE-FIX diagnostic evidence. Performance is NOT accepted, and this archive
does NOT qualify the final implementation. After these measurements, production
changed by two lines to avoid calling names.match when names is nil. R8b requires
new tests and benchmarks. Baseline: 2645eba. See [candidate status](candidate-status.txt)
and [provenance](provenance.tsv) for source and validation boundaries.

All eight scripts exited 0 per main. The archive contains 170 raw JSON reports,
311 median groups and 50 canonical export checks:
27 original, 6 read recheck, 14 write recheck, 3 paired paging recheck.
[Checks](checks.tsv): 1566 checks, 0 failures.
[Export checks](export-checks.tsv) include SHA256 computed from all 50 actual source
canonical files, each 100,002 entries, cksum 2143929969 and 42,712,438 bytes.

[Medians](medians.tsv) and [comparisons](comparisons.tsv) preserve method, members,
endpoint and variant. Original negatives remain. Independent [read](read-recheck-comparisons.tsv),
[write](write-recheck-comparisons.tsv) and [paired paging](paged-recheck-comparisons.tsv)
rechecks never replace or pool original samples. Setup, warmup and verification
boundaries are recorded in [timing scope](timing-scope.tsv) and provenance.

Official Compare uses only compare-before.txt and compare-current.txt, unprofiled
1s x 3; before used the immutable R7 test binary. Schema component tables separate
original, cloning, warmed current and cold fallback, 300ms x 3. Preliminary Compare,
superseded copy-only and warm-only measurements, and intermediate validation logs
remain explicitly excluded under diagnostics/. No causal attribution to host load.

SHA256SUMS covers every archived file except itself. No passwords, databases,
LDIF, canonical fixture contents, binaries, profiles or personal process lists
are archived. Main owns temporary fixture deletion, R8b and formal reports.

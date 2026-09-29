# R16 Evidence

Status: **REJECTED / NOT SHIPPED**. Small-group overhead remained unresolved, and main rejected this candidate to avoid regressions in common small-group workloads. The main performance report remains at R13; these files preserve the unsuccessful candidate for review.

Main confirmed withdrawal of R16: its six new Go files were removed and write.go was restored to HEAD before integrating the next candidate. The frozen source snapshot preserves the rejected implementation independently of those changes.

Baseline `747e5bd307b361ec03705a16303fb9b363c263d1`; current executable SHA256 `7c647988fe088d415725c4f75868bb0fd67c72145877301bedb0a2b2407545ea`. Full binary and source hashes are in [binary-hashes.tsv](binary-hashes.tsv) and [source-hashes.tsv](source-hashes.tsv). Eligible local DN Compare uses a callback-scoped read-only first Get, lazy decoder acquisition, and owned fallback for encoded entries smaller than 4096 bytes. Main's environment, validation and completion records are preserved under [generator/](generator/).

All 12 [candidate source files](source-origin.tsv), including the fixture proof and diagnostic benchmark tests, are read and hashed solely from `/var/tmp/ldap-go-perf-20260930-r16/frozen-source`. Main preserved this frozen R16 candidate using rsync -aR before withdrawing it. Archive and hash paths retain the original repository-relative names; generation does not depend on live repository source.

The retained baseline is the R13 final executable. Its actual [Go build metadata](binary-metadata/before.txt) records eced1dc with a dirty worktree. Main identifies that final source as subsequently committed in 747e5bd; this archive does not claim a clean 747e5bd build.

Additional [real-fixture guard proofs](fixture-proof-status.tsv) use the explicit and default 100k seeds. Their opt-in test sources and raw logs are archived. These test-only additions followed the full-suite run and frozen production build; they add no timing samples and do not change the production binary.

[Checks](checks.tsv) contain 897 passing checks. All 18 [exports](export-checks.tsv) have identical canonical SHA256 values: 100,002 entries, cksum 2143929969, and 42,712,438 bytes each. Six workload scripts completed; 37 final raw JSON reports include warmups and smoke. Full tests, vet, native differential checks and focused logs are preserved with their actual cached and skipped counts in [log-status.tsv](log-status.tsv).

[Medians](medians.tsv) and [comparisons](comparisons.tsv) retain 822 measured samples, 162 medians and 54 comparisons. Methods, endpoints, access modes, member counts and root DN variants remain separate. Common runs use three repeats, paired root runs seven, and final nonroot group Compare seven 1000-operation batches. The independent explicit [read recheck](read-recheck-comparisons.tsv) uses seven batches and never replaces the original common results. Warmups and smoke are excluded from medians. First/last denotes fixture insertion order, not native storage order.

R15 was an unadopted initial candidate. Negative small-group observations in its 20 x 5 experiment prompted larger 1000 x 7 batches; those still showed small-group regressions. Its two large-batch group JSON reports, original component logs and binary identity are preserved under [exploratory-r15/](exploratory-r15/), excluded from every final comparison. R16 adds the small-entry fallback and lazy decoder. Counts are fixed before execution; there is no repetition until favorable results or performance-based early stopping.

The earlier R16 wrapper diagnostic is preserved under [exploratory-r16/](exploratory-r16/). Final source creates the wrapper only after borrowing eligibility succeeds; earlier component and validation observations are excluded from the final results.

All 29 negative reduction rows remain in the complete comparisons and [negative-comparisons.tsv](negative-comparisons.tsv). Component [comparisons](component-comparisons.tsv) retain UID 1/1024-target and Group1000 first/last/missing cases, with ns/op, B/op and allocs/op separate. Each case uses three unprofiled 500ms measurements per implementation. Their root identity differs from nonroot LDAP macros.

The additional [forced-owned versus eligible diagnostic](diagnostic-components/borrowed-entry-comparisons.tsv) measures missing-member Compare for 10/1000 members on the same candidate source. It uses a decorated Store to force the owned path. These local diagnostics are separate from the before/current components and network results; they do not by themselves explain the network regressions.

In the independent five-repeat diagnostic, the 10-member eligible case adds 549 ns/op, 232 B/op and 4 allocs/op versus forced-owned. This regression remains unresolved. [Profiling text logs](profile-status.tsv) distinguish the initial mixed 10/1000-member run from the corrected anchored 10-member run; both are excluded from all comparison tables, and no binary profiles are bundled.

No aggregate/native parity, complete compatibility, retained-heap improvement, fresh fuzz or race-detector result is claimed. No historical timings are pooled. SHA256SUMS covers every archive file except itself, including this README and the generator. No passwords, databases, LDIF/canonical contents, binaries or binary profiles are bundled.

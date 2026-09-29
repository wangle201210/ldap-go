# R13 Evidence

Baseline `eced1dc`; Go 1.26.4, `CGO_ENABLED=0`, Apple M1 Pro, OpenLDAP 2.6.13,
100,000-user fixture. The [formal report](../../common-ldap-performance.md)
describes the implementation and remaining native gaps.

The server opts into existing bounded DN normalization reuse. Syntax/length
validation stays live; schema mutation invalidates normalization. No authorization
or comparison result is cached, and the default API stays uncached.

[Checks](checks.tsv) retain 473 passing checks. All 18 [exports](export-checks.tsv)
match the same canonical contents: 100,002 entries, cksum 2143929969 and
42,712,438 bytes. Six workload scripts completed successfully, including the
independent default Bind recheck. Full tests, vet, native checks and final
cache-specific tests passed; raw logs distinguish cached packages and targeted runs.

[Medians](medians.tsv) and [comparisons](comparisons.tsv) keep methods, endpoints,
access modes, member counts and variants separate. Common runs use three repeats;
paired root runs seven; nonroot group Compare uses five 20-call batches. Shared
fixture assertions and WhoAmI checks apply to every endpoint with no root fallback.
First/last refers to fixture order, not native storage order. Setup, connections,
verification and cleanup are outside SDK timing.

The seven-repeat Bind recheck does not replace the original SSHA slowdown;
SSHA remains 1.31% slower in the recheck. All other negative rows remain.
Component benchmarks use three unprofiled 500ms repetitions with operational
attributes in the fixture. Exploratory profiling included setup and is not a
before/current timing pair. No new fuzz or race-detector result is claimed.

Broad R8b results are historical, not rerun or pooled into R13. No aggregate
parity or complete compatibility is claimed. SHA256SUMS covers this archive;
no credentials, databases, LDIF contents, binaries or profiles are bundled.

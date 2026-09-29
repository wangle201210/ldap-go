# Common LDAP performance qualification

September 29, 2026, R4; baseline `6f31d43`, frozen `current`, 100,000 users,
Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Results are mixed; uniform latency gains and overall parity remain unproven.
The optimization goal remains active.** Versus baseline `6f31d43`,
1,000-member group Base improves 2.5% with explicit ACLs but is 0.4% slower
with default access. Default hot non-root Base is 4.9% slower; explicit
distributed equality is 5.5% slower. All samples and negative rows remain.

The [R3 archive](common-ldap-performance-20260929-r3.md) preserves the previous
report verbatim. [R4 evidence index](evidence/performance-20260929-r4/README.md).

## Scope and method

Opt-in `SelectForResponse` packs eligible sets of at least eight values into
exact-sized owned blocks of at most 4,096 bytes; packed values have `cap == len`.
Nil/empty distinctions remain; oversized individual clones retain their usual
capacity. Only two
small root/non-root search callers opt in after ACL checks. Default `Select`,
normal cache deep-cloning and logical candidate budgets remain unchanged;
focused tests check ownership, budgets and wire-equivalent responses.

Common rows are medians of three `total_ms` batches with per-request endpoint
rotation; only SDK calls are timed. Setup, connections, verification and cleanup
are excluded. Methods, hot/distributed reads and group sizes are never pooled.
Frequency is qualitative. `Relative = OpenLDAP/current * 100%` (100% is parity);
`Time reduction = (1-current/before) * 100%`, versus `6f31d43`, so negative
means slower. Ratios use unrounded medians. [All 72 common medians](evidence/performance-20260929-r4/medians.tsv).

## Explicit ACL

All endpoints use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 102.87 ms | 101.36 ms | 81.23 ms | 80.1% | 1.5% |
| Wrong password, SSHA | Low | 1,000 | 94.56 ms | 94.08 ms | 75.32 ms | 80.1% | 0.5% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 100.44 ms | 101.30 ms | 81.16 ms | 80.1% | -0.8% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 96.76 ms | 96.96 ms | 76.77 ms | 79.2% | -0.2% |
| Non-root Base, hot | High | 1,000 | 115.30 ms | 114.60 ms | 90.17 ms | 78.7% | 0.6% |
| Non-root equality, hot | Very high | 1,000 | 118.28 ms | 119.47 ms | 91.13 ms | 76.3% | -1.0% |
| Non-root Base, distributed | High | 1,000 | 125.61 ms | 127.77 ms | 87.79 ms | 68.7% | -1.7% |
| Non-root equality, distributed | Very high | 1,000 | 143.82 ms | 151.71 ms | 106.07 ms | 69.9% | -5.5% |
| Direct group discovery | High | 100 | 17.88 ms | 18.05 ms | 12.24 ms | 67.8% | -0.9% |
| Group Base, 10 members | Medium | 100 | 14.86 ms | 14.68 ms | 11.38 ms | 77.5% | 1.2% |
| Group Base, 1,000 members | Medium | 100 | 103.68 ms | 101.09 ms | 94.97 ms | 93.9% | 2.5% |
| Nested membership, client BFS | Medium-high | 100 traversals | 62.77 ms | 62.68 ms | 46.35 ms | 74.0% | 0.2% |

## Default access

No explicit ACL rules; otherwise the same common-operation method.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 106.33 ms | 106.07 ms | 87.71 ms | 82.7% | 0.2% |
| Wrong password, SSHA | Low | 1,000 | 108.90 ms | 105.21 ms | 83.32 ms | 79.2% | 3.4% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 106.09 ms | 104.81 ms | 86.86 ms | 82.9% | 1.2% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 98.94 ms | 100.16 ms | 81.91 ms | 81.8% | -1.2% |
| Non-root Base, hot | High | 1,000 | 116.55 ms | 122.21 ms | 96.08 ms | 78.6% | -4.9% |
| Non-root equality, hot | Very high | 1,000 | 123.47 ms | 124.05 ms | 97.79 ms | 78.8% | -0.5% |
| Non-root Base, distributed | High | 1,000 | 140.75 ms | 141.57 ms | 100.88 ms | 71.3% | -0.6% |
| Non-root equality, distributed | Very high | 1,000 | 183.22 ms | 175.70 ms | 130.50 ms | 74.3% | 4.1% |
| Direct group discovery | High | 100 | 15.63 ms | 15.25 ms | 11.29 ms | 74.0% | 2.5% |
| Group Base, 10 members | Medium | 100 | 15.84 ms | 15.78 ms | 13.46 ms | 85.3% | 0.4% |
| Group Base, 1,000 members | Medium | 100 | 105.64 ms | 106.10 ms | 98.04 ms | 92.4% | -0.4% |
| Nested membership, client BFS | Medium-high | 100 traversals | 58.54 ms | 56.18 ms | 42.67 ms | 75.9% | 4.0% |

## Broader evidence

- [Serial read tables](evidence/performance-20260929-r4/read-tables.md) retain
  literal-root, uppercase-root, scans, CLI, RSS and extended-fixture results
  separately. Root Base is a hot container; equality/Compare use distributed UIDs.
- [Interleaved root tables](evidence/performance-20260929-r4/root-paired-tables.md)
  use seven repeats per DN variant. Per-request rotation, untimed WhoAmI and
  fixture work differ from the serial probe; these results do not replace it.
- [Fixed-write medians](evidence/performance-20260929-r4/write-medians.tsv) and
  [raw probes/checks](evidence/performance-20260929-r4/writes/) retain three
  fresh processes per endpoint, 20 operations per stage and the same fixed
  token across before/current/OpenLDAP. Add improves 14.8%, Modify is 3.4%
  slower, ModifyDN improves 3.0%, and Delete improves 0.4%. No rounds are pooled.
- Common concurrent CLI medians (before/current/native) are 308/311/317 ms
  with explicit ACLs and 337/319/370 ms with default access. Repeat 0 is warmup;
  repeats 1-3 are measured. These remain separate from full-read CLI batches.

## Component, validation and limits

The [selection benchmark](evidence/performance-20260929-r4/selection-bench.txt)
retains every case and three repetitions each. For 1,000 values, median
`Select`/`SelectForResponse` is **24,417/13,900 ns, 72,768/65,088 B/op and
1,006/16 allocs/op**. This isolates selection, not whole requests or process
memory. Small/nil/empty/types-only cases remain, including slower medians;
there is no every-request saving or new allocation-profile claim.

All five scripts exited 0. SDK stage errors, operation/repeat counts, write
postconditions and cleanup passed. **All 27 exports match** 100,002 entries,
checksum 2143929969 and 42,712,438 canonical bytes: six common, three paired,
nine read, nine write. Focused tests passed (schema 0.036 s, server 19.426 s);
full Go tests passed (server 135.794 s; some packages cached), vet exited 0,
and native validation has 355 PASS records, no failures/skips, terminal PASS
(9.813 s). No race-detector result is claimed.

Shared-host measurements do not establish causality or deployment performance.
The [September 24 operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. Component gains do not prove uniform SDK gains.

Frozen executable SHA-256, read from `/var/tmp/ldap-go-perf-20260929-r4`:

```text
before (6f31d43)  365079e52a578b2180f8fb10d2a647be9d5dd663177587f0a105b63e0ccbb5f3
current           14f64911aa8f5f1505f36e20b4eb735e7b6216afa27234d0df8a5cb2a6e17202
```

Replays require environment passwords and preserve existing local dependencies.
No passwords, binaries, databases, profiles or large exports are archived.
Documentation preparation ran no workloads and made no commits.

# R5 common-operation tables

Before is baseline `f78523a`; current is the frozen R5 server. This file
covers the completed explicit-ACL and default-access runs.

**Regression controls: these standard runs do not exercise the changed audit
fast path.** Standard launches supply no audit sink; without runtime accesslog,
`newAuditObservation` returns nil. The coordinator identified these runs as
baseline controls. The [completed audit-enabled comparison](audited-paired-tables.md)
and [same-binary A/A control](audited-aa-tables.md) are separate evidence.
Do not attribute these timing differences to R5 or claim a default-latency
gain. The observer microbenchmark alone does not establish production SDK
latency; the audit-enabled timings do not establish a causal improvement.
R5 does not repeat unaudited full-read/full-write runs. Broader measurements
remain [historical R4 evidence](README.md#applicability-and-scope), not R5 results;
the existing broad deficits and overall parity goal remain unchanged.

Rows are medians of three `total_ms` batches, grouped by run, batch, stage,
method, member count and endpoint. All samples remain. SSHA/plaintext,
hot/distributed reads and group sizes stay separate. Endpoints rotate per
request; setup, connection, verification and cleanup are outside SDK timing.
Frequency is qualitative.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `f78523a`;
negative means slower. Ratios use unrounded medians; tiny negative changes
remain explicit. These controls do not measure audit-fast-path performance
or establish overall parity; the optimization goal remains active.

## Explicit ACL

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 92.94 ms | 94.01 ms | 74.54 ms | 79.3% | -1.2% |
| Wrong password, SSHA | Low | 1,000 | 100.76 ms | 100.22 ms | 79.65 ms | 79.5% | 0.5% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 92.25 ms | 92.27 ms | 74.10 ms | 80.3% | <0.1% slower |
| Wrong password, plaintext diagnostic | Low | 1,000 | 90.25 ms | 90.26 ms | 72.36 ms | 80.2% | <0.1% slower |
| Non-root Base, hot | High | 1,000 | 101.55 ms | 101.61 ms | 80.32 ms | 79.1% | -0.1% |
| Non-root equality, hot | Very high | 1,000 | 109.56 ms | 108.57 ms | 83.34 ms | 76.8% | 0.9% |
| Non-root Base, distributed | High | 1,000 | 121.90 ms | 119.79 ms | 86.43 ms | 72.1% | 1.7% |
| Non-root equality, distributed | Very high | 1,000 | 117.79 ms | 116.81 ms | 85.35 ms | 73.1% | 0.8% |
| Direct group discovery | High | 100 | 21.28 ms | 19.01 ms | 13.18 ms | 69.3% | 10.7% |
| Group Base, 10 members | Medium | 100 | 13.38 ms | 13.54 ms | 10.29 ms | 76.0% | -1.2% |
| Group Base, 1,000 members | Medium | 100 | 95.51 ms | 96.57 ms | 87.89 ms | 91.0% | -1.1% |
| Nested membership, client BFS | Medium-high | 100 traversals | 55.06 ms | 54.80 ms | 41.32 ms | 75.4% | 0.5% |

## Default access

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 99.56 ms | 99.72 ms | 80.70 ms | 80.9% | -0.2% |
| Wrong password, SSHA | Low | 1,000 | 95.40 ms | 95.52 ms | 76.29 ms | 79.9% | -0.1% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 103.07 ms | 107.09 ms | 84.98 ms | 79.4% | -3.9% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 102.30 ms | 104.37 ms | 81.28 ms | 77.9% | -2.0% |
| Non-root Base, hot | High | 1,000 | 113.49 ms | 112.58 ms | 92.16 ms | 81.9% | 0.8% |
| Non-root equality, hot | Very high | 1,000 | 114.37 ms | 115.36 ms | 88.75 ms | 76.9% | -0.9% |
| Non-root Base, distributed | High | 1,000 | 117.82 ms | 119.27 ms | 85.59 ms | 71.8% | -1.2% |
| Non-root equality, distributed | Very high | 1,000 | 130.20 ms | 133.40 ms | 97.27 ms | 72.9% | -2.5% |
| Direct group discovery | High | 100 | 17.50 ms | 16.84 ms | 12.32 ms | 73.1% | 3.7% |
| Group Base, 10 members | Medium | 100 | 14.14 ms | 14.68 ms | 10.81 ms | 73.6% | -3.8% |
| Group Base, 1,000 members | Medium | 100 | 94.63 ms | 97.78 ms | 90.46 ms | 92.5% | -3.3% |
| Nested membership, client BFS | Medium-high | 100 traversals | 54.38 ms | 54.81 ms | 45.19 ms | 82.4% | -0.8% |

## Separate concurrent check

Eight root-bound CLI clients each issue 1,000 indexed queries. Wall-clock
timing includes client startup/Bind; repeat 0 is retained as warmup and
repeats 1-3 supply the medians. This is separate from SDK request timing.

| Access | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Explicit ACL | 307 | 287 | 321 | 111.8% | 6.5% |
| Default | 307 | 319 | 323 | 101.3% | -3.9% |

[All 72 endpoint medians](medians.tsv), [explicit samples](explicit-final/),
[default samples](default-final/),
[explicit completion](common-explicit.log.txt), [default completion](common-default.log.txt),
[explicit replay](common-explicit.sh.txt), [default replay](common-default.sh.txt),
[executable identities](executable-sha256.txt).

The coordinator confirmed both scripts exited 0. All six exports match 100,002 entries,
checksum 2143929969 and 42,712,438 canonical bytes. SDK errors, counts, repeats
and cleanup checks passed. Replay requires the fixture password through the
environment and retains local dependencies. No new workload was run.

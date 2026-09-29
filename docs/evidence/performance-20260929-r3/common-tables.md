# R3 common-operation tables

September 29, 2026; before is baseline `a9de7d4`, current is the frozen R3
server. This file covers the completed explicit-ACL and default-access runs.

SDK rows are medians of three `total_ms` batches, grouped by run, batch, stage,
method, member count and endpoint. All samples remain. SSHA/plaintext,
hot/distributed reads and group sizes stay separate. Endpoints rotate per
request; setup, connection, verification and cleanup are outside SDK timing.
Usage frequency is qualitative.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `a9de7d4`;
negative means slower. Ratios use unrounded medians. Results are mixed;
no uniform gain or overall parity is established, and the goal remains active.

## Explicit ACL

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 103.67 ms | 98.39 ms | 78.81 ms | 80.1% | 5.1% |
| Wrong password, SSHA | Low | 1,000 | 124.06 ms | 103.23 ms | 94.29 ms | 91.3% | 16.8% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 98.83 ms | 99.85 ms | 79.81 ms | 79.9% | -1.0% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 98.80 ms | 101.77 ms | 80.71 ms | 79.3% | -3.0% |
| Non-root Base, hot | High | 1,000 | 108.36 ms | 104.06 ms | 83.31 ms | 80.1% | 4.0% |
| Non-root equality, hot | Very high | 1,000 | 134.90 ms | 131.73 ms | 101.88 ms | 77.3% | 2.4% |
| Non-root Base, distributed | High | 1,000 | 135.26 ms | 138.34 ms | 95.73 ms | 69.2% | -2.3% |
| Non-root equality, distributed | Very high | 1,000 | 145.08 ms | 150.58 ms | 106.64 ms | 70.8% | -3.8% |
| Direct group discovery | High | 100 | 19.42 ms | 17.73 ms | 12.96 ms | 73.1% | 8.7% |
| Group Base, 10 members | Medium | 100 | 12.64 ms | 12.78 ms | 9.70 ms | 75.9% | -1.1% |
| Group Base, 1,000 members | Medium | 100 | 95.97 ms | 103.24 ms | 92.18 ms | 89.3% | -7.6% |
| Nested membership, client BFS | Medium-high | 100 traversals | 58.85 ms | 60.17 ms | 45.95 ms | 76.4% | -2.3% |

## Default access

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 102.82 ms | 102.32 ms | 91.55 ms | 89.5% | 0.5% |
| Wrong password, SSHA | Low | 1,000 | 98.83 ms | 99.30 ms | 81.23 ms | 81.8% | -0.5% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 92.71 ms | 92.17 ms | 75.98 ms | 82.4% | 0.6% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 90.92 ms | 93.27 ms | 73.24 ms | 78.5% | -2.6% |
| Non-root Base, hot | High | 1,000 | 115.55 ms | 114.50 ms | 92.69 ms | 81.0% | 0.9% |
| Non-root equality, hot | Very high | 1,000 | 113.88 ms | 112.39 ms | 88.76 ms | 79.0% | 1.3% |
| Non-root Base, distributed | High | 1,000 | 128.23 ms | 130.48 ms | 94.27 ms | 72.2% | -1.8% |
| Non-root equality, distributed | Very high | 1,000 | 150.58 ms | 154.59 ms | 116.07 ms | 75.1% | -2.7% |
| Direct group discovery | High | 100 | 16.66 ms | 16.47 ms | 11.65 ms | 70.7% | 1.1% |
| Group Base, 10 members | Medium | 100 | 14.01 ms | 13.70 ms | 10.73 ms | 78.3% | 2.2% |
| Group Base, 1,000 members | Medium | 100 | 115.36 ms | 113.42 ms | 98.68 ms | 87.0% | 1.7% |
| Nested membership, client BFS | Medium-high | 100 traversals | 58.32 ms | 55.40 ms | 43.01 ms | 77.6% | 5.0% |

## Separate concurrent check

Eight root-bound CLI clients each issue 1,000 indexed queries. Wall-clock
timing includes client startup/Bind; repeat 0 is retained as warmup and
repeats 1-3 supply the medians. This is separate from SDK request timing.

| Access | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Explicit ACL | 365 | 343 | 369 | 107.6% | 6.0% |
| Default | 317 | 303 | 317 | 104.6% | 4.4% |

[All 72 endpoint medians](medians.tsv), [explicit samples](explicit-final/),
[default samples](default-final/),
[explicit completion](common-explicit.log.txt), [default completion](common-default.log.txt),
[explicit replay](common-explicit.sh.txt), [default replay](common-default.sh.txt),
[verified executable identities](executable-sha256.txt).

The coordinator confirmed both scripts exited 0. All six exports match 100,002 entries,
checksum 2143929969 and 42,712,438 canonical bytes. SDK error, count, repeat
and cleanup checks passed. Replay requires the fixture password through the
environment and preserves its existing local dependencies. No new workload
was run to prepare these tables.

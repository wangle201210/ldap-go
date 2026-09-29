# R4 common-operation tables

September 29, 2026; before is baseline `6f31d43`, current is the frozen R4
server. This file covers the completed explicit-ACL and default-access runs.

SDK rows are medians of three `total_ms` batches, grouped by run, batch, stage,
method, member count and endpoint. All samples remain. SSHA/plaintext,
hot/distributed reads and group sizes stay separate. Endpoints rotate per
request; setup, connection, verification and cleanup are outside SDK timing.
Usage frequency is qualitative.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `6f31d43`;
negative means slower. Ratios use unrounded medians. Results are mixed;
no uniform gain or overall parity is established, and the goal remains active.
Compact-copy component allocation gains do not establish uniform SDK latency
improvement; every slower row is retained, including small negative changes.

## Explicit ACL

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

## Separate concurrent check

Eight root-bound CLI clients each issue 1,000 indexed queries. Wall-clock
timing includes client startup/Bind; repeat 0 is retained as warmup and
repeats 1-3 supply the medians. This is separate from SDK request timing.

| Access | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Explicit ACL | 308 | 311 | 317 | 101.9% | -1.0% |
| Default | 337 | 319 | 370 | 116.0% | 5.3% |

[All 72 endpoint medians](medians.tsv), [explicit samples](explicit-final/),
[default samples](default-final/),
[explicit completion](common-explicit.log.txt), [default completion](common-default.log.txt),
[explicit replay](common-explicit.sh.txt), [default replay](common-default.sh.txt),
[verified executable identities](executable-sha256.txt).

The coordinator confirmed both scripts exited 0. All six exports match 100,002 entries,
checksum 2143929969 and 42,712,438 canonical bytes. SDK error, count, repeat
and cleanup checks passed. Replay requires the fixture password through the
environment and preserves existing local dependencies. No new workload was
run to prepare these tables.

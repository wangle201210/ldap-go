# R2 common-operation tables

September 29, 2026; before is baseline `b55f670`, current is the frozen R2
server. These tables cover only the completed common-operation runs.

Each SDK row is the median of three `total_ms` batches. Grouping retains run,
batch, stage, method, member count and endpoint. All samples are retained;
SSHA/plaintext, hot/distributed reads and group sizes remain separate.
Endpoints rotate per request; only SDK calls are timed. Setup, connection,
verification and cleanup are outside timing. Frequency is qualitative.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `b55f670`;
negative means slower. Ratios use unrounded medians; 0.0% is rounded, not an
assertion of identical times. The broader parity goal remains active and unproven.

## Explicit ACL

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 95.61 ms | 95.78 ms | 75.73 ms | 79.1% | -0.2% |
| Wrong password, SSHA | Low | 1,000 | 98.75 ms | 98.41 ms | 77.94 ms | 79.2% | 0.3% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 97.51 ms | 97.48 ms | 76.73 ms | 78.7% | 0.0% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 91.64 ms | 91.66 ms | 74.08 ms | 80.8% | <0.1% slower |
| Non-root Base, hot | High | 1,000 | 115.63 ms | 110.38 ms | 87.10 ms | 78.9% | 4.5% |
| Non-root equality, hot | Very high | 1,000 | 119.88 ms | 114.25 ms | 88.80 ms | 77.7% | 4.7% |
| Non-root Base, distributed | High | 1,000 | 133.97 ms | 126.69 ms | 89.20 ms | 70.4% | 5.4% |
| Non-root equality, distributed | Very high | 1,000 | 131.64 ms | 125.10 ms | 90.68 ms | 72.5% | 5.0% |
| Direct group discovery | High | 100 | 18.70 ms | 17.37 ms | 11.79 ms | 67.9% | 7.1% |
| Group Base, 10 members | Medium | 100 | 14.66 ms | 13.27 ms | 10.48 ms | 78.9% | 9.5% |
| Group Base, 1,000 members | Medium | 100 | 96.90 ms | 95.60 ms | 88.50 ms | 92.6% | 1.3% |
| Nested membership, client BFS | Medium-high | 100 traversals | 58.27 ms | 56.98 ms | 41.52 ms | 72.9% | 2.2% |

## Default access

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 89.37 ms | 89.35 ms | 70.77 ms | 79.2% | 0.0% |
| Wrong password, SSHA | Low | 1,000 | 99.06 ms | 100.33 ms | 80.38 ms | 80.1% | -1.3% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 98.32 ms | 98.14 ms | 79.32 ms | 80.8% | 0.2% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 93.43 ms | 93.96 ms | 74.75 ms | 79.6% | -0.6% |
| Non-root Base, hot | High | 1,000 | 113.12 ms | 108.68 ms | 87.90 ms | 80.9% | 3.9% |
| Non-root equality, hot | Very high | 1,000 | 121.82 ms | 118.26 ms | 93.65 ms | 79.2% | 2.9% |
| Non-root Base, distributed | High | 1,000 | 135.42 ms | 126.90 ms | 91.50 ms | 72.1% | 6.3% |
| Non-root equality, distributed | Very high | 1,000 | 147.47 ms | 130.79 ms | 113.02 ms | 86.4% | 11.3% |
| Direct group discovery | High | 100 | 17.90 ms | 17.19 ms | 12.11 ms | 70.4% | 4.0% |
| Group Base, 10 members | Medium | 100 | 14.92 ms | 14.72 ms | 11.37 ms | 77.2% | 1.3% |
| Group Base, 1,000 members | Medium | 100 | 100.19 ms | 99.85 ms | 90.09 ms | 90.2% | 0.3% |
| Nested membership, client BFS | Medium-high | 100 traversals | 56.51 ms | 54.73 ms | 40.87 ms | 74.7% | 3.1% |

## Separate concurrent check

Eight root-bound CLI clients each issue 1,000 indexed searches. Wall-clock
timing includes client startup/Bind. Repeat 0 is retained as warmup; repeats
1-3 supply the medians. These results are separate from SDK request timing.

| Access | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Explicit ACL | 309 | 314 | 325 | 103.5% | -1.6% |
| Default | 309 | 303 | 327 | 107.9% | 1.9% |

[All 72 endpoint medians](medians.tsv),
[explicit samples and export checks](explicit-final/),
[default samples and export checks](default-final/). Both scripts exited 0;
all six exports match 100,002 entries, checksum 2143929969 and 42,712,438
canonical bytes. No sample was discarded and no new workload was run.

Executable SHA-256 supplied by the coordinator:

```text
before (b55f670)  9cac059895ac9fff6999e9ce958b1a1f6f3f44ddd447a065e98a94726a5f9df7
current           d93aea5cd433bbe3b20805074de8e670286f57eefa2ead015a5028dd53de189f
```

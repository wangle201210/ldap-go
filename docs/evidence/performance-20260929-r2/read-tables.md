# R2 broader-read tables

September 29, 2026. Before is baseline `b55f670`; current is the frozen R2
server. Three fresh processes per endpoint ran in rotating order. Each SDK
row below uses nine batches, three per process. All samples remain; no DN
variants, stages, operation counts or SDK/CLI methods are pooled.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `b55f670`;
negative means slower. Ratios use unrounded medians. These shared-host results
are mixed and do not establish overall latency improvement or parity.

## Literal-root and short-user SDK

SSHA rows use all measured `user-bind.json` repeats 0, 1 and 2. Root rows use
`fast-1/2/3.json`, binding as `cn=admin,dc=scale,dc=qualification`.
Root Base repeatedly reads the fixed `c.Base` container. Root equality and
both Compare stages sample UIDs across the 100k range, as recorded by the
[unchanged fast-probe source](../performance-20260929-r1/helpers/fast-probe.go.txt).

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA; 1,000 calls | 9 | 97.46 | 99.12 | 74.93 | 75.6% | -1.7% |
| Wrong password, SSHA; 1,000 calls | 9 | 89.37 | 97.57 | 74.81 | 76.7% | -9.2% |
| Root Bind; 1,000 calls | 9 | 71.12 | 67.28 | 76.27 | 113.4% | 5.4% |
| Root Base, hot container; 1,000 calls | 9 | 102.70 | 100.64 | 84.98 | 84.4% | 2.0% |
| Root equality, distributed; 1,000 calls | 9 | 106.65 | 122.07 | 93.28 | 76.4% | -14.5% |
| Root Compare true, distributed; 1,000 calls | 9 | 107.71 | 105.61 | 73.24 | 69.4% | 2.0% |
| Root Compare false, distributed; 1,000 calls | 9 | 105.00 | 115.47 | 70.54 | 61.1% | -10.0% |

## Normalized-root SDK variant

`normalized-root-1/2/3.json` supplies nine measured batches per endpoint.
The client Bind DN is `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`; this is an additional
client DN spelling, not a different account. Base is still the hot container,
and equality/Compare still use distributed UIDs. Results remain separate from
literal-root batches and the interleaved common-operation matrix.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Root Bind; 1,000 calls | 9 | 75.45 | 74.40 | 69.01 | 92.7% | 1.4% |
| Root Base, hot container; 1,000 calls | 9 | 101.91 | 102.51 | 84.46 | 82.4% | -0.6% |
| Root equality, distributed; 1,000 calls | 9 | 112.02 | 116.41 | 89.80 | 77.1% | -3.9% |
| Root Compare true, distributed; 1,000 calls | 9 | 109.15 | 110.73 | 76.54 | 69.1% | -1.4% |
| Root Compare false, distributed; 1,000 calls | 9 | 112.11 | 105.12 | 72.64 | 69.1% | 6.2% |

## Scans and CLI

Twenty-scan SDK rows use `probe-1/2/3.json`, nine batches per endpoint.
CLI timings are wall-clock milliseconds from `online/timings.tsv`, including
client startup/Bind. Full prefix has nine samples; other CLI rows have three.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Prefix substring scans; 20 scans | 9 | 931.43 | 973.28 | 624.07 | 64.1% | -4.5% |
| Negative substring scans; 20 scans | 9 | 920.02 | 937.92 | 640.83 | 68.3% | -1.9% |
| CLI full prefix, 100k returned | 9 | 663.00 | 675.00 | 620.00 | 91.9% | -1.8% |
| CLI indexed queries, 10,000 | 3 | 896.00 | 985.00 | 885.00 | 89.8% | -9.9% |
| CLI concurrent indexed, 8 x 1,000 | 3 | 286.00 | 451.00 | 322.00 | 71.4% | -57.7% |
| CLI paged traversal, 2 x 100k | 3 | 1406.00 | 1397.00 | 1231.00 | 88.1% | 0.6% |
| CLI negative unindexed equality, 10 | 3 | 263.00 | 264.00 | 434.00 | 164.4% | -0.4% |

## Read RSS

Median of three `rss_bytes` values per endpoint, recorded after the complete
read/authentication sequence, including both root-DN variants, before export.
These are process RSS observations, not query allocation or latency.

| RSS (bytes) | Before | Current | OpenLDAP |
| --- | ---: | ---: | ---: |
| Read/authentication | 437,059,584 | 431,603,712 | 100,270,080 |

## Extended-fixture diagnostics

Long-DN and long-password files remain separate from short-user and root
workloads. Each row retains all nine batches, including repeats 0, 1 and 2.

| Diagnostic fixture | Stage, 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| long-dn | User Bind, SSHA | 91.74 | 96.52 | 75.21 | 77.9% | -5.2% |
| long-dn | Wrong password | 90.85 | 99.53 | 75.32 | 75.7% | -9.6% |
| long-dn | Compare true | 112.60 | 121.24 | 78.97 | 65.1% | -7.7% |
| long-dn | Compare false | 110.09 | 116.82 | 81.39 | 69.7% | -6.1% |
| long-password | User Bind, SSHA | 96.03 | 94.54 | 82.57 | 87.3% | 1.5% |
| long-password | Wrong password | 90.92 | 87.48 | 85.47 | 97.7% | 3.8% |
| long-password | Compare true | 103.90 | 98.03 | 75.98 | 77.5% | 5.7% |
| long-password | Compare false | 101.22 | 108.29 | 70.77 | 65.4% | -7.0% |

## Evidence

[All 108 read median groups](read-medians.tsv) retain variant, stage,
operation count, endpoint and unit, including connect and 20-call root
diagnostics not used in the main 1,000-call tables. All 117 original JSON
files, including warmups, are in [online/](online/); warmups are excluded from
medians. [Validation](online/validation.tsv) records nine matching exports:
100,002 entries, checksum 2143929969 and 42,712,438 canonical bytes.

[Completion log](full-read.log.txt), [redacted replay](full-read.sh.txt).
The coordinator confirmed exit 0. Replay retains the persistent native
environment and existing fixture/probe paths, and requires the fixture
password through `LDAP_BENCH_PASSWORD`. No workloads were run for this report.
[Fixed-fixture writes](write-medians.tsv) remain separate; R2's parity goal remains active.

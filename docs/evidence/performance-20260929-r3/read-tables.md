# R3 broader-read tables

Before is baseline `a9de7d4`; current is the frozen R3 server. Three fresh
processes per endpoint run in rotating order. SDK rows use nine batches,
three per process. All samples remain; variants, stages, operation counts
and SDK/CLI methods are not pooled.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `a9de7d4`;
negative means slower. Ratios use unrounded medians. These shared-host
measurements do not establish causal or uniform gains or overall parity.

## Literal-root and short-user SDK

SSHA uses all `user-bind.json` measured repeats 0-2. Root rows use
`fast-1/2/3.json`, with client DN `cn=admin,dc=scale,dc=qualification`.
Base repeatedly reads the fixed `c.Base` container; equality and both Compare
stages use distributed UIDs across 100k, as recorded in the
[unchanged fast-probe source](../performance-20260929-r1/helpers/fast-probe.go.txt).

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA; 1,000 calls | 9 | 96.97 | 93.02 | 70.18 | 75.4% | 4.1% |
| Wrong password, SSHA; 1,000 calls | 9 | 91.04 | 87.53 | 70.98 | 81.1% | 3.9% |
| Root Bind; 1,000 calls | 9 | 70.33 | 69.61 | 64.30 | 92.4% | 1.0% |
| Root Base, hot container; 1,000 calls | 9 | 101.26 | 97.30 | 82.56 | 84.9% | 3.9% |
| Root equality, distributed; 1,000 calls | 9 | 107.74 | 108.08 | 88.00 | 81.4% | -0.3% |
| Root Compare true, distributed; 1,000 calls | 9 | 107.65 | 102.66 | 71.95 | 70.1% | 4.6% |
| Root Compare false, distributed; 1,000 calls | 9 | 106.98 | 98.74 | 70.23 | 71.1% | 7.7% |

## Uppercase-root serial variant

`normalized-root-1/2/3.json` uses client DN `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`
for the same account. Base remains the hot container and equality/Compare
remain distributed. These serial batches are separate from literal-root and
[interleaved paired-root results](root-paired-tables.md), whose observer and
fixture work differ.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Root Bind; 1,000 calls | 9 | 77.35 | 73.17 | 64.94 | 88.7% | 5.4% |
| Root Base, hot container; 1,000 calls | 9 | 110.48 | 106.78 | 82.70 | 77.5% | 3.3% |
| Root equality, distributed; 1,000 calls | 9 | 115.83 | 115.25 | 86.48 | 75.0% | 0.5% |
| Root Compare true, distributed; 1,000 calls | 9 | 124.46 | 111.15 | 69.80 | 62.8% | 10.7% |
| Root Compare false, distributed; 1,000 calls | 9 | 114.89 | 110.82 | 69.21 | 62.5% | 3.5% |

## Scans and CLI

Twenty-scan SDK rows use `probe-1/2/3.json`. CLI rows time wall-clock
execution, including client startup/Bind. Full prefix has nine batches;
other CLI rows have three.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Prefix substring scans; 20 scans | 9 | 939.26 | 919.73 | 622.27 | 67.7% | 2.1% |
| Negative substring scans; 20 scans | 9 | 930.25 | 915.91 | 621.13 | 67.8% | 1.5% |
| CLI full prefix, 100k returned | 9 | 638.00 | 627.00 | 591.00 | 94.3% | 1.7% |
| CLI indexed queries, 10,000 | 3 | 847.00 | 875.00 | 669.00 | 76.5% | -3.3% |
| CLI concurrent indexed, 8 x 1,000 | 3 | 297.00 | 307.00 | 306.00 | 99.7% | -3.4% |
| CLI paged traversal, 2 x 100k | 3 | 1290.00 | 1311.00 | 1125.00 | 85.8% | -1.6% |
| CLI negative unindexed equality, 10 | 3 | 249.00 | 241.00 | 382.00 | 158.5% | 3.2% |

## Read RSS

Median of three `rss_bytes` measurements after the complete read/authentication
sequence and before export. RSS is not sampled cumulative allocation or
per-operation memory. Current read RSS is 11.3% higher.

| RSS (bytes) | Before | Current | OpenLDAP |
| --- | ---: | ---: | ---: |
| Read/authentication | 434,356,224 | 483,229,696 | 151,601,152 |

## Extended-fixture diagnostics

Each row has nine batches; all repeats 0-2 are measured. Long-DN and
long-password variants remain separate from short-user and root workloads.

| Diagnostic fixture | Stage, 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| long-dn | User Bind, SSHA | 94.77 | 86.70 | 72.87 | 84.0% | 8.5% |
| long-dn | Wrong password | 95.84 | 90.49 | 74.22 | 82.0% | 5.6% |
| long-dn | Compare true | 114.90 | 110.14 | 74.58 | 67.7% | 4.1% |
| long-dn | Compare false | 108.44 | 104.69 | 75.14 | 71.8% | 3.5% |
| long-password | User Bind, SSHA | 87.21 | 86.81 | 71.38 | 82.2% | 0.5% |
| long-password | Wrong password | 87.71 | 86.54 | 70.13 | 81.0% | 1.3% |
| long-password | Compare true | 101.06 | 95.83 | 69.85 | 72.9% | 5.2% |
| long-password | Compare false | 104.71 | 101.13 | 74.15 | 73.3% | 3.4% |

## Evidence

[All 108 median groups](read-medians.tsv) retain variant, stage, count,
endpoint and unit, including connect and 20-call root diagnostics. All
117 JSONs, including excluded warmups, remain in [online/](online/).
[Validation](online/validation.tsv) records nine matching exports: 100,002
entries, checksum 2143929969 and 42,712,438 canonical bytes.

[Completion log](full-read.log.txt), [redacted replay](full-read.sh.txt).
The coordinator confirmed exit 0. Replay preserves the persistent native
environment and local fixture/probe dependencies; supply `LDAP_BENCH_PASSWORD`.
No new workload was run for these tables. The parity goal remains active.

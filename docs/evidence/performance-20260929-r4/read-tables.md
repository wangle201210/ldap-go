# R4 broader-read tables

Before is baseline `6f31d43`; current is the frozen R4 server. Three fresh
processes per endpoint run in rotating order. SDK rows use nine batches,
three per process. All samples remain; variants, stages, counts and SDK/CLI
methods are not pooled.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `6f31d43`;
negative means slower. Ratios use unrounded medians. Shared-host results
do not establish causality, uniform gains or overall parity.

## Literal-root and short-user SDK

SSHA uses all `user-bind.json` measured repeats 0-2. Root rows use
`fast-1/2/3.json`, with client DN `cn=admin,dc=scale,dc=qualification`.
Base repeatedly reads the fixed `c.Base` container; equality and both Compare
stages use distributed UIDs across 100k, as recorded in the
[unchanged fast-probe source](../performance-20260929-r1/helpers/fast-probe.go.txt).

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA; 1,000 calls | 9 | 100.93 | 88.74 | 71.81 | 80.9% | 12.1% |
| Wrong password, SSHA; 1,000 calls | 9 | 99.36 | 90.72 | 75.89 | 83.7% | 8.7% |
| Root Bind; 1,000 calls | 9 | 76.91 | 70.73 | 67.78 | 95.8% | 8.0% |
| Root Base, hot container; 1,000 calls | 9 | 102.63 | 102.29 | 82.94 | 81.1% | 0.3% |
| Root equality, distributed; 1,000 calls | 9 | 113.29 | 110.12 | 91.21 | 82.8% | 2.8% |
| Root Compare true, distributed; 1,000 calls | 9 | 110.00 | 103.53 | 70.18 | 67.8% | 5.9% |
| Root Compare false, distributed; 1,000 calls | 9 | 104.88 | 106.85 | 74.06 | 69.3% | -1.9% |

## Uppercase-root serial variant

`normalized-root-1/2/3.json` uses client DN `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`
for the same account. Base remains the hot container and equality/Compare
remain distributed. These serial batches are separate from literal-root and
[interleaved paired-root results](root-paired-tables.md), whose observer and
fixture work differ.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Root Bind; 1,000 calls | 9 | 74.41 | 72.96 | 67.22 | 92.1% | 2.0% |
| Root Base, hot container; 1,000 calls | 9 | 104.97 | 103.69 | 81.82 | 78.9% | 1.2% |
| Root equality, distributed; 1,000 calls | 9 | 112.27 | 111.03 | 88.27 | 79.5% | 1.1% |
| Root Compare true, distributed; 1,000 calls | 9 | 113.12 | 107.93 | 71.41 | 66.2% | 4.6% |
| Root Compare false, distributed; 1,000 calls | 9 | 114.89 | 108.58 | 70.16 | 64.6% | 5.5% |

## Scans and CLI

Twenty-scan SDK rows use `probe-1/2/3.json`. CLI rows time wall-clock execution,
including client startup/Bind. Full prefix has nine batches; other CLI rows three.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Prefix substring scans; 20 scans | 9 | 937.29 | 929.86 | 623.01 | 67.0% | 0.8% |
| Negative substring scans; 20 scans | 9 | 924.25 | 918.16 | 623.94 | 68.0% | 0.7% |
| CLI full prefix, 100k returned | 9 | 660.00 | 625.00 | 590.00 | 94.4% | 5.3% |
| CLI indexed queries, 10,000 | 3 | 865.00 | 831.00 | 692.00 | 83.3% | 3.9% |
| CLI concurrent indexed, 8 x 1,000 | 3 | 328.00 | 296.00 | 314.00 | 106.1% | 9.8% |
| CLI paged traversal, 2 x 100k | 3 | 1372.00 | 1296.00 | 1291.00 | 99.6% | 5.5% |
| CLI negative unindexed equality, 10 | 3 | 254.00 | 243.00 | 407.00 | 167.5% | 4.3% |

## Read RSS

Median of three `rss_bytes` measurements after the complete read/authentication
sequence and before export. Current read RSS is 1.5% lower. This is process
RSS, not sampled cumulative allocation or per-operation memory.

| RSS (bytes) | Before | Current | OpenLDAP |
| --- | ---: | ---: | ---: |
| Read/authentication | 434,585,600 | 428,130,304 | 100,270,080 |

## Extended-fixture diagnostics

Each row has nine batches; all repeats 0-2 are measured. Long-DN and
long-password variants remain separate from short-user and root workloads.

| Diagnostic fixture | Stage, 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| long-dn | User Bind, SSHA | 98.94 | 92.05 | 69.86 | 75.9% | 7.0% |
| long-dn | Wrong password | 98.24 | 91.34 | 74.05 | 81.1% | 7.0% |
| long-dn | Compare true | 112.20 | 107.50 | 78.23 | 72.8% | 4.2% |
| long-dn | Compare false | 124.30 | 107.84 | 77.28 | 71.7% | 13.2% |
| long-password | User Bind, SSHA | 89.56 | 89.37 | 73.89 | 82.7% | 0.2% |
| long-password | Wrong password | 86.83 | 89.88 | 73.73 | 82.0% | -3.5% |
| long-password | Compare true | 114.27 | 99.44 | 71.75 | 72.2% | 13.0% |
| long-password | Compare false | 119.26 | 101.43 | 75.55 | 74.5% | 15.0% |

## Evidence

[All 108 median groups](read-medians.tsv) retain variant, stage, count,
endpoint and unit, including connect and 20-call root diagnostics. All
117 JSONs, including excluded warmups, remain in [online/](online/).
[Validation](online/validation.tsv) records nine matching exports: 100,002
entries, checksum 2143929969 and 42,712,438 canonical bytes.

[Completion log](full-read.log.txt), [redacted replay](full-read.sh.txt).
The coordinator confirmed exit 0. Replay preserves the persistent native
environment and local dependencies; supply `LDAP_BENCH_PASSWORD`. No workloads
or profiles were run for these tables. The parity goal remains active.

# R3 interleaved root SDK tables

Before is baseline `a9de7d4`; current is the frozen R3 server. Each row is
the median of seven 1,000-call `total_ms` batches per endpoint. All samples
remain, grouped by exact client root DN, stage, method and endpoint. Smoke
and startup warmup records are retained but excluded from medians.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `a9de7d4`;
negative means slower. Ratios use unrounded medians; 0.0% denotes rounding,
not identical times. Mixed results do not establish uniform gains or parity.

## Literal root

Client DN: `cn=admin,dc=scale,dc=qualification`.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 82.82 | 88.21 | 82.85 | 93.9% | -6.5% |
| Root Base, hot container | 125.67 | 127.05 | 105.41 | 83.0% | -1.1% |
| Root equality, distributed | 150.09 | 150.02 | 119.15 | 79.4% | 0.0% |
| Root Compare true, distributed | 132.42 | 130.98 | 91.99 | 70.2% | 1.1% |
| Root Compare false, distributed | 140.07 | 137.48 | 94.61 | 68.8% | 1.8% |

## Uppercase root

Client DN: `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`. This is the same account
with a different client DN spelling; these samples are not pooled with literal root.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 106.00 | 104.89 | 98.91 | 94.3% | 1.0% |
| Root Base, hot container | 132.38 | 136.67 | 103.99 | 76.1% | -3.2% |
| Root equality, distributed | 130.78 | 124.69 | 99.32 | 79.7% | 4.6% |
| Root Compare true, distributed | 128.93 | 129.69 | 85.71 | 66.1% | -0.6% |
| Root Compare false, distributed | 143.67 | 142.90 | 97.22 | 68.0% | 0.5% |

## Method and validation

The [repository runner](../../../internal/cmd/ldapcommonbench/README.md#optional-root-sdk-stages)
rotates endpoints per request and follows each primary request with untimed
WhoAmI verification. Root Base reads the fixed base container; equality and
both Compare stages sample UIDs across the 100k range. The primary calls
match the old fast probe, but its serial sequence did not include WhoAmI
after every request. This runner also creates an isolated OU/eight-user
fixture and performs service Bind and cleanup. Those untimed operations
still add server work. Observer, fixture and execution-sequence differences
require keeping these results separate from serial full-read variants.

Both measured reports contain 105 successful samples, each with 1,000
attempted/completed/timed primary requests and 1,000 latency entries. The
seven-repeat sequence is complete for every method/endpoint. Each smoke
report has 15 successful samples of two calls. All four reports have empty
errors, 27 setup Adds and complete cleanup for before/current/OpenLDAP.

The coordinator confirmed exit 0. The [three exports](root-paired/validation.tsv)
match 100,002 entries, checksum 2143929969 and 42,712,438 canonical bytes.
These three exports remain separate from the common, full-read, original
fixed-write and larger write-recheck validation records.

[All 30 endpoint medians](root-paired-medians.tsv), [raw evidence](root-paired/),
[completion log](root-paired.log.txt), [redacted replay](root-paired.sh.txt),
[executable identities](executable-sha256.txt). No new workload was run for
this document. The overall parity goal remains active and unproven.

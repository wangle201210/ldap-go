# R4 interleaved root SDK tables

Before is baseline `6f31d43`; current is the frozen R4 server. Each row is
the median of seven 1,000-call `total_ms` batches per endpoint. All samples
remain, grouped by exact client root DN, stage, method and endpoint. Smoke
and startup warmup records are retained but excluded from medians.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `6f31d43`;
negative means slower. Ratios use unrounded medians. All small negative rows
remain. Component copy/allocation gains do not establish uniform SDK gains
or overall parity.

## Literal root

Client DN: `cn=admin,dc=scale,dc=qualification`.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 105.77 | 107.01 | 106.67 | 99.7% | -1.2% |
| Root Base, hot container | 156.71 | 143.61 | 117.02 | 81.5% | 8.4% |
| Root equality, distributed | 122.70 | 122.80 | 100.05 | 81.5% | -0.1% |
| Root Compare true, distributed | 120.12 | 120.93 | 82.47 | 68.2% | -0.7% |
| Root Compare false, distributed | 122.07 | 123.32 | 86.71 | 70.3% | -1.0% |

## Uppercase root

Client DN: `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`. This is the same account
with a different client DN spelling; these samples are not pooled with literal root.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 82.47 | 82.20 | 77.87 | 94.7% | 0.3% |
| Root Base, hot container | 117.27 | 117.58 | 95.97 | 81.6% | -0.3% |
| Root equality, distributed | 135.81 | 131.42 | 101.67 | 77.4% | 3.2% |
| Root Compare true, distributed | 143.54 | 142.55 | 94.73 | 66.5% | 0.7% |
| Root Compare false, distributed | 129.99 | 130.95 | 85.98 | 65.7% | -0.7% |

## Method and validation

The [repository runner](../../../internal/cmd/ldapcommonbench/README.md#optional-root-sdk-stages)
rotates endpoints per request and follows each primary request with untimed
WhoAmI verification. Root Base reads the fixed base container; equality and
both Compare stages sample UIDs across the 100k range. Primary calls match
the old fast probe, but that serial sequence lacked per-request WhoAmI.
This runner also creates an isolated OU/eight-user fixture and performs
service Bind and cleanup. Untimed operations still add server work. These
observer, fixture and sequence differences require keeping paired results
separate from serial full-read variants.

Each measured report contains 105 successful samples, each with 1,000
attempted/completed/timed primary requests and 1,000 latency entries. Every
method/endpoint has repeats 1-7. Each smoke report has 15 successful samples
of two calls. All four reports have empty errors, 27 setup Adds and complete
cleanup for before/current/OpenLDAP.

The coordinator confirmed exit 0. The [three exports](root-paired/validation.tsv)
match 100,002 entries, checksum 2143929969 and 42,712,438 canonical bytes.
They remain separate from the common and broader read/write export checks.

[All 30 endpoint medians](root-paired-medians.tsv), [raw evidence](root-paired/),
[completion log](root-paired.log.txt), [redacted replay](root-paired.sh.txt),
[executable identities](executable-sha256.txt). No workloads or profiles were
run for this document. The overall parity goal remains active and unproven.

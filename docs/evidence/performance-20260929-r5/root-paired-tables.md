# R5 standard interleaved root regression controls

Before is baseline `f78523a`; current is the frozen R5 server.

**These standard runs do not exercise the changed audit fast path.** Standard
launches provide no audit sink; without runtime accesslog, `newAuditObservation`
returns nil. Treat these rows as regression controls, not audit-optimization
or default-latency gains. The separate audit-enabled before/current run uses
a real file sink with HMAC and Sync; [completed A/B evidence](audited-paired-tables.md)
and the [same-binary A/A control](audited-aa-tables.md) remain separate. Neither
has a native comparison; do not pool these runs or infer a causal latency gain.
Broader read/write evidence remains historical R4 data, not remeasured R5
results; see the [conditional-change evidence scope](README.md#applicability-and-scope).

Each row below is the median of seven 1,000-call `total_ms` batches per
endpoint, retaining exact client root DN, stage, method and endpoint. All
samples remain; smoke and startup warmups are excluded. `Relative =
OpenLDAP/current * 100%`; `Time reduction = (1-current/before) * 100%`, versus
`f78523a`, with negative meaning slower. Ratios use unrounded medians.

## Literal root

Client DN: `cn=admin,dc=scale,dc=qualification`.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 74.58 | 75.14 | 72.20 | 96.1% | -0.8% |
| Root Base, hot container | 106.83 | 107.44 | 90.40 | 84.1% | -0.6% |
| Root equality, distributed | 113.70 | 115.90 | 94.75 | 81.8% | -1.9% |
| Root Compare true, distributed | 114.89 | 115.75 | 79.99 | 69.1% | -0.8% |
| Root Compare false, distributed | 112.99 | 113.03 | 78.63 | 69.6% | <0.1% slower |

## Uppercase root

Client DN: `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`, the same account with a
different client DN spelling. These samples remain separate from literal root.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 68.21 | 68.13 | 65.04 | 95.5% | 0.1% |
| Root Base, hot container | 95.95 | 95.38 | 78.45 | 82.3% | 0.6% |
| Root equality, distributed | 116.13 | 115.62 | 93.17 | 80.6% | 0.4% |
| Root Compare true, distributed | 117.81 | 118.77 | 77.13 | 64.9% | -0.8% |
| Root Compare false, distributed | 112.98 | 113.82 | 74.63 | 65.6% | -0.7% |

## Method and validation

The [repository runner](../../../internal/cmd/ldapcommonbench/README.md#optional-root-sdk-stages)
rotates per request and performs untimed WhoAmI after every primary call.
Root Base reads the fixed container; equality/Compare use distributed UIDs.
The serial fast probe lacks this per-request observer. This runner also
creates an OU/eight-user fixture and performs service Bind and cleanup.
Untimed work still loads the server; observer, fixture and sequence differences
prevent replacing or pooling serial and paired measurements.

Each measured report has 105 successful samples, 1,000 attempted/completed/
timed primary calls and latency entries per sample, and complete repeats 1-7.
Each smoke report has 15 successful samples of two calls. All reports have
empty errors, 27 setup Adds and cleanup for all three endpoints.

The coordinator confirmed exit 0. [Three exports](root-paired/validation.tsv)
match 100,002 entries, checksum 2143929969 and 42,712,438 canonical bytes.
[All 30 endpoint medians](root-paired-medians.tsv), [raw records](root-paired/),
[completion log](root-paired.log.txt), [replay](root-paired.sh.txt),
[executable identities](executable-sha256.txt). No workloads or profiles
were run for these tables; the overall parity goal remains active and unproven.

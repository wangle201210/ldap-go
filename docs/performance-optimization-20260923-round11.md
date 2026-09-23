# Long Bind/Compare decoding and direct error responses

Baseline: `4a990fd`. This continues the
[common-operation investigation](performance-optimization-20260923-round10.md).
All Go builds, tests and benchmarks use `CGO_ENABLED=0`.

## Changes

Simple Bind and Compare requests without controls now use the existing direct
decoder for minimal definite long-form lengths as well as short-form lengths.
This avoids constructing a BER packet tree for longer DNs, passwords and
assertion values. Lengths are checked as unsigned values against the enclosing
slice before conversion to `int`. Request limits, nesting limits, owned field
copies and filter-depth provider calls remain unchanged. SASL, controls,
nonminimal lengths and unsupported shapes retain the original BER decoder and
its errors. Search decoding and transport reads are unchanged.

LDAP results with nonnegative IDs/codes, ordinary application tags and no
controls or referrals encode their complete BER message directly. Matched DN
and diagnostic bytes, integer sign padding and output ownership are preserved.
Negative IDs/codes, high tags, referrals and controls keep the packet encoder.
The existing success/Compare response optimization predates this round.

A connection-read-buffer prototype was measured and removed because its
end-to-end results were mixed. Its samples are retained separately as
[discarded prototype evidence](evidence/performance-20260923-round11/buffer-prototype-timings.json);
they do not describe the final implementation.

## Component Results

Three 300ms samples, medians. These are encoding costs, not request latency:

| Component | Old packet path | Current | Allocations before / current |
| --- | ---: | ---: | ---: |
| Invalid credentials, empty fields | 923.2 ns | 38.17 ns | 41 / 1 |
| Bind error with diagnostic | 943.8 ns | 42.77 ns | 42 / 1 |
| Controlled error, fallback | 1,562 ns | 1,591 ns | 69 / 69 |

The small fallback timing increase is retained. The raw benchmark also contains
Compare's packet-reference comparison, which is not a new optimization.
[Raw encoding samples](evidence/performance-20260923-round11/encode-bench.txt).

Direct decoding is compared with the generic packet decoder using the same
encoded input, including outer framing and owned request fields:

| Decode fixture | Packet reference | Current | Bytes before / current | Allocations before / current |
| --- | ---: | ---: | ---: | ---: |
| Bind, 256-byte password | 2,402 ns | 237.0 ns | 5,448 / 656 | 79 / 6 |
| Compare, 256-byte assertion | 2,879 ns | 244.4 ns | 6,576 / 624 | 98 / 7 |
| Bind, long DN | 2,510 ns | 242.3 ns | 5,696 / 520 | 82 / 7 |
| Compare, long DN | 2,894 ns | 521.0 ns | 6,312 / 488 | 95 / 8 |
| Long Bind with controls, fallback | 4,332 ns | 5,021 ns | 9,392 / 9,392 | 140 / 140 |

The packet reference does not include the direct-path recognition attempt, so
its controlled-request cost is not an exact before/current comparison. The
fallback overhead and shared-host timing variability are retained rather than
discarded. Short-request packet-reference gains in the raw output predate this
round. [Raw decoding samples](evidence/performance-20260923-round11/decode-bench.txt).

An exact baseline-decoder overlay, changing only the private function name to
match the current test callsite, gives 2,273 / 223.3 ns for long-password Bind
and 2,732 / 216.8 ns for long-assertion Compare before/current. Short Bind changes
136.0 / 142.9 ns and short Compare 136.7 / 139.4 ns, with unchanged allocation
counts. One controlled-request batch stalled to 17,966 ns, so that path was
rechecked alone rather than attributing the stall to the decoder.

Five 500ms controlled-request samples, current first and baseline second, give
medians **3,808 / 3,819 ns**, with the same **9,392 bytes / 140 allocations**.
The recognizer alone costs **14.71 / 2.536 ns**, both allocation-free: supporting
long lengths adds roughly 12 ns when rejecting a long controlled request.
The full fallback slowdown did not reproduce; this does not claim zero added
recognition work. All earlier samples remain available.
[Baseline](evidence/performance-20260923-round11/decode-baseline-bench.txt),
[current](evidence/performance-20260923-round11/decode-current-recheck.txt),
[controlled current](evidence/performance-20260923-round11/controlled-current-final.txt),
[controlled baseline](evidence/performance-20260923-round11/controlled-baseline-final.txt),
[baseline decoder source](evidence/performance-20260923-round11/decode-bind-before.go.txt).

## Method

The online replay copies the same 100k fixture used in round 10. Before/current/
native run in rotating order, with three fresh processes each and three batches
per process. Ordinary Bind and short queries use 1,000 operations per batch;
scan queries use 20. Additional temporary users exercise a 202-byte DN or a
256-byte SSHA password. Each batch checks every Bind/Compare result and checks
the bound identity after authentication. User creation, identity checks and
cleanup are outside the measured batches.

The long-DN fixture also has a long uid assertion; the long-password fixture's
matching Compare is short. Both fixtures use a 256-byte nonmatching Compare
assertion. Wrong-password Bind deliberately uses a short wrong password, so
that request has long-form BER only in the long-DN fixture. These variants must
not be treated as equivalent decoder workloads.

All temporary users are deleted before full ordinary-attribute exports are
canonicalized and compared. Existing indexes, password hashes/work factors,
durability configuration, ACL and server limits are unchanged. Benchmarks run
without concurrent builds or tests. Source snapshots are not modified.

An initial 294-byte-DN fixture had a single RDN too large for the native MDB
dn2id duplicate value and failed during Add with `MDB_BAD_VALSIZE`/LDAP 80.
That incomplete replay is excluded as a whole. The smaller 202-byte-DN fixture
passed native create/Bind/Compare/delete checks before the complete replay was
restarted. This is a fixture correction, not a server limit change.
[Native diagnostic](evidence/performance-20260923-round11/native-oversized-rdn.txt).

## Validation

The final [full Go suite](evidence/performance-20260923-round11/go-test.txt),
[vet](evidence/performance-20260923-round11/go-vet.txt) and
[200 native differential checks, including subtests](evidence/performance-20260923-round11/openldap-differential.txt)
passed, with no skips in the native selection. Decoder tests compare results,
errors, sizes, provider calls and ownership with the original packet decoder;
they cover short/long transitions through 64 KiB, inner truncation, nonminimal
and indefinite lengths, oversized 1-8-octet declarations, controls and SASL.
Encoder tests compare complete response bytes across result/ID/sign/length
boundaries, binary strings, referrals and controls.

[Additional transport checks](evidence/performance-20260923-round11/openldap-transports-patched.txt)
passed 12 checks including subtests. DIGEST-MD5 3DES checks use the existing
locally parity-repaired Cyrus 2.1.28 with unmodified OpenLDAP 2.6.13. The ordinary
native provider crashed in its own 3DES self-check during the discarded
prototype investigation; the same failure was reproduced against the baseline.
This is not an unmodified-Cyrus 3DES success claim. Prototype-specific evidence
is named `buffer-prototype-*` and does not validate the final implementation.

The component benchmarks can be rerun from this checkout:

```sh
CGO_ENABLED=0 go test ./internal/ldapwire -run '^$' \
  -bench '^BenchmarkReadBindCompareMessage(PacketReference)?$/^(LongBind|LongCompare|LongDNBind|LongDNCompare|LongBindControls)$' \
  -benchtime=300ms -count=3 -benchmem
CGO_ENABLED=0 go test ./internal/ldapwire -run '^$' \
  -bench '^BenchmarkEncodeGeneralizedResultResponse$/^(InvalidCredentials|BindDiagnostic|ControlFallback)$' \
  -benchtime=300ms -count=3 -benchmem
```

## Online Results

The complete nine-process replay passed all SDK assertions and full ordinary-
attribute export comparisons: 100,002 entries, 42,712,438 canonical bytes,
POSIX checksum `2143929969`. All samples are retained, including stalls.
Values below are batch-time medians. Relative performance is
`OpenLDAP / current * 100%`; larger is better.

| Stage, 1,000 operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 132.03 ms | 140.50 ms | 65.34 ms | +6.4% | 46.5% |
| User Bind, wrong password | 131.40 ms | 129.17 ms | 72.12 ms | -1.7% | 55.8% |
| Root Bind | 99.20 ms | 100.74 ms | 65.67 ms | +1.6% | 65.2% |
| Base search | 110.90 ms | 119.92 ms | 84.65 ms | +8.1% | 70.6% |
| Indexed equality | 113.65 ms | 129.43 ms | 88.44 ms | +13.9% | 68.3% |
| Compare true | 117.18 ms | 125.69 ms | 68.90 ms | +7.3% | 54.8% |
| Compare false | 106.59 ms | 120.96 ms | 71.07 ms | +13.5% | 58.8% |

| Workload | Before | Current | OpenLDAP |
| --- | ---: | ---: | ---: |
| Prefix substring, 20 | 1,144.93 ms | 1,112.34 ms | 621.19 ms |
| Negative substring, 20 | 1,112.83 ms | 1,108.70 ms | 621.08 ms |
| Full prefix, 100k returned | 620 ms | 597 ms | 526 ms |
| Indexed CLI searches, 10,000 | 786 ms | 970 ms | 711 ms |
| Concurrent indexed, 8 x 1,000 | 194 ms | 264 ms | 220 ms |
| Paged traversal, 2 x 100k | 1,151 ms | 1,258 ms | 1,104 ms |
| Unindexed negative equality, 10 | 208 ms | 211 ms | 345 ms |

The initial replay does not demonstrate an end-to-end improvement. Some
current batches stalled to 300-487 ms while other batches of the same workload
took 100-130 ms. Before and native also have outliers. The apparent regressions
must be checked rather than dismissed as noise or removed from the evidence.
The interleaved recheck below did not reproduce those large regressions.

Read/auth RSS medians were 404.9 / 414.9 / 95.4 MiB before/current/native.
This round includes additional temporary-user creation and authentication;
its memory figures are not directly interchangeable with round 10's workload.
[Short-operation samples](evidence/performance-20260923-round11/long-timings.json),
[extended requests](evidence/performance-20260923-round11/extended-timings.json),
[scan samples](evidence/performance-20260923-round11/sdk-timings.json),
[traversal samples](evidence/performance-20260923-round11/online-timings.tsv),
[export/RSS checks](evidence/performance-20260923-round11/sdk-validation.tsv).

## Interleaved Recheck

One warmed process per implementation was kept resident simultaneously, with
only one client workload active at a time. Each workload was sent to the three
implementations in rotating order over three rounds, with three batches per
round. Batches increased to 3,000 operations. This reduces temporal separation
between versions; it does not reproduce the original isolated-process memory
conditions or establish independence across nine fresh processes. Medians use
all nine batches per metric, without removing any outliers.

| Stage, 3,000 operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 371.45 ms | 360.74 ms | 200.82 ms | -2.9% | 55.7% |
| User Bind, wrong password | 372.19 ms | 362.83 ms | 202.75 ms | -2.5% | 55.9% |
| Root Bind | 258.38 ms | 254.80 ms | 191.71 ms | -1.4% | 75.2% |
| Base search | 287.48 ms | 287.94 ms | 239.10 ms | +0.2% | 83.0% |
| Indexed equality | 308.10 ms | 306.60 ms | 249.43 ms | -0.5% | 81.4% |
| Compare true | 299.94 ms | 302.24 ms | 199.92 ms | +0.8% | 66.1% |
| Compare false | 301.57 ms | 304.27 ms | 195.56 ms | +0.9% | 64.3% |

| Extended stage, 3,000 operations | Before | Current | OpenLDAP | Time change |
| --- | ---: | ---: | ---: | ---: |
| Long DN, successful Bind | 437.01 ms | 418.32 ms | 199.29 ms | -4.3% |
| Long DN, wrong password | 435.57 ms | 411.88 ms | 205.33 ms | -5.4% |
| Long DN, matching Compare | 336.02 ms | 315.09 ms | 208.81 ms | -6.2% |
| Long DN, nonmatching Compare | 337.92 ms | 323.10 ms | 208.85 ms | -4.4% |
| Long password, successful Bind | 379.74 ms | 374.23 ms | 201.85 ms | -1.5% |
| Long password fixture, short wrong password | 363.18 ms | 363.42 ms | 201.49 ms | +0.1% |
| Long password fixture, short matching Compare | 290.19 ms | 299.13 ms | 196.88 ms | +3.1% |
| Long password fixture, long nonmatching Compare | 316.40 ms | 310.06 ms | 204.67 ms | -2.0% |

The larger initial regressions were not reproduced. Ordinary search/Compare
changes are around 1% in this recheck and are not claimed as improvements.
Long-DN requests show a modest 4-6% reduction here, much smaller than the isolated
decoder improvement. The +3.1% short Compare result is retained; the two sets
do not prove a blanket no-regression guarantee across workloads or hosts.
Protocol allocations are reliably reduced; overall OpenLDAP parity is not
achieved. Authentication, substring scans and memory remain meaningful gaps.

All three final ordinary-attribute exports match both each other and the
initial replay's canonical data. Across the read, write and interleaved runs,
21 complete export comparisons passed.
[Short-operation samples](evidence/performance-20260923-round11/interleaved-timings.json),
[extended samples](evidence/performance-20260923-round11/interleaved-extended-timings.json),
[export checks](evidence/performance-20260923-round11/interleaved-validation.tsv).

## Write Regression

The separate write replay used three fresh processes per implementation, in
rotating order, with 20 entries per stage. Setup, verification and cleanup are
outside each measured stage. All nine runs passed SDK checks and the same full
canonical export comparison.

| Twenty operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Add | 19.88 ms | 15.51 ms | 97.49 ms | -22.0% | 628.6% |
| Modify, unindexed description | 8.71 ms | 8.45 ms | 94.64 ms | -3.0% | 1,119.6% |
| ModifyDN | 25.96 ms | 27.36 ms | 89.73 ms | +5.4% | 328.0% |
| Delete | 20.49 ms | 18.35 ms | 88.51 ms | -10.5% | 482.5% |

Successful write responses already used direct encoding. These timings are
regression observations, not an attributable write-path speedup. Small serial
leaf writes under the existing durability settings do not represent every
production workload. Write RSS medians were 348.0 / 346.7 / 135.2 MiB.
[Samples](evidence/performance-20260923-round11/write-timings.json),
[export/RSS checks](evidence/performance-20260923-round11/write-validation.tsv).

## Reproduction Artifacts

Accepted binaries, SHA-256:

```text
before  272d069355ab4eed62b04052399d3a32e839be30faff0ea0d4a63a9807f24b04
current 7d39057484e2849576dba6abe8d075460d483d0c5f81d1d5173f375742af113f
```

Both use Go 1.26.4, darwin/arm64 and `CGO_ENABLED=0`. Their dependencies and
build settings match. The baseline is clean `4a990fd`; current adds this round's
protocol changes. Exact local replay artifacts are under
`/var/tmp/ldap-go-perf-round14-20260923`. Disposable servers are stopped and
their database copies removed after validation; source snapshots are unchanged.

The [read replay](evidence/performance-20260923-round11/replay.sh.txt),
[write replay](evidence/performance-20260923-round11/write-replay.sh.txt),
[interleaved recheck](evidence/performance-20260923-round11/interleaved.sh.txt),
[extended SDK probe](evidence/performance-20260923-round11/extended-probe.go.txt)
and [sample summarizer](evidence/performance-20260923-round11/summarize.mjs)
retain the exact local invocation and fixture paths. They require the existing
100k qualification snapshots and compiled probes; they are not portable setup
scripts. For fresh environments, start with the repository's
[comparison runner](../scripts/qualification/compare-openldap.sh) and
[100k reproduction documentation](openldap-100k-evidence.md#reproduction-and-limits).

# R6 common-operation evidence

Source: `/var/tmp/ldap-go-common-perf-20260924-r6`. Baseline: `49af259`.
The [current report](../../common-ldap-performance.md) interprets this run;
the [R5 archive](../../common-ldap-performance-20260924-r5.md) preserves the
previous report unchanged. The OpenLDAP parity goal remains unachieved.

## Main measurements and rechecks

`explicit-final/` and `default-final/` contain byte-for-byte copies of
`hot.json`, `distributed.json`, `groups.json`, `smoke.json`,
`concurrent.tsv` and `validation.tsv`. Main SDK medians use three repeats.
The four `common-*.sh.txt` / `common-*.log.txt` files preserve replay and
completion evidence; only the `.txt` suffix was added.

`default-recheck/recheck.json` is a separate seven-repeat Bind/wrong-password
run, with SSHA and plaintext methods kept separate. SSHA Bind medians are
91.22 / 90.35 / 71.21 ms (before/current/native). The original
123.72 / 131.94 / 106.12 ms result, with current 6.6% slower, remains in the
main report and raw data. That regression was not reproduced; no stable Bind
gain is claimed.

`explicit-recheck/recheck.json` is a completed seven-repeat group-Base run.
For 10 members its medians are 13.52 / 14.06 / 9.96 ms; current remains 4.0%
slower, with mixed paired signs. For 1,000 members they are
97.46 / 96.94 / 90.40 ms. The original 112.73 / 120.69 / 103.01 ms
result, with current 7.1% slower, remains. The large-group regression was not
reproduced, but the recheck's 0.5% reduction is not a stable speedup claim.

Both rechecks retain their scripts, successful completion logs and export
validation. All **12 exports** match **100,002 entries**, POSIX checksum
`2143929969` and **42,712,438 canonical bytes**. No main or recheck sample
was removed, replaced or pooled across runs.

## Calculations

`medians.tsv` has 90 endpoint groups: 72 main, 12 default-Bind recheck and six
explicit-group recheck. Keys are run, batch, stage, method, member count and
endpoint. Each group has its complete repeat sequence, fixed operation/request
counts and `completed == operations`. SSHA/plaintext and 10/1,000-member rows
are separate. Smoke and profiling runs are excluded.

Medians use `total_ms`; no measured outlier is discarded.
Relative performance is `openldap / current * 100`.
Time reduction is `(1 - current / before) * 100`; negatives are retained.
Ratios use unrounded medians. TSV values retain nine decimal places; report
times use two and percentages one. Nested membership is 100 traversals and
417 timed SDK searches per batch.

The root-bound concurrent CLI checks remain in raw TSVs, separate from SDK
timing. Eight clients each issue 1,000 UID queries. Repeat 0 is warmup; measured
repeats 1-3 give before/current/native medians of 267/229/256 ms with explicit
ACLs and 197/228/221 ms with default access. The default 15.7% slowdown is retained.
These are not non-root throughput or uniform-speedup claims.

## Profiles

`profile/` contains the existing before/current CPU and warm/measured heap
profiles, SDK JSONs, completion logs, overlay and helper source. The helper is
stored as `profile_test.go.txt`, outside active Go test sources; the overlay
retains its original absolute paths.

`query-alloc-before.txt` and `query-alloc-current.txt` are unchanged copies of
the coordinator's focused `alloc_space` reports, subtracting each warm heap
profile from its measured heap profile and focusing `trySmallNonRootSearch`.
Both runs use the same SDK `memberEquality` workload with 10 warmup and
10,000 measured queries. Focused cumulative allocation is **626.84 MiB before
and 267.03 MiB current**, a **57.4% reduction**. pprof prints `MB` for these
binary-megabyte units; the report labels them MiB.

The full harness includes Add and WhoAmI setup/verification work.
Whole-process allocation, CPU percentages and profile-run timings are not
query-only evidence or paired latency results. The claim is restricted to the
focused sampled allocation. No new component benchmark was run for R6.

## Validation and diagnostics

`go-test-accepted.txt`, `go-vet-accepted.txt` and
`openldap-differential-accepted.txt` are the final successful validation logs.
The coordinator confirmed exit status 0 after source/test freeze. Go ran with
`CGO_ENABLED=0`; some package results are cached. Vet's empty file is expected.
The native log has 355 PASS records, no failures/skips and terminal PASS.

`diagnostics/` preserves earlier full-suite attempts, vet/native logs and
focused existing pool/search checks. `go-test.txt` and `go-test-final.txt`
are failed runs against in-progress test fixtures, including the corrected
invalid-UTF-8 rejection expectation. They are not accepted validation results.
No failed log has been relabeled as passing.

The bounded idle decoder pool retains no entry/payload references; DN assertion
reuse preserves per-call syntax/length validation and custom callback fallback.
Authorization/password/snapshot checks remain. The R2 operational-attribute gap,
including root reads and types-only output, remains outside the passing matrix.
No tests, builds or benchmarks were run to prepare this documentation.

## Executable identity

SHA-256 supplied by the coordinator and independently verified against the files:

```text
before (49af259)  dacceacf149cd9e8789790ee631bca362f6f6d1d8011f4b4e1e0f4c27b5735df
current           f65475df23fa7fa127f688dd6ee475263fdf978af437efecb9a5f009509a46e2
```

The final and recheck JSON endpoint `current` maps to the R6 executable named
`current`. `before` is the R5 final executable. Final endpoint measurements
ran in a quiet window after accepted validation and profiling, as confirmed by
the coordinator. No further profiling or benchmark is planned for this checkpoint.

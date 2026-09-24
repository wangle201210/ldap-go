# R5 common-operation evidence

Source: `/var/tmp/ldap-go-common-perf-20260924-r5`. Baseline: `b7e6cc1`.
The [report](../../common-ldap-performance-20260924-r5.md) and
[R4 archive](../../common-ldap-performance-20260924-r4.md) retain interpretation
and historical limitations.

## Final measurements

`explicit-final/` and `default-final/` contain unchanged copies of `hot.json`,
`distributed.json`, `groups.json`, `smoke.json`, `concurrent.tsv` and
`validation.tsv`. The `final-*.sh.txt` and `final-*.log.txt` files preserve replay
scripts and completion logs; only the `.txt` suffix was added. Their JSON
`current` endpoint uses the `final` executable.

`explicit-distributed-recheck/` is a separate seven-repeat run, with its own
replay/log. It does not replace or pool with the original three-repeat equality
result, including the observed regression. All six final exports and three
distributed-recheck exports match 100,002 entries, checksum `2143929969`,
42,712,438 bytes.

`concurrent-recheck/` and `recheck-concurrent.sh.txt`/`.log.txt` preserve a separate
seven-measured-batch explicit-ACL check on fresh servers after normal warmup,
without a preceding group fixture. The same eight clients each issue 1,000 UID
queries, all checked. Excluding repeat 0, before/current/native medians are
292/276/259 ms, with ranges 195-419/196-568/203-355 ms. Its three exports also
match the values above. The original 191/223/214 ms concurrent row remains;
neither run is replaced or pooled, and no stable speedup is claimed.

## Calculations

`medians.tsv` retains 174 endpoint groups from final, recheck and diagnostic
runs. Group keys are run, batch, stage, method, member count and endpoint.
Each group contains the complete repeat sequence, with matching operation and
request counts across endpoints and `completed == operations`. SSHA/plaintext
and 10/1,000-member measurements remain separate. Smoke is excluded.

Medians use `total_ms`; no measured outlier is discarded. Relative performance
is `openldap / current * 100`; time reduction is `(1 - current / before) * 100`.
Ratios use unrounded values. TSV values retain nine decimals; report milliseconds
use two and percentages one. Nested membership is 100 traversals and 417 timed
SDK searches per batch. Concurrent medians exclude warmup repeat 0: three
measured batches in the original runs, seven in the dedicated recheck. The
174-row TSV covers SDK samples; concurrent results remain in their raw TSVs.

## Validation and components

`go-test-optimized.txt`, `go-vet-optimized.txt` and
`openldap-differential-optimized.txt` are the final successful validation logs.
The coordinator confirmed exit status 0; vet is empty. Native output has 355
PASS records, no failures/skips and terminal PASS. `component-bench.txt` is
complete with terminal PASS; its local allocation measurements are not wire
latency claims. No new tests, builds or benchmarks were run to prepare these docs.

## Diagnostics

`diagnostics/{explicit,default}-experiment/` preserves all four-endpoint raw
measurements. Their `current` means the rejected buffer prototype; `projection`
is the earlier projection-only build, not the final R5 implementation.
Replay scripts/logs and the projection overlay are retained alongside them.
`diagnostics/discarded-buffer/*.go.txt` preserves the removed prototype and test
snapshots as text, outside production and active test sources.

Earlier test logs, buffer checks and Web Admin baseline/recheck failures remain
diagnostics. The Web Admin fixture failed on pristine baseline at count 100;
the expired-parent-context fixture passed count 100. No Web production logic
changed. The R2 operational-attribute gaps remain limitations.

## Executable identity

SHA-256 verified against the supplied files and the coordinator's values:

```text
before (b7e6cc1)  bf22f861ebe6a5e2eebfaea08bf11ed42f3acee4c9cf997760d3747786e322c4
final             dacceacf149cd9e8789790ee631bca362f6f6d1d8011f4b4e1e0f4c27b5735df
```

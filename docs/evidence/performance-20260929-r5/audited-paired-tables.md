# R5 audit-enabled A/B production-path evidence

Before is baseline `f78523a`; current is the frozen R5 binary. Both Go servers
enable a real file AuditSink with HMAC and Sync through `-audit-log`, separate
files, and an environment key. This exercises the conditional audit observer;
the standard unaudited matrices remain regression controls. No OpenLDAP
comparator is included because audit semantics are not comparable.

Each row is the median of five batches of 200 primary SDK calls per endpoint.
The runner rotates requests and performs exact response/WhoAmI verification
outside the SDK timer. Keep the exact client DN, method, counts and audit mode
separate. `Time reduction = (1-current/before) * 100%` versus `f78523a`;
negative means slower. All samples and outliers remain.

**Large uppercase regressions are retained.** Base is 112.5% slower, equality
160.1% slower, true Compare 210.0% slower, and false Compare 279.3% slower.
File Sync behavior and shared-host conditions do not establish causality or
justify dismissing these results. The completed [same-binary A/A control](audited-aa-tables.md)
uses 100 calls and three repeats, labeled A1/A2. Its large timing variation
limits A/B interpretation; it is a noise control, not speedup evidence.
Different batch counts prevent absolute A/B-to-A/A comparison or pooling.
No causal code effect or uniform latency gain is established.

## Literal root

Client DN: `cn=admin,dc=scale,dc=qualification`.

| 200 primary calls | Before (ms) | Current (ms) | Time reduction |
| --- | ---: | ---: | ---: |
| Root Bind | 726.66 | 714.88 | 1.6% |
| Root Base, hot container | 853.74 | 891.08 | -4.4% |
| Root equality, distributed | 1135.76 | 765.52 | 32.6% |
| Root Compare true, distributed | 1139.79 | 779.33 | 31.6% |
| Root Compare false, distributed | 1014.05 | 953.94 | 5.9% |

## Uppercase root

Client DN: `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`.

| 200 primary calls | Before (ms) | Current (ms) | Time reduction |
| --- | ---: | ---: | ---: |
| Root Bind | 648.43 | 668.95 | -3.2% |
| Root Base, hot container | 564.43 | 1199.37 | -112.5% |
| Root equality, distributed | 470.66 | 1224.42 | -160.1% |
| Root Compare true, distributed | 429.38 | 1331.13 | -210.0% |
| Root Compare false, distributed | 369.32 | 1400.79 | -279.3% |

## Verification and retained events

The coordinator confirmed exit 0. Each measured case has 50 samples: five
stages, two endpoints and five repeats; every sample completed 200 primary
calls. Both smoke reports have ten samples of two calls. All four reports
have empty errors, 18 setup Adds and both endpoint cleanups complete.

After server shutdown, both audit logs verified **20,294 records**. Comparing
each record's event after dropping only `timestamp`, `connection_id`,
`message_id`, `remote_address` and `duration_micros` produces **900 identical
semantic groups and counts**. [Canonical event counts](audited-paired/audit-semantic-counts.json)
retain every remaining event field. [Verification summary and raw-log hashes](audit-validation.json)
and per-endpoint integrity-verification logs are archived. Raw audit logs and
audit keys are not archived.

[Two exports](audited-paired/validation.tsv) match 100,002 entries, checksum
2143929969 and 42,712,438 canonical bytes. Together with the nine standard
control exports and two A/A exports, R5 has 13 matching export records.

[All 20 endpoint medians](audited-paired-medians.tsv),
[raw probes and verification](audited-paired/), [completion log](audited-paired.log.txt),
[replay](audited-paired.sh.txt), [frozen executable hashes](executable-sha256.txt).
Replay requires the fixture password and `LDAP_PERF_AUDIT_KEY` externally;
the audit key is passed through `LDAP_GO_AUDIT_KEY`. No workload or audit
verification command was run by documentation preparation.

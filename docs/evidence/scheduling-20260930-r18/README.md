# R18 Scheduling Diagnostic

This is a separate same-binary diagnostic, not R19 qualification or a project
default change. All three Go endpoints ran frozen R18 source `8918569`, binary
SHA256 `5546307a886f3b507e8f418eebeab0e020d074a1a49cea476fc66f657c3c6370`.
Only server GOMAXPROCS differed. Actual process identities and input hashes are
retained. OpenLDAP 2.6.13 was the fourth endpoint; all used private 100k fixtures.

Seven batches of 1,000 SDK operations, median total milliseconds:

| Operation | Go 2 | Go 4 | Go 8 | OpenLDAP |
| --- | ---: | ---: | ---: | ---: |
| Correct SSHA Bind | 90.423 | 90.966 | 89.908 | 72.339 |
| Correct plaintext Bind | 94.492 | 92.618 | 92.695 | 74.911 |
| Wrong SSHA Bind | 88.317 | 87.159 | 86.000 | 70.549 |
| Wrong plaintext Bind | 91.330 | 89.701 | 89.539 | 71.714 |
| Non-root Base | 101.445 | 101.847 | 101.814 | 82.126 |
| Non-root equality | 107.583 | 105.982 | 106.813 | 85.612 |

Separate root equality throughput uses eight ldapsearch clients, 1,000 queries
each, one excluded warmup and three measured batches with rotating endpoint
order. Median throughput is 27,307 / 26,729 / 27,523 / 24,462 queries/s for
Go 2 / Go 4 / Go 8 / OpenLDAP. It does not offset single-connection latency gaps.

The lower parallelism settings did not remove the latency gap or consistently
win across workloads. Project defaults were not changed. No universal tuning,
statistical-significance or causal conclusion is claimed. Client settings are
recorded in runtime.tsv; server parallelism and launch order are in endpoints.tsv.
Warmups, fixture setup and verification are excluded from SDK timing.

All four exports matched 100,002 entries, cksum 2143929969, 42,712,438 bytes and
SHA256 `5dbd9fc0096a98c9a4818972cbc612fb1af150c581c930c604123854549852a0`.
All task-created processes and private databases/password files were cleaned up.
Raw JSON, throughput rows, validation and the exact script are retained; no
database, LDIF, canonical contents, executable or password is bundled.

Shared-host variation, APFS COW, fixed startup order and warm caches remain
limitations. This archive must not be pooled with before/current qualification.

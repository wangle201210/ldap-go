# R25 deferred borrowing checks: not adopted

Production baseline is `47f5bad`, whose server logic remains R22. The private
candidate is `160724e`, based on the unshipped direct-Get lease prototype
`c4e5dd3`, in `/var/tmp/ldap-go-direct-get-20260930`.

The source reconstruction includes the explicit lease and the deferred pure
eligibility check. Ordinary Get stays owned. Borrowing remains limited to
eligible binary rows of at least 8 KiB, 64 attributes and 4096 total values
within one read-only View. Source identity, normalization, migration/context
checks, lookup, decoding, ACL and response ordering remain authoritative.

The first deferred-check prototype stored a closure on the lease, adding 48 B
and one allocation per call. `stored-check.patch` and `group-*` logs preserve
that rejected version. The final API passes its check synchronously through
concrete calls and never retains it. Component observations are in `transient-*`;
Small10 allocation counts match baseline, and Group1000 bytes fall from about
82 KiB to 8 KiB per operation. This does not establish network parity.

Three primary runs validate 756 batches and nine exports. Two explicit-ACL
calibrations add 504 batches and six exports. Each export matches 100002
canonical user-data entries, cksum 2143929969 and 42712438 bytes. Generated
operational attributes and physical MDB layout are not compared.

Primary Small10 explicit-ACL first/last/missing are 2.7%/2.4%/3.0% slower.
The identical-candidate A/A run changes those rows by +1.1%/+0.4%/-0.2%, while
SSHA Bind is 1.3% slower under the current label. Actual A/B explicit startup/
port swap changes Small10 by -1.9%/-0.2%/-0.3%, Group1000 by +3.7%/+2.0%/+3.3%,
and leaves SSHA 2.5% and equality 7.4% slower. Calibration is not pooled with
primary statistics and does not prove all negative values are noise.

The candidate is not adopted: a reliable overall latency benefit has not been
established. Further work should isolate added calls on ordinary owned Get
paths. Per-operation native parity remains the acceptance criterion.

Focused storage/server tests pass in 3.057s/0.665s. Full tests pass (server
164.070s, schema 89.567s, storage 26.895s, webadmin 0.256s); vet and all 355 native
differential checks pass (9.667s). An initial test incorrectly expected missing
migration metadata to block already schema-aware rows. That expectation was
corrected to the original Get behavior; both logs are retained. No CGO or race
detector was used. Performance runs did not overlap CPU tests/builds/profiling.

Raw JSON is gzip-compressed. Replay scripts require the recovered R20 fixtures
and pinned native reference. Exact build metadata, executable hashes, source
patch and primary/calibration observations are retained. `SHA256SUMS` verifies
the archived files. No complete OpenLDAP compatibility claim is made.

# R25: direct-Get lease qualification

**Not adopted.** The private candidate `160724e` reduces Group1000 Compare
allocation by about 90%, but still has negative latency observations on common
operations. Production server logic remains R22.

The experiment uses 100,000 users, Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`
and pinned OpenLDAP 2.6.13. Seven batches of 1,000 SDK calls run per case.
Times exclude setup, connection establishment, identity checks and cleanup.
Time reduction is `(1-current/before)*100%`; negative means slower.

## Paired network changes

| Operation | Default | Explicit ACL | Default startup/port swap |
| --- | ---: | ---: | ---: |
| Small10 Compare, first | 1.3% | -2.7% | 0.3% |
| Small10 Compare, last | -0.1% | -2.4% | -0.4% |
| Small10 Compare, missing | -1.2% | -3.0% | -1.5% |
| Group1000 Compare, first | 3.0% | 2.6% | 3.5% |
| Group1000 Compare, last | -0.2% | 2.6% | 1.7% |
| Group1000 Compare, missing | 3.4% | 2.1% | 2.5% |

Other operations also have negative observations. Explicit SSHA/plaintext Bind
are 2.5%/5.3% slower in the primary run. The full table and raw samples remain
in the [evidence](evidence/performance-20260930-r25/README.md).

The identical-candidate A/A explicit-ACL run changes Small10 first/last/missing
by +1.1%/+0.4%/-0.2%; SSHA is 1.3% slower under the current label. The real A/B
explicit startup/port swap changes Small10 by -1.9%/-0.2%/-0.3%, Group1000 by
+3.7%/+2.0%/+3.3%, and leaves SSHA 2.5% and equality 7.4% slower. These separate
calibrations do not correct primary statistics or prove regressions are noise.

## Implementation

An explicit lease borrows eligible large binary rows inside the original
read-only Bolt View; ordinary `Reader.Get` retains owned output. The target Get
stays at its original referral-processing checkpoint and authorization still
runs. The lease is released before View returns. DN caches and escaping values
retain their ownership copies.

The initial R24 version checked borrowing eligibility even for small rows.
R25 keeps source/store/normalizer/protocol/control checks early and defers the
remaining pure proof until a binary row of at least 8 KiB has been found.
The check passes synchronously through concrete calls and is never retained.
A rejected version that stored the callback added 48 B and one allocation.

Three alternating 500ms handler repeats show Group1000 allocation falling from
about 82 KiB to 8 KiB per call. Small10 bytes/allocation counts are unchanged;
first/missing component time is approximately flat, while last is 2.3% slower.
Large component times improve 26%-35%. These are hot-loop diagnostics, not
end-to-end or cold-start claims.

## Validation

Full tests, vet and 355 native differential checks pass. Focused checks cover
callback suppression, false-check owned decoding, source identity, error order,
nested leases, release/reuse and panic cleanup. One test expectation about
absent migration metadata was corrected to match the original Get behavior.

Primary runs verify 756 batches and nine exports; calibration adds 504 batches
and six exports. All 15 exports match 100,002 canonical user-data entries.
Physical MDB layout and generated operational attributes are outside this check.
No race detector or CGO was used. No overall parity or universal improvement is
claimed. The current shipped comparison remains [R22](common-ldap-performance-20260930-r22.md),
with verified TLS results in [R23](common-ldap-performance-20260930-r23.md).

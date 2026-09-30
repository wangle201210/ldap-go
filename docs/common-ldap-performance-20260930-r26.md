# R26: owned Get path isolation

**Not adopted.** R26 restores ordinary storage Get implementations to the
shipped R22 bodies while keeping the explicit large-entry lease separate. The
private candidate is `2b00402` in `/var/tmp/ldap-go-direct-get-20260930`.

The candidate passes full Go tests (server 168.730s, schema 90.834s, storage
27.640s, webadmin 0.241s), vet, and all 355 OpenLDAP differential checks
(9.793s). Main remains unchanged at `70e018d`.

Component allocation savings remain for large groups: roughly 82 KiB to 8 KiB
per Compare, with 26%-35% lower component time. Small10 allocations and bytes
match the baseline; Small10 timing remains variable. Bind component timings are
also effectively unchanged.

The final network runs use seven batches of 1,000 calls and nine matching
canonical exports. Group1000 reductions are 5.4%/3.2%/4.7% for first/last/
missing under default access, 6.4%/4.0%/4.1% with explicit ACL, and
6.9%/3.3%/1.1% in the explicit startup/port swap. Small and unchanged paths
contain negative observations. Same-candidate A/A calibration shows Group1000
first -0.9%, last +1.4%, missing +0.1%; therefore the larger positive network
values cannot all be attributed to the lease. Explicit A/B calibration also
leaves Bind and equality slower.

The candidate is retained for further investigation and is not merged. Ordinary
Get now follows the shipped path directly; only the leased Compare entry point
uses the additional storage route. No ACL, referral, error ordering, data format
or authentication behavior is changed. No complete OpenLDAP parity claim is
made; per-operation parity remains unmet.
